//! Blocking, fail-closed retrieval and cache handling for signed agent builds.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use semver::Version;
use sha2::{Digest, Sha256};
use thiserror::Error;
use ureq::http::Response;
use ureq::tls::{TlsConfig, TlsProvider};
use url::Url;

use crate::{
    artifact_url, signature_url, verify_manifest, AgentTarget, Artifact, TrustedKeySet,
    UrlPolicyError, VerificationError, VerifiedManifest, ARTIFACT_MAX_BYTES, MANIFEST_MAX_BYTES,
    SIGNATURE_DOCUMENT_MAX_BYTES,
};

const MAX_REDIRECTS: usize = 5;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Inputs whose trust and compatibility policy must be applied on every fetch.
#[derive(Clone, Debug)]
pub struct FetchConfig<'a> {
    /// Fully expanded (version-specific) manifest URL.
    pub manifest_url: &'a Url,
    pub target: AgentTarget,
    pub expected_version: &'a Version,
    pub expected_protocol_version: u32,
    pub trusted_keys: &'a TrustedKeySet,
    pub signature_threshold: usize,
    pub cache_dir: &'a Path,
    pub cache_max_bytes: u64,
    /// Whole-operation budget, including retrieval, verification, cache I/O,
    /// artifact hashing/copying, and eviction.
    pub timeout: Duration,
}

/// Where the artifact bytes returned to the caller originated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactSource {
    Network,
    File,
    Cache,
}

/// Where the verified manifest/signature pair originated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestSource {
    Network,
    File,
    /// Network retrieval failed in an explicitly recoverable way and a cached
    /// pair passed the current trust policy.
    VerifiedCacheFallback,
}

/// Cache decisions useful to health reporting without exposing cache paths.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheState {
    pub manifest_fallback: bool,
    pub artifact_hit: bool,
}

/// A locally readable artifact whose signed size and digest were rechecked.
#[derive(Clone, Debug)]
pub struct FetchedArtifact {
    /// Cache location for diagnostics. Consumers should stream from
    /// [`Self::try_clone_file`] so the verified object remains pinned.
    pub local_path: PathBuf,
    pub sha256: String,
    pub source: ArtifactSource,
    pub manifest_source: ManifestSource,
    pub cache_state: CacheState,
    pub verified_manifest: VerifiedManifest,
    pub artifact: Artifact,
    // A shared advisory lock prevents cooperative cache eviction until the
    // caller has finished using this result. `Arc` keeps cloning cheap.
    artifact_lease: Arc<File>,
}

impl FetchedArtifact {
    /// Clone the pinned, verified cache handle for streaming without a
    /// path-reopen race. Keeping either this result or the cloned handle alive
    /// prevents cooperative eviction of the cache entry.
    pub fn try_clone_file(&self) -> io::Result<File> {
        let mut file = self.artifact_lease.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkFailureKind {
    Timeout,
    Connection,
    Protocol,
}

/// Stable, machine-readable classification for a registry fetch failure.
///
/// These codes intentionally describe the failure family rather than carrying
/// any URL, path, or other potentially sensitive context. Callers should use
/// [`Self::as_str`] for persistence and protocol fields, and keep
/// [`FetchError`]'s display text for human-facing diagnostics only.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum FetchErrorCode {
    UrlPolicy,
    MalformedManifest,
    MalformedSignature,
    InvalidSignatureThreshold,
    InsufficientSignatures,
    VersionMismatch,
    ProtocolVersionMismatch,
    TargetNotPublished,
    InvalidTimeout,
    OperationDeadline,
    InvalidCacheLimit,
    CacheLockTimeout,
    LocalIo,
    NetworkTimeout,
    NetworkConnection,
    NetworkProtocol,
    HttpRateLimited,
    HttpServerError,
    HttpClientError,
    HttpUnexpectedStatus,
    RedirectLocationMissing,
    RedirectLimitExceeded,
    RedirectPolicy,
    BodyTooLarge,
    ArtifactSizeMismatch,
    ArtifactDigestMismatch,
    FileArtifactEscapes,
    NotRegularFile,
    CacheBudgetExceeded,
    CacheFallbackUnavailable,
}

impl FetchErrorCode {
    /// Return the stable snake-case representation for health and protocol
    /// reporting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UrlPolicy => "url_policy",
            Self::MalformedManifest => "malformed_manifest",
            Self::MalformedSignature => "malformed_signature",
            Self::InvalidSignatureThreshold => "invalid_signature_threshold",
            Self::InsufficientSignatures => "insufficient_signatures",
            Self::VersionMismatch => "version_mismatch",
            Self::ProtocolVersionMismatch => "protocol_version_mismatch",
            Self::TargetNotPublished => "target_not_published",
            Self::InvalidTimeout => "invalid_timeout",
            Self::OperationDeadline => "operation_deadline",
            Self::InvalidCacheLimit => "invalid_cache_limit",
            Self::CacheLockTimeout => "cache_lock_timeout",
            Self::LocalIo => "local_io",
            Self::NetworkTimeout => "network_timeout",
            Self::NetworkConnection => "network_connection",
            Self::NetworkProtocol => "network_protocol",
            Self::HttpRateLimited => "http_rate_limited",
            Self::HttpServerError => "http_server_error",
            Self::HttpClientError => "http_client_error",
            Self::HttpUnexpectedStatus => "http_unexpected_status",
            Self::RedirectLocationMissing => "redirect_location_missing",
            Self::RedirectLimitExceeded => "redirect_limit_exceeded",
            Self::RedirectPolicy => "redirect_policy",
            Self::BodyTooLarge => "body_too_large",
            Self::ArtifactSizeMismatch => "artifact_size_mismatch",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::FileArtifactEscapes => "file_artifact_escapes",
            Self::NotRegularFile => "not_regular_file",
            Self::CacheBudgetExceeded => "cache_budget_exceeded",
            Self::CacheFallbackUnavailable => "cache_fallback_unavailable",
        }
    }
}

impl fmt::Display for FetchErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error(transparent)]
    UrlPolicy(#[from] UrlPolicyError),
    #[error(transparent)]
    Verification(#[from] VerificationError),
    #[error("manifest does not publish an artifact for {0}")]
    TargetNotPublished(AgentTarget),
    #[error("registry timeout must be greater than zero")]
    InvalidTimeout,
    #[error("registry operation deadline elapsed during {phase}")]
    OperationDeadline { phase: &'static str },
    #[error("registry cache limit must be greater than zero")]
    InvalidCacheLimit,
    #[error("timed out waiting for registry cache lock {0}")]
    CacheLockTimeout(PathBuf),
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{kind:?} failure retrieving {url}: {source}")]
    Network {
        kind: NetworkFailureKind,
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    #[error("registry request to {url} returned HTTP {status}")]
    HttpStatus { url: String, status: u16 },
    #[error("redirect from {url} has no valid Location header")]
    MissingRedirectLocation { url: String },
    #[error("registry request exceeded the maximum of {max} redirects")]
    TooManyRedirects { max: usize },
    #[error("redirect from {from} to {to} violates registry policy: {reason}")]
    RedirectPolicy {
        from: String,
        to: String,
        reason: &'static str,
    },
    #[error("{kind} from {url} exceeds the {max}-byte limit")]
    BodyTooLarge {
        kind: &'static str,
        url: String,
        max: u64,
    },
    #[error("artifact {filename:?} has size {actual}, expected {expected}")]
    ArtifactSize {
        filename: String,
        expected: u64,
        actual: u64,
    },
    #[error("artifact {filename:?} has SHA-256 {actual}, expected {expected}")]
    ArtifactDigest {
        filename: String,
        expected: String,
        actual: String,
    },
    #[error("file registry artifact {artifact} escapes manifest directory {manifest_dir}")]
    FileArtifactEscapes {
        artifact: PathBuf,
        manifest_dir: PathBuf,
    },
    #[error("file registry entry is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error(
        "cache requires at least {required} bytes for the selected build, but its limit is {max}"
    )]
    CacheBudget { required: u64, max: u64 },
    #[error("network retrieval failed ({network}); no usable verified cache pair exists: {cache}")]
    CacheFallbackUnavailable { network: String, cache: String },
}

impl FetchError {
    /// Classify this failure without parsing its human-readable display text.
    #[must_use]
    pub const fn code(&self) -> FetchErrorCode {
        match self {
            Self::UrlPolicy(_) => FetchErrorCode::UrlPolicy,
            Self::Verification(error) => match error {
                VerificationError::SignatureDocument(_) => FetchErrorCode::MalformedSignature,
                VerificationError::InvalidThreshold { .. } => {
                    FetchErrorCode::InvalidSignatureThreshold
                }
                VerificationError::InsufficientSignatures { .. } => {
                    FetchErrorCode::InsufficientSignatures
                }
                VerificationError::Manifest(error) => match error {
                    crate::ManifestError::VersionMismatch { .. } => FetchErrorCode::VersionMismatch,
                    crate::ManifestError::ProtocolVersionMismatch { .. } => {
                        FetchErrorCode::ProtocolVersionMismatch
                    }
                    _ => FetchErrorCode::MalformedManifest,
                },
            },
            Self::TargetNotPublished(_) => FetchErrorCode::TargetNotPublished,
            Self::InvalidTimeout => FetchErrorCode::InvalidTimeout,
            Self::OperationDeadline { .. } => FetchErrorCode::OperationDeadline,
            Self::InvalidCacheLimit => FetchErrorCode::InvalidCacheLimit,
            Self::CacheLockTimeout(_) => FetchErrorCode::CacheLockTimeout,
            Self::Io { .. } => FetchErrorCode::LocalIo,
            Self::Network { kind, .. } => match kind {
                NetworkFailureKind::Timeout => FetchErrorCode::NetworkTimeout,
                NetworkFailureKind::Connection => FetchErrorCode::NetworkConnection,
                NetworkFailureKind::Protocol => FetchErrorCode::NetworkProtocol,
            },
            Self::HttpStatus { status: 429, .. } => FetchErrorCode::HttpRateLimited,
            Self::HttpStatus { status, .. } if *status >= 500 && *status <= 599 => {
                FetchErrorCode::HttpServerError
            }
            Self::HttpStatus { status, .. } if *status >= 400 && *status <= 499 => {
                FetchErrorCode::HttpClientError
            }
            Self::HttpStatus { .. } => FetchErrorCode::HttpUnexpectedStatus,
            Self::MissingRedirectLocation { .. } => FetchErrorCode::RedirectLocationMissing,
            Self::TooManyRedirects { .. } => FetchErrorCode::RedirectLimitExceeded,
            Self::RedirectPolicy { .. } => FetchErrorCode::RedirectPolicy,
            Self::BodyTooLarge { .. } => FetchErrorCode::BodyTooLarge,
            Self::ArtifactSize { .. } => FetchErrorCode::ArtifactSizeMismatch,
            Self::ArtifactDigest { .. } => FetchErrorCode::ArtifactDigestMismatch,
            Self::FileArtifactEscapes { .. } => FetchErrorCode::FileArtifactEscapes,
            Self::NotRegularFile(_) => FetchErrorCode::NotRegularFile,
            Self::CacheBudget { .. } => FetchErrorCode::CacheBudgetExceeded,
            Self::CacheFallbackUnavailable { .. } => FetchErrorCode::CacheFallbackUnavailable,
        }
    }

    fn is_cache_fallback_eligible(&self) -> bool {
        match self {
            Self::Network {
                kind: NetworkFailureKind::Timeout | NetworkFailureKind::Connection,
                ..
            } => true,
            Self::HttpStatus { status, .. } => *status == 429 || (500..=599).contains(status),
            _ => false,
        }
    }
}

/// One monotonic deadline shared by every phase of a registry operation.
///
/// Individual filesystem calls cannot be preempted portably, so callers check
/// immediately before and after each bounded syscall and between stream/hash
/// chunks. This prevents later work or cache fallback once the budget expires.
#[derive(Clone, Copy, Debug)]
struct FetchDeadline {
    started: Instant,
    total: Duration,
}

impl FetchDeadline {
    fn from_timeout(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            total: timeout,
        }
    }

    fn check(self, phase: &'static str) -> Result<(), FetchError> {
        if self.remaining_duration().is_zero() {
            Err(FetchError::OperationDeadline { phase })
        } else {
            Ok(())
        }
    }

    fn remaining(self, phase: &'static str) -> Result<Duration, FetchError> {
        let remaining = self.remaining_duration();
        if remaining.is_zero() {
            Err(FetchError::OperationDeadline { phase })
        } else {
            Ok(remaining)
        }
    }

    fn remaining_duration(self) -> Duration {
        self.total.saturating_sub(self.started.elapsed())
    }

    #[cfg(test)]
    fn expired() -> Self {
        Self {
            started: Instant::now()
                .checked_sub(Duration::from_millis(1))
                .unwrap_or_else(Instant::now),
            total: Duration::from_nanos(1),
        }
    }
}

/// Resolve and validate one redirect without performing I/O.
///
/// This intentionally accepts only HTTPS input and output and rejects a
/// redirect to credentials or a local/private literal destination. It is a
/// small pure surface for policy fuzzing as well as the network implementation.
pub fn validate_redirect_url(current: &Url, location: &str) -> Result<Url, FetchError> {
    resolve_redirect(current, location, RedirectPolicyMode::Production)
}

/// Fetch, verify, and cache one platform artifact.
///
/// Cached manifest bytes are only considered after a timeout, connection
/// failure, HTTP 429, or HTTP 5xx response. Regardless of their source,
/// manifests are verified with the keys and threshold in `config`, and cached
/// artifacts are rehashed before this function returns.
/// `config.timeout` is one whole-operation budget; an elapsed budget is never
/// converted into a cache fallback attempt.
pub fn fetch_verified_artifact(config: &FetchConfig<'_>) -> Result<FetchedArtifact, FetchError> {
    fetch_verified_artifact_inner(config, RedirectPolicyMode::Production)
}

fn fetch_verified_artifact_inner(
    config: &FetchConfig<'_>,
    redirect_mode: RedirectPolicyMode,
) -> Result<FetchedArtifact, FetchError> {
    if config.timeout.is_zero() {
        return Err(FetchError::InvalidTimeout);
    }
    if config.cache_max_bytes == 0 {
        return Err(FetchError::InvalidCacheLimit);
    }

    let deadline = FetchDeadline::from_timeout(config.timeout);
    deadline.check("registry URL resolution")?;
    let signature = sibling_url(config.manifest_url, Sibling::Signature, redirect_mode)?;
    deadline.check("registry URL resolution")?;
    let cache = CacheGuard::open(config.cache_dir, config.cache_max_bytes, deadline)?;
    // Enforce a reduced cache limit before consulting any old entries.
    cache.evict_to_budget(&[])?;
    let pair_paths = cache.manifest_paths(config.manifest_url)?;

    let (manifest_bytes, signature_bytes, manifest_source) = match config.manifest_url.scheme() {
        "file" => {
            let manifest = read_file_url_bounded(
                config.manifest_url,
                MANIFEST_MAX_BYTES as u64,
                "manifest",
                deadline,
            )?;
            let signature_bytes = read_file_url_bounded(
                &signature,
                SIGNATURE_DOCUMENT_MAX_BYTES as u64,
                "signature document",
                deadline,
            )?;
            (manifest, signature_bytes, ManifestSource::File)
        }
        "https" => match retrieve_manifest_pair(
            config.manifest_url,
            &signature,
            config.timeout,
            deadline,
            redirect_mode,
        ) {
            Ok((manifest, signature_bytes)) => (manifest, signature_bytes, ManifestSource::Network),
            Err(error) => recover_cached_manifest_pair(&cache, &pair_paths, error)?,
        },
        // Only tests enter here. Production URLs are rejected by sibling_url.
        "http" if redirect_mode == RedirectPolicyMode::LocalTest => {
            match retrieve_manifest_pair(
                config.manifest_url,
                &signature,
                config.timeout,
                deadline,
                redirect_mode,
            ) {
                Ok((manifest, signature_bytes)) => {
                    (manifest, signature_bytes, ManifestSource::Network)
                }
                Err(error) => recover_cached_manifest_pair(&cache, &pair_paths, error)?,
            }
        }
        scheme => {
            return Err(UrlPolicyError::UnsupportedScheme(scheme.to_owned()).into());
        }
    };

    // This is deliberately after every source selection, including cache.
    deadline.check("manifest verification")?;
    let verified_manifest = verify_manifest(
        &manifest_bytes,
        &signature_bytes,
        config.trusted_keys,
        config.signature_threshold,
        config.expected_version,
        config.expected_protocol_version,
    );
    deadline.check("manifest verification")?;
    let verified_manifest = verified_manifest?;
    deadline.check("manifest target selection")?;
    let artifact = verified_manifest
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.target == config.target)
        .cloned()
        .ok_or(FetchError::TargetNotPublished(config.target))?;
    deadline.check("manifest target selection")?;

    // The content-addressed artifact is the only entry that must remain in the
    // cache when this function returns. The manifest pair may be evicted under
    // a deliberately small budget (at the cost of offline fallback).
    let minimum_required = artifact.size;
    if minimum_required > config.cache_max_bytes {
        return Err(FetchError::CacheBudget {
            required: minimum_required,
            max: config.cache_max_bytes,
        });
    }

    if manifest_source != ManifestSource::VerifiedCacheFallback {
        let pair_size = (manifest_bytes.len() as u64).saturating_add(signature_bytes.len() as u64);
        if pair_size <= config.cache_max_bytes {
            cache.write_manifest_pair(&pair_paths, &manifest_bytes, &signature_bytes)?;
            cache.evict_to_budget(&[&pair_paths.manifest, &pair_paths.signature])?;
        } else {
            // Do not leave a stale pair for this immutable URL when the newly
            // verified bytes cannot fit under the current cache policy.
            remove_invalid_cache_entry(&pair_paths.manifest, deadline)?;
            remove_invalid_cache_entry(&pair_paths.signature, deadline)?;
        }
    }

    let artifact_path = cache.artifact_path(&artifact.sha256)?;
    if let Some(artifact_lease) = cache.open_verified_cached_artifact(&artifact_path, &artifact)? {
        cache.touch(&artifact_path)?;
        cache.touch_manifest_pair(&pair_paths)?;
        cache.evict_for_result(
            &artifact_path,
            &pair_paths,
            artifact.size,
            manifest_bytes.len() as u64 + signature_bytes.len() as u64,
        )?;
        deadline.check("registry result preparation")?;
        return Ok(FetchedArtifact {
            local_path: artifact_path,
            sha256: artifact.sha256.clone(),
            source: ArtifactSource::Cache,
            manifest_source,
            cache_state: CacheState {
                manifest_fallback: manifest_source == ManifestSource::VerifiedCacheFallback,
                artifact_hit: true,
            },
            verified_manifest,
            artifact,
            artifact_lease,
        });
    }

    let source = match config.manifest_url.scheme() {
        "file" => {
            let artifact_url = sibling_url(
                config.manifest_url,
                Sibling::Artifact(&artifact.filename),
                redirect_mode,
            )?;
            let source =
                open_contained_file_artifact(config.manifest_url, &artifact_url, deadline)?;
            cache.install_artifact_from_file(source, &artifact_path, &artifact)?;
            ArtifactSource::File
        }
        "https" | "http" => {
            let artifact_url = sibling_url(
                config.manifest_url,
                Sibling::Artifact(&artifact.filename),
                redirect_mode,
            )?;
            cache.install_artifact_from_network(
                &artifact_url,
                &artifact_path,
                &artifact,
                config.timeout,
                redirect_mode,
            )?;
            ArtifactSource::Network
        }
        _ => unreachable!("manifest URL scheme checked above"),
    };

    // Re-open and rehash the published cache entry, rather than trusting the
    // staging handle or rename result.
    let Some(artifact_lease) = cache.open_verified_cached_artifact(&artifact_path, &artifact)?
    else {
        return Err(FetchError::ArtifactDigest {
            filename: artifact.filename.clone(),
            expected: artifact.sha256.clone(),
            actual: "cache changed after verified write".to_owned(),
        });
    };
    cache.touch(&artifact_path)?;
    cache.touch_manifest_pair(&pair_paths)?;
    cache.evict_for_result(
        &artifact_path,
        &pair_paths,
        artifact.size,
        manifest_bytes.len() as u64 + signature_bytes.len() as u64,
    )?;

    deadline.check("registry result preparation")?;
    Ok(FetchedArtifact {
        local_path: artifact_path,
        sha256: artifact.sha256.clone(),
        source,
        manifest_source,
        cache_state: CacheState {
            manifest_fallback: manifest_source == ManifestSource::VerifiedCacheFallback,
            artifact_hit: false,
        },
        verified_manifest,
        artifact,
        artifact_lease,
    })
}

enum ManifestPairRetrievalError {
    Manifest(FetchError),
    Signature {
        fresh_manifest: Vec<u8>,
        error: FetchError,
    },
}

fn recover_cached_manifest_pair(
    cache: &CacheGuard,
    pair_paths: &ManifestCachePaths,
    retrieval_error: ManifestPairRetrievalError,
) -> Result<(Vec<u8>, Vec<u8>, ManifestSource), FetchError> {
    cache.deadline.check("manifest cache fallback")?;
    let (fresh_manifest, network_error) = match retrieval_error {
        ManifestPairRetrievalError::Manifest(error) => (None, error),
        ManifestPairRetrievalError::Signature {
            fresh_manifest,
            error,
        } => (Some(fresh_manifest), error),
    };
    if !network_error.is_cache_fallback_eligible() {
        return Err(network_error);
    }

    let (cached_manifest, cached_signature) = match cache.read_manifest_pair(pair_paths) {
        Ok(pair) => pair,
        Err(error) if error.code() == FetchErrorCode::OperationDeadline => return Err(error),
        Err(cache_error) => {
            return Err(FetchError::CacheFallbackUnavailable {
                network: network_error.to_string(),
                cache: cache_error.to_string(),
            });
        }
    };
    if let Some(fresh_manifest) = fresh_manifest {
        // A transient signature-endpoint failure must not hide a changed or
        // malformed manifest response. Reusing the cached detached signature
        // is safe only when it authenticates the exact bytes just retrieved.
        if fresh_manifest != cached_manifest {
            return Err(network_error);
        }
        cache.deadline.check("manifest cache fallback")?;
        return Ok((
            fresh_manifest,
            cached_signature,
            ManifestSource::VerifiedCacheFallback,
        ));
    }

    cache.deadline.check("manifest cache fallback")?;
    Ok((
        cached_manifest,
        cached_signature,
        ManifestSource::VerifiedCacheFallback,
    ))
}

fn retrieve_manifest_pair(
    manifest_url: &Url,
    signature_url: &Url,
    timeout: Duration,
    deadline: FetchDeadline,
    mode: RedirectPolicyMode,
) -> Result<(Vec<u8>, Vec<u8>), ManifestPairRetrievalError> {
    let agent = http_agent(timeout, mode);
    let manifest = get_bounded(
        &agent,
        manifest_url,
        MANIFEST_MAX_BYTES as u64,
        "manifest",
        deadline,
        mode,
    )
    .map_err(ManifestPairRetrievalError::Manifest)?;
    let signature = match get_bounded(
        &agent,
        signature_url,
        SIGNATURE_DOCUMENT_MAX_BYTES as u64,
        "signature document",
        deadline,
        mode,
    ) {
        Ok(signature) => signature,
        Err(error) => {
            return Err(ManifestPairRetrievalError::Signature {
                fresh_manifest: manifest,
                error,
            });
        }
    };
    Ok((manifest, signature))
}

fn http_agent(timeout: Duration, mode: RedirectPolicyMode) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .https_only(mode == RedirectPolicyMode::Production)
        .proxy(None)
        .user_agent("")
        .accept_encoding("")
        .tls_config(TlsConfig::builder().provider(TlsProvider::Rustls).build())
        .build()
        .new_agent()
}

fn get_bounded(
    agent: &ureq::Agent,
    url: &Url,
    max: u64,
    kind: &'static str,
    deadline: FetchDeadline,
    mode: RedirectPolicyMode,
) -> Result<Vec<u8>, FetchError> {
    deadline.check("network response headers")?;
    let (final_url, mut response) = open_with_redirects(agent, url, deadline, mode)?;
    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    deadline.check("network response headers")?;
    if let Some(length) = content_length {
        if length > max {
            return Err(FetchError::BodyTooLarge {
                kind,
                url: redacted_url(final_url).to_string(),
                max,
            });
        }
    }
    deadline.check("network response headers")?;
    read_bounded(
        response.body_mut().as_reader(),
        max,
        kind,
        final_url,
        deadline,
    )
}

fn open_with_redirects(
    agent: &ureq::Agent,
    initial: &Url,
    deadline: FetchDeadline,
    mode: RedirectPolicyMode,
) -> Result<(Url, Response<ureq::Body>), FetchError> {
    let mut current = initial.clone();
    for redirects in 0..=MAX_REDIRECTS {
        let remaining = deadline.remaining("network request")?;
        let response = agent
            .get(current.as_str())
            .config()
            .timeout_global(Some(remaining))
            .build()
            .call();
        deadline.check("network request")?;
        let response = response.map_err(|source| network_error(current.clone(), source))?;
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if redirects == MAX_REDIRECTS {
                return Err(FetchError::TooManyRedirects { max: MAX_REDIRECTS });
            }
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| FetchError::MissingRedirectLocation {
                    url: redacted_url(current.clone()).to_string(),
                })?;
            current = resolve_redirect(&current, location, mode)?;
            deadline.check("network redirect")?;
            continue;
        }
        if !(200..=299).contains(&status) {
            return Err(FetchError::HttpStatus {
                url: redacted_url(current).to_string(),
                status,
            });
        }
        deadline.check("network response headers")?;
        return Ok((current, response));
    }
    unreachable!("redirect loop always returns at the configured limit")
}

fn network_error(url: Url, source: ureq::Error) -> FetchError {
    let kind = match &source {
        ureq::Error::Timeout(_) => NetworkFailureKind::Timeout,
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => NetworkFailureKind::Connection,
        ureq::Error::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
                    | io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ) =>
        {
            if error.kind() == io::ErrorKind::TimedOut {
                NetworkFailureKind::Timeout
            } else {
                NetworkFailureKind::Connection
            }
        }
        _ => NetworkFailureKind::Protocol,
    };
    FetchError::Network {
        kind,
        url: redacted_url(url).to_string(),
        source: Box::new(source),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RedirectPolicyMode {
    Production,
    LocalTest,
}

fn resolve_redirect(
    current: &Url,
    location: &str,
    mode: RedirectPolicyMode,
) -> Result<Url, FetchError> {
    if !current.username().is_empty()
        || current.password().is_some()
        || url_authority_contains_at(current)
    {
        return Err(FetchError::RedirectPolicy {
            from: redacted_url(current.clone()).to_string(),
            to: "<redacted>".to_owned(),
            reason: "redirect source URL contains credentials",
        });
    }
    if mode == RedirectPolicyMode::Production && current.scheme() != "https" {
        return Err(FetchError::RedirectPolicy {
            from: redacted_url(current.clone()).to_string(),
            to: "<invalid>".to_owned(),
            reason: "redirect source is not HTTPS",
        });
    }
    if raw_redirect_authority_contains_at(location) {
        return Err(FetchError::RedirectPolicy {
            from: redacted_url(current.clone()).to_string(),
            to: "<redacted>".to_owned(),
            reason: "redirect URL contains credentials",
        });
    }
    let target = current
        .join(location)
        .map_err(|_| FetchError::RedirectPolicy {
            from: redacted_url(current.clone()).to_string(),
            to: "<invalid>".to_owned(),
            reason: "Location is not a valid URL reference",
        })?;
    let allowed_scheme = target.scheme() == "https"
        || (mode == RedirectPolicyMode::LocalTest && target.scheme() == "http");
    if !allowed_scheme {
        return Err(FetchError::RedirectPolicy {
            from: redacted_url(current.clone()).to_string(),
            to: redacted_url(target).to_string(),
            reason: "redirect would downgrade or change the HTTPS scheme",
        });
    }
    if !target.username().is_empty()
        || target.password().is_some()
        || url_authority_contains_at(&target)
    {
        return Err(FetchError::RedirectPolicy {
            from: redacted_url(current.clone()).to_string(),
            to: redacted_url(target).to_string(),
            reason: "redirect URL contains credentials",
        });
    }
    if target.fragment().is_some() {
        return Err(FetchError::RedirectPolicy {
            from: redacted_url(current.clone()).to_string(),
            to: redacted_url(target).to_string(),
            reason: "redirect URL contains a fragment",
        });
    }
    if mode == RedirectPolicyMode::Production
        && target
            .host()
            .is_some_and(|host| !crate::url_policy::host_is_globally_routable(host))
    {
        return Err(FetchError::RedirectPolicy {
            from: redacted_url(current.clone()).to_string(),
            to: redacted_url(target).to_string(),
            reason: "redirect destination is local or private",
        });
    }
    Ok(target)
}

fn url_authority_contains_at(url: &Url) -> bool {
    url.as_str()
        .split_once("://")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'))
}

fn raw_redirect_authority_contains_at(location: &str) -> bool {
    let authority = if let Some((_, rest)) = location.split_once("://") {
        Some(rest)
    } else {
        location.strip_prefix("//")
    };
    authority
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| authority.contains('@'))
}

#[derive(Clone, Copy)]
enum Sibling<'a> {
    Signature,
    Artifact(&'a str),
}

fn sibling_url(
    manifest_url: &Url,
    sibling: Sibling<'_>,
    mode: RedirectPolicyMode,
) -> Result<Url, FetchError> {
    if mode == RedirectPolicyMode::Production {
        return match sibling {
            Sibling::Signature => signature_url(manifest_url).map_err(Into::into),
            Sibling::Artifact(filename) => artifact_url(manifest_url, filename).map_err(Into::into),
        };
    }

    let filename = match sibling {
        Sibling::Signature => {
            let name = manifest_url
                .path_segments()
                .and_then(|mut segments| segments.next_back())
                .ok_or(UrlPolicyError::MissingManifestFilename)?;
            format!("{name}.sig")
        }
        Sibling::Artifact(filename) => filename.to_owned(),
    };
    let mut url = manifest_url.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| UrlPolicyError::MissingManifestFilename)?;
        segments.pop();
        segments.push(&filename);
    }
    Ok(url)
}

fn read_bounded(
    mut reader: impl Read,
    max: u64,
    kind: &'static str,
    url: Url,
    deadline: FetchDeadline,
) -> Result<Vec<u8>, FetchError> {
    let capacity = usize::try_from(max.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    let mut remaining = max.saturating_add(1);
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        deadline.check("network response read")?;
        let limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..limit]);
        deadline.check("network response read")?;
        let read = match read {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(network_error(url.clone(), ureq::Error::Io(source))),
        };
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        remaining = remaining.saturating_sub(read as u64);
    }
    if bytes.len() as u64 > max {
        return Err(FetchError::BodyTooLarge {
            kind,
            url: redacted_url(url).to_string(),
            max,
        });
    }
    deadline.check("network response read")?;
    Ok(bytes)
}

fn read_file_url_bounded(
    url: &Url,
    max: u64,
    kind: &'static str,
    deadline: FetchDeadline,
) -> Result<Vec<u8>, FetchError> {
    deadline.check("file registry read")?;
    let path = url
        .to_file_path()
        .map_err(|()| UrlPolicyError::FileUrlNotLocalAbsolute)?;
    let metadata = fs::metadata(&path);
    deadline.check("file registry stat")?;
    let metadata = metadata.map_err(|source| io_error("stat", &path, source))?;
    if !metadata.is_file() {
        return Err(FetchError::NotRegularFile(path));
    }
    if metadata.len() > max {
        return Err(FetchError::BodyTooLarge {
            kind,
            url: redacted_url(url.clone()).to_string(),
            max,
        });
    }
    let file = File::open(&path);
    deadline.check("file registry open")?;
    let mut file = file.map_err(|source| io_error("open", &path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut remaining = max.saturating_add(1);
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        deadline.check("file registry read")?;
        let limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = file.read(&mut buffer[..limit]);
        deadline.check("file registry read")?;
        let read = match read {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(io_error("read", &path, source)),
        };
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        remaining = remaining.saturating_sub(read as u64);
    }
    if bytes.len() as u64 > max {
        return Err(FetchError::BodyTooLarge {
            kind,
            url: redacted_url(url.clone()).to_string(),
            max,
        });
    }
    deadline.check("file registry read")?;
    Ok(bytes)
}

fn open_contained_file_artifact(
    manifest_url: &Url,
    artifact_url: &Url,
    deadline: FetchDeadline,
) -> Result<File, FetchError> {
    deadline.check("file artifact containment")?;
    let manifest_path = manifest_url
        .to_file_path()
        .map_err(|()| UrlPolicyError::FileUrlNotLocalAbsolute)?;
    let manifest_parent = manifest_path
        .parent()
        .ok_or(UrlPolicyError::FileUrlNotLocalAbsolute)?;
    let manifest_dir = fs::canonicalize(manifest_parent);
    deadline.check("file artifact containment")?;
    let manifest_dir =
        manifest_dir.map_err(|source| io_error("canonicalize", manifest_parent, source))?;
    let artifact_path = artifact_url
        .to_file_path()
        .map_err(|()| UrlPolicyError::FileUrlNotLocalAbsolute)?;
    let canonical_artifact = fs::canonicalize(&artifact_path);
    deadline.check("file artifact containment")?;
    let canonical_artifact =
        canonical_artifact.map_err(|source| io_error("canonicalize", &artifact_path, source))?;
    if !canonical_artifact.starts_with(&manifest_dir) {
        return Err(FetchError::FileArtifactEscapes {
            artifact: canonical_artifact,
            manifest_dir,
        });
    }
    let file = File::open(&artifact_path);
    deadline.check("file artifact open")?;
    let file =
        file.map_err(|source| io_error("open file registry artifact", &artifact_path, source))?;
    let opened_metadata = file.metadata();
    deadline.check("file artifact stat")?;
    let opened_metadata = opened_metadata
        .map_err(|source| io_error("stat open file registry artifact", &artifact_path, source))?;
    if !opened_metadata.is_file() {
        return Err(FetchError::NotRegularFile(canonical_artifact));
    }
    // Re-resolve after opening and compare the pinned handle with the resolved
    // entry. This closes the ordinary canonicalize-then-open swap window; the
    // bytes are subsequently copied from this handle, not by reopening a path.
    let canonical_after = fs::canonicalize(&artifact_path);
    deadline.check("file artifact containment")?;
    let canonical_after =
        canonical_after.map_err(|source| io_error("canonicalize", &artifact_path, source))?;
    if !canonical_after.starts_with(&manifest_dir) {
        return Err(FetchError::FileArtifactEscapes {
            artifact: canonical_after,
            manifest_dir,
        });
    }
    let same_identity = same_file_identity(&file, &canonical_after);
    deadline.check("file artifact identity")?;
    if !same_identity
        .map_err(|source| io_error("identify file registry artifact", &artifact_path, source))?
    {
        return Err(io_error(
            "pin file registry artifact",
            &artifact_path,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact changed while it was opened",
            ),
        ));
    }
    deadline.check("file artifact preparation")?;
    Ok(file)
}

#[cfg(unix)]
fn same_file_identity(opened: &File, resolved: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let left = opened.metadata()?;
    let right = fs::metadata(resolved)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_file_identity(opened: &File, resolved: &Path) -> io::Result<bool> {
    use std::ffi::c_void;
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle as _;

    #[repr(C)]
    struct FileTime {
        low_date_time: u32,
        high_date_time: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    fn identity(file: &File) -> io::Result<(u32, u32, u32)> {
        let mut information = MaybeUninit::<ByHandleFileInformation>::uninit();
        // SAFETY: `file` owns a valid Windows handle and `information` points
        // to writable storage of the exact documented C layout.
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if succeeded == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful call initializes the complete output struct.
        let information = unsafe { information.assume_init() };
        Ok((
            information.volume_serial_number,
            information.file_index_high,
            information.file_index_low,
        ))
    }

    let resolved = File::open(resolved)?;
    Ok(identity(opened)? == identity(&resolved)?)
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(_opened: &File, _resolved: &Path) -> io::Result<bool> {
    Ok(false)
}

struct CacheGuard {
    manifests: PathBuf,
    artifacts: PathBuf,
    max_bytes: u64,
    deadline: FetchDeadline,
    _lock: File,
}

struct ManifestCachePaths {
    manifest: PathBuf,
    signature: PathBuf,
}

#[derive(Clone, Copy)]
enum ArtifactReadSource<'a> {
    File,
    Network(&'a Url),
}

impl ArtifactReadSource<'_> {
    fn error(self, destination: &Path, source: io::Error) -> FetchError {
        match self {
            Self::File => io_error("read artifact", destination, source),
            Self::Network(url) => network_error(url.clone(), ureq::Error::Io(source)),
        }
    }
}

impl CacheGuard {
    fn open(root: &Path, max_bytes: u64, deadline: FetchDeadline) -> Result<Self, FetchError> {
        deadline.check("cache directory creation")?;
        let created = fs::create_dir_all(root);
        deadline.check("cache directory creation")?;
        created.map_err(|source| io_error("create cache directory", root, source))?;
        let manifests = root.join("manifests");
        let artifacts = root.join("artifacts");
        let created = fs::create_dir_all(&manifests);
        deadline.check("cache directory creation")?;
        created.map_err(|source| io_error("create cache directory", &manifests, source))?;
        let created = fs::create_dir_all(&artifacts);
        deadline.check("cache directory creation")?;
        created.map_err(|source| io_error("create cache directory", &artifacts, source))?;
        let lock_path = root.join(".lock");
        let lock = open_private(&lock_path, true, false);
        deadline.check("cache lock open")?;
        let lock = lock.map_err(|source| io_error("open cache lock", &lock_path, source))?;
        loop {
            if deadline.check("cache lock wait").is_err() {
                return Err(FetchError::CacheLockTimeout(lock_path));
            }
            let attempt = fs4::FileExt::try_lock(&lock);
            if deadline.check("cache lock wait").is_err() {
                return Err(FetchError::CacheLockTimeout(lock_path));
            }
            match attempt {
                Ok(()) => break,
                Err(fs4::TryLockError::WouldBlock) => {
                    let remaining = deadline
                        .remaining("cache lock wait")
                        .map_err(|_| FetchError::CacheLockTimeout(lock_path.clone()))?;
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Err(fs4::TryLockError::Error(source)) => {
                    return Err(io_error("lock cache", &lock_path, source));
                }
            }
        }
        Ok(Self {
            manifests,
            artifacts,
            max_bytes,
            deadline,
            _lock: lock,
        })
    }

    fn manifest_paths(&self, url: &Url) -> Result<ManifestCachePaths, FetchError> {
        self.deadline.check("manifest cache key")?;
        let key = sha256_hex(url.as_str().as_bytes());
        self.deadline.check("manifest cache key")?;
        Ok(ManifestCachePaths {
            manifest: self.manifests.join(format!("{key}.json")),
            signature: self.manifests.join(format!("{key}.sig")),
        })
    }

    fn artifact_path(&self, digest: &str) -> Result<PathBuf, FetchError> {
        self.deadline.check("artifact cache path")?;
        Ok(self.artifacts.join(digest))
    }

    fn read_manifest_pair(
        &self,
        paths: &ManifestCachePaths,
    ) -> Result<(Vec<u8>, Vec<u8>), FetchError> {
        let manifest = read_cache_file(&paths.manifest, MANIFEST_MAX_BYTES as u64, self.deadline)?;
        let signature = read_cache_file(
            &paths.signature,
            SIGNATURE_DOCUMENT_MAX_BYTES as u64,
            self.deadline,
        )?;
        self.deadline.check("manifest cache read")?;
        Ok((manifest, signature))
    }

    fn write_manifest_pair(
        &self,
        paths: &ManifestCachePaths,
        manifest: &[u8],
        signature: &[u8],
    ) -> Result<(), FetchError> {
        atomic_write(&paths.manifest, manifest, self.deadline)?;
        atomic_write(&paths.signature, signature, self.deadline)?;
        self.touch(&paths.manifest)?;
        self.touch(&paths.signature)?;
        Ok(())
    }

    fn touch_manifest_pair(&self, paths: &ManifestCachePaths) -> Result<(), FetchError> {
        self.touch(&paths.manifest)?;
        self.touch(&paths.signature)
    }

    fn evict_for_result(
        &self,
        artifact_path: &Path,
        pair_paths: &ManifestCachePaths,
        artifact_size: u64,
        pair_size: u64,
    ) -> Result<(), FetchError> {
        self.deadline.check("cache result eviction")?;
        let keep_pair = artifact_size.saturating_add(pair_size) <= self.max_bytes
            && pair_paths.manifest.is_file()
            && pair_paths.signature.is_file();
        self.deadline.check("cache result eviction")?;
        if keep_pair {
            self.evict_to_budget(&[artifact_path, &pair_paths.manifest, &pair_paths.signature])
        } else {
            self.evict_to_budget(&[artifact_path])
        }
    }

    fn open_verified_cached_artifact(
        &self,
        path: &Path,
        artifact: &Artifact,
    ) -> Result<Option<Arc<File>>, FetchError> {
        self.deadline.check("cached artifact stat")?;
        let metadata = fs::symlink_metadata(path);
        self.deadline.check("cached artifact stat")?;
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(io_error("stat cached artifact", path, source)),
        };
        if !metadata.file_type().is_file() || metadata.len() != artifact.size {
            remove_invalid_cache_entry(path, self.deadline)?;
            return Ok(None);
        }
        let file = File::open(path);
        self.deadline.check("cached artifact open")?;
        let file =
            file.map_err(|source| io_error("open verified cached artifact", path, source))?;
        self.deadline.check("cached artifact lease")?;
        let lease = fs4::FileExt::try_lock_shared(&file);
        self.deadline.check("cached artifact lease")?;
        match lease {
            Ok(()) => {}
            Err(fs4::TryLockError::WouldBlock) => {
                return Err(io_error(
                    "lease verified cached artifact",
                    path,
                    io::Error::from(io::ErrorKind::WouldBlock),
                ));
            }
            Err(fs4::TryLockError::Error(source)) => {
                return Err(io_error("lease verified cached artifact", path, source));
            }
        }
        self.deadline.check("cached artifact lease")?;
        let (actual_size, actual_digest) =
            digest_open_file(&file, path, ARTIFACT_MAX_BYTES, self.deadline)?;
        if actual_size != artifact.size || actual_digest != artifact.sha256 {
            drop(file);
            remove_invalid_cache_entry(path, self.deadline)?;
            return Ok(None);
        }
        self.deadline.check("cached artifact verification")?;
        Ok(Some(Arc::new(file)))
    }

    fn install_artifact_from_file(
        &self,
        source: File,
        destination: &Path,
        artifact: &Artifact,
    ) -> Result<(), FetchError> {
        self.install_artifact_reader(source, destination, artifact, ArtifactReadSource::File)
    }

    fn install_artifact_from_network(
        &self,
        url: &Url,
        destination: &Path,
        artifact: &Artifact,
        timeout: Duration,
        mode: RedirectPolicyMode,
    ) -> Result<(), FetchError> {
        self.deadline.check("artifact network request")?;
        let agent = http_agent(timeout, mode);
        let (final_url, mut response) = open_with_redirects(&agent, url, self.deadline, mode)?;
        let content_length = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        self.deadline.check("artifact response headers")?;
        if let Some(length) = content_length {
            if length > ARTIFACT_MAX_BYTES {
                return Err(FetchError::BodyTooLarge {
                    kind: "artifact",
                    url: redacted_url(final_url).to_string(),
                    max: ARTIFACT_MAX_BYTES,
                });
            }
            if length != artifact.size {
                return Err(FetchError::ArtifactSize {
                    filename: artifact.filename.clone(),
                    expected: artifact.size,
                    actual: length,
                });
            }
        }
        self.deadline.check("artifact response headers")?;
        self.install_artifact_reader(
            response.body_mut().as_reader(),
            destination,
            artifact,
            ArtifactReadSource::Network(&final_url),
        )
    }

    fn install_artifact_reader(
        &self,
        mut reader: impl Read,
        destination: &Path,
        artifact: &Artifact,
        source_kind: ArtifactReadSource<'_>,
    ) -> Result<(), FetchError> {
        self.deadline.check("artifact cache copy")?;
        let (temp_path, mut temp) = create_temp_for(destination, self.deadline)?;
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = [0_u8; COPY_BUFFER_BYTES];
            loop {
                self.deadline.check("artifact cache copy")?;
                let read = reader.read(&mut buffer);
                self.deadline.check("artifact cache copy")?;
                let read = match read {
                    Ok(read) => read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(source) => return Err(source_kind.error(destination, source)),
                };
                if read == 0 {
                    break;
                }
                total = total.saturating_add(read as u64);
                if total > ARTIFACT_MAX_BYTES || total > artifact.size {
                    return Err(FetchError::ArtifactSize {
                        filename: artifact.filename.clone(),
                        expected: artifact.size,
                        actual: total,
                    });
                }
                write_all_deadlined(
                    &mut temp,
                    &buffer[..read],
                    self.deadline,
                    "artifact cache write",
                    "write artifact cache",
                    &temp_path,
                )?;
                hasher.update(&buffer[..read]);
                self.deadline.check("artifact digest")?;
            }
            if total != artifact.size {
                return Err(FetchError::ArtifactSize {
                    filename: artifact.filename.clone(),
                    expected: artifact.size,
                    actual: total,
                });
            }
            let digest = hex_bytes(&hasher.finalize());
            if digest != artifact.sha256 {
                return Err(FetchError::ArtifactDigest {
                    filename: artifact.filename.clone(),
                    expected: artifact.sha256.clone(),
                    actual: digest,
                });
            }
            self.deadline.check("artifact cache sync")?;
            let synced = temp.sync_all();
            self.deadline.check("artifact cache sync")?;
            synced.map_err(|source| io_error("sync artifact cache", &temp_path, source))?;
            drop(temp);
            replace_file(&temp_path, destination, self.deadline)?;
            sync_parent(destination, self.deadline)?;
            self.deadline.check("artifact cache activation")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn touch(&self, path: &Path) -> Result<(), FetchError> {
        self.deadline.check("cache recency update")?;
        let opened = OpenOptions::new().write(true).open(path);
        self.deadline.check("cache recency update")?;
        if let Ok(file) = opened {
            let now = SystemTime::now();
            let updated = file.set_times(
                std::fs::FileTimes::new()
                    .set_accessed(now)
                    .set_modified(now),
            );
            self.deadline.check("cache recency update")?;
            let _ = updated;
        }
        Ok(())
    }

    fn evict_to_budget(&self, protected: &[&Path]) -> Result<(), FetchError> {
        self.deadline.check("cache eviction")?;
        let protected: HashSet<PathBuf> = protected.iter().map(|path| path.to_path_buf()).collect();
        let mut files = Vec::new();
        let mut total = 0_u64;
        for directory in [&self.manifests, &self.artifacts] {
            self.deadline.check("cache eviction scan")?;
            let entries = fs::read_dir(directory);
            self.deadline.check("cache eviction scan")?;
            let entries =
                entries.map_err(|source| io_error("read cache directory", directory, source))?;
            for entry in entries {
                self.deadline.check("cache eviction scan")?;
                let entry =
                    entry.map_err(|source| io_error("read cache directory", directory, source))?;
                let path = entry.path();
                let metadata = entry.metadata();
                self.deadline.check("cache eviction scan")?;
                let metadata =
                    metadata.map_err(|source| io_error("stat cache entry", &path, source))?;
                if !metadata.is_file() {
                    continue;
                }
                total = total.saturating_add(metadata.len());
                let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                files.push((modified, path, metadata.len()));
            }
        }
        if total <= self.max_bytes {
            self.deadline.check("cache eviction")?;
            return Ok(());
        }
        self.deadline.check("cache eviction sort")?;
        files.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        self.deadline.check("cache eviction sort")?;
        for (_, path, size) in files {
            self.deadline.check("cache eviction")?;
            if total <= self.max_bytes {
                break;
            }
            if protected.contains(&path) {
                continue;
            }
            let eviction_handle = OpenOptions::new().read(true).write(true).open(&path);
            self.deadline.check("cache eviction open")?;
            let eviction_handle = match eviction_handle {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    total = total.saturating_sub(size);
                    continue;
                }
                Err(source) => {
                    return Err(io_error("open cache entry for eviction", &path, source))
                }
            };
            self.deadline.check("cache eviction lock")?;
            let locked = fs4::FileExt::try_lock(&eviction_handle);
            self.deadline.check("cache eviction lock")?;
            match locked {
                Ok(()) => {}
                Err(fs4::TryLockError::WouldBlock) => continue,
                Err(fs4::TryLockError::Error(source)) => {
                    return Err(io_error("lock cache entry for eviction", &path, source));
                }
            }
            self.deadline.check("cache eviction lock")?;
            let removed = fs::remove_file(&path);
            self.deadline.check("cache eviction remove")?;
            match removed {
                Ok(()) => total = total.saturating_sub(size),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    total = total.saturating_sub(size);
                }
                Err(source) => return Err(io_error("evict cache entry", &path, source)),
            }
        }
        if total > self.max_bytes {
            return Err(FetchError::CacheBudget {
                required: total,
                max: self.max_bytes,
            });
        }
        self.deadline.check("cache eviction")?;
        Ok(())
    }
}

fn read_cache_file(path: &Path, max: u64, deadline: FetchDeadline) -> Result<Vec<u8>, FetchError> {
    deadline.check("registry cache read")?;
    let metadata = fs::symlink_metadata(path);
    deadline.check("registry cache stat")?;
    let metadata =
        metadata.map_err(|source| io_error("stat cached registry data", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(FetchError::NotRegularFile(path.to_owned()));
    }
    if metadata.len() > max {
        return Err(FetchError::Io {
            operation: "read oversized cached registry data",
            path: path.to_owned(),
            source: io::Error::new(io::ErrorKind::InvalidData, "cache entry exceeds limit"),
        });
    }
    let file = File::open(path);
    deadline.check("registry cache open")?;
    let mut file = file.map_err(|source| io_error("open cache entry", path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut remaining = max.saturating_add(1);
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        deadline.check("registry cache read")?;
        let limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = file.read(&mut buffer[..limit]);
        deadline.check("registry cache read")?;
        let read = match read {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(io_error("read cache entry", path, source)),
        };
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        remaining = remaining.saturating_sub(read as u64);
    }
    if bytes.len() as u64 > max {
        return Err(FetchError::Io {
            operation: "read oversized cached registry data",
            path: path.to_owned(),
            source: io::Error::new(io::ErrorKind::InvalidData, "cache entry exceeds limit"),
        });
    }
    deadline.check("registry cache read")?;
    Ok(bytes)
}

fn digest_open_file(
    file: &File,
    path: &Path,
    max: u64,
    deadline: FetchDeadline,
) -> Result<(u64, String), FetchError> {
    deadline.check("cached artifact digest")?;
    let mut reader = file;
    let sought = reader.seek(SeekFrom::Start(0));
    deadline.check("cached artifact seek")?;
    sought.map_err(|source| io_error("seek cached artifact", path, source))?;
    let result = (|| {
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            deadline.check("cached artifact digest")?;
            let read = reader.read(&mut buffer);
            deadline.check("cached artifact digest")?;
            let read = match read {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(io_error("read cached artifact", path, source)),
            };
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > max {
                return Ok((total, String::new()));
            }
            hasher.update(&buffer[..read]);
            deadline.check("cached artifact digest")?;
        }
        Ok((total, hex_bytes(&hasher.finalize())))
    })();
    if matches!(&result, Err(error) if error.code() == FetchErrorCode::OperationDeadline) {
        return result;
    }
    let rewound = reader.seek(SeekFrom::Start(0));
    deadline.check("cached artifact rewind")?;
    rewound.map_err(|source| io_error("rewind cached artifact", path, source))?;
    result
}

fn atomic_write(
    destination: &Path,
    bytes: &[u8],
    deadline: FetchDeadline,
) -> Result<(), FetchError> {
    deadline.check("cache entry write")?;
    let (temp_path, mut temp) = create_temp_for(destination, deadline)?;
    let result = (|| {
        for chunk in bytes.chunks(COPY_BUFFER_BYTES) {
            write_all_deadlined(
                &mut temp,
                chunk,
                deadline,
                "cache entry write",
                "write cache entry",
                &temp_path,
            )?;
        }
        deadline.check("cache entry sync")?;
        let synced = temp.sync_all();
        deadline.check("cache entry sync")?;
        synced.map_err(|source| io_error("sync cache entry", &temp_path, source))?;
        drop(temp);
        replace_file(&temp_path, destination, deadline)?;
        sync_parent(destination, deadline)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn write_all_deadlined(
    writer: &mut impl Write,
    mut bytes: &[u8],
    deadline: FetchDeadline,
    phase: &'static str,
    operation: &'static str,
    path: &Path,
) -> Result<(), FetchError> {
    while !bytes.is_empty() {
        deadline.check(phase)?;
        let written = writer.write(bytes);
        deadline.check(phase)?;
        match written {
            Ok(0) => {
                return Err(io_error(
                    operation,
                    path,
                    io::Error::from(io::ErrorKind::WriteZero),
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => return Err(io_error(operation, path, source)),
        }
    }
    Ok(())
}

fn create_temp_for(
    destination: &Path,
    deadline: FetchDeadline,
) -> Result<(PathBuf, File), FetchError> {
    deadline.check("cache temporary file creation")?;
    let parent = destination.parent().ok_or_else(|| FetchError::Io {
        operation: "create cache temporary file",
        path: destination.to_owned(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent"),
    })?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("entry");
    for _ in 0..128 {
        deadline.check("cache temporary file creation")?;
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), sequence));
        let opened = open_private(&path, true, true);
        deadline.check("cache temporary file creation")?;
        match opened {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("create cache temporary file", &path, source)),
        }
    }
    Err(FetchError::Io {
        operation: "create cache temporary file",
        path: destination.to_owned(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary name attempts exhausted",
        ),
    })
}

fn open_private(path: &Path, write: bool, create_new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(not(windows))]
fn replace_file(
    source: &Path,
    destination: &Path,
    deadline: FetchDeadline,
) -> Result<(), FetchError> {
    deadline.check("cache entry replacement")?;
    let replaced = fs::rename(source, destination);
    deadline.check("cache entry replacement")?;
    replaced.map_err(|source| io_error("replace cache entry", destination, source))
}

#[cfg(windows)]
fn replace_file(
    source: &Path,
    destination: &Path,
    deadline: FetchDeadline,
) -> Result<(), FetchError> {
    use std::os::windows::ffi::OsStrExt as _;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    deadline.check("cache entry replacement")?;
    let existing: Vec<u16> = source.as_os_str().encode_wide().chain([0]).collect();
    let replacement: Vec<u16> = destination.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: both pointers refer to live, NUL-terminated UTF-16 buffers for
    // the duration of the call, and the flags are documented MoveFileExW bits.
    let replaced = unsafe {
        MoveFileExW(
            existing.as_ptr(),
            replacement.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    deadline.check("cache entry replacement")?;
    if replaced == 0 {
        return Err(io_error(
            "replace cache entry",
            destination,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn remove_invalid_cache_entry(path: &Path, deadline: FetchDeadline) -> Result<(), FetchError> {
    deadline.check("invalid cache entry removal")?;
    let removed = fs::remove_file(path);
    deadline.check("invalid cache entry removal")?;
    match removed {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove invalid cache entry", path, source)),
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path, deadline: FetchDeadline) -> Result<(), FetchError> {
    deadline.check("cache directory sync")?;
    let parent = path.parent().ok_or_else(|| FetchError::Io {
        operation: "sync cache directory",
        path: path.to_owned(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent"),
    })?;
    let directory = File::open(parent);
    deadline.check("cache directory sync")?;
    let directory = directory.map_err(|source| io_error("open cache directory", parent, source))?;
    let synced = directory.sync_all();
    deadline.check("cache directory sync")?;
    synced.map_err(|source| io_error("sync cache directory", parent, source))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path, deadline: FetchDeadline) -> Result<(), FetchError> {
    deadline.check("cache directory sync")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn redacted_url(mut url: Url) -> Url {
    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("");
        let _ = url.set_password(None);
    }
    if url.query().is_some() {
        url.set_query(Some("redacted"));
    }
    url.set_fragment(None);
    url
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> FetchError {
    FetchError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    const VERSION_TEXT: &str = "0.1.0";
    const PROTOCOL_VERSION: u32 = 7;
    const TARGET: AgentTarget = AgentTarget::Aarch64AppleDarwin;
    const FILENAME: &str = "nrm-agent-0.1.0-aarch64-apple-darwin";

    fn version() -> Version {
        Version::parse(VERSION_TEXT).unwrap()
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn trusted_key(key_id: &str, key: &SigningKey) -> TrustedKeySet {
        TrustedKeySet::from_base64([(
            key_id.to_owned(),
            STANDARD.encode(key.verifying_key().as_bytes()),
        )])
        .unwrap()
    }

    fn assert_code(error: FetchError, expected: FetchErrorCode) {
        assert_eq!(error.code(), expected, "{error}");
        assert_eq!(error.code().to_string(), expected.as_str());
    }

    fn test_network_error(kind: NetworkFailureKind) -> FetchError {
        FetchError::Network {
            kind,
            url: "https://registry.example/manifest.json".to_owned(),
            source: Box::new(ureq::Error::Io(io::Error::other("test failure"))),
        }
    }

    #[test]
    fn fetch_error_codes_are_stable_and_unique() {
        let codes = [
            FetchErrorCode::UrlPolicy,
            FetchErrorCode::MalformedManifest,
            FetchErrorCode::MalformedSignature,
            FetchErrorCode::InvalidSignatureThreshold,
            FetchErrorCode::InsufficientSignatures,
            FetchErrorCode::VersionMismatch,
            FetchErrorCode::ProtocolVersionMismatch,
            FetchErrorCode::TargetNotPublished,
            FetchErrorCode::InvalidTimeout,
            FetchErrorCode::OperationDeadline,
            FetchErrorCode::InvalidCacheLimit,
            FetchErrorCode::CacheLockTimeout,
            FetchErrorCode::LocalIo,
            FetchErrorCode::NetworkTimeout,
            FetchErrorCode::NetworkConnection,
            FetchErrorCode::NetworkProtocol,
            FetchErrorCode::HttpRateLimited,
            FetchErrorCode::HttpServerError,
            FetchErrorCode::HttpClientError,
            FetchErrorCode::HttpUnexpectedStatus,
            FetchErrorCode::RedirectLocationMissing,
            FetchErrorCode::RedirectLimitExceeded,
            FetchErrorCode::RedirectPolicy,
            FetchErrorCode::BodyTooLarge,
            FetchErrorCode::ArtifactSizeMismatch,
            FetchErrorCode::ArtifactDigestMismatch,
            FetchErrorCode::FileArtifactEscapes,
            FetchErrorCode::NotRegularFile,
            FetchErrorCode::CacheBudgetExceeded,
            FetchErrorCode::CacheFallbackUnavailable,
        ];
        let strings: HashSet<_> = codes.into_iter().map(FetchErrorCode::as_str).collect();
        assert_eq!(strings.len(), codes.len());
        assert!(strings.iter().all(|code| {
            !code.is_empty()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        }));
    }

    #[test]
    fn fetch_error_code_classifies_top_level_failure_families() {
        assert_code(
            FetchError::UrlPolicy(UrlPolicyError::VersionPlaceholderCount),
            FetchErrorCode::UrlPolicy,
        );
        assert_code(
            FetchError::TargetNotPublished(TARGET),
            FetchErrorCode::TargetNotPublished,
        );
        assert_code(FetchError::InvalidTimeout, FetchErrorCode::InvalidTimeout);
        assert_code(
            FetchError::OperationDeadline { phase: "test" },
            FetchErrorCode::OperationDeadline,
        );
        assert_code(
            FetchError::InvalidCacheLimit,
            FetchErrorCode::InvalidCacheLimit,
        );
        assert_code(
            FetchError::CacheLockTimeout(PathBuf::from("cache.lock")),
            FetchErrorCode::CacheLockTimeout,
        );
        assert_code(
            FetchError::Io {
                operation: "open",
                path: PathBuf::from("cache"),
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            },
            FetchErrorCode::LocalIo,
        );

        for (kind, code) in [
            (NetworkFailureKind::Timeout, FetchErrorCode::NetworkTimeout),
            (
                NetworkFailureKind::Connection,
                FetchErrorCode::NetworkConnection,
            ),
            (
                NetworkFailureKind::Protocol,
                FetchErrorCode::NetworkProtocol,
            ),
        ] {
            assert_code(test_network_error(kind), code);
        }
        for (status, code) in [
            (429, FetchErrorCode::HttpRateLimited),
            (500, FetchErrorCode::HttpServerError),
            (599, FetchErrorCode::HttpServerError),
            (400, FetchErrorCode::HttpClientError),
            (499, FetchErrorCode::HttpClientError),
            (304, FetchErrorCode::HttpUnexpectedStatus),
            (600, FetchErrorCode::HttpUnexpectedStatus),
        ] {
            assert_code(
                FetchError::HttpStatus {
                    url: "https://registry.example/manifest.json".to_owned(),
                    status,
                },
                code,
            );
        }

        assert_code(
            FetchError::MissingRedirectLocation {
                url: "https://registry.example/manifest.json".to_owned(),
            },
            FetchErrorCode::RedirectLocationMissing,
        );
        assert_code(
            FetchError::TooManyRedirects { max: 5 },
            FetchErrorCode::RedirectLimitExceeded,
        );
        assert_code(
            FetchError::RedirectPolicy {
                from: "https://registry.example/manifest.json".to_owned(),
                to: "http://registry.example/manifest.json".to_owned(),
                reason: "test policy",
            },
            FetchErrorCode::RedirectPolicy,
        );
        assert_code(
            FetchError::BodyTooLarge {
                kind: "artifact",
                url: "https://registry.example/artifact".to_owned(),
                max: 1,
            },
            FetchErrorCode::BodyTooLarge,
        );
        assert_code(
            FetchError::ArtifactSize {
                filename: "artifact".to_owned(),
                expected: 1,
                actual: 2,
            },
            FetchErrorCode::ArtifactSizeMismatch,
        );
        assert_code(
            FetchError::ArtifactDigest {
                filename: "artifact".to_owned(),
                expected: "00".to_owned(),
                actual: "11".to_owned(),
            },
            FetchErrorCode::ArtifactDigestMismatch,
        );
        assert_code(
            FetchError::FileArtifactEscapes {
                artifact: PathBuf::from("artifact"),
                manifest_dir: PathBuf::from("registry"),
            },
            FetchErrorCode::FileArtifactEscapes,
        );
        assert_code(
            FetchError::NotRegularFile(PathBuf::from("manifest")),
            FetchErrorCode::NotRegularFile,
        );
        assert_code(
            FetchError::CacheBudget {
                required: 2,
                max: 1,
            },
            FetchErrorCode::CacheBudgetExceeded,
        );
        assert_code(
            FetchError::CacheFallbackUnavailable {
                network: "offline".to_owned(),
                cache: "missing".to_owned(),
            },
            FetchErrorCode::CacheFallbackUnavailable,
        );
    }

    #[test]
    fn fetch_error_code_distinguishes_compatibility_from_malformed_manifests() {
        let malformed = [
            crate::ManifestError::TooLarge { actual: 2, max: 1 },
            crate::ManifestError::Json(
                serde_json::from_slice::<serde_json::Value>(b"{").unwrap_err(),
            ),
            crate::ManifestError::UnsupportedSchema(2),
            crate::ManifestError::WrongPackage("other".to_owned()),
            crate::ManifestError::InvalidVersion {
                value: "not-semver".to_owned(),
                source: Version::parse("not-semver").unwrap_err(),
            },
            crate::ManifestError::InvalidSourceCommit,
            crate::ManifestError::ArtifactCount { actual: 0, max: 6 },
            crate::ManifestError::UnsupportedTarget("other".to_owned()),
            crate::ManifestError::DuplicateTarget(TARGET),
            crate::ManifestError::InvalidFilename {
                actual: "bad".to_owned(),
                expected: FILENAME.to_owned(),
            },
            crate::ManifestError::InvalidSha256 { target: TARGET },
            crate::ManifestError::InvalidSize {
                target: TARGET,
                actual: 0,
                max: ARTIFACT_MAX_BYTES,
            },
        ];
        for error in malformed {
            assert_code(
                FetchError::Verification(VerificationError::Manifest(error)),
                FetchErrorCode::MalformedManifest,
            );
        }

        assert_code(
            FetchError::Verification(VerificationError::Manifest(
                crate::ManifestError::VersionMismatch {
                    actual: Version::new(0, 2, 0),
                    expected: version(),
                },
            )),
            FetchErrorCode::VersionMismatch,
        );
        assert_code(
            FetchError::Verification(VerificationError::Manifest(
                crate::ManifestError::ProtocolVersionMismatch {
                    actual: PROTOCOL_VERSION + 1,
                    expected: PROTOCOL_VERSION,
                },
            )),
            FetchErrorCode::ProtocolVersionMismatch,
        );
    }

    #[test]
    fn fetch_error_code_classifies_all_signature_verification_families() {
        let malformed = [
            crate::SignatureError::TooLarge { actual: 2, max: 1 },
            crate::SignatureError::Json(
                serde_json::from_slice::<serde_json::Value>(b"{").unwrap_err(),
            ),
            crate::SignatureError::UnsupportedSchema(2),
            crate::SignatureError::SignatureCount { actual: 0, max: 32 },
            crate::SignatureError::InvalidKeyId("bad key".to_owned()),
            crate::SignatureError::DuplicateKeyId("key".to_owned()),
            crate::SignatureError::InvalidSignatureEncoding {
                key_id: "key".to_owned(),
            },
        ];
        for error in malformed {
            assert_code(
                FetchError::Verification(VerificationError::SignatureDocument(error)),
                FetchErrorCode::MalformedSignature,
            );
        }
        assert_code(
            FetchError::Verification(VerificationError::InvalidThreshold {
                threshold: 0,
                trusted_keys: 1,
            }),
            FetchErrorCode::InvalidSignatureThreshold,
        );
        assert_code(
            FetchError::Verification(VerificationError::InsufficientSignatures {
                required: 2,
                actual: 1,
            }),
            FetchErrorCode::InsufficientSignatures,
        );
    }

    fn manifest_bytes(artifact: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "package": "nrm-agent",
            "version": VERSION_TEXT,
            "protocol_version": PROTOCOL_VERSION,
            "source_commit": "0123456789abcdef0123456789abcdef01234567",
            "artifacts": [{
                "target": TARGET.as_str(),
                "filename": FILENAME,
                "sha256": sha256_hex(artifact),
                "size": artifact.len(),
            }]
        }))
        .unwrap()
    }

    fn signature_bytes(manifest: &[u8], key_id: &str, key: &SigningKey) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "signatures": [{
                "key_id": key_id,
                "signature": STANDARD.encode(key.sign(manifest).to_bytes()),
            }]
        }))
        .unwrap()
    }

    fn config<'a>(
        url: &'a Url,
        expected_version: &'a Version,
        trusted_keys: &'a TrustedKeySet,
        cache_dir: &'a Path,
        cache_max_bytes: u64,
    ) -> FetchConfig<'a> {
        FetchConfig {
            manifest_url: url,
            target: TARGET,
            expected_version,
            expected_protocol_version: PROTOCOL_VERSION,
            trusted_keys,
            signature_threshold: 1,
            cache_dir,
            cache_max_bytes,
            timeout: Duration::from_secs(2),
        }
    }

    fn http_response(
        status: u16,
        reason: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n");
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    fn ok(body: &[u8]) -> Vec<u8> {
        http_response(
            200,
            "OK",
            &[("Content-Length", body.len().to_string())],
            body,
        )
    }

    fn status(code: u16) -> Vec<u8> {
        http_response(code, "Test", &[("Content-Length", "0".to_owned())], &[])
    }

    type Handler = dyn Fn(&str) -> Vec<u8> + Send + Sync + 'static;

    struct TestServer {
        address: std::net::SocketAddr,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl TestServer {
        fn spawn(handler: Arc<Handler>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread = thread::spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let path = read_request_path(&mut stream);
                            let response = handler(&path);
                            let _ = stream.write_all(&response);
                            let _ = stream.flush();
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                address,
                stop,
                thread: Some(thread),
            }
        }

        fn url(&self, path: &str) -> Url {
            Url::parse(&format!("http://{}{path}", self.address)).unwrap()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(self.address);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    fn read_request_path(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while request.len() < 16 * 1024 {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&request)
            .lines()
            .next()
            .and_then(|line| line.split_ascii_whitespace().nth(1))
            .unwrap_or("/")
            .to_owned()
    }

    #[test]
    fn redirect_policy_rejects_downgrades_credentials_and_local_literals() {
        let current = Url::parse("https://registry.example/releases/manifest.json").unwrap();
        assert!(validate_redirect_url(&current, "../artifact?token=value").is_ok());

        for location in [
            "http://registry.example/manifest.json",
            "https://user:secret@registry.example/manifest.json",
            "https://@registry.example/manifest.json",
            "https://registry.localhost/manifest.json",
            "https://127.0.0.1/manifest.json",
            "https://[::127.0.0.1]/manifest.json",
            "https://[::ffff:127.0.0.1]/manifest.json",
            "https://[2001:db8::1]/manifest.json",
        ] {
            assert!(
                validate_redirect_url(&current, location).is_err(),
                "{location}"
            );
        }

        let error = validate_redirect_url(
            &Url::parse("https://user:source-secret@registry.example/manifest.json").unwrap(),
            "https://registry.example/next",
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("source-secret"));
    }

    #[test]
    fn follows_at_most_five_redirects() {
        let requests = Arc::new(AtomicUsize::new(0));
        let handler_requests = Arc::clone(&requests);
        let server = TestServer::spawn(Arc::new(move |_| {
            handler_requests.fetch_add(1, Ordering::Relaxed);
            http_response(302, "Found", &[("Location", "/loop".to_owned())], &[])
        }));
        let agent = http_agent(Duration::from_secs(2), RedirectPolicyMode::LocalTest);
        let error = open_with_redirects(
            &agent,
            &server.url("/loop"),
            FetchDeadline::from_timeout(Duration::from_secs(2)),
            RedirectPolicyMode::LocalTest,
        )
        .unwrap_err();
        assert!(matches!(error, FetchError::TooManyRedirects { max: 5 }));
        assert_eq!(requests.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn redirected_query_secrets_are_redacted_from_errors() {
        let server = TestServer::spawn(Arc::new(move |path| {
            if path == "/start" {
                http_response(
                    302,
                    "Found",
                    &[("Location", "/failure?token=very-secret".to_owned())],
                    &[],
                )
            } else {
                status(500)
            }
        }));
        let agent = http_agent(Duration::from_secs(2), RedirectPolicyMode::LocalTest);
        let error = open_with_redirects(
            &agent,
            &server.url("/start"),
            FetchDeadline::from_timeout(Duration::from_secs(2)),
            RedirectPolicyMode::LocalTest,
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("very-secret"));
        assert!(error.contains("redacted"));
    }

    #[test]
    fn common_offline_io_errors_are_cache_fallback_eligible() {
        for kind in [
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
        ] {
            let error = network_error(
                Url::parse("https://registry.example/manifest.json").unwrap(),
                ureq::Error::Io(io::Error::from(kind)),
            );
            assert!(error.is_cache_fallback_eligible(), "{kind:?}");
        }

        for status in [429, 500, 503, 599] {
            assert!(FetchError::HttpStatus {
                url: "https://registry.example/manifest.json".to_owned(),
                status,
            }
            .is_cache_fallback_eligible());
        }
        for status in [400, 404, 408, 600] {
            assert!(!FetchError::HttpStatus {
                url: "https://registry.example/manifest.json".to_owned(),
                status,
            }
            .is_cache_fallback_eligible());
        }
    }

    #[derive(Clone, Copy)]
    enum ServerMode {
        Online,
        Status(u16),
        Malformed,
        Truncated,
        OversizedManifest,
        ArtifactFailure,
        SignatureStatus(u16),
        ChangedManifestSignatureStatus(u16),
        MalformedManifestSignatureStatus(u16),
        ArtifactTruncated,
        ArtifactCorrupt,
    }

    struct NetworkFixture {
        _server: TestServer,
        url: Url,
        mode: Arc<Mutex<ServerMode>>,
        manifest: Vec<u8>,
        signature: Vec<u8>,
        artifact: Vec<u8>,
    }

    impl NetworkFixture {
        fn new(artifact: Vec<u8>, key_id: &str, key: &SigningKey) -> Self {
            let manifest = manifest_bytes(&artifact);
            let signature = signature_bytes(&manifest, key_id, key);
            let malformed = b"{".to_vec();
            let malformed_signature = signature_bytes(&malformed, key_id, key);
            let mut changed_manifest = manifest.clone();
            changed_manifest.push(b'\n');
            let mode = Arc::new(Mutex::new(ServerMode::Online));
            let handler_mode = Arc::clone(&mode);
            let handler_manifest = manifest.clone();
            let handler_signature = signature.clone();
            let handler_artifact = artifact.clone();
            let server = TestServer::spawn(Arc::new(move |path| {
                let selected = *handler_mode.lock().unwrap();
                if path == "/manifest.json" {
                    return match selected {
                        ServerMode::Online
                        | ServerMode::ArtifactFailure
                        | ServerMode::SignatureStatus(_)
                        | ServerMode::ArtifactTruncated
                        | ServerMode::ArtifactCorrupt => ok(&handler_manifest),
                        ServerMode::ChangedManifestSignatureStatus(_) => ok(&changed_manifest),
                        ServerMode::MalformedManifestSignatureStatus(_) => ok(&malformed),
                        ServerMode::Status(code) => status(code),
                        ServerMode::Malformed => ok(&malformed),
                        ServerMode::Truncated => http_response(
                            200,
                            "OK",
                            &[("Content-Length", (handler_manifest.len() + 10).to_string())],
                            &handler_manifest[..handler_manifest.len() / 2],
                        ),
                        ServerMode::OversizedManifest => http_response(
                            200,
                            "OK",
                            &[(
                                "Content-Length",
                                (MANIFEST_MAX_BYTES as u64 + 1).to_string(),
                            )],
                            &[],
                        ),
                    };
                }
                if path == "/manifest.json.sig" {
                    return match selected {
                        ServerMode::Malformed => ok(&malformed_signature),
                        ServerMode::SignatureStatus(code)
                        | ServerMode::ChangedManifestSignatureStatus(code)
                        | ServerMode::MalformedManifestSignatureStatus(code) => status(code),
                        _ => ok(&handler_signature),
                    };
                }
                if path == format!("/{FILENAME}") {
                    return match selected {
                        ServerMode::ArtifactFailure => status(500),
                        ServerMode::ArtifactTruncated => http_response(
                            200,
                            "OK",
                            &[("Content-Length", handler_artifact.len().to_string())],
                            &handler_artifact[..handler_artifact.len() / 2],
                        ),
                        ServerMode::ArtifactCorrupt => {
                            let mut corrupt = handler_artifact.clone();
                            corrupt[0] ^= 0xff;
                            ok(&corrupt)
                        }
                        _ => ok(&handler_artifact),
                    };
                }
                status(404)
            }));
            let url = server.url("/manifest.json");
            Self {
                _server: server,
                url,
                mode,
                manifest,
                signature,
                artifact,
            }
        }

        fn set_mode(&self, mode: ServerMode) {
            *self.mode.lock().unwrap() = mode;
        }
    }

    #[test]
    fn network_cache_fallback_is_allowlisted_and_reverified_with_current_trust() {
        let temp = TempDir::new().unwrap();
        let key = signing_key(1);
        let trusted = trusted_key("old", &key);
        let fixture = NetworkFixture::new(b"verified agent bytes".to_vec(), "old", &key);
        let expected_version = version();
        let fetch_config = config(
            &fixture.url,
            &expected_version,
            &trusted,
            temp.path(),
            2 * 1024 * 1024,
        );

        let fetched =
            fetch_verified_artifact_inner(&fetch_config, RedirectPolicyMode::LocalTest).unwrap();
        assert_eq!(fetched.source, ArtifactSource::Network);
        assert_eq!(fetched.manifest_source, ManifestSource::Network);

        fixture.set_mode(ServerMode::Status(503));
        let fallback =
            fetch_verified_artifact_inner(&fetch_config, RedirectPolicyMode::LocalTest).unwrap();
        assert_eq!(fallback.source, ArtifactSource::Cache);
        assert_eq!(
            fallback.manifest_source,
            ManifestSource::VerifiedCacheFallback
        );
        assert_eq!(
            fallback.cache_state,
            CacheState {
                manifest_fallback: true,
                artifact_hit: true
            }
        );

        fixture.set_mode(ServerMode::Truncated);
        let truncated =
            fetch_verified_artifact_inner(&fetch_config, RedirectPolicyMode::LocalTest).unwrap();
        assert_eq!(
            truncated.manifest_source,
            ManifestSource::VerifiedCacheFallback
        );

        fixture.set_mode(ServerMode::Status(404));
        assert!(matches!(
            fetch_verified_artifact_inner(&fetch_config, RedirectPolicyMode::LocalTest),
            Err(FetchError::HttpStatus { status: 404, .. })
        ));

        fixture.set_mode(ServerMode::OversizedManifest);
        assert!(matches!(
            fetch_verified_artifact_inner(&fetch_config, RedirectPolicyMode::LocalTest),
            Err(FetchError::BodyTooLarge {
                kind: "manifest",
                ..
            })
        ));

        fixture.set_mode(ServerMode::Malformed);
        assert!(matches!(
            fetch_verified_artifact_inner(&fetch_config, RedirectPolicyMode::LocalTest),
            Err(FetchError::Verification(_))
        ));

        fixture.set_mode(ServerMode::Status(503));
        let new_key = signing_key(2);
        let new_trust = trusted_key("new", &new_key);
        let rotated = config(
            &fixture.url,
            &expected_version,
            &new_trust,
            temp.path(),
            2 * 1024 * 1024,
        );
        assert!(matches!(
            fetch_verified_artifact_inner(&rotated, RedirectPolicyMode::LocalTest),
            Err(FetchError::Verification(
                VerificationError::InsufficientSignatures { .. }
            ))
        ));
    }

    #[test]
    fn signature_outage_uses_cache_only_for_the_exact_fresh_manifest() {
        let temp = TempDir::new().unwrap();
        let key = signing_key(12);
        let trusted = trusted_key("release", &key);
        let fixture = NetworkFixture::new(b"verified agent bytes".to_vec(), "release", &key);
        let expected_version = version();
        let config = config(
            &fixture.url,
            &expected_version,
            &trusted,
            temp.path(),
            2 * 1024 * 1024,
        );

        fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest).unwrap();

        fixture.set_mode(ServerMode::SignatureStatus(503));
        let exact = fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest).unwrap();
        assert_eq!(exact.manifest_source, ManifestSource::VerifiedCacheFallback);
        assert!(exact.cache_state.manifest_fallback);

        fixture.set_mode(ServerMode::ChangedManifestSignatureStatus(503));
        assert!(matches!(
            fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest),
            Err(FetchError::HttpStatus { status: 503, .. })
        ));

        fixture.set_mode(ServerMode::MalformedManifestSignatureStatus(503));
        assert!(matches!(
            fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest),
            Err(FetchError::HttpStatus { status: 503, .. })
        ));

        // Neither rejected response may replace or poison the exact cached
        // pair used for a later signature-only outage.
        fixture.set_mode(ServerMode::SignatureStatus(503));
        let exact_again =
            fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest).unwrap();
        assert_eq!(
            exact_again.manifest_source,
            ManifestSource::VerifiedCacheFallback
        );
    }

    #[test]
    fn poisoned_manifest_cache_is_never_used() {
        let temp = TempDir::new().unwrap();
        let key = signing_key(3);
        let trusted = trusted_key("release", &key);
        let fixture = NetworkFixture::new(b"agent".to_vec(), "release", &key);
        let expected_version = version();
        let config = config(
            &fixture.url,
            &expected_version,
            &trusted,
            temp.path(),
            1024 * 1024,
        );
        fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest).unwrap();

        let key = sha256_hex(fixture.url.as_str().as_bytes());
        fs::write(
            temp.path().join("manifests").join(format!("{key}.json")),
            b"{}",
        )
        .unwrap();
        fixture.set_mode(ServerMode::Status(503));
        assert!(matches!(
            fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest),
            Err(FetchError::Verification(_))
        ));
    }

    #[test]
    fn cache_stays_bounded_when_artifact_retrieval_fails() {
        let temp = TempDir::new().unwrap();
        let key = signing_key(4);
        let trusted = trusted_key("release", &key);
        let fixture = NetworkFixture::new(vec![42; 256], "release", &key);
        fixture.set_mode(ServerMode::ArtifactFailure);
        let expected_version = version();
        let config = config(&fixture.url, &expected_version, &trusted, temp.path(), 300);
        assert!(matches!(
            fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest),
            Err(FetchError::HttpStatus { status: 500, .. })
        ));

        let cached_bytes = [temp.path().join("manifests"), temp.path().join("artifacts")]
            .into_iter()
            .flat_map(|directory| fs::read_dir(directory).unwrap())
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum::<u64>();
        assert!(cached_bytes <= 300, "cache contains {cached_bytes} bytes");
    }

    struct FailingReader(io::ErrorKind);

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
    }

    #[test]
    fn artifact_stream_read_errors_keep_their_network_classification() {
        let temp = TempDir::new().unwrap();
        let cache = CacheGuard::open(
            temp.path(),
            1024,
            FetchDeadline::from_timeout(Duration::from_secs(1)),
        )
        .unwrap();
        let artifact = Artifact {
            target: TARGET,
            filename: FILENAME.to_owned(),
            sha256: "00".repeat(32),
            size: 1,
        };
        let url = Url::parse("https://registry.example/artifact").unwrap();
        let destination = cache.artifact_path(&artifact.sha256).unwrap();

        for (kind, expected) in [
            (io::ErrorKind::TimedOut, FetchErrorCode::NetworkTimeout),
            (
                io::ErrorKind::ConnectionReset,
                FetchErrorCode::NetworkConnection,
            ),
            (io::ErrorKind::InvalidData, FetchErrorCode::NetworkProtocol),
        ] {
            let error = cache
                .install_artifact_reader(
                    FailingReader(kind),
                    &destination,
                    &artifact,
                    ArtifactReadSource::Network(&url),
                )
                .unwrap_err();
            assert_eq!(error.code(), expected, "{kind:?}: {error}");
            assert!(!destination.exists());
        }

        let local_error = cache
            .install_artifact_reader(
                FailingReader(io::ErrorKind::InvalidData),
                &destination,
                &artifact,
                ArtifactReadSource::File,
            )
            .unwrap_err();
        assert_eq!(local_error.code(), FetchErrorCode::LocalIo);
    }

    #[test]
    fn artifact_body_truncation_and_hash_failure_never_use_manifest_cache_as_fallback() {
        let temp = TempDir::new().unwrap();
        let key = signing_key(13);
        let trusted = trusted_key("release", &key);
        let fixture = NetworkFixture::new(vec![42; 256], "release", &key);
        let expected_version = version();
        let config = config(
            &fixture.url,
            &expected_version,
            &trusted,
            temp.path(),
            2 * 1024 * 1024,
        );
        let artifact_path = temp
            .path()
            .join("artifacts")
            .join(sha256_hex(&fixture.artifact));

        fixture.set_mode(ServerMode::ArtifactTruncated);
        let truncated =
            fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest).unwrap_err();
        assert!(matches!(
            truncated,
            FetchError::Network {
                kind: NetworkFailureKind::Connection,
                ..
            }
        ));
        assert!(!artifact_path.exists());

        // The first attempt cached a verified manifest pair. A corrupt current
        // artifact must still fail instead of treating that pair as a fallback
        // for artifact bytes.
        fixture.set_mode(ServerMode::ArtifactCorrupt);
        let corrupt =
            fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest).unwrap_err();
        assert_eq!(corrupt.code(), FetchErrorCode::ArtifactDigestMismatch);
        assert!(!artifact_path.exists());

        fixture.set_mode(ServerMode::ArtifactFailure);
        assert!(matches!(
            fetch_verified_artifact_inner(&config, RedirectPolicyMode::LocalTest),
            Err(FetchError::HttpStatus { status: 500, .. })
        ));
        assert!(!artifact_path.exists());
    }

    #[test]
    fn file_registry_is_contained_and_cached_artifacts_are_rehashed() {
        let registry = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let artifact = b"local artifact bytes".to_vec();
        let key = signing_key(5);
        let trusted = trusted_key("file", &key);
        let manifest = manifest_bytes(&artifact);
        let signature = signature_bytes(&manifest, "file", &key);
        let manifest_path = registry.path().join("manifest.json");
        fs::write(&manifest_path, &manifest).unwrap();
        fs::write(registry.path().join("manifest.json.sig"), &signature).unwrap();
        fs::write(registry.path().join(FILENAME), &artifact).unwrap();
        let url = Url::from_file_path(&manifest_path).unwrap();
        let expected_version = version();
        let config = config(&url, &expected_version, &trusted, cache.path(), 1024 * 1024);

        let first = fetch_verified_artifact(&config).unwrap();
        assert_eq!(first.source, ArtifactSource::File);
        fs::write(&first.local_path, b"bad").unwrap();
        let repaired = fetch_verified_artifact(&config).unwrap();
        assert_eq!(repaired.source, ArtifactSource::File);
        assert_eq!(fs::read(&repaired.local_path).unwrap(), artifact);

        let mut pinned = repaired.try_clone_file().unwrap();
        let mut pinned_bytes = Vec::new();
        pinned.read_to_end(&mut pinned_bytes).unwrap();
        assert_eq!(pinned_bytes, artifact);

        let artifact_path = repaired.local_path.clone();
        let constrained = CacheGuard::open(
            cache.path(),
            1,
            FetchDeadline::from_timeout(Duration::from_secs(1)),
        )
        .unwrap();
        assert!(matches!(
            constrained.evict_to_budget(&[]),
            Err(FetchError::CacheBudget { .. })
        ));
        assert!(artifact_path.exists(), "leased artifact was evicted");
        drop(constrained);
        drop(pinned);
        drop(repaired);
        let unconstrained = CacheGuard::open(
            cache.path(),
            1,
            FetchDeadline::from_timeout(Duration::from_secs(1)),
        )
        .unwrap();
        unconstrained.evict_to_budget(&[]).unwrap();
        assert!(!artifact_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn file_registry_rejects_artifact_symlink_escape() {
        use std::os::unix::fs::symlink;

        let registry = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let artifact = b"outside artifact".to_vec();
        let key = signing_key(6);
        let trusted = trusted_key("file", &key);
        let manifest = manifest_bytes(&artifact);
        let signature = signature_bytes(&manifest, "file", &key);
        let manifest_path = registry.path().join("manifest.json");
        let outside_artifact = outside.path().join("agent");
        fs::write(&outside_artifact, &artifact).unwrap();
        fs::write(&manifest_path, &manifest).unwrap();
        fs::write(registry.path().join("manifest.json.sig"), &signature).unwrap();
        symlink(&outside_artifact, registry.path().join(FILENAME)).unwrap();
        let url = Url::from_file_path(&manifest_path).unwrap();
        let expected_version = version();
        let config = config(&url, &expected_version, &trusted, cache.path(), 1024 * 1024);

        assert!(matches!(
            fetch_verified_artifact(&config),
            Err(FetchError::FileArtifactEscapes { .. })
        ));
    }

    #[test]
    fn expired_deadline_stops_file_registry_reads() {
        let registry = TempDir::new().unwrap();
        let manifest_path = registry.path().join("manifest.json");
        fs::write(&manifest_path, b"signed bytes must not be read").unwrap();
        let url = Url::from_file_path(&manifest_path).unwrap();

        let error = read_file_url_bounded(
            &url,
            MANIFEST_MAX_BYTES as u64,
            "manifest",
            FetchDeadline::expired(),
        )
        .unwrap_err();

        assert_code(error, FetchErrorCode::OperationDeadline);
    }

    #[test]
    fn nonzero_maximum_duration_remains_a_valid_deadline() {
        let deadline = FetchDeadline::from_timeout(Duration::MAX);

        deadline.check("test").unwrap();
        assert!(deadline.remaining("test").unwrap() > Duration::from_secs(60 * 60 * 24 * 365));
    }

    #[test]
    fn expired_deadline_stops_cached_artifact_rehash() {
        let cache = TempDir::new().unwrap();
        let artifact_path = cache.path().join("artifact");
        let bytes = vec![0x5a; COPY_BUFFER_BYTES * 2];
        fs::write(&artifact_path, &bytes).unwrap();
        let file = File::open(&artifact_path).unwrap();

        let error = digest_open_file(
            &file,
            &artifact_path,
            ARTIFACT_MAX_BYTES,
            FetchDeadline::expired(),
        )
        .unwrap_err();

        assert_code(error, FetchErrorCode::OperationDeadline);
    }

    #[test]
    fn expired_deadline_never_enters_manifest_cache_fallback() {
        let cache_dir = TempDir::new().unwrap();
        let mut cache = CacheGuard::open(
            cache_dir.path(),
            1024 * 1024,
            FetchDeadline::from_timeout(Duration::from_secs(1)),
        )
        .unwrap();
        let url = Url::parse("https://registry.example/manifest.json").unwrap();
        let paths = cache.manifest_paths(&url).unwrap();
        cache
            .write_manifest_pair(&paths, b"cached manifest", b"cached signatures")
            .unwrap();
        cache.deadline = FetchDeadline::expired();

        let error = recover_cached_manifest_pair(
            &cache,
            &paths,
            ManifestPairRetrievalError::Manifest(test_network_error(NetworkFailureKind::Timeout)),
        )
        .unwrap_err();

        assert_code(error, FetchErrorCode::OperationDeadline);
        assert!(paths.manifest.exists());
        assert!(paths.signature.exists());
    }

    #[test]
    fn expired_deadline_stops_artifact_copy_and_eviction() {
        let cache_dir = TempDir::new().unwrap();
        let mut cache = CacheGuard::open(
            cache_dir.path(),
            1,
            FetchDeadline::from_timeout(Duration::from_secs(1)),
        )
        .unwrap();
        let bytes = vec![0x2a; COPY_BUFFER_BYTES * 2];
        let artifact = Artifact {
            target: TARGET,
            filename: FILENAME.to_owned(),
            sha256: sha256_hex(&bytes),
            size: bytes.len() as u64,
        };
        let destination = cache.artifacts.join(&artifact.sha256);
        let eviction_candidate = cache.manifests.join("old.json");
        fs::write(&eviction_candidate, b"too large for the cache").unwrap();
        cache.deadline = FetchDeadline::expired();

        let copy_error = cache
            .install_artifact_reader(
                io::Cursor::new(bytes),
                &destination,
                &artifact,
                ArtifactReadSource::File,
            )
            .unwrap_err();
        assert_code(copy_error, FetchErrorCode::OperationDeadline);
        assert!(!destination.exists());

        let eviction_error = cache.evict_to_budget(&[]).unwrap_err();
        assert_code(eviction_error, FetchErrorCode::OperationDeadline);
        assert!(eviction_candidate.exists());
    }

    #[test]
    fn cache_lock_wait_obeys_deadline() {
        let cache = TempDir::new().unwrap();
        let lock_path = cache.path().join(".lock");
        let lock = open_private(&lock_path, true, false).unwrap();
        fs4::FileExt::lock(&lock).unwrap();
        let start = Instant::now();
        let result = CacheGuard::open(
            cache.path(),
            1024,
            FetchDeadline::from_timeout(Duration::from_millis(25)),
        );
        assert!(matches!(result, Err(FetchError::CacheLockTimeout(_))));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn fixture_documents_are_nontrivial_for_cache_budget_test() {
        let key = signing_key(7);
        let fixture = NetworkFixture::new(vec![0; 256], "release", &key);
        assert!(fixture.manifest.len() + fixture.signature.len() > 300);
        assert_eq!(fixture.artifact.len(), 256);
    }
}
