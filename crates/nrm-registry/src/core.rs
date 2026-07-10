use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MANIFEST_MAX_BYTES: usize = 1024 * 1024;
pub const SIGNATURE_DOCUMENT_MAX_BYTES: usize = 64 * 1024;
pub const ARTIFACT_MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 6;
const MAX_SIGNATURES: usize = 32;
const MAX_TRUSTED_KEYS: usize = 32;
const MAX_KEY_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AgentTarget {
    X86_64UnknownLinuxMusl,
    Aarch64UnknownLinuxMusl,
    X86_64AppleDarwin,
    Aarch64AppleDarwin,
    X86_64PcWindowsMsvc,
    Aarch64PcWindowsMsvc,
}

impl AgentTarget {
    pub const ALL: [Self; 6] = [
        Self::X86_64UnknownLinuxMusl,
        Self::Aarch64UnknownLinuxMusl,
        Self::X86_64AppleDarwin,
        Self::Aarch64AppleDarwin,
        Self::X86_64PcWindowsMsvc,
        Self::Aarch64PcWindowsMsvc,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64UnknownLinuxMusl => "x86_64-unknown-linux-musl",
            Self::Aarch64UnknownLinuxMusl => "aarch64-unknown-linux-musl",
            Self::X86_64AppleDarwin => "x86_64-apple-darwin",
            Self::Aarch64AppleDarwin => "aarch64-apple-darwin",
            Self::X86_64PcWindowsMsvc => "x86_64-pc-windows-msvc",
            Self::Aarch64PcWindowsMsvc => "aarch64-pc-windows-msvc",
        }
    }

    #[must_use]
    pub const fn is_windows(self) -> bool {
        matches!(self, Self::X86_64PcWindowsMsvc | Self::Aarch64PcWindowsMsvc)
    }
}

impl fmt::Display for AgentTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for AgentTarget {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|target| target.as_str() == value)
            .ok_or(())
    }
}

impl Serialize for AgentTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value)
            .map_err(|()| serde::de::Error::custom(format!("unsupported agent target {value:?}")))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Artifact {
    pub target: AgentTarget,
    pub filename: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub package: String,
    pub version: Version,
    pub protocol_version: u32,
    pub source_commit: String,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest is {actual} bytes; the limit is {max} bytes")]
    TooLarge { actual: usize, max: usize },
    #[error("manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported manifest schema version {0}")]
    UnsupportedSchema(u32),
    #[error("manifest package must be nrm-agent, not {0:?}")]
    WrongPackage(String),
    #[error("manifest version {value:?} is not valid SemVer: {source}")]
    InvalidVersion {
        value: String,
        source: semver::Error,
    },
    #[error("manifest version {actual} does not match requested version {expected}")]
    VersionMismatch { actual: Version, expected: Version },
    #[error("manifest protocol version {actual} does not match required version {expected}")]
    ProtocolVersionMismatch { actual: u32, expected: u32 },
    #[error("source_commit must be exactly 40 lowercase hexadecimal characters")]
    InvalidSourceCommit,
    #[error("manifest must contain between 1 and {max} artifacts, not {actual}")]
    ArtifactCount { actual: usize, max: usize },
    #[error("unsupported artifact target {0:?}")]
    UnsupportedTarget(String),
    #[error("artifact target {0} occurs more than once")]
    DuplicateTarget(AgentTarget),
    #[error("artifact filename {actual:?} must be exactly {expected:?}")]
    InvalidFilename { actual: String, expected: String },
    #[error("artifact SHA-256 for target {target} must be 64 lowercase hexadecimal characters")]
    InvalidSha256 { target: AgentTarget },
    #[error("artifact size for target {target} must be between 1 and {max} bytes, not {actual}")]
    InvalidSize {
        target: AgentTarget,
        actual: u64,
        max: u64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema_version: u32,
    package: String,
    version: String,
    protocol_version: u32,
    source_commit: String,
    artifacts: Vec<RawArtifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    target: String,
    filename: String,
    sha256: String,
    size: u64,
}

pub fn parse_manifest(
    bytes: &[u8],
    expected_version: &Version,
    expected_protocol_version: u32,
) -> Result<Manifest, ManifestError> {
    if bytes.len() > MANIFEST_MAX_BYTES {
        return Err(ManifestError::TooLarge {
            actual: bytes.len(),
            max: MANIFEST_MAX_BYTES,
        });
    }

    let raw: RawManifest = serde_json::from_slice(bytes)?;
    if raw.schema_version != 1 {
        return Err(ManifestError::UnsupportedSchema(raw.schema_version));
    }
    if raw.package != "nrm-agent" {
        return Err(ManifestError::WrongPackage(raw.package));
    }
    let version = Version::parse(&raw.version).map_err(|source| ManifestError::InvalidVersion {
        value: raw.version.clone(),
        source,
    })?;
    if version != *expected_version {
        return Err(ManifestError::VersionMismatch {
            actual: version,
            expected: expected_version.clone(),
        });
    }
    if raw.protocol_version != expected_protocol_version {
        return Err(ManifestError::ProtocolVersionMismatch {
            actual: raw.protocol_version,
            expected: expected_protocol_version,
        });
    }
    if raw.source_commit.len() != 40
        || !raw
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManifestError::InvalidSourceCommit);
    }
    if raw.artifacts.is_empty() || raw.artifacts.len() > MAX_ARTIFACTS {
        return Err(ManifestError::ArtifactCount {
            actual: raw.artifacts.len(),
            max: MAX_ARTIFACTS,
        });
    }

    let mut artifacts = Vec::with_capacity(raw.artifacts.len());
    let mut targets = std::collections::BTreeSet::new();
    for raw_artifact in raw.artifacts {
        let target = AgentTarget::from_str(&raw_artifact.target)
            .map_err(|()| ManifestError::UnsupportedTarget(raw_artifact.target.clone()))?;
        if !targets.insert(target) {
            return Err(ManifestError::DuplicateTarget(target));
        }
        let extension = if target.is_windows() { ".exe" } else { "" };
        let expected_filename = format!("nrm-agent-{version}-{target}{extension}");
        if raw_artifact.filename != expected_filename {
            return Err(ManifestError::InvalidFilename {
                actual: raw_artifact.filename,
                expected: expected_filename,
            });
        }
        if raw_artifact.sha256.len() != 64
            || !raw_artifact
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ManifestError::InvalidSha256 { target });
        }
        if !(1..=ARTIFACT_MAX_BYTES).contains(&raw_artifact.size) {
            return Err(ManifestError::InvalidSize {
                target,
                actual: raw_artifact.size,
                max: ARTIFACT_MAX_BYTES,
            });
        }
        artifacts.push(Artifact {
            target,
            filename: raw_artifact.filename,
            sha256: raw_artifact.sha256,
            size: raw_artifact.size,
        });
    }

    Ok(Manifest {
        schema_version: raw.schema_version,
        package: raw.package,
        version,
        protocol_version: raw.protocol_version,
        source_commit: raw.source_commit,
        artifacts,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetachedSignature {
    pub key_id: String,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureDocument {
    pub schema_version: u32,
    pub signatures: Vec<DetachedSignature>,
}

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("signature document is {actual} bytes; the limit is {max} bytes")]
    TooLarge { actual: usize, max: usize },
    #[error("signature document JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported signature document schema version {0}")]
    UnsupportedSchema(u32),
    #[error("signature document must contain between 1 and {max} signatures, not {actual}")]
    SignatureCount { actual: usize, max: usize },
    #[error("invalid signing key ID {0:?}")]
    InvalidKeyId(String),
    #[error("signing key ID {0:?} occurs more than once")]
    DuplicateKeyId(String),
    #[error("signature for key {key_id:?} is not canonical standard base64 encoding of 64 bytes")]
    InvalidSignatureEncoding { key_id: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignatureDocument {
    schema_version: u32,
    signatures: Vec<RawSignature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    key_id: String,
    signature: String,
}

pub fn parse_signature_document(bytes: &[u8]) -> Result<SignatureDocument, SignatureError> {
    if bytes.len() > SIGNATURE_DOCUMENT_MAX_BYTES {
        return Err(SignatureError::TooLarge {
            actual: bytes.len(),
            max: SIGNATURE_DOCUMENT_MAX_BYTES,
        });
    }
    let raw: RawSignatureDocument = serde_json::from_slice(bytes)?;
    if raw.schema_version != 1 {
        return Err(SignatureError::UnsupportedSchema(raw.schema_version));
    }
    if raw.signatures.is_empty() || raw.signatures.len() > MAX_SIGNATURES {
        return Err(SignatureError::SignatureCount {
            actual: raw.signatures.len(),
            max: MAX_SIGNATURES,
        });
    }

    let mut key_ids = std::collections::BTreeSet::new();
    let mut signatures = Vec::with_capacity(raw.signatures.len());
    for raw_signature in raw.signatures {
        validate_key_id(&raw_signature.key_id)
            .map_err(|()| SignatureError::InvalidKeyId(raw_signature.key_id.clone()))?;
        if !key_ids.insert(raw_signature.key_id.clone()) {
            return Err(SignatureError::DuplicateKeyId(raw_signature.key_id));
        }
        let signature = decode_canonical_base64::<64>(&raw_signature.signature).map_err(|()| {
            SignatureError::InvalidSignatureEncoding {
                key_id: raw_signature.key_id.clone(),
            }
        })?;
        signatures.push(DetachedSignature {
            key_id: raw_signature.key_id,
            signature,
        });
    }

    Ok(SignatureDocument {
        schema_version: raw.schema_version,
        signatures,
    })
}

#[derive(Clone, Debug)]
struct TrustedPublicKey {
    verifying_key: VerifyingKey,
    fingerprint: String,
}

#[derive(Clone, Debug)]
pub struct TrustedKeySet {
    keys: BTreeMap<String, TrustedPublicKey>,
}

impl TrustedKeySet {
    pub fn from_base64<I, K, V>(entries: I) -> Result<Self, TrustError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: AsRef<str>,
    {
        let mut keys = BTreeMap::new();
        let mut key_material = BTreeMap::<[u8; 32], String>::new();
        for (key_id, encoded) in entries {
            if keys.len() == MAX_TRUSTED_KEYS {
                return Err(TrustError::TooManyKeys {
                    max: MAX_TRUSTED_KEYS,
                });
            }
            let key_id = key_id.into();
            validate_key_id(&key_id).map_err(|()| TrustError::InvalidKeyId(key_id.clone()))?;
            if keys.contains_key(&key_id) {
                return Err(TrustError::DuplicateKeyId(key_id));
            }
            let bytes = decode_canonical_base64::<32>(encoded.as_ref())
                .map_err(|()| TrustError::InvalidPublicKeyEncoding(key_id.clone()))?;
            let verifying_key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| TrustError::InvalidPublicKey(key_id.clone()))?;
            if verifying_key.is_weak() || verifying_key.to_edwards().compress().to_bytes() != bytes
            {
                return Err(TrustError::InvalidPublicKey(key_id));
            }
            let fingerprint = sha256_hex(&bytes);
            if let Some(first_key_id) = key_material.insert(bytes, key_id.clone()) {
                return Err(TrustError::DuplicateKeyMaterial {
                    first_key_id,
                    duplicate_key_id: key_id,
                });
            }
            keys.insert(
                key_id,
                TrustedPublicKey {
                    verifying_key,
                    fingerprint,
                },
            );
        }
        if keys.is_empty() {
            return Err(TrustError::NoKeys);
        }
        Ok(Self { keys })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn key_ids(&self) -> impl ExactSizeIterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    pub fn fingerprints(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.keys
            .iter()
            .map(|(key_id, key)| (key_id.as_str(), key.fingerprint.as_str()))
    }
}

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("at least one trusted public key is required")]
    NoKeys,
    #[error("at most {max} trusted public keys are allowed")]
    TooManyKeys { max: usize },
    #[error("invalid trusted key ID {0:?}")]
    InvalidKeyId(String),
    #[error("trusted key ID {0:?} occurs more than once")]
    DuplicateKeyId(String),
    #[error(
        "trusted key IDs {first_key_id:?} and {duplicate_key_id:?} contain the same public key"
    )]
    DuplicateKeyMaterial {
        first_key_id: String,
        duplicate_key_id: String,
    },
    #[error("public key {0:?} is not canonical standard base64 encoding of 32 bytes")]
    InvalidPublicKeyEncoding(String),
    #[error("public key {0:?} is not a valid Ed25519 public key")]
    InvalidPublicKey(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSigner {
    pub key_id: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedManifest {
    pub manifest: Manifest,
    pub manifest_sha256: String,
    pub verified_signers: Vec<VerifiedSigner>,
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error(transparent)]
    SignatureDocument(#[from] SignatureError),
    #[error("signature threshold must be between 1 and {trusted_keys}, not {threshold}")]
    InvalidThreshold {
        threshold: usize,
        trusted_keys: usize,
    },
    #[error("only {actual} trusted signatures verified; {required} are required")]
    InsufficientSignatures { required: usize, actual: usize },
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature_document_bytes: &[u8],
    trusted_keys: &TrustedKeySet,
    threshold: usize,
    expected_version: &Version,
    expected_protocol_version: u32,
) -> Result<VerifiedManifest, VerificationError> {
    if threshold == 0 || threshold > trusted_keys.len() {
        return Err(VerificationError::InvalidThreshold {
            threshold,
            trusted_keys: trusted_keys.len(),
        });
    }
    if manifest_bytes.len() > MANIFEST_MAX_BYTES {
        return Err(ManifestError::TooLarge {
            actual: manifest_bytes.len(),
            max: MANIFEST_MAX_BYTES,
        }
        .into());
    }

    let document = parse_signature_document(signature_document_bytes)?;
    let mut verified_signers = Vec::new();
    for detached in document.signatures {
        let Some(trusted) = trusted_keys.keys.get(&detached.key_id) else {
            continue;
        };
        let signature = Signature::from_bytes(&detached.signature);
        if trusted
            .verifying_key
            .verify_strict(manifest_bytes, &signature)
            .is_ok()
        {
            verified_signers.push(VerifiedSigner {
                key_id: detached.key_id,
                fingerprint: trusted.fingerprint.clone(),
            });
        }
    }
    if verified_signers.len() < threshold {
        return Err(VerificationError::InsufficientSignatures {
            required: threshold,
            actual: verified_signers.len(),
        });
    }

    let manifest = parse_manifest(manifest_bytes, expected_version, expected_protocol_version)?;
    Ok(VerifiedManifest {
        manifest,
        manifest_sha256: sha256_hex(manifest_bytes),
        verified_signers,
    })
}

fn decode_canonical_base64<const N: usize>(encoded: &str) -> Result<[u8; N], ()> {
    let decoded = STANDARD.decode(encoded).map_err(|_| ())?;
    if decoded.len() != N || STANDARD.encode(&decoded) != encoded {
        return Err(());
    }
    decoded.try_into().map_err(|_| ())
}

fn validate_key_id(key_id: &str) -> Result<(), ()> {
    if key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_BYTES
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
