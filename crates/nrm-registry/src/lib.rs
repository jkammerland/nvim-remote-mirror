//! Signed registry primitives for distributing `nrm-agent` builds.

mod core;
mod fetch;
mod url_policy;

pub use crate::core::{
    parse_manifest, parse_signature_document, verify_manifest, AgentTarget, Artifact,
    DetachedSignature, Manifest, ManifestError, SignatureDocument, SignatureError, TrustError,
    TrustedKeySet, VerificationError, VerifiedManifest, VerifiedSigner, ARTIFACT_MAX_BYTES,
    MANIFEST_MAX_BYTES, SIGNATURE_DOCUMENT_MAX_BYTES,
};
pub use crate::fetch::{
    fetch_verified_artifact, validate_redirect_url, ArtifactSource, CacheState, FetchConfig,
    FetchError, FetchErrorCode, FetchedArtifact, ManifestSource, NetworkFailureKind,
};
pub use crate::url_policy::{
    artifact_url, signature_url, validate_artifact_filename, validate_https_url,
    RegistryUrlTemplate, UrlPolicyError,
};
