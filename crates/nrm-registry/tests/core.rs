use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use nrm_registry::{
    parse_manifest, parse_signature_document, verify_manifest, AgentTarget, ManifestError,
    SignatureError, TrustError, TrustedKeySet, VerificationError, ARTIFACT_MAX_BYTES,
    MANIFEST_MAX_BYTES, SIGNATURE_DOCUMENT_MAX_BYTES,
};
use semver::Version;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const VERSION: &str = "0.1.0";
const PROTOCOL_VERSION: u32 = 7;
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn version() -> Version {
    Version::parse(VERSION).unwrap()
}

fn filename(target: &str) -> String {
    let extension = if target.ends_with("windows-msvc") {
        ".exe"
    } else {
        ""
    };
    format!("nrm-agent-{VERSION}-{target}{extension}")
}

fn artifact(target: &str) -> Value {
    json!({
        "target": target,
        "filename": filename(target),
        "sha256": HASH,
        "size": 1234567
    })
}

fn manifest_value() -> Value {
    json!({
        "schema_version": 1,
        "package": "nrm-agent",
        "version": VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "source_commit": COMMIT,
        "artifacts": [artifact("aarch64-apple-darwin")]
    })
}

fn manifest_bytes() -> Vec<u8> {
    serde_json::to_vec(&manifest_value()).unwrap()
}

fn parse_value(value: &Value) -> Result<nrm_registry::Manifest, ManifestError> {
    parse_manifest(
        &serde_json::to_vec(value).unwrap(),
        &version(),
        PROTOCOL_VERSION,
    )
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn trusted_keys(keys: &[(&str, &SigningKey)]) -> TrustedKeySet {
    TrustedKeySet::from_base64(keys.iter().map(|(key_id, key)| {
        (
            (*key_id).to_owned(),
            STANDARD.encode(key.verifying_key().as_bytes()),
        )
    }))
    .unwrap()
}

fn signatures(bytes: &[u8], keys: &[(&str, &SigningKey)]) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "signatures": keys
            .iter()
            .map(|(key_id, key)| json!({
                "key_id": key_id,
                "signature": STANDARD.encode(key.sign(bytes).to_bytes()),
            }))
            .collect::<Vec<_>>()
    }))
    .unwrap()
}

#[test]
fn parses_valid_manifest_for_every_supported_target() {
    let targets = [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ];
    let mut value = manifest_value();
    value["artifacts"] = Value::Array(targets.into_iter().map(artifact).collect());

    let manifest = parse_value(&value).unwrap();
    assert_eq!(manifest.artifacts.len(), 6);
    assert_eq!(
        manifest.artifacts[4].target,
        AgentTarget::X86_64PcWindowsMsvc
    );
    assert!(manifest.artifacts[4].filename.ends_with(".exe"));
    assert!(!manifest.artifacts[0].filename.ends_with(".exe"));
}

#[test]
fn rejects_unknown_and_duplicate_manifest_fields() {
    let mut unknown = manifest_value();
    unknown["unexpected"] = json!(true);
    assert!(matches!(parse_value(&unknown), Err(ManifestError::Json(_))));

    let mut unknown_nested = manifest_value();
    unknown_nested["artifacts"][0]["unexpected"] = json!(true);
    assert!(matches!(
        parse_value(&unknown_nested),
        Err(ManifestError::Json(_))
    ));

    let duplicate = format!(
        r#"{{"schema_version":1,"schema_version":1,"package":"nrm-agent","version":"{VERSION}","protocol_version":{PROTOCOL_VERSION},"source_commit":"{COMMIT}","artifacts":[{{"target":"aarch64-apple-darwin","filename":"{}","sha256":"{HASH}","size":1}}]}}"#,
        filename("aarch64-apple-darwin")
    );
    assert!(matches!(
        parse_manifest(duplicate.as_bytes(), &version(), PROTOCOL_VERSION),
        Err(ManifestError::Json(_))
    ));

    let duplicate_nested = format!(
        r#"{{"schema_version":1,"package":"nrm-agent","version":"{VERSION}","protocol_version":{PROTOCOL_VERSION},"source_commit":"{COMMIT}","artifacts":[{{"target":"aarch64-apple-darwin","target":"aarch64-apple-darwin","filename":"{}","sha256":"{HASH}","size":1}}]}}"#,
        filename("aarch64-apple-darwin")
    );
    assert!(matches!(
        parse_manifest(duplicate_nested.as_bytes(), &version(), PROTOCOL_VERSION),
        Err(ManifestError::Json(_))
    ));
}

#[test]
fn rejects_manifest_identity_and_compatibility_mismatches() {
    let mut value = manifest_value();
    value["schema_version"] = json!(2);
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::UnsupportedSchema(2))
    ));

    let mut value = manifest_value();
    value["package"] = json!("other");
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::WrongPackage(_))
    ));

    let mut value = manifest_value();
    value["version"] = json!("01.0.0");
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::InvalidVersion { .. })
    ));

    let mut value = manifest_value();
    value["version"] = json!("0.1.1");
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::VersionMismatch { .. })
    ));

    let mut value = manifest_value();
    value["protocol_version"] = json!(8);
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::ProtocolVersionMismatch {
            actual: 8,
            expected: 7
        })
    ));
}

#[test]
fn rejects_invalid_source_commit_forms() {
    for commit in [
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789abcdef0123456789abcdef0123456g",
        "0123456789ABCDEF0123456789ABCDEF01234567",
    ] {
        let mut value = manifest_value();
        value["source_commit"] = json!(commit);
        assert!(matches!(
            parse_value(&value),
            Err(ManifestError::InvalidSourceCommit)
        ));
    }
}

#[test]
fn rejects_duplicate_unsupported_and_too_many_targets() {
    let mut value = manifest_value();
    value["artifacts"] = json!([]);
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::ArtifactCount { actual: 0, .. })
    ));

    let mut value = manifest_value();
    value["artifacts"] = json!([
        artifact("aarch64-apple-darwin"),
        artifact("aarch64-apple-darwin")
    ]);
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::DuplicateTarget(
            AgentTarget::Aarch64AppleDarwin
        ))
    ));

    let mut unsupported = artifact("riscv64gc-unknown-linux-gnu");
    unsupported["filename"] = json!("nrm-agent-0.1.0-riscv64gc-unknown-linux-gnu");
    let mut value = manifest_value();
    value["artifacts"] = json!([unsupported]);
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::UnsupportedTarget(_))
    ));

    let mut value = manifest_value();
    value["artifacts"] = Value::Array(vec![artifact("aarch64-apple-darwin"); 7]);
    assert!(matches!(
        parse_value(&value),
        Err(ManifestError::ArtifactCount { actual: 7, .. })
    ));
}

#[test]
fn rejects_non_exact_or_traversing_filenames() {
    for bad_filename in [
        "../nrm-agent-0.1.0-aarch64-apple-darwin",
        "nrm-agent-0.1.0-aarch64-apple-darwin.exe",
        "/nrm-agent-0.1.0-aarch64-apple-darwin",
        "nrm-agent-0.1.0-aarch64-apple-darwin/other",
    ] {
        let mut value = manifest_value();
        value["artifacts"][0]["filename"] = json!(bad_filename);
        assert!(matches!(
            parse_value(&value),
            Err(ManifestError::InvalidFilename { .. })
        ));
    }

    let mut windows = manifest_value();
    windows["artifacts"] = json!([artifact("x86_64-pc-windows-msvc")]);
    windows["artifacts"][0]["filename"] = json!("nrm-agent-0.1.0-x86_64-pc-windows-msvc");
    assert!(matches!(
        parse_value(&windows),
        Err(ManifestError::InvalidFilename { .. })
    ));
}

#[test]
fn rejects_invalid_hashes_and_artifact_sizes() {
    for bad_hash in [
        "0123",
        "G123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "A123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        let mut value = manifest_value();
        value["artifacts"][0]["sha256"] = json!(bad_hash);
        assert!(matches!(
            parse_value(&value),
            Err(ManifestError::InvalidSha256 { .. })
        ));
    }

    for bad_size in [0, ARTIFACT_MAX_BYTES + 1] {
        let mut value = manifest_value();
        value["artifacts"][0]["size"] = json!(bad_size);
        assert!(matches!(
            parse_value(&value),
            Err(ManifestError::InvalidSize { actual, .. }) if actual == bad_size
        ));
    }

    let mut value = manifest_value();
    value["artifacts"][0]["size"] = json!(ARTIFACT_MAX_BYTES);
    assert!(parse_value(&value).is_ok());
}

#[test]
fn enforces_manifest_size_before_json_parsing() {
    let bytes = vec![b' '; MANIFEST_MAX_BYTES + 1];
    assert!(matches!(
        parse_manifest(&bytes, &version(), PROTOCOL_VERSION),
        Err(ManifestError::TooLarge { .. })
    ));
}

#[test]
fn signature_document_is_strict_and_bounded() {
    let key = signing_key(1);
    let bytes = manifest_bytes();
    assert_eq!(
        parse_signature_document(&signatures(&bytes, &[("key", &key)]))
            .unwrap()
            .signatures
            .len(),
        1
    );

    let unsupported_schema = serde_json::to_vec(&json!({
        "schema_version": 2,
        "signatures": [{
            "key_id": "key",
            "signature": STANDARD.encode([0_u8; 64]),
        }]
    }))
    .unwrap();
    assert!(matches!(
        parse_signature_document(&unsupported_schema),
        Err(SignatureError::UnsupportedSchema(2))
    ));

    let unknown = br#"{"schema_version":1,"signatures":[],"extra":true}"#;
    assert!(matches!(
        parse_signature_document(unknown),
        Err(SignatureError::Json(_))
    ));
    let unknown_nested = format!(
        r#"{{"schema_version":1,"signatures":[{{"key_id":"key","signature":"{}","extra":true}}]}}"#,
        STANDARD.encode([0_u8; 64])
    );
    assert!(matches!(
        parse_signature_document(unknown_nested.as_bytes()),
        Err(SignatureError::Json(_))
    ));
    let duplicate = br#"{"schema_version":1,"schema_version":1,"signatures":[]}"#;
    assert!(matches!(
        parse_signature_document(duplicate),
        Err(SignatureError::Json(_))
    ));
    let duplicate_nested =
        br#"{"schema_version":1,"signatures":[{"key_id":"a","key_id":"b","signature":"AA=="}]}"#;
    assert!(matches!(
        parse_signature_document(duplicate_nested),
        Err(SignatureError::Json(_))
    ));

    let oversized = vec![b' '; SIGNATURE_DOCUMENT_MAX_BYTES + 1];
    assert!(matches!(
        parse_signature_document(&oversized),
        Err(SignatureError::TooLarge { .. })
    ));
}

#[test]
fn signature_document_rejects_counts_ids_duplicates_and_base64() {
    let empty = serde_json::to_vec(&json!({"schema_version": 1, "signatures": []})).unwrap();
    assert!(matches!(
        parse_signature_document(&empty),
        Err(SignatureError::SignatureCount { actual: 0, .. })
    ));

    let too_many = serde_json::to_vec(&json!({
        "schema_version": 1,
        "signatures": (0..33)
            .map(|index| json!({
                "key_id": format!("key-{index}"),
                "signature": STANDARD.encode([0_u8; 64]),
            }))
            .collect::<Vec<_>>()
    }))
    .unwrap();
    assert!(matches!(
        parse_signature_document(&too_many),
        Err(SignatureError::SignatureCount { actual: 33, .. })
    ));

    let signature = STANDARD.encode([0_u8; 64]);
    let duplicate = serde_json::to_vec(&json!({
        "schema_version": 1,
        "signatures": [
            {"key_id": "same", "signature": signature},
            {"key_id": "same", "signature": signature},
        ]
    }))
    .unwrap();
    assert!(matches!(
        parse_signature_document(&duplicate),
        Err(SignatureError::DuplicateKeyId(id)) if id == "same"
    ));

    for key_id in ["", "bad key", "bad/key", "\n", &"a".repeat(129)] {
        let document = serde_json::to_vec(&json!({
            "schema_version": 1,
            "signatures": [{"key_id": key_id, "signature": signature}]
        }))
        .unwrap();
        assert!(matches!(
            parse_signature_document(&document),
            Err(SignatureError::InvalidKeyId(_))
        ));
    }

    for encoded in [
        STANDARD.encode([0_u8; 63]),
        STANDARD.encode([0_u8; 64]).trim_end_matches('=').to_owned(),
        "_w==".to_owned(),
        format!("{}\n", STANDARD.encode([0_u8; 64])),
    ] {
        let document = serde_json::to_vec(&json!({
            "schema_version": 1,
            "signatures": [{"key_id": "key", "signature": encoded}]
        }))
        .unwrap();
        assert!(matches!(
            parse_signature_document(&document),
            Err(SignatureError::InvalidSignatureEncoding { .. })
        ));
    }
}

#[test]
fn trusted_keys_require_distinct_valid_canonical_public_keys() {
    let key = signing_key(3);
    let encoded = STANDARD.encode(key.verifying_key().as_bytes());
    let trusted = TrustedKeySet::from_base64([("release-2026-q3", encoded.clone())]).unwrap();
    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted.key_ids().collect::<Vec<_>>(), ["release-2026-q3"]);
    let fingerprint = trusted.fingerprints().next().unwrap().1;
    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));

    assert!(matches!(
        TrustedKeySet::from_base64(std::iter::empty::<(String, String)>()),
        Err(TrustError::NoKeys)
    ));
    assert!(matches!(
        TrustedKeySet::from_base64([("dup", encoded.clone()), ("dup", encoded.clone())]),
        Err(TrustError::DuplicateKeyId(id)) if id == "dup"
    ));
    assert!(matches!(
        TrustedKeySet::from_base64([
            ("first", encoded.clone()),
            ("alias", encoded.clone())
        ]),
        Err(TrustError::DuplicateKeyMaterial {
            first_key_id,
            duplicate_key_id
        }) if first_key_id == "first" && duplicate_key_id == "alias"
    ));
    assert!(matches!(
        TrustedKeySet::from_base64([("bad key", encoded.clone())]),
        Err(TrustError::InvalidKeyId(_))
    ));
    assert!(matches!(
        TrustedKeySet::from_base64([("key", encoded.trim_end_matches('='))]),
        Err(TrustError::InvalidPublicKeyEncoding(_))
    ));
    assert!(matches!(
        TrustedKeySet::from_base64([("key", STANDARD.encode([0_u8; 31]))]),
        Err(TrustError::InvalidPublicKeyEncoding(_))
    ));
    assert!(matches!(
        TrustedKeySet::from_base64([("weak", STANDARD.encode([0_u8; 32]))]),
        Err(TrustError::InvalidPublicKey(_))
    ));

    let too_many = (0..33).map(|index| {
        let key = signing_key(index + 20);
        (
            format!("key-{index}"),
            STANDARD.encode(key.verifying_key().as_bytes()),
        )
    });
    assert!(matches!(
        TrustedKeySet::from_base64(too_many),
        Err(TrustError::TooManyKeys { max: 32 })
    ));
}

#[test]
fn verifies_exact_raw_bytes_and_returns_digest_and_signer_identity() {
    let bytes = manifest_bytes();
    let key = signing_key(4);
    let trusted = trusted_keys(&[("release", &key)]);
    let signature_document = signatures(&bytes, &[("release", &key)]);

    let verified = verify_manifest(
        &bytes,
        &signature_document,
        &trusted,
        1,
        &version(),
        PROTOCOL_VERSION,
    )
    .unwrap();
    assert_eq!(verified.manifest.version, version());
    assert_eq!(verified.verified_signers[0].key_id, "release");
    assert_eq!(verified.verified_signers[0].fingerprint.len(), 64);
    let digest = Sha256::digest(&bytes);
    assert_eq!(
        verified.manifest_sha256,
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );

    let mut mutated = bytes.clone();
    mutated.push(b'\n');
    assert!(matches!(
        verify_manifest(
            &mutated,
            &signature_document,
            &trusted,
            1,
            &version(),
            PROTOCOL_VERSION,
        ),
        Err(VerificationError::InsufficientSignatures {
            required: 1,
            actual: 0
        })
    ));
}

#[test]
fn supports_rotation_thresholds_and_ignores_unknown_or_invalid_signatures() {
    let bytes = manifest_bytes();
    let old = signing_key(5);
    let new = signing_key(6);
    let unknown = signing_key(7);
    let trusted = trusted_keys(&[("old", &old), ("new", &new)]);

    let both = signatures(&bytes, &[("old", &old), ("new", &new)]);
    let verified =
        verify_manifest(&bytes, &both, &trusted, 2, &version(), PROTOCOL_VERSION).unwrap();
    assert_eq!(
        verified
            .verified_signers
            .iter()
            .map(|signer| signer.key_id.as_str())
            .collect::<Vec<_>>(),
        ["old", "new"]
    );

    let with_unknown = signatures(&bytes, &[("unknown", &unknown), ("new", &new)]);
    let verified = verify_manifest(
        &bytes,
        &with_unknown,
        &trusted,
        1,
        &version(),
        PROTOCOL_VERSION,
    )
    .unwrap();
    assert_eq!(verified.verified_signers.len(), 1);
    assert_eq!(verified.verified_signers[0].key_id, "new");

    let invalid_old = old.sign(b"different bytes");
    let mixed = serde_json::to_vec(&json!({
        "schema_version": 1,
        "signatures": [
            {"key_id": "old", "signature": STANDARD.encode(invalid_old.to_bytes())},
            {"key_id": "new", "signature": STANDARD.encode(new.sign(&bytes).to_bytes())},
        ]
    }))
    .unwrap();
    assert!(verify_manifest(&bytes, &mixed, &trusted, 1, &version(), PROTOCOL_VERSION,).is_ok());
    assert!(matches!(
        verify_manifest(&bytes, &mixed, &trusted, 2, &version(), PROTOCOL_VERSION,),
        Err(VerificationError::InsufficientSignatures {
            required: 2,
            actual: 1
        })
    ));
}

#[test]
fn rejects_impossible_or_zero_signature_thresholds() {
    let bytes = manifest_bytes();
    let key = signing_key(8);
    let trusted = trusted_keys(&[("key", &key)]);
    let document = signatures(&bytes, &[("key", &key)]);

    for threshold in [0, 2] {
        assert!(matches!(
            verify_manifest(
                &bytes,
                &document,
                &trusted,
                threshold,
                &version(),
                PROTOCOL_VERSION,
            ),
            Err(VerificationError::InvalidThreshold { .. })
        ));
    }
}
