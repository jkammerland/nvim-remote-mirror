//! Deterministic release assembly, signing, and pre-publish verification.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer as _, SigningKey};
use nrm_registry::{
    parse_manifest, parse_signature_document, verify_manifest, AgentTarget, Artifact, Manifest,
    ManifestError, SignatureError, TrustError, TrustedKeySet, VerificationError,
    ARTIFACT_MAX_BYTES, MANIFEST_MAX_BYTES, SIGNATURE_DOCUMENT_MAX_BYTES,
};
use semver::Version;
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SIGNING_KEYS_ENV: &str = "NRM_REGISTRY_SIGNING_KEYS_JSON";
const TRUSTED_PUBLIC_KEYS_ENV: &str = "NRM_REGISTRY_TRUSTED_PUBLIC_KEYS_JSON";
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(name = "nrm-registry-release")]
#[command(about = "Assemble, sign, and verify deterministic nrm-agent releases")]
struct Cli {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    /// Assemble exactly six native agent binaries into a canonical manifest.
    Assemble(AssembleArgs),
    /// Sign the exact manifest bytes with protected Ed25519 seed material.
    Sign(SignArgs),
    /// Verify signatures, release identity, completeness, and artifact bytes.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
struct AssembleArgs {
    #[arg(long)]
    artifacts_dir: PathBuf,
    #[arg(long)]
    version: Version,
    #[arg(long)]
    protocol_version: u32,
    #[arg(long)]
    source_commit: String,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Clone, Debug, Args)]
struct ExpectedIdentityArgs {
    #[arg(long)]
    expected_version: Version,
    #[arg(long)]
    expected_protocol_version: u32,
    #[arg(long)]
    expected_source_commit: String,
}

#[derive(Debug, Args)]
struct SignArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    identity: ExpectedIdentityArgs,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    signatures: PathBuf,
    #[arg(long)]
    artifacts_dir: PathBuf,
    /// Strict JSON key-ID-to-public-key map. If omitted, read
    /// NRM_REGISTRY_TRUSTED_PUBLIC_KEYS_JSON.
    #[arg(long)]
    trusted_public_keys: Option<PathBuf>,
    #[command(flatten)]
    identity: ExpectedIdentityArgs,
}

#[derive(Debug, Error)]
enum ReleaseError {
    #[error("{0}")]
    Policy(String),
    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("manifest is invalid: {0}")]
    Manifest(#[from] ManifestError),
    #[error("signature document is invalid: {0}")]
    Signature(#[from] SignatureError),
    #[error("signing or trust configuration is invalid: {0}")]
    Trust(#[from] TrustError),
    #[error("signed manifest verification failed: {0}")]
    Verification(#[from] VerificationError),
    #[error("JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
struct VerifiedRelease {
    manifest_sha256: String,
    verified_signers: usize,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("nrm-registry-release: {error}");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> Result<(), ReleaseError> {
    match cli.command {
        ReleaseCommand::Assemble(args) => {
            let bytes = assemble_manifest_bytes(
                &args.artifacts_dir,
                &args.version,
                args.protocol_version,
                &args.source_commit,
            )?;
            write_output(&args.output, &bytes)?;
            println!(
                "assembled {}-byte manifest for six targets at {}",
                bytes.len(),
                args.output.display()
            );
        }
        ReleaseCommand::Sign(args) => {
            let manifest_bytes =
                read_regular_file_bounded(&args.manifest, MANIFEST_MAX_BYTES as u64, "manifest")?;
            let signing_json = read_secret_environment(SIGNING_KEYS_ENV)?;
            let signatures = sign_manifest_bytes(
                &manifest_bytes,
                &args.identity.expected_version,
                args.identity.expected_protocol_version,
                &args.identity.expected_source_commit,
                &signing_json,
            )?;
            let signature_count = parse_signature_document(&signatures)?.signatures.len();
            write_output(&args.output, &signatures)?;
            println!(
                "signed exact manifest bytes with {signature_count} key(s) at {}",
                args.output.display()
            );
        }
        ReleaseCommand::Verify(args) => {
            let manifest_bytes =
                read_regular_file_bounded(&args.manifest, MANIFEST_MAX_BYTES as u64, "manifest")?;
            let signature_bytes = read_regular_file_bounded(
                &args.signatures,
                SIGNATURE_DOCUMENT_MAX_BYTES as u64,
                "signature document",
            )?;
            let trusted_json = read_trusted_public_keys(args.trusted_public_keys.as_deref())?;
            let verified = verify_release(
                &manifest_bytes,
                &signature_bytes,
                &args.artifacts_dir,
                &args.identity.expected_version,
                args.identity.expected_protocol_version,
                &args.identity.expected_source_commit,
                &trusted_json,
            )?;
            println!(
                "verified six artifacts and {} trusted signature(s); manifest sha256 {}",
                verified.verified_signers, verified.manifest_sha256
            );
        }
    }
    Ok(())
}

fn assemble_manifest_bytes(
    artifacts_dir: &Path,
    version: &Version,
    protocol_version: u32,
    source_commit: &str,
) -> Result<Vec<u8>, ReleaseError> {
    let artifact_paths = exact_artifact_paths(artifacts_dir, version)?;
    let mut artifacts = Vec::with_capacity(AgentTarget::ALL.len());
    let mut digests = BTreeMap::new();
    for (target, filename, path) in artifact_paths {
        let (size, sha256) = artifact_size_and_digest(&path, target)?;
        record_unique_digest(&mut digests, target, &sha256)?;
        artifacts.push(Artifact {
            target,
            filename,
            sha256,
            size,
        });
    }
    artifacts.sort_by_key(|artifact| artifact.target);

    let manifest = Manifest {
        schema_version: 1,
        package: "nrm-agent".to_owned(),
        version: version.clone(),
        protocol_version,
        source_commit: source_commit.to_owned(),
        artifacts,
    };
    let mut bytes = serde_json::to_vec(&manifest)?;
    bytes.push(b'\n');

    let parsed = parse_manifest(&bytes, version, protocol_version)?;
    ensure_complete_manifest(&parsed, source_commit)?;
    Ok(bytes)
}

fn sign_manifest_bytes(
    manifest_bytes: &[u8],
    expected_version: &Version,
    expected_protocol_version: u32,
    expected_source_commit: &str,
    signing_keys_json: &[u8],
) -> Result<Vec<u8>, ReleaseError> {
    if manifest_bytes.len() > MANIFEST_MAX_BYTES {
        return Err(ReleaseError::Policy(format!(
            "manifest is {} bytes; limit is {MANIFEST_MAX_BYTES}",
            manifest_bytes.len()
        )));
    }
    let manifest = parse_manifest(manifest_bytes, expected_version, expected_protocol_version)?;
    ensure_complete_manifest(&manifest, expected_source_commit)?;

    let signing_keys = parse_signing_keys(signing_keys_json)?;
    let signatures = signing_keys
        .keys
        .iter()
        .map(|(key_id, key)| SerializedSignature {
            key_id: key_id.clone(),
            signature: STANDARD.encode(key.sign(manifest_bytes).to_bytes()),
        })
        .collect();
    let document = SerializedSignatureDocument {
        schema_version: 1,
        signatures,
    };
    let mut bytes = serde_json::to_vec(&document)?;
    bytes.push(b'\n');
    parse_signature_document(&bytes)?;

    // Catch any signing or serialization defect before publishing the detached
    // signatures. Requiring every configured key also proves rotation bundles
    // contain all intended signatures.
    verify_manifest(
        manifest_bytes,
        &bytes,
        &signing_keys.trusted,
        signing_keys.keys.len(),
        expected_version,
        expected_protocol_version,
    )?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn verify_release(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    artifacts_dir: &Path,
    expected_version: &Version,
    expected_protocol_version: u32,
    expected_source_commit: &str,
    trusted_public_keys_json: &[u8],
) -> Result<VerifiedRelease, ReleaseError> {
    let trusted_keys = parse_trusted_public_keys(trusted_public_keys_json)?;
    let signature_document = parse_signature_document(signature_bytes)?;
    let expected_signers: BTreeSet<_> = trusted_keys.key_ids().map(str::to_owned).collect();
    let actual_signers: BTreeSet<_> = signature_document
        .signatures
        .iter()
        .map(|signature| signature.key_id.clone())
        .collect();
    if actual_signers != expected_signers {
        return Err(ReleaseError::Policy(format!(
            "detached signature key IDs must exactly match the release trust policy: expected {}, got {}",
            string_list(&expected_signers),
            string_list(&actual_signers)
        )));
    }
    let verified = verify_manifest(
        manifest_bytes,
        signature_bytes,
        &trusted_keys,
        trusted_keys.len(),
        expected_version,
        expected_protocol_version,
    )?;
    ensure_complete_manifest(&verified.manifest, expected_source_commit)?;

    let paths = exact_artifact_paths(artifacts_dir, expected_version)?;
    let paths_by_target: BTreeMap<_, _> = paths
        .into_iter()
        .map(|(target, _, path)| (target, path))
        .collect();
    let mut digests = BTreeMap::new();
    for artifact in &verified.manifest.artifacts {
        let path = paths_by_target.get(&artifact.target).ok_or_else(|| {
            ReleaseError::Policy(format!(
                "artifact directory is missing target {}",
                artifact.target
            ))
        })?;
        let (actual_size, actual_digest) = artifact_size_and_digest(path, artifact.target)?;
        record_unique_digest(&mut digests, artifact.target, &actual_digest)?;
        if actual_size != artifact.size {
            return Err(ReleaseError::Policy(format!(
                "artifact {:?} size mismatch: got {actual_size}, expected {}",
                artifact.filename, artifact.size
            )));
        }
        if actual_digest != artifact.sha256 {
            return Err(ReleaseError::Policy(format!(
                "artifact {:?} SHA-256 mismatch",
                artifact.filename
            )));
        }
    }

    Ok(VerifiedRelease {
        manifest_sha256: verified.manifest_sha256,
        verified_signers: verified.verified_signers.len(),
    })
}

fn string_list(values: &BTreeSet<String>) -> String {
    if values.is_empty() {
        return "<none>".to_owned();
    }
    values.iter().cloned().collect::<Vec<_>>().join(",")
}

fn ensure_complete_manifest(
    manifest: &Manifest,
    expected_source_commit: &str,
) -> Result<(), ReleaseError> {
    if manifest.source_commit != expected_source_commit {
        return Err(ReleaseError::Policy(format!(
            "manifest source commit {:?} does not match expected {:?}",
            manifest.source_commit, expected_source_commit
        )));
    }
    let actual: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.target)
        .collect();
    if actual != AgentTarget::ALL {
        return Err(ReleaseError::Policy(format!(
            "manifest targets are incomplete or not in canonical AgentTarget order: expected {}, got {}",
            target_list(AgentTarget::ALL.iter().copied()),
            target_list(actual)
        )));
    }
    Ok(())
}

fn target_list(targets: impl IntoIterator<Item = AgentTarget>) -> String {
    targets
        .into_iter()
        .map(|target| target.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn exact_artifact_paths(
    artifacts_dir: &Path,
    version: &Version,
) -> Result<Vec<(AgentTarget, String, PathBuf)>, ReleaseError> {
    let metadata = fs::symlink_metadata(artifacts_dir)
        .map_err(|source| io_error("stat artifacts directory", artifacts_dir, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReleaseError::Policy(format!(
            "artifacts path is not a real directory: {}",
            artifacts_dir.display()
        )));
    }

    let expected: BTreeMap<_, _> = AgentTarget::ALL
        .into_iter()
        .map(|target| (target.artifact_filename(version), target))
        .collect();
    let mut found = BTreeSet::new();
    let entries = fs::read_dir(artifacts_dir)
        .map_err(|source| io_error("read artifacts directory", artifacts_dir, source))?;
    for entry in entries {
        let entry = entry
            .map_err(|source| io_error("read artifacts directory entry", artifacts_dir, source))?;
        let filename = entry.file_name().into_string().map_err(|_| {
            ReleaseError::Policy("artifact directory contains a non-UTF-8 filename".to_owned())
        })?;
        if !expected.contains_key(&filename) {
            return Err(ReleaseError::Policy(format!(
                "artifact directory contains unexpected entry {filename:?}"
            )));
        }
        found.insert(filename);
    }

    for filename in expected.keys() {
        if !found.contains(filename) {
            return Err(ReleaseError::Policy(format!(
                "artifact directory is missing {filename:?}"
            )));
        }
    }

    let mut paths: Vec<_> = expected
        .into_iter()
        .map(|(filename, target)| {
            let path = artifacts_dir.join(&filename);
            (target, filename, path)
        })
        .collect();
    paths.sort_by_key(|(target, _, _)| *target);
    Ok(paths)
}

fn artifact_size_and_digest(
    path: &Path,
    target: AgentTarget,
) -> Result<(u64, String), ReleaseError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("stat artifact", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReleaseError::Policy(format!(
            "artifact is not a regular non-symlink file: {}",
            path.display()
        )));
    }
    if metadata.len() == 0 || metadata.len() > ARTIFACT_MAX_BYTES {
        return Err(ReleaseError::Policy(format!(
            "artifact {} size must be between 1 and {ARTIFACT_MAX_BYTES} bytes",
            path.display()
        )));
    }

    let mut file = File::open(path).map_err(|source| io_error("open artifact", path, source))?;
    validate_executable(&mut file, metadata.len(), target, path)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind artifact", path, source))?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("read artifact", path, source))?;
        if read == 0 {
            break;
        }
        size = size.saturating_add(read as u64);
        if size > ARTIFACT_MAX_BYTES {
            return Err(ReleaseError::Policy(format!(
                "artifact {} exceeds {ARTIFACT_MAX_BYTES} bytes",
                path.display()
            )));
        }
        hasher.update(&buffer[..read]);
    }
    if size == 0 {
        return Err(ReleaseError::Policy(format!(
            "artifact is empty: {}",
            path.display()
        )));
    }
    Ok((size, hex_bytes(&hasher.finalize())))
}

fn record_unique_digest(
    digests: &mut BTreeMap<String, AgentTarget>,
    target: AgentTarget,
    digest: &str,
) -> Result<(), ReleaseError> {
    if let Some(first) = digests.insert(digest.to_owned(), target) {
        return Err(ReleaseError::Policy(format!(
            "targets {first} and {target} publish identical artifact SHA-256 {digest}"
        )));
    }
    Ok(())
}

fn validate_executable(
    file: &mut File,
    size: u64,
    target: AgentTarget,
    path: &Path,
) -> Result<(), ReleaseError> {
    match target {
        AgentTarget::X86_64UnknownLinuxMusl | AgentTarget::Aarch64UnknownLinuxMusl => {
            validate_elf(file, size, target, path)
        }
        AgentTarget::X86_64AppleDarwin | AgentTarget::Aarch64AppleDarwin => {
            validate_mach_o(file, size, target, path)
        }
        AgentTarget::X86_64PcWindowsMsvc | AgentTarget::Aarch64PcWindowsMsvc => {
            validate_pe(file, size, target, path)
        }
    }
}

fn validate_elf(
    file: &mut File,
    size: u64,
    target: AgentTarget,
    path: &Path,
) -> Result<(), ReleaseError> {
    const ELF_HEADER_BYTES: usize = 64;
    const ELF64_PROGRAM_HEADER_BYTES: u64 = 56;
    const PT_INTERP: u32 = 3;

    let header = read_at::<ELF_HEADER_BYTES>(file, 0, size, path, "ELF header")?;
    if &header[..4] != b"\x7fELF" {
        return invalid_executable(path, target, "expected an ELF executable");
    }
    if header[4] != 2 {
        return invalid_executable(path, target, "ELF class must be 64-bit");
    }
    if header[5] != 1 {
        return invalid_executable(path, target, "ELF byte order must be little-endian");
    }
    if header[6] != 1 || u32::from_le_bytes(header[20..24].try_into().unwrap()) != 1 {
        return invalid_executable(path, target, "ELF version must be one");
    }
    let object_type = u16::from_le_bytes(header[16..18].try_into().unwrap());
    if !matches!(object_type, 2 | 3) {
        return invalid_executable(path, target, "ELF file is not an executable image");
    }
    let expected_machine = match target {
        AgentTarget::X86_64UnknownLinuxMusl => 62,
        AgentTarget::Aarch64UnknownLinuxMusl => 183,
        _ => unreachable!("ELF validation is only used for Linux targets"),
    };
    let machine = u16::from_le_bytes(header[18..20].try_into().unwrap());
    if machine != expected_machine {
        return invalid_executable(
            path,
            target,
            &format!("ELF machine {machine} does not match expected {expected_machine}"),
        );
    }
    if u16::from_le_bytes(header[52..54].try_into().unwrap()) != ELF_HEADER_BYTES as u16 {
        return invalid_executable(path, target, "ELF header has a noncanonical size");
    }

    let program_offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let program_entry_size = u16::from_le_bytes(header[54..56].try_into().unwrap()) as u64;
    let program_count = u16::from_le_bytes(header[56..58].try_into().unwrap()) as u64;
    if program_count == 0
        || program_offset < ELF_HEADER_BYTES as u64
        || !program_offset.is_multiple_of(8)
        || program_entry_size != ELF64_PROGRAM_HEADER_BYTES
    {
        return invalid_executable(path, target, "ELF program-header table is invalid");
    }
    let program_bytes = program_entry_size
        .checked_mul(program_count)
        .and_then(|bytes| program_offset.checked_add(bytes))
        .filter(|end| *end <= size)
        .ok_or_else(|| {
            ReleaseError::Policy(format!(
                "artifact {} for {target} has an out-of-bounds ELF program-header table",
                path.display()
            ))
        })?;
    let _ = program_bytes;
    for index in 0..program_count {
        let offset = program_offset + index * program_entry_size;
        let entry = read_at::<4>(file, offset, size, path, "ELF program header")?;
        if u32::from_le_bytes(entry) == PT_INTERP {
            return invalid_executable(
                path,
                target,
                "Linux artifact has a dynamic program interpreter",
            );
        }
    }
    Ok(())
}

fn validate_mach_o(
    file: &mut File,
    size: u64,
    target: AgentTarget,
    path: &Path,
) -> Result<(), ReleaseError> {
    const MACH_HEADER_64_BYTES: usize = 32;
    const MH_EXECUTE: u32 = 2;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;

    let header = read_at::<MACH_HEADER_64_BYTES>(file, 0, size, path, "Mach-O header")?;
    match &header[..4] {
        b"\xcf\xfa\xed\xfe" => {}
        b"\xca\xfe\xba\xbe" | b"\xbe\xba\xfe\xca" | b"\xca\xfe\xba\xbf" | b"\xbf\xba\xfe\xca" => {
            return invalid_executable(path, target, "fat/universal Mach-O files are not allowed");
        }
        b"\xfe\xed\xfa\xcf" | b"\xfe\xed\xfa\xce" => {
            return invalid_executable(path, target, "Mach-O byte order must be little-endian");
        }
        b"\xce\xfa\xed\xfe" => {
            return invalid_executable(path, target, "Mach-O class must be 64-bit");
        }
        _ => return invalid_executable(path, target, "expected a thin 64-bit Mach-O executable"),
    }
    let expected_cpu = match target {
        AgentTarget::X86_64AppleDarwin => CPU_TYPE_X86_64,
        AgentTarget::Aarch64AppleDarwin => CPU_TYPE_ARM64,
        _ => unreachable!("Mach-O validation is only used for Darwin targets"),
    };
    let cpu = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if cpu != expected_cpu {
        return invalid_executable(
            path,
            target,
            &format!("Mach-O CPU type {cpu:#x} does not match expected {expected_cpu:#x}"),
        );
    }
    if u32::from_le_bytes(header[12..16].try_into().unwrap()) != MH_EXECUTE {
        return invalid_executable(path, target, "Mach-O file type is not MH_EXECUTE");
    }
    let command_count = u32::from_le_bytes(header[16..20].try_into().unwrap()) as u64;
    let command_bytes = u32::from_le_bytes(header[20..24].try_into().unwrap()) as u64;
    let commands_end = (MACH_HEADER_64_BYTES as u64)
        .checked_add(command_bytes)
        .filter(|end| *end <= size);
    if command_count == 0 || command_count > 65_535 || commands_end.is_none() {
        return invalid_executable(path, target, "Mach-O load-command table is invalid");
    }
    let commands_end = commands_end.unwrap();
    let mut command_offset = MACH_HEADER_64_BYTES as u64;
    for _ in 0..command_count {
        let command = read_at::<8>(file, command_offset, size, path, "Mach-O load command")?;
        let command_size = u32::from_le_bytes(command[4..8].try_into().unwrap()) as u64;
        let next = command_offset
            .checked_add(command_size)
            .filter(|next| {
                command_size >= 8 && command_size.is_multiple_of(8) && *next <= commands_end
            })
            .ok_or_else(|| {
                ReleaseError::Policy(format!(
                    "artifact {} for {target} has an invalid Mach-O load command",
                    path.display()
                ))
            })?;
        command_offset = next;
    }
    if command_offset != commands_end {
        return invalid_executable(
            path,
            target,
            "Mach-O load-command count and byte size disagree",
        );
    }
    Ok(())
}

fn validate_pe(
    file: &mut File,
    size: u64,
    target: AgentTarget,
    path: &Path,
) -> Result<(), ReleaseError> {
    const DOS_HEADER_BYTES: usize = 64;
    const COFF_HEADER_BYTES: usize = 20;
    const SECTION_HEADER_BYTES: u64 = 40;
    const PE32_PLUS_MAGIC: u16 = 0x020b;
    const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

    let dos = read_at::<DOS_HEADER_BYTES>(file, 0, size, path, "DOS header")?;
    if &dos[..2] != b"MZ" {
        return invalid_executable(path, target, "expected a PE executable with an MZ header");
    }
    let pe_offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
    if pe_offset < DOS_HEADER_BYTES as u64 {
        return invalid_executable(path, target, "PE header offset overlaps the DOS header");
    }
    let prefix = read_at::<{ 4 + COFF_HEADER_BYTES }>(
        file,
        pe_offset,
        size,
        path,
        "PE signature and COFF header",
    )?;
    if &prefix[..4] != b"PE\0\0" {
        return invalid_executable(path, target, "PE signature is invalid");
    }
    let expected_machine = match target {
        AgentTarget::X86_64PcWindowsMsvc => IMAGE_FILE_MACHINE_AMD64,
        AgentTarget::Aarch64PcWindowsMsvc => IMAGE_FILE_MACHINE_ARM64,
        _ => unreachable!("PE validation is only used for Windows targets"),
    };
    let machine = u16::from_le_bytes(prefix[4..6].try_into().unwrap());
    if machine != expected_machine {
        return invalid_executable(
            path,
            target,
            &format!("PE machine {machine:#x} does not match expected {expected_machine:#x}"),
        );
    }
    let section_count = u16::from_le_bytes(prefix[6..8].try_into().unwrap()) as u64;
    if section_count == 0 || section_count > 96 {
        return invalid_executable(path, target, "PE section count is invalid");
    }
    let optional_size = u16::from_le_bytes(prefix[20..22].try_into().unwrap()) as u64;
    if optional_size < 112 {
        return invalid_executable(path, target, "PE32+ optional header is too short");
    }
    let characteristics = u16::from_le_bytes(prefix[22..24].try_into().unwrap());
    if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        return invalid_executable(path, target, "PE COFF header is not executable");
    }
    let optional_offset = pe_offset + 4 + COFF_HEADER_BYTES as u64;
    let magic = read_at::<2>(file, optional_offset, size, path, "PE optional header")?;
    if u16::from_le_bytes(magic) != PE32_PLUS_MAGIC {
        return invalid_executable(path, target, "PE optional header is not PE32+");
    }
    let sections_end = optional_offset
        .checked_add(optional_size)
        .and_then(|offset| offset.checked_add(section_count * SECTION_HEADER_BYTES))
        .filter(|end| *end <= size)
        .ok_or_else(|| {
            ReleaseError::Policy(format!(
                "artifact {} for {target} has an out-of-bounds PE header table",
                path.display()
            ))
        })?;
    let _ = sections_end;
    Ok(())
}

fn read_at<const N: usize>(
    file: &mut File,
    offset: u64,
    size: u64,
    path: &Path,
    kind: &'static str,
) -> Result<[u8; N], ReleaseError> {
    let end = offset.checked_add(N as u64).filter(|end| *end <= size);
    if end.is_none() {
        return Err(ReleaseError::Policy(format!(
            "artifact {} has a truncated or out-of-bounds {kind}",
            path.display()
        )));
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| io_error("seek in artifact", path, source))?;
    let mut bytes = [0_u8; N];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read executable header", path, source))?;
    Ok(bytes)
}

fn invalid_executable<T>(
    path: &Path,
    target: AgentTarget,
    reason: &str,
) -> Result<T, ReleaseError> {
    Err(ReleaseError::Policy(format!(
        "artifact {} is not a valid {target} executable: {reason}",
        path.display()
    )))
}

fn read_regular_file_bounded(
    path: &Path,
    max: u64,
    kind: &'static str,
) -> Result<Vec<u8>, ReleaseError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("stat release input", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReleaseError::Policy(format!(
            "{kind} is not a regular non-symlink file: {}",
            path.display()
        )));
    }
    if metadata.len() > max {
        return Err(ReleaseError::Policy(format!(
            "{kind} exceeds the {max}-byte limit"
        )));
    }
    let file = File::open(path).map_err(|source| io_error("open release input", path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read release input", path, source))?;
    if bytes.len() as u64 > max {
        return Err(ReleaseError::Policy(format!(
            "{kind} exceeds the {max}-byte limit"
        )));
    }
    Ok(bytes)
}

fn write_output(path: &Path, bytes: &[u8]) -> Result<(), ReleaseError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ReleaseError::Policy(format!(
                "release output is not a regular non-symlink file: {}",
                path.display()
            )));
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|source| io_error("create release output", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write release output", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync release output", path, source))
}

struct SigningKeys {
    keys: BTreeMap<String, SigningKey>,
    trusted: TrustedKeySet,
}

impl std::fmt::Debug for SigningKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningKeys")
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

fn parse_signing_keys(bytes: &[u8]) -> Result<SigningKeys, ReleaseError> {
    let encoded = parse_strict_string_map(bytes, "signing secret")?;
    let mut keys = BTreeMap::new();
    let mut public_keys = Vec::with_capacity(encoded.len());
    for (key_id, value) in encoded {
        let seed = decode_canonical_key::<32>(&key_id, &value, "Ed25519 seed")?;
        let key = SigningKey::from_bytes(&seed);
        public_keys.push((
            key_id.clone(),
            STANDARD.encode(key.verifying_key().as_bytes()),
        ));
        keys.insert(key_id, key);
    }
    let trusted = TrustedKeySet::from_base64(public_keys)?;
    Ok(SigningKeys { keys, trusted })
}

fn parse_trusted_public_keys(bytes: &[u8]) -> Result<TrustedKeySet, ReleaseError> {
    let encoded = parse_strict_string_map(bytes, "trusted public key")?;
    Ok(TrustedKeySet::from_base64(encoded)?)
}

fn parse_strict_string_map(
    bytes: &[u8],
    kind: &'static str,
) -> Result<BTreeMap<String, String>, ReleaseError> {
    if bytes.len() > SIGNATURE_DOCUMENT_MAX_BYTES {
        return Err(ReleaseError::Policy(format!(
            "{kind} JSON exceeds the {SIGNATURE_DOCUMENT_MAX_BYTES}-byte limit"
        )));
    }
    serde_json::from_slice::<StrictStringMap>(bytes)
        .map(|map| map.0)
        .map_err(|error| ReleaseError::Policy(format!("{kind} JSON is invalid: {error}")))
}

fn decode_canonical_key<const N: usize>(
    key_id: &str,
    encoded: &str,
    kind: &'static str,
) -> Result<[u8; N], ReleaseError> {
    let decoded = STANDARD.decode(encoded).map_err(|_| {
        ReleaseError::Policy(format!(
            "{kind} for key ID {key_id:?} is not canonical standard base64 encoding of {N} bytes"
        ))
    })?;
    if decoded.len() != N || STANDARD.encode(&decoded) != encoded {
        return Err(ReleaseError::Policy(format!(
            "{kind} for key ID {key_id:?} is not canonical standard base64 encoding of {N} bytes"
        )));
    }
    decoded.try_into().map_err(|_| {
        ReleaseError::Policy(format!("{kind} for key ID {key_id:?} has the wrong length"))
    })
}

fn read_secret_environment(name: &'static str) -> Result<Vec<u8>, ReleaseError> {
    let value = env::var_os(name)
        .ok_or_else(|| {
            ReleaseError::Policy(format!("required environment variable {name} is unset"))
        })?
        .into_string()
        .map_err(|_| ReleaseError::Policy(format!("environment variable {name} is not UTF-8")))?;
    if value.len() > SIGNATURE_DOCUMENT_MAX_BYTES {
        return Err(ReleaseError::Policy(format!(
            "environment variable {name} exceeds the {SIGNATURE_DOCUMENT_MAX_BYTES}-byte limit"
        )));
    }
    Ok(value.into_bytes())
}

fn read_trusted_public_keys(path: Option<&Path>) -> Result<Vec<u8>, ReleaseError> {
    match path {
        Some(path) => read_regular_file_bounded(
            path,
            SIGNATURE_DOCUMENT_MAX_BYTES as u64,
            "trusted public key JSON",
        ),
        None => read_secret_environment(TRUSTED_PUBLIC_KEYS_ENV),
    }
}

struct StrictStringMap(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for StrictStringMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringMapVisitor;

        impl<'de> Visitor<'de> for StringMapVisitor {
            type Value = StrictStringMap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object mapping key IDs to base64 strings")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut entries = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, String>()? {
                    if entries.insert(key, value).is_some() {
                        return Err(M::Error::custom("duplicate key ID"));
                    }
                }
                Ok(StrictStringMap(entries))
            }
        }

        deserializer.deserialize_map(StringMapVisitor)
    }
}

#[derive(Debug, Serialize)]
struct SerializedSignatureDocument {
    schema_version: u32,
    signatures: Vec<SerializedSignature>,
}

#[derive(Debug, Serialize)]
struct SerializedSignature {
    key_id: String,
    signature: String,
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

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> ReleaseError {
    ReleaseError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    const VERSION_TEXT: &str = "0.1.0";
    const PROTOCOL_VERSION: u32 = 7;
    const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn version() -> Version {
        Version::parse(VERSION_TEXT).unwrap()
    }

    fn write_six_artifacts(directory: &Path) {
        fs::create_dir_all(directory).unwrap();
        for target in AgentTarget::ALL {
            let bytes = test_executable(target, target.as_str().as_bytes());
            fs::write(directory.join(target.artifact_filename(&version())), bytes).unwrap();
        }
    }

    fn test_executable(target: AgentTarget, marker: &[u8]) -> Vec<u8> {
        let mut bytes = match target {
            AgentTarget::X86_64UnknownLinuxMusl | AgentTarget::Aarch64UnknownLinuxMusl => {
                let mut bytes = vec![0_u8; 64 + 56];
                bytes[..4].copy_from_slice(b"\x7fELF");
                bytes[4] = 2;
                bytes[5] = 1;
                bytes[6] = 1;
                bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
                let machine = match target {
                    AgentTarget::X86_64UnknownLinuxMusl => 62_u16,
                    AgentTarget::Aarch64UnknownLinuxMusl => 183_u16,
                    _ => unreachable!(),
                };
                bytes[18..20].copy_from_slice(&machine.to_le_bytes());
                bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
                bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
                bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
                bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
                bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
                bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
                bytes
            }
            AgentTarget::X86_64AppleDarwin | AgentTarget::Aarch64AppleDarwin => {
                const LOAD_COMMAND_BYTES: usize = 72;
                let mut bytes = vec![0_u8; 32 + LOAD_COMMAND_BYTES];
                bytes[..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
                let cpu = match target {
                    AgentTarget::X86_64AppleDarwin => 0x0100_0007_u32,
                    AgentTarget::Aarch64AppleDarwin => 0x0100_000c_u32,
                    _ => unreachable!(),
                };
                bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
                bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
                bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
                bytes[20..24].copy_from_slice(&(LOAD_COMMAND_BYTES as u32).to_le_bytes());
                bytes[32..36].copy_from_slice(&0x19_u32.to_le_bytes());
                bytes[36..40].copy_from_slice(&(LOAD_COMMAND_BYTES as u32).to_le_bytes());
                bytes
            }
            AgentTarget::X86_64PcWindowsMsvc | AgentTarget::Aarch64PcWindowsMsvc => {
                const PE_OFFSET: usize = 64;
                const OPTIONAL_BYTES: usize = 240;
                const SECTION_BYTES: usize = 40;
                let mut bytes = vec![0_u8; PE_OFFSET + 4 + 20 + OPTIONAL_BYTES + SECTION_BYTES];
                bytes[..2].copy_from_slice(b"MZ");
                bytes[60..64].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
                bytes[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
                let coff = PE_OFFSET + 4;
                let machine = match target {
                    AgentTarget::X86_64PcWindowsMsvc => 0x8664_u16,
                    AgentTarget::Aarch64PcWindowsMsvc => 0xaa64_u16,
                    _ => unreachable!(),
                };
                bytes[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
                bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
                bytes[coff + 16..coff + 18].copy_from_slice(&(OPTIONAL_BYTES as u16).to_le_bytes());
                bytes[coff + 18..coff + 20].copy_from_slice(&2_u16.to_le_bytes());
                bytes[coff + 20..coff + 22].copy_from_slice(&0x020b_u16.to_le_bytes());
                bytes
            }
        };
        bytes.extend_from_slice(marker);
        bytes
    }

    fn signing_json(entries: &[(&str, u8)]) -> Vec<u8> {
        let map: BTreeMap<_, _> = entries
            .iter()
            .map(|(key_id, seed)| ((*key_id).to_owned(), STANDARD.encode([*seed; 32])))
            .collect();
        serde_json::to_vec(&map).unwrap()
    }

    fn public_json(entries: &[(&str, u8)]) -> Vec<u8> {
        let map: BTreeMap<_, _> = entries
            .iter()
            .map(|(key_id, seed)| {
                let key = SigningKey::from_bytes(&[*seed; 32]);
                (
                    (*key_id).to_owned(),
                    STANDARD.encode(key.verifying_key().as_bytes()),
                )
            })
            .collect();
        serde_json::to_vec(&map).unwrap()
    }

    fn release_fixture() -> (TempDir, PathBuf, Vec<u8>, Vec<u8>) {
        let temp = TempDir::new().unwrap();
        let artifacts = temp.path().join("artifacts");
        write_six_artifacts(&artifacts);
        let manifest =
            assemble_manifest_bytes(&artifacts, &version(), PROTOCOL_VERSION, SOURCE_COMMIT)
                .unwrap();
        let signatures = sign_manifest_bytes(
            &manifest,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &signing_json(&[("release-old", 1), ("release-new", 2)]),
        )
        .unwrap();
        (temp, artifacts, manifest, signatures)
    }

    #[test]
    fn assembly_is_deterministic_newline_terminated_and_canonically_sorted() {
        let temp = TempDir::new().unwrap();
        let artifacts = temp.path().join("artifacts");
        write_six_artifacts(&artifacts);

        let first =
            assemble_manifest_bytes(&artifacts, &version(), PROTOCOL_VERSION, SOURCE_COMMIT)
                .unwrap();
        let second =
            assemble_manifest_bytes(&artifacts, &version(), PROTOCOL_VERSION, SOURCE_COMMIT)
                .unwrap();
        assert_eq!(first, second);
        assert!(first.ends_with(b"\n"));
        assert!(!first.ends_with(b"\n\n"));

        let parsed = parse_manifest(&first, &version(), PROTOCOL_VERSION).unwrap();
        assert_eq!(parsed.artifacts.len(), 6);
        assert_eq!(
            parsed
                .artifacts
                .iter()
                .map(|artifact| artifact.target)
                .collect::<Vec<_>>(),
            AgentTarget::ALL
        );
        let target_names: Vec<_> = parsed
            .artifacts
            .iter()
            .map(|artifact| artifact.target.as_str())
            .collect();
        assert!(target_names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(parsed
            .artifacts
            .iter()
            .all(|artifact| artifact.filename == artifact.target.artifact_filename(&version())));
    }

    #[test]
    fn assembly_and_signing_reject_incomplete_or_extra_target_sets() {
        let temp = TempDir::new().unwrap();
        let artifacts = temp.path().join("artifacts");
        write_six_artifacts(&artifacts);
        let missing = AgentTarget::Aarch64PcWindowsMsvc.artifact_filename(&version());
        fs::remove_file(artifacts.join(&missing)).unwrap();
        let error =
            assemble_manifest_bytes(&artifacts, &version(), PROTOCOL_VERSION, SOURCE_COMMIT)
                .unwrap_err();
        assert!(error.to_string().contains("missing"));

        fs::write(
            artifacts.join(&missing),
            test_executable(AgentTarget::Aarch64PcWindowsMsvc, b"restored"),
        )
        .unwrap();
        fs::write(artifacts.join("unexpected.txt"), b"extra").unwrap();
        let error =
            assemble_manifest_bytes(&artifacts, &version(), PROTOCOL_VERSION, SOURCE_COMMIT)
                .unwrap_err();
        assert!(error.to_string().contains("unexpected"));
        fs::remove_file(artifacts.join("unexpected.txt")).unwrap();

        let complete =
            assemble_manifest_bytes(&artifacts, &version(), PROTOCOL_VERSION, SOURCE_COMMIT)
                .unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&complete).unwrap();
        value["artifacts"].as_array_mut().unwrap().pop();
        let incomplete = serde_json::to_vec(&value).unwrap();
        let error = sign_manifest_bytes(
            &incomplete,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &signing_json(&[("release", 1)]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("incomplete"));
    }

    #[test]
    fn release_verification_requires_the_exact_rotation_signer_set() {
        let (_temp, artifacts, manifest, signatures) = release_fixture();
        let repeated = sign_manifest_bytes(
            &manifest,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &signing_json(&[("release-new", 2), ("release-old", 1)]),
        )
        .unwrap();
        assert_eq!(signatures, repeated);
        let document = parse_signature_document(&signatures).unwrap();
        assert_eq!(
            document
                .signatures
                .iter()
                .map(|signature| signature.key_id.as_str())
                .collect::<Vec<_>>(),
            ["release-new", "release-old"]
        );

        let both = verify_release(
            &manifest,
            &signatures,
            &artifacts,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &public_json(&[("release-old", 1), ("release-new", 2)]),
        )
        .unwrap();
        assert_eq!(both.verified_signers, 2);

        for key in [("release-old", 1), ("release-new", 2)] {
            let error = verify_release(
                &manifest,
                &signatures,
                &artifacts,
                &version(),
                PROTOCOL_VERSION,
                SOURCE_COMMIT,
                &public_json(&[key]),
            )
            .unwrap_err();
            assert!(error.to_string().contains("exactly match"));
        }

        let only_new = sign_manifest_bytes(
            &manifest,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &signing_json(&[("release-new", 2)]),
        )
        .unwrap();
        let error = verify_release(
            &manifest,
            &only_new,
            &artifacts,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &public_json(&[("release-old", 1), ("release-new", 2)]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("exactly match"));

        // Client-side threshold verification remains intentionally available
        // through the registry library rather than the strict release gate.
        let client_trust = parse_trusted_public_keys(&public_json(&[("release-new", 2)])).unwrap();
        let client = verify_manifest(
            &manifest,
            &signatures,
            &client_trust,
            1,
            &version(),
            PROTOCOL_VERSION,
        )
        .unwrap();
        assert_eq!(client.verified_signers.len(), 1);
    }

    #[test]
    fn verification_rejects_tampered_missing_and_extra_artifacts() {
        let (_temp, artifacts, manifest, signatures) = release_fixture();
        let trust = public_json(&[("release-old", 1), ("release-new", 2)]);
        verify_release(
            &manifest,
            &signatures,
            &artifacts,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &trust,
        )
        .unwrap();

        let target_path =
            artifacts.join(AgentTarget::X86_64UnknownLinuxMusl.artifact_filename(&version()));
        let original = fs::read(&target_path).unwrap();
        let mut changed = original.clone();
        *changed.last_mut().unwrap() ^= 0xff;
        fs::write(&target_path, &changed).unwrap();
        let error = verify_release(
            &manifest,
            &signatures,
            &artifacts,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &trust,
        )
        .unwrap_err();
        assert!(error.to_string().contains("mismatch"));

        fs::write(&target_path, &original).unwrap();
        fs::remove_file(&target_path).unwrap();
        let error = verify_release(
            &manifest,
            &signatures,
            &artifacts,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &trust,
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing"));

        fs::write(&target_path, &original).unwrap();
        fs::write(artifacts.join("extra-agent"), b"extra").unwrap();
        let error = verify_release(
            &manifest,
            &signatures,
            &artifacts,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &trust,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unexpected"));
    }

    #[test]
    fn executable_validation_rejects_wrong_architecture_and_format() {
        let temp = TempDir::new().unwrap();
        let cases = [
            (
                AgentTarget::Aarch64UnknownLinuxMusl,
                AgentTarget::X86_64UnknownLinuxMusl,
                "ELF machine",
            ),
            (
                AgentTarget::Aarch64AppleDarwin,
                AgentTarget::X86_64AppleDarwin,
                "Mach-O CPU type",
            ),
            (
                AgentTarget::Aarch64PcWindowsMsvc,
                AgentTarget::X86_64PcWindowsMsvc,
                "PE machine",
            ),
        ];
        for (expected, actual, message) in cases {
            let path = temp.path().join(expected.artifact_filename(&version()));
            fs::write(&path, test_executable(actual, b"wrong-machine")).unwrap();
            let error = artifact_size_and_digest(&path, expected).unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
        }

        let path = temp.path().join("not-an-executable");
        fs::write(&path, vec![0x55; 512]).unwrap();
        let error = artifact_size_and_digest(&path, AgentTarget::X86_64PcWindowsMsvc).unwrap_err();
        assert!(error.to_string().contains("MZ header"));
    }

    #[test]
    fn executable_validation_rejects_wrong_endian_fat_dynamic_and_truncated_headers() {
        let temp = TempDir::new().unwrap();

        let elf_path = temp.path().join("agent-elf");
        let mut elf = test_executable(AgentTarget::Aarch64UnknownLinuxMusl, b"big-endian");
        elf[5] = 2;
        fs::write(&elf_path, &elf).unwrap();
        let error =
            artifact_size_and_digest(&elf_path, AgentTarget::Aarch64UnknownLinuxMusl).unwrap_err();
        assert!(error.to_string().contains("little-endian"));

        let mut elf = test_executable(AgentTarget::Aarch64UnknownLinuxMusl, b"interpreter");
        elf[64..68].copy_from_slice(&3_u32.to_le_bytes());
        fs::write(&elf_path, &elf).unwrap();
        let error =
            artifact_size_and_digest(&elf_path, AgentTarget::Aarch64UnknownLinuxMusl).unwrap_err();
        assert!(error.to_string().contains("dynamic program interpreter"));

        let mach_path = temp.path().join("agent-mach");
        let mut mach = test_executable(AgentTarget::Aarch64AppleDarwin, b"fat");
        mach[..4].copy_from_slice(b"\xca\xfe\xba\xbe");
        fs::write(&mach_path, &mach).unwrap();
        let error =
            artifact_size_and_digest(&mach_path, AgentTarget::Aarch64AppleDarwin).unwrap_err();
        assert!(error.to_string().contains("fat/universal"));

        let pe_path = temp.path().join("agent-pe");
        let mut pe = test_executable(AgentTarget::Aarch64PcWindowsMsvc, b"bad-offset");
        pe[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&pe_path, &pe).unwrap();
        let error =
            artifact_size_and_digest(&pe_path, AgentTarget::Aarch64PcWindowsMsvc).unwrap_err();
        assert!(error.to_string().contains("out-of-bounds"));
    }

    #[test]
    fn duplicate_artifact_digests_are_rejected() {
        let mut digests = BTreeMap::new();
        let digest = "1".repeat(64);
        record_unique_digest(&mut digests, AgentTarget::X86_64UnknownLinuxMusl, &digest).unwrap();
        let error =
            record_unique_digest(&mut digests, AgentTarget::Aarch64UnknownLinuxMusl, &digest)
                .unwrap_err();
        assert!(error.to_string().contains("identical artifact SHA-256"));
    }

    #[test]
    fn signatures_cover_exact_manifest_bytes_and_expected_identity() {
        let (_temp, artifacts, manifest, signatures) = release_fixture();
        let trust = public_json(&[("release-old", 1), ("release-new", 2)]);

        let mut changed = manifest.clone();
        changed.push(b'\n');
        let error = verify_release(
            &changed,
            &signatures,
            &artifacts,
            &version(),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &trust,
        )
        .unwrap_err();
        assert!(matches!(error, ReleaseError::Verification(_)));

        let error = verify_release(
            &manifest,
            &signatures,
            &artifacts,
            &version(),
            PROTOCOL_VERSION,
            "ffffffffffffffffffffffffffffffffffffffff",
            &trust,
        )
        .unwrap_err();
        assert!(error.to_string().contains("source commit"));

        let error = verify_release(
            &manifest,
            &signatures,
            &artifacts,
            &Version::new(0, 1, 1),
            PROTOCOL_VERSION,
            SOURCE_COMMIT,
            &trust,
        )
        .unwrap_err();
        assert!(error.to_string().contains("requested version"));

        let error = verify_release(
            &manifest,
            &signatures,
            &artifacts,
            &version(),
            PROTOCOL_VERSION + 1,
            SOURCE_COMMIT,
            &trust,
        )
        .unwrap_err();
        assert!(error.to_string().contains("protocol version"));
    }

    #[test]
    fn malformed_signing_secret_maps_are_rejected_without_echoing_secrets() {
        let canonical = STANDARD.encode([7_u8; 32]);
        let wrong_length = STANDARD.encode([7_u8; 31]);
        let duplicate = format!(r#"{{"key":"{canonical}","key":"{canonical}"}}"#);
        let noncanonical = canonical.trim_end_matches('=').to_owned();
        let cases = [
            b"{".to_vec(),
            duplicate.into_bytes(),
            serde_json::to_vec(&BTreeMap::from([("bad key", canonical.clone())])).unwrap(),
            serde_json::to_vec(&BTreeMap::from([("key", noncanonical.clone())])).unwrap(),
            serde_json::to_vec(&BTreeMap::from([("key", wrong_length.clone())])).unwrap(),
            serde_json::to_vec(&BTreeMap::from([
                ("first", canonical.clone()),
                ("second", canonical.clone()),
            ]))
            .unwrap(),
            b"{}".to_vec(),
        ];
        for bytes in cases {
            let error = parse_signing_keys(&bytes).unwrap_err();
            let message = error.to_string();
            assert!(!message.contains(&canonical));
            assert!(!message.contains(&noncanonical));
            assert!(!message.contains(&wrong_length));
        }
    }

    #[test]
    fn trusted_public_keys_can_be_loaded_from_a_strict_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("trusted.json");
        let expected = public_json(&[("release", 9)]);
        fs::write(&path, &expected).unwrap();
        assert_eq!(read_trusted_public_keys(Some(&path)).unwrap(), expected);

        let duplicate = format!(
            r#"{{"release":"{}","release":"{}"}}"#,
            STANDARD.encode(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes()),
            STANDARD.encode(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes())
        );
        assert!(parse_trusted_public_keys(duplicate.as_bytes()).is_err());
    }
}
