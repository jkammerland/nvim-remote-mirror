use super::{
    default_state_dir, validate_managed_remote_agent_name, workspace_key, RemoteTransport,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use nrm_protocol::{
    read_runtime_frame, write_runtime_frame, CapabilitySet, RuntimeCapability, RuntimeExitStatus,
    RuntimeMessage, RuntimeOutputStream, RuntimePeerRole, RuntimePersistence, RuntimeProcessId,
    RuntimeProcessSpec, RuntimeSignal, RuntimeStateMachine, TerminalSize, PROTOCOL_VERSION,
    RUNTIME_MAX_DATA_CHUNK_LEN,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TICKET_SCHEMA_VERSION: u8 = 1;
const TICKET_ID_BYTES: usize = 32;
const TICKET_ID_HEX_LEN: usize = TICKET_ID_BYTES * 2;
const MAX_TICKET_BYTES: usize = 256 * 1024;
const MAX_TICKET_FILE_BYTES: usize = 384 * 1024;
const MAX_TICKET_CREATE_ATTEMPTS: usize = 16;
const TICKET_TTL: Duration = Duration::from_secs(30);
const TICKET_CLOCK_SKEW: Duration = Duration::from_secs(5);
const TICKET_ORPHAN_MAX_AGE: Duration = Duration::from_secs(5 * 60);
const MAX_RUNTIME_RECORD_ENTRIES: usize = 4_096;
const MAX_RUNTIME_RECORD_SCAN_ENTRIES: usize = MAX_RUNTIME_RECORD_ENTRIES + 1_024;
const MAX_RUNTIME_RECORD_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const RUNTIME_RECORD_LOCK_FILE: &str = ".records.lock";
const MAX_RUNTIME_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_SSH_CONNECT_TIMEOUT_SECONDS: u64 = 3_600;
const RUNTIME_READER_QUEUE_DEPTH: usize = 32;
const RUNTIME_WRITER_QUEUE_DEPTH: usize = 16;
const RUNTIME_OUTPUT_QUEUE_DEPTH: usize = 16;
const RUNTIME_WRITER_TIMEOUT: Duration = Duration::from_secs(10);
const RUNTIME_OUTPUT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const RUNTIME_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const RUNTIME_BRIDGE_EXIT_GRACE: Duration = Duration::from_secs(3);
const RUNTIME_TRANSPORT_EXIT_CODE: i32 = 125;
const RUNTIME_RESULT_SCHEMA_VERSION: u8 = 1;
const MAX_RUNTIME_RESULT_BYTES: usize = 32 * 1024;
const MAX_RUNTIME_DIAGNOSTIC_BYTES: usize = 8 * 1024;
const RUNTIME_CONTROL_SCHEMA_VERSION: u8 = 1;
const RUNTIME_CONTROL_NONCE_BYTES: usize = 16;
const MAX_RUNTIME_CONTROL_BYTES: usize = 4 * 1024;
const MAX_RUNTIME_CONTROL_ENTRIES: usize = 4_096;
const MAX_RUNTIME_CONTROL_SCAN_ENTRIES: usize = MAX_RUNTIME_CONTROL_ENTRIES + 1_024;
const RUNTIME_CONTROL_MAX_AGE: Duration = Duration::from_secs(5 * 60);
const RUNTIME_CONTROL_LOCK_FILE: &str = ".mailbox.lock";
const RUNTIME_CONTROL_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const RUNTIME_CONTROL_LOCK_POLL: Duration = Duration::from_millis(5);
const RUNTIME_TRUST_SCHEMA_VERSION: u8 = 1;
const RUNTIME_TRUST_STORE_FILE: &str = "trusted-workspaces-v1.json";
const RUNTIME_TRUST_LOCK_FILE: &str = ".trusted-workspaces-v1.lock";
const RUNTIME_TRUST_MAX_BYTES: usize = 1024 * 1024;
const RUNTIME_TRUST_MAX_ENTRIES: usize = 4_096;
const RUNTIME_TRUST_PENDING_MAX_ENTRIES: usize = 16;
const RUNTIME_TRUST_PENDING_SCAN_ENTRIES: usize = 64;
const RUNTIME_TRUST_PENDING_MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeTicket {
    pub schema_version: u8,
    pub workspace_key: String,
    pub remote_root: String,
    pub ssh: Option<String>,
    pub agent: String,
    pub ssh_connect_timeout_seconds: u64,
    pub request_timeout_ms: u64,
    pub capability: RuntimeCapability,
    pub spec: RuntimeProcessSpec,
    #[serde(default)]
    pub remote_host: Option<super::RemoteHostInfo>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRuntimeTicket {
    schema_version: u8,
    ticket_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    ticket: RuntimeTicket,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTicketEnvelope {
    schema_version: u8,
    workspace_key: String,
    protection: RuntimeContentProtection,
    protected_payload: String,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RuntimeContentProtection {
    PosixMode,
    WindowsDpapi,
    WindowsAcl,
}

struct ProtectedRuntimeContent {
    protection: RuntimeContentProtection,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[serde(rename_all = "snake_case")]
enum RuntimeResultKind {
    ProcessExit,
    Signal,
    TimedOut,
    OutputLimit,
    Cancelled,
    Detached,
    RuntimeError,
    TransportError,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeProxyResult {
    schema_version: u8,
    exit_code: i32,
    kind: RuntimeResultKind,
    error_code: Option<String>,
    message: Option<String>,
    output_truncated: bool,
    bridge_stderr: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeResultEnvelope {
    schema_version: u8,
    protection: RuntimeContentProtection,
    protected_payload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeControlMessage {
    schema_version: u8,
    ticket_id: String,
    issued_at_unix_ms: u64,
    signal: RuntimeSignal,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTrustStore {
    schema_version: u8,
    trusted: BTreeMap<String, bool>,
}

struct RuntimeStateEntry {
    path: PathBuf,
    name: String,
    size: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RuntimeStateUsage {
    entries: usize,
    bytes: u64,
}

struct RuntimeStateScan {
    entries: Vec<RuntimeStateEntry>,
    overflow: bool,
}

pub(super) fn create_ticket_from_stdin(state_dir: Option<PathBuf>) -> Result<()> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_TICKET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("failed to read runtime ticket request")?;
    if bytes.len() > MAX_TICKET_BYTES {
        bail!("runtime ticket request exceeds its {MAX_TICKET_BYTES}-byte limit");
    }
    let ticket: RuntimeTicket =
        serde_json::from_slice(&bytes).context("runtime ticket request is not strict JSON")?;
    let id = create_ticket(state_dir.as_deref(), &ticket)?;
    if let Err(error) = writeln!(io::stdout().lock(), "{id}") {
        let _ = remove_ticket(state_dir.as_deref(), &id);
        return Err(error).context("failed to return runtime ticket ID");
    }
    Ok(())
}

pub(super) fn run_from_ticket(state_dir: Option<PathBuf>, ticket_id: &str) -> i32 {
    let mut local_terminal_mode = None;
    let result = (|| -> Result<RuntimeProxyResult> {
        let ticket = consume_ticket(state_dir.as_deref(), ticket_id)?;
        validate_ticket(&ticket)?;
        // Neovim starts a terminal bridge inside a local PTY/ConPTY. Its line
        // discipline must not echo or interpret bytes before the authoritative
        // remote PTY sees them, or users observe duplicate input and local
        // Ctrl-C handling. Pipe-backed process bridges intentionally retain
        // their ordinary stdio behavior.
        if ticket.capability == RuntimeCapability::ProcessPtyV1 {
            local_terminal_mode = enter_local_runtime_terminal_mode()?;
        }
        run_proxy(ticket, state_dir.as_deref(), ticket_id)
    })()
    .unwrap_or_else(|error| transport_error_result(&error));
    let exit_code = publish_runtime_result(state_dir.as_deref(), ticket_id, &result);
    // Keep the local endpoint raw until after the result is durably published;
    // dropping earlier leaves a short post-process window in which the local
    // PTY could echo bytes that the stopped input flow will not forward.
    drop(local_terminal_mode);
    exit_code
}

fn publish_runtime_result(
    state_dir: Option<&Path>,
    ticket_id: &str,
    result: &RuntimeProxyResult,
) -> i32 {
    if write_runtime_result(state_dir, ticket_id, result).is_ok() {
        result.exit_code
    } else {
        // Child stdout/stderr must remain byte-exact, so publication failures
        // cannot be reported on either stream. A transport exit guarantees the
        // frontend will not mistake a successful child for a complete runtime
        // result when the structured side channel is missing.
        RUNTIME_TRANSPORT_EXIT_CODE
    }
}

pub(super) fn read_result_to_stdout(state_dir: Option<PathBuf>, ticket_id: &str) -> Result<()> {
    let result = consume_runtime_result(state_dir.as_deref(), ticket_id)?;
    let bytes = serde_json::to_vec(&result).context("failed to encode runtime result")?;
    io::stdout()
        .lock()
        .write_all(&bytes)
        .context("failed to return runtime result")
}

pub(super) fn enqueue_signal(
    state_dir: Option<PathBuf>,
    ticket_id: &str,
    signal: &str,
) -> Result<()> {
    let signal = match signal {
        "interrupt" => RuntimeSignal::Interrupt,
        "terminate" => RuntimeSignal::Terminate,
        "kill" => RuntimeSignal::Kill,
        "hangup" => RuntimeSignal::Hangup,
        _ => bail!("runtime signal must be interrupt, terminate, kill, or hangup"),
    };
    validate_ticket_id(ticket_id)?;
    let directory = control_directory(state_dir.as_deref());
    let _directory_guard = ensure_private_ticket_directory(&directory)?;
    let _mailbox_lock = acquire_runtime_control_lock(&directory)?;
    cleanup_orphan_control_files(&directory)?;
    if bounded_control_paths(&directory)?.len() >= MAX_RUNTIME_CONTROL_ENTRIES {
        bail!("runtime control directory reached its {MAX_RUNTIME_CONTROL_ENTRIES}-entry limit");
    }

    let message = RuntimeControlMessage {
        schema_version: RUNTIME_CONTROL_SCHEMA_VERSION,
        ticket_id: ticket_id.to_owned(),
        issued_at_unix_ms: unix_time_ms()?,
        signal,
    };
    let content = serde_json::to_vec(&message).context("failed to encode runtime signal")?;
    if content.len() > MAX_RUNTIME_CONTROL_BYTES {
        bail!("runtime signal exceeds its file limit");
    }
    for _ in 0..MAX_TICKET_CREATE_ATTEMPTS {
        let nonce = random_hex_id(RUNTIME_CONTROL_NONCE_BYTES)?;
        let path = directory.join(format!("{ticket_id}-{nonce}.json"));
        let pending_nonce = random_hex_id(RUNTIME_CONTROL_NONCE_BYTES)?;
        let pending_path = directory.join(format!(".pending-{pending_nonce}.tmp"));
        match create_private_ticket_file(&pending_path) {
            Ok(mut file) => {
                let write_result = (|| -> Result<()> {
                    validate_private_ticket_file(&pending_path, &file)?;
                    file.write_all(&content)
                        .context("failed to write runtime signal")?;
                    file.sync_all().context("failed to sync runtime signal")
                })();
                drop(file);
                if let Err(error) = write_result {
                    let _ = fs::remove_file(&pending_path);
                    return Err(error);
                }
                if let Err(error) = publish_private_record_noreplace(&pending_path, &path)
                    .context("failed to publish runtime signal")
                {
                    let _ = fs::remove_file(&pending_path);
                    if error.chain().any(|cause| {
                        cause
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
                    }) {
                        continue;
                    }
                    return Err(error);
                }
                super::sync_parent_dir(&path)?;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create pending runtime signal {}",
                        pending_path.display()
                    )
                })
            }
        }
    }
    bail!("failed to allocate a unique runtime signal record")
}

pub(super) fn prepare_runtime_state(state_dir: Option<PathBuf>) -> Result<()> {
    let directory = runtime_state_directory(state_dir.as_deref());
    let _directory_guard = ensure_private_ticket_directory(&directory)?;
    let _trust_lock =
        acquire_private_runtime_lock(&directory, RUNTIME_TRUST_LOCK_FILE, "workspace trust store")?;
    cleanup_orphan_trust_pending_files(&directory)?;
    read_runtime_trust_store(&directory)?;
    Ok(())
}

pub(super) fn check_workspace_trust(state_dir: Option<PathBuf>, digest: &str) -> Result<()> {
    validate_trust_digest(digest)?;
    let directory = runtime_state_directory(state_dir.as_deref());
    let _directory_guard = ensure_private_ticket_directory(&directory)?;
    let _trust_lock =
        acquire_private_runtime_lock(&directory, RUNTIME_TRUST_LOCK_FILE, "workspace trust store")?;
    cleanup_orphan_trust_pending_files(&directory)?;
    let store = read_runtime_trust_store(&directory)?;
    let status = if store.trusted.contains_key(digest) {
        "trusted"
    } else {
        "untrusted"
    };
    writeln!(io::stdout().lock(), "{status}").context("failed to return workspace trust status")
}

pub(super) fn set_workspace_trust(
    state_dir: Option<PathBuf>,
    digest: &str,
    trusted: bool,
) -> Result<()> {
    validate_trust_digest(digest)?;
    let directory = runtime_state_directory(state_dir.as_deref());
    let _directory_guard = ensure_private_ticket_directory(&directory)?;
    let _trust_lock =
        acquire_private_runtime_lock(&directory, RUNTIME_TRUST_LOCK_FILE, "workspace trust store")?;
    cleanup_orphan_trust_pending_files(&directory)?;
    let mut store = read_runtime_trust_store(&directory)?;
    if trusted {
        if !store.trusted.contains_key(digest) && store.trusted.len() >= RUNTIME_TRUST_MAX_ENTRIES {
            bail!("workspace trust store reached its {RUNTIME_TRUST_MAX_ENTRIES}-entry limit");
        }
        store.trusted.insert(digest.to_owned(), true);
    } else {
        store.trusted.remove(digest);
    }
    write_runtime_trust_store(&directory, &store)
}

fn runtime_state_directory(state_dir: Option<&Path>) -> PathBuf {
    state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(default_state_dir)
        .join("runtime")
}

fn validate_trust_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("workspace trust digest must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_runtime_trust_store(store: &RuntimeTrustStore) -> Result<()> {
    if store.schema_version != RUNTIME_TRUST_SCHEMA_VERSION {
        bail!(
            "unsupported workspace trust schema version {}",
            store.schema_version
        );
    }
    if store.trusted.len() > RUNTIME_TRUST_MAX_ENTRIES {
        bail!("workspace trust store exceeds its {RUNTIME_TRUST_MAX_ENTRIES}-entry limit");
    }
    for (digest, trusted) in &store.trusted {
        validate_trust_digest(digest)?;
        if !trusted {
            bail!("workspace trust store values must be true");
        }
    }
    Ok(())
}

fn read_runtime_trust_store(directory: &Path) -> Result<RuntimeTrustStore> {
    let path = directory.join(RUNTIME_TRUST_STORE_FILE);
    let file = match open_private_ticket_file(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RuntimeTrustStore {
                schema_version: RUNTIME_TRUST_SCHEMA_VERSION,
                trusted: BTreeMap::new(),
            })
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to open workspace trust store {}", path.display())
            })
        }
    };
    validate_private_ticket_file(&path, &file)
        .context("workspace trust store does not have private file security")?;
    let size = file
        .metadata()
        .context("failed to inspect workspace trust store")?
        .len();
    if size > RUNTIME_TRUST_MAX_BYTES as u64 {
        bail!("workspace trust store exceeds its {RUNTIME_TRUST_MAX_BYTES}-byte limit");
    }
    let mut bytes = Vec::new();
    file.take((RUNTIME_TRUST_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("failed to read workspace trust store")?;
    if bytes.len() > RUNTIME_TRUST_MAX_BYTES {
        bail!("workspace trust store exceeds its {RUNTIME_TRUST_MAX_BYTES}-byte limit");
    }
    let store: RuntimeTrustStore =
        serde_json::from_slice(&bytes).context("workspace trust store is not strict JSON")?;
    validate_runtime_trust_store(&store)?;
    Ok(store)
}

fn is_trust_pending_file(name: &str) -> bool {
    let Some(nonce) = name
        .strip_prefix(".trust-pending-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    nonce.len() == RUNTIME_CONTROL_NONCE_BYTES * 2
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn scan_trust_pending_files(directory: &Path, maximum: usize) -> Result<RuntimeStateScan> {
    let entries = fs::read_dir(directory).with_context(|| {
        format!(
            "failed to inspect private runtime state directory {}",
            directory.display()
        )
    })?;
    let mut paths = Vec::new();
    let mut overflow = false;
    for entry in entries {
        let entry = entry.context("failed to inspect runtime state directory entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_trust_pending_file(name) {
            continue;
        }
        if paths.len() == maximum {
            overflow = true;
            break;
        }
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).context("failed to inspect pending workspace trust store")
            }
        };
        paths.push(RuntimeStateEntry {
            path,
            name: name.to_owned(),
            size: metadata.len(),
            modified: metadata.modified().ok(),
        });
    }
    paths.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(RuntimeStateScan {
        entries: paths,
        overflow,
    })
}

fn runtime_state_usage(entries: &[RuntimeStateEntry]) -> Result<RuntimeStateUsage> {
    let mut usage = RuntimeStateUsage::default();
    for entry in entries {
        usage.entries = usage
            .entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("runtime state entry count overflow"))?;
        usage.bytes = usage
            .bytes
            .checked_add(entry.size)
            .ok_or_else(|| anyhow!("runtime state byte count overflow"))?;
    }
    Ok(usage)
}

fn ensure_runtime_state_capacity(
    label: &str,
    usage: RuntimeStateUsage,
    additional_bytes: usize,
    maximum_entries: usize,
    maximum_bytes: u64,
) -> Result<()> {
    let projected_entries = usage
        .entries
        .checked_add(1)
        .ok_or_else(|| anyhow!("{label} entry count overflow"))?;
    if projected_entries > maximum_entries {
        bail!("{label} reached its {maximum_entries}-entry limit");
    }
    let additional_bytes =
        u64::try_from(additional_bytes).context("runtime state record size does not fit u64")?;
    let projected_bytes = usage
        .bytes
        .checked_add(additional_bytes)
        .ok_or_else(|| anyhow!("{label} byte count overflow"))?;
    if projected_bytes > maximum_bytes {
        bail!("{label} reached its {maximum_bytes}-byte limit");
    }
    Ok(())
}

fn cleanup_orphan_trust_pending_files(directory: &Path) -> Result<()> {
    // The caller owns the workspace-trust lock. A conforming writer cannot
    // still be using any pending file once this lock has been acquired, so a
    // strictly named, private pending file is a crash orphan regardless of
    // wall-clock age.
    let scan = scan_trust_pending_files(directory, RUNTIME_TRUST_PENDING_SCAN_ENTRIES)?;
    let mut removed = false;
    for entry in scan.entries {
        let file = match open_private_ticket_file(&entry.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to open pending workspace trust store {}",
                        entry.path.display()
                    )
                })
            }
        };
        validate_private_ticket_file(&entry.path, &file)
            .context("pending workspace trust store is not private")?;
        remove_open_ticket_file(&entry.path, &file).with_context(|| {
            format!(
                "failed to remove pending workspace trust store {}",
                entry.path.display()
            )
        })?;
        removed = true;
    }
    if removed {
        super::sync_parent_dir(&directory.join(RUNTIME_TRUST_STORE_FILE))?;
    }
    if scan.overflow {
        bail!(
            "pending workspace trust store cleanup exceeded its {}-entry batch limit; retry",
            RUNTIME_TRUST_PENDING_SCAN_ENTRIES
        );
    }
    Ok(())
}

fn ensure_trust_pending_capacity(directory: &Path, additional_bytes: usize) -> Result<()> {
    let scan = scan_trust_pending_files(directory, RUNTIME_TRUST_PENDING_MAX_ENTRIES + 1)?;
    if scan.overflow {
        bail!(
            "pending workspace trust stores exceed their {}-entry limit",
            RUNTIME_TRUST_PENDING_MAX_ENTRIES
        );
    }
    let usage = runtime_state_usage(&scan.entries)?;
    ensure_runtime_state_capacity(
        "pending workspace trust stores",
        usage,
        additional_bytes,
        RUNTIME_TRUST_PENDING_MAX_ENTRIES,
        RUNTIME_TRUST_PENDING_MAX_BYTES,
    )
}

fn write_runtime_trust_store(directory: &Path, store: &RuntimeTrustStore) -> Result<()> {
    validate_runtime_trust_store(store)?;
    let content = serde_json::to_vec(store).context("failed to encode workspace trust store")?;
    if content.len() > RUNTIME_TRUST_MAX_BYTES {
        bail!("workspace trust store exceeds its {RUNTIME_TRUST_MAX_BYTES}-byte limit");
    }
    ensure_trust_pending_capacity(directory, content.len())?;
    let destination = directory.join(RUNTIME_TRUST_STORE_FILE);
    match open_private_ticket_file(&destination) {
        Ok(existing) => {
            validate_private_ticket_file(&destination, &existing)
                .context("existing workspace trust store does not have private file security")?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect existing workspace trust store {}",
                    destination.display()
                )
            })
        }
    }

    for _ in 0..MAX_TICKET_CREATE_ATTEMPTS {
        let nonce = random_hex_id(RUNTIME_CONTROL_NONCE_BYTES)?;
        let temporary = directory.join(format!(".trust-pending-{nonce}.tmp"));
        match create_private_ticket_file(&temporary) {
            Ok(mut file) => {
                let write_result = (|| -> Result<()> {
                    validate_private_ticket_file(&temporary, &file)?;
                    file.write_all(&content)
                        .context("failed to write workspace trust store")?;
                    file.sync_all()
                        .context("failed to sync workspace trust store")
                })();
                drop(file);
                if let Err(error) = write_result {
                    let _ = fs::remove_file(&temporary);
                    return Err(error);
                }
                if let Err(error) = replace_private_record(&temporary, &destination) {
                    let _ = fs::remove_file(&temporary);
                    return Err(error)
                        .context("failed to atomically replace workspace trust store");
                }
                super::sync_parent_dir(&destination)?;
                let activated = open_private_ticket_file(&destination).with_context(|| {
                    format!(
                        "failed to reopen activated workspace trust store {}",
                        destination.display()
                    )
                })?;
                validate_private_ticket_file(&destination, &activated)
                    .context("activated workspace trust store is not private")?;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create pending workspace trust store {}",
                        temporary.display()
                    )
                })
            }
        }
    }
    bail!("failed to allocate a unique pending workspace trust store")
}

fn ticket_directory(state_dir: Option<&Path>) -> PathBuf {
    state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(default_state_dir)
        .join("runtime")
        .join("tickets")
}

fn result_directory(state_dir: Option<&Path>) -> PathBuf {
    state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(default_state_dir)
        .join("runtime")
        .join("results")
}

fn control_directory(state_dir: Option<&Path>) -> PathBuf {
    state_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(default_state_dir)
        .join("runtime")
        .join("control")
}

fn validate_ticket_id(ticket_id: &str) -> Result<()> {
    if ticket_id.len() != TICKET_ID_HEX_LEN
        || !ticket_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("runtime ticket ID must be {TICKET_ID_HEX_LEN} lowercase hexadecimal characters");
    }
    Ok(())
}

fn ticket_path(state_dir: Option<&Path>, ticket_id: &str) -> Result<PathBuf> {
    validate_ticket_id(ticket_id)?;
    Ok(ticket_directory(state_dir).join(format!("{ticket_id}.json")))
}

fn result_path(state_dir: Option<&Path>, ticket_id: &str) -> Result<PathBuf> {
    validate_ticket_id(ticket_id)?;
    Ok(result_directory(state_dir).join(format!("{ticket_id}.json")))
}

fn write_runtime_result(
    state_dir: Option<&Path>,
    ticket_id: &str,
    result: &RuntimeProxyResult,
) -> Result<()> {
    validate_ticket_id(ticket_id)?;
    let directory = result_directory(state_dir);
    let _directory_guard = ensure_private_ticket_directory(&directory)?;

    let plaintext = serde_json::to_vec(result).context("failed to encode runtime result")?;
    if plaintext.len() > MAX_RUNTIME_RESULT_BYTES {
        bail!("runtime result exceeds its {MAX_RUNTIME_RESULT_BYTES}-byte limit");
    }
    let protected = protect_result_content(&plaintext, ticket_id)?;
    let envelope = RuntimeResultEnvelope {
        schema_version: RUNTIME_RESULT_SCHEMA_VERSION,
        protection: protected.protection,
        protected_payload: BASE64_STANDARD.encode(protected.bytes),
    };
    let content =
        serde_json::to_vec(&envelope).context("failed to encode runtime result envelope")?;
    if content.len() > MAX_TICKET_FILE_BYTES {
        bail!("protected runtime result exceeds its file limit");
    }

    let _record_lock = acquire_runtime_record_lock(&directory)?;
    prepare_runtime_record_publication(&directory, Some(ticket_id), content.len())?;
    let path = result_path(state_dir, ticket_id)?;
    let mut file = create_private_ticket_file(&path)
        .with_context(|| format!("failed to create runtime result {}", path.display()))?;
    let write_result = (|| -> Result<()> {
        validate_private_ticket_file(&path, &file)?;
        file.write_all(&content)
            .context("failed to write runtime result")?;
        file.sync_all().context("failed to sync runtime result")?;
        super::sync_parent_dir(&path)
    })();
    if let Err(error) = write_result {
        drop(file);
        remove_new_runtime_record(&path);
        return Err(error);
    }
    drop(file);
    if let Err(error) = validate_runtime_record_publication(&directory) {
        remove_new_runtime_record(&path);
        let _ = super::sync_parent_dir(&path);
        return Err(error).context("runtime result publication exceeded state limits");
    }
    Ok(())
}

fn consume_runtime_result(state_dir: Option<&Path>, ticket_id: &str) -> Result<RuntimeProxyResult> {
    let directory = result_directory(state_dir);
    let _directory_guard = ensure_private_ticket_directory(&directory)?;
    let path = result_path(state_dir, ticket_id)?;
    let file = take_runtime_record(&directory, &path, "runtime result")?;

    let mut bytes = Vec::new();
    file.take((MAX_TICKET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("failed to read runtime result")?;
    if bytes.len() > MAX_TICKET_FILE_BYTES {
        bail!("runtime result exceeds its file limit");
    }
    let envelope: RuntimeResultEnvelope =
        serde_json::from_slice(&bytes).context("runtime result envelope is not strict JSON")?;
    if envelope.schema_version != RUNTIME_RESULT_SCHEMA_VERSION {
        bail!(
            "unsupported runtime result envelope schema version {}",
            envelope.schema_version
        );
    }
    let protected = BASE64_STANDARD
        .decode(envelope.protected_payload.as_bytes())
        .context("runtime result envelope payload is not standard base64")?;
    let plaintext = unprotect_result_content(&protected, ticket_id, envelope.protection)?;
    if plaintext.len() > MAX_RUNTIME_RESULT_BYTES {
        bail!("runtime result exceeds its {MAX_RUNTIME_RESULT_BYTES}-byte limit");
    }
    let result = serde_json::from_slice(&plaintext).context("runtime result is not strict JSON")?;
    if let Ok(mailbox) = RuntimeControlMailbox::open(state_dir, ticket_id) {
        let _ = mailbox.discard();
    }
    Ok(result)
}

fn random_ticket_id() -> Result<String> {
    random_hex_id(TICKET_ID_BYTES)
}

fn random_hex_id(byte_length: usize) -> Result<String> {
    let mut random = vec![0_u8; byte_length];
    getrandom::fill(&mut random).context("failed to obtain randomness for runtime record")?;
    let mut id = String::with_capacity(byte_length * 2);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut id, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(id)
}

fn create_ticket(state_dir: Option<&Path>, ticket: &RuntimeTicket) -> Result<String> {
    validate_ticket(ticket)?;
    let directory = ticket_directory(state_dir);
    let _directory_guard = ensure_private_ticket_directory(&directory)?;
    let _record_lock = acquire_runtime_record_lock(&directory)?;

    let issued_at_unix_ms = unix_time_ms()?;
    let expires_at_unix_ms = issued_at_unix_ms
        .checked_add(TICKET_TTL.as_millis() as u64)
        .ok_or_else(|| anyhow!("runtime ticket expiry overflow"))?;
    for _ in 0..MAX_TICKET_CREATE_ATTEMPTS {
        let id = random_ticket_id()?;
        let path = ticket_path(state_dir, &id)?;
        let stored = StoredRuntimeTicket {
            schema_version: TICKET_SCHEMA_VERSION,
            ticket_id: id.clone(),
            issued_at_unix_ms,
            expires_at_unix_ms,
            ticket: ticket.clone(),
        };
        let plaintext = serde_json::to_vec(&stored).context("failed to encode runtime ticket")?;
        let protected = protect_ticket_content(&plaintext, &id, &ticket.workspace_key)?;
        let envelope = RuntimeTicketEnvelope {
            schema_version: TICKET_SCHEMA_VERSION,
            workspace_key: ticket.workspace_key.clone(),
            protection: protected.protection,
            protected_payload: BASE64_STANDARD.encode(protected.bytes),
        };
        let content = serde_json::to_vec(&envelope)
            .context("failed to encode protected runtime ticket envelope")?;
        if content.len() > MAX_TICKET_FILE_BYTES {
            bail!("protected runtime ticket exceeds its {MAX_TICKET_FILE_BYTES}-byte file limit");
        }
        prepare_runtime_record_publication(&directory, None, content.len())?;
        match create_private_ticket_file(&path) {
            Ok(mut file) => {
                let result = (|| -> Result<()> {
                    validate_private_ticket_file(&path, &file)?;
                    file.write_all(&content)
                        .context("failed to write runtime ticket")?;
                    file.sync_all().context("failed to sync runtime ticket")?;
                    super::sync_parent_dir(&path)?;
                    Ok(())
                })();
                if let Err(error) = result {
                    drop(file);
                    remove_new_runtime_record(&path);
                    return Err(error);
                }
                drop(file);
                if let Err(error) = validate_runtime_record_publication(&directory) {
                    remove_new_runtime_record(&path);
                    let _ = super::sync_parent_dir(&path);
                    return Err(error).context("runtime ticket publication exceeded state limits");
                }
                return Ok(id);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create runtime ticket {}", path.display()))
            }
        }
    }
    bail!("failed to allocate a unique runtime ticket ID")
}

fn consume_ticket(state_dir: Option<&Path>, ticket_id: &str) -> Result<RuntimeTicket> {
    let path = ticket_path(state_dir, ticket_id)?;
    let directory = ticket_directory(state_dir);
    let _directory_guard = ensure_private_ticket_directory(&directory)?;
    let file = take_runtime_record(&directory, &path, "runtime ticket")?;

    let mut bytes = Vec::new();
    file.take((MAX_TICKET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("failed to read runtime ticket")?;
    if bytes.len() > MAX_TICKET_FILE_BYTES {
        bail!("runtime ticket exceeds its {MAX_TICKET_FILE_BYTES}-byte file limit");
    }
    let envelope: RuntimeTicketEnvelope =
        serde_json::from_slice(&bytes).context("runtime ticket envelope is not strict JSON")?;
    if envelope.schema_version != TICKET_SCHEMA_VERSION {
        bail!(
            "unsupported runtime ticket envelope schema version {}",
            envelope.schema_version
        );
    }
    if envelope.workspace_key.len() != 24
        || !envelope
            .workspace_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("runtime ticket envelope workspace key is invalid");
    }
    let protected = BASE64_STANDARD
        .decode(envelope.protected_payload.as_bytes())
        .context("runtime ticket envelope payload is not standard base64")?;
    let bytes = unprotect_ticket_content(
        &protected,
        ticket_id,
        &envelope.workspace_key,
        envelope.protection,
    )?;
    if bytes.len() > MAX_TICKET_BYTES {
        bail!("runtime ticket plaintext exceeds its {MAX_TICKET_BYTES}-byte limit");
    }
    let stored: StoredRuntimeTicket =
        serde_json::from_slice(&bytes).context("runtime ticket is not strict JSON")?;
    validate_stored_ticket(&stored, ticket_id, &envelope.workspace_key)?;
    Ok(stored.ticket)
}

fn unix_time_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("system clock does not fit runtime ticket timestamp")
}

fn validate_stored_ticket(
    stored: &StoredRuntimeTicket,
    ticket_id: &str,
    workspace_key: &str,
) -> Result<()> {
    validate_stored_ticket_at(stored, ticket_id, workspace_key, unix_time_ms()?)
}

fn validate_stored_ticket_at(
    stored: &StoredRuntimeTicket,
    ticket_id: &str,
    workspace_key: &str,
    now: u64,
) -> Result<()> {
    if stored.schema_version != TICKET_SCHEMA_VERSION {
        bail!(
            "unsupported stored runtime ticket schema version {}",
            stored.schema_version
        );
    }
    if stored.ticket.workspace_key != workspace_key {
        bail!("runtime ticket workspace binding does not match its envelope");
    }
    if stored.ticket_id != ticket_id {
        bail!("runtime ticket ID binding does not match its file name");
    }
    let ttl_ms = TICKET_TTL.as_millis() as u64;
    if stored.expires_at_unix_ms < stored.issued_at_unix_ms
        || stored.expires_at_unix_ms - stored.issued_at_unix_ms != ttl_ms
    {
        bail!("runtime ticket lifetime is invalid");
    }
    let allowed_future = now.saturating_add(TICKET_CLOCK_SKEW.as_millis() as u64);
    if stored.issued_at_unix_ms > allowed_future {
        bail!("runtime ticket issue time is in the future");
    }
    if now > stored.expires_at_unix_ms {
        bail!("ticket_expired: runtime ticket has expired");
    }
    validate_ticket(&stored.ticket)
}

fn scan_runtime_record_directory(directory: &Path, maximum: usize) -> Result<RuntimeStateScan> {
    let entries = fs::read_dir(directory).with_context(|| {
        format!(
            "failed to inspect private runtime record directory {}",
            directory.display()
        )
    })?;
    let mut records = Vec::new();
    let mut overflow = false;
    for entry in entries {
        let entry = entry.context("failed to inspect runtime record directory entry")?;
        let name = entry.file_name();
        if name.to_str() == Some(RUNTIME_RECORD_LOCK_FILE) {
            continue;
        }
        if records.len() == maximum {
            overflow = true;
            break;
        }
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("failed to inspect runtime state record"),
        };
        records.push(RuntimeStateEntry {
            path,
            name: name.to_string_lossy().into_owned(),
            size: metadata.len(),
            modified: metadata.modified().ok(),
        });
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(RuntimeStateScan {
        entries: records,
        overflow,
    })
}

fn runtime_record_id(name: &str) -> Option<&str> {
    let id = name.strip_suffix(".json")?;
    validate_ticket_id(id).is_ok().then_some(id)
}

fn cleanup_orphan_runtime_records_with_policy(
    directory: &Path,
    excluded_id: Option<&str>,
    orphan_age: Duration,
    scan_limit: usize,
) -> Result<RuntimeStateUsage> {
    if scan_limit == 0 {
        bail!("runtime record cleanup scan limit must be positive");
    }
    // The caller owns this directory's record lock. Process a bounded batch
    // even when legacy/external state exceeds the scan limit; stale records in
    // later batches become reachable on retries instead of being permanently
    // hidden behind an arbitrary read_dir prefix.
    let scan = scan_runtime_record_directory(directory, scan_limit)?;
    let now = SystemTime::now();
    let mut removed = false;
    for entry in scan.entries {
        let Some(id) = runtime_record_id(&entry.name) else {
            continue;
        };
        if excluded_id == Some(id) {
            continue;
        }
        let is_orphan = entry
            .modified
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= orphan_age);
        if !is_orphan {
            continue;
        }
        let file = match open_private_ticket_file(&entry.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to open orphan runtime record {}",
                        entry.path.display()
                    )
                })
            }
        };
        validate_private_ticket_file(&entry.path, &file)
            .context("orphan runtime record is not private")?;
        remove_open_ticket_file(&entry.path, &file).with_context(|| {
            format!(
                "failed to remove orphan runtime record {}",
                entry.path.display()
            )
        })?;
        removed = true;
    }
    if removed {
        super::sync_parent_dir(&directory.join(RUNTIME_RECORD_LOCK_FILE))?;
    }
    if scan.overflow {
        bail!("runtime record cleanup exceeded its {scan_limit}-entry batch limit; retry");
    }
    let remaining = scan_runtime_record_directory(directory, scan_limit)?;
    if remaining.overflow {
        bail!("runtime record directory exceeds its {scan_limit}-entry scan limit");
    }
    runtime_state_usage(&remaining.entries)
}

fn prepare_runtime_record_publication(
    directory: &Path,
    excluded_id: Option<&str>,
    additional_bytes: usize,
) -> Result<()> {
    let usage = cleanup_orphan_runtime_records_with_policy(
        directory,
        excluded_id,
        TICKET_ORPHAN_MAX_AGE,
        MAX_RUNTIME_RECORD_SCAN_ENTRIES,
    )?;
    ensure_runtime_state_capacity(
        "runtime record directory",
        usage,
        additional_bytes,
        MAX_RUNTIME_RECORD_ENTRIES,
        MAX_RUNTIME_RECORD_TOTAL_BYTES,
    )
}

fn acquire_runtime_record_lock(directory: &Path) -> Result<PrivateRuntimeLock> {
    acquire_private_runtime_lock(
        directory,
        RUNTIME_RECORD_LOCK_FILE,
        "runtime record directory",
    )
}

fn remove_ticket(state_dir: Option<&Path>, ticket_id: &str) -> Result<()> {
    let directory = ticket_directory(state_dir);
    let _directory_guard = ensure_private_ticket_directory(&directory)?;
    let _record_lock = acquire_runtime_record_lock(&directory)?;
    let path = ticket_path(state_dir, ticket_id)?;
    let file = open_private_ticket_file(&path)
        .with_context(|| format!("failed to open runtime ticket {}", path.display()))?;
    validate_private_ticket_file(&path, &file)?;
    remove_open_ticket_file(&path, &file)?;
    super::sync_parent_dir(&path)
}

/*
 * The record lock serializes every publisher and remover. Readers unlink the
 * validated record while holding it, then decode from the already-open handle.
 * This keeps single-use semantics without holding a filesystem lock during
 * JSON/DPAPI work.
 */
fn take_runtime_record(directory: &Path, path: &Path, label: &str) -> Result<File> {
    let _record_lock = acquire_runtime_record_lock(directory)?;
    let file = open_private_ticket_file(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    validate_private_ticket_file(path, &file)?;
    remove_open_ticket_file(path, &file)
        .with_context(|| format!("failed to consume {label} {}", path.display()))?;
    super::sync_parent_dir(path)?;
    Ok(file)
}

fn runtime_record_usage(directory: &Path) -> Result<RuntimeStateUsage> {
    let scan = scan_runtime_record_directory(directory, MAX_RUNTIME_RECORD_SCAN_ENTRIES)?;
    if scan.overflow {
        bail!(
            "runtime record directory exceeds its {}-entry scan limit",
            MAX_RUNTIME_RECORD_SCAN_ENTRIES
        );
    }
    let usage = runtime_state_usage(&scan.entries)?;
    if usage.entries > MAX_RUNTIME_RECORD_ENTRIES {
        bail!(
            "runtime record directory exceeds its {}-entry limit",
            MAX_RUNTIME_RECORD_ENTRIES
        );
    }
    if usage.bytes > MAX_RUNTIME_RECORD_TOTAL_BYTES {
        bail!(
            "runtime record directory exceeds its {}-byte limit",
            MAX_RUNTIME_RECORD_TOTAL_BYTES
        );
    }
    Ok(usage)
}

fn validate_runtime_record_publication(directory: &Path) -> Result<()> {
    runtime_record_usage(directory).map(|_| ())
}

fn remove_new_runtime_record(path: &Path) {
    match open_private_ticket_file(path) {
        Ok(file) if validate_private_ticket_file(path, &file).is_ok() => {
            let _ = remove_open_ticket_file(path, &file);
        }
        _ => {}
    }
}

fn control_file_ids(name: &str) -> Option<(&str, &str)> {
    let stem = name.strip_suffix(".json")?;
    let (ticket_id, nonce) = stem.split_once('-')?;
    if validate_ticket_id(ticket_id).is_err()
        || nonce.len() != RUNTIME_CONTROL_NONCE_BYTES * 2
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some((ticket_id, nonce))
}

fn is_pending_control_file(name: &str) -> bool {
    let Some(nonce) = name
        .strip_prefix(".pending-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    nonce.len() == RUNTIME_CONTROL_NONCE_BYTES * 2
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_control_paths(directory: &Path) -> Result<Vec<(PathBuf, String)>> {
    bounded_control_paths_at_limit(directory, MAX_RUNTIME_CONTROL_ENTRIES)
}

fn bounded_control_paths_at_limit(
    directory: &Path,
    maximum: usize,
) -> Result<Vec<(PathBuf, String)>> {
    let entries = fs::read_dir(directory).with_context(|| {
        format!(
            "failed to inspect private runtime control directory {}",
            directory.display()
        )
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.context("failed to inspect runtime control directory entry")?;
        let name = entry.file_name();
        if name.to_str() == Some(RUNTIME_CONTROL_LOCK_FILE) {
            continue;
        }
        if paths.len() == maximum {
            bail!("runtime control directory exceeds its {maximum}-entry limit");
        }
        paths.push((entry.path(), name.to_string_lossy().into_owned()));
    }
    paths.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(paths)
}

fn cleanup_orphan_control_files(directory: &Path) -> Result<()> {
    // Permit a bounded amount of legacy/transient excess so stale records
    // from an older publisher can be reclaimed. New publishers serialize on
    // the mailbox lock and can never create an over-cap directory.
    for (path, name) in bounded_control_paths_at_limit(directory, MAX_RUNTIME_CONTROL_SCAN_ENTRIES)?
    {
        if control_file_ids(&name).is_none() && !is_pending_control_file(&name) {
            continue;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("failed to inspect orphan runtime signal"),
        };
        let is_orphan = metadata
            .modified()
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age > RUNTIME_CONTROL_MAX_AGE);
        if is_orphan {
            match open_private_ticket_file(&path) {
                Ok(file) => {
                    validate_private_ticket_file(&path, &file)?;
                    remove_open_ticket_file(&path, &file)?;
                    super::sync_parent_dir(&path)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to open orphan runtime signal {}", path.display())
                    })
                }
            }
        }
    }
    Ok(())
}

struct PrivateRuntimeLock {
    file: File,
}

impl Drop for PrivateRuntimeLock {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

#[cfg(unix)]
fn open_private_runtime_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(windows)]
fn open_private_runtime_lock(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn acquire_private_runtime_lock(
    directory: &Path,
    file_name: &str,
    label: &str,
) -> Result<PrivateRuntimeLock> {
    let path = directory.join(file_name);
    let open_deadline = Instant::now() + RUNTIME_CONTROL_LOCK_TIMEOUT;
    let file = loop {
        match open_private_runtime_lock(&path) {
            Ok(file) => break file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match create_private_ticket_file(&path) {
                    Ok(file) => {
                        validate_private_ticket_file(&path, &file)?;
                        // Windows creates private records without sharing. Drop
                        // the creation handle and reopen with read/write sharing
                        // so other helpers can coordinate through the lock.
                        drop(file);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to create private {label} lock {}", path.display())
                        })
                    }
                }
            }
            Err(error)
                if runtime_lock_open_should_retry(&error) && Instant::now() < open_deadline =>
            {
                // A Windows creator initially owns a zero-share handle while
                // it validates the new lock file. Retry only that documented
                // sharing violation; permission and security failures remain
                // fail-closed.
                thread::sleep(RUNTIME_CONTROL_LOCK_POLL);
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to open private {label} lock {}", path.display())
                })
            }
        }
    };
    validate_private_ticket_file(&path, &file)?;

    let deadline = Instant::now() + RUNTIME_CONTROL_LOCK_TIMEOUT;
    loop {
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => break,
            Err(fs4::TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(RUNTIME_CONTROL_LOCK_POLL);
            }
            Err(fs4::TryLockError::WouldBlock) => {
                bail!(
                    "private {label} lock timed out after {} ms",
                    RUNTIME_CONTROL_LOCK_TIMEOUT.as_millis()
                )
            }
            Err(fs4::TryLockError::Error(error)) => {
                return Err(error).with_context(|| format!("failed to lock private {label}"))
            }
        }
    }
    // Revalidate after acquiring the cross-process lock. This catches any
    // replacement that raced the initial open on platforms where the path may
    // have been swapped before the private directory was fully established.
    validate_private_ticket_file(&path, &file)?;
    Ok(PrivateRuntimeLock { file })
}

#[cfg(windows)]
fn runtime_lock_open_should_retry(error: &io::Error) -> bool {
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32)
}

#[cfg(not(windows))]
fn runtime_lock_open_should_retry(_error: &io::Error) -> bool {
    false
}

fn acquire_runtime_control_lock(directory: &Path) -> Result<PrivateRuntimeLock> {
    acquire_private_runtime_lock(
        directory,
        RUNTIME_CONTROL_LOCK_FILE,
        "runtime signal mailbox",
    )
}

struct RuntimeControlMailbox {
    directory: PathBuf,
    ticket_id: String,
    _directory_guard: PrivateDirectoryGuard,
}

impl RuntimeControlMailbox {
    fn open(state_dir: Option<&Path>, ticket_id: &str) -> Result<Self> {
        validate_ticket_id(ticket_id)?;
        let directory = control_directory(state_dir);
        let directory_guard = ensure_private_ticket_directory(&directory)?;
        let _mailbox_lock = acquire_runtime_control_lock(&directory)?;
        cleanup_orphan_control_files(&directory)?;
        bounded_control_paths(&directory)?;
        Ok(Self {
            directory,
            ticket_id: ticket_id.to_owned(),
            _directory_guard: directory_guard,
        })
    }

    fn matching_paths(&self) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for (path, name) in bounded_control_paths(&self.directory)? {
            if control_file_ids(&name).is_some_and(|(ticket_id, _)| ticket_id == self.ticket_id) {
                paths.push(path);
            }
        }
        Ok(paths)
    }

    fn drain(&self) -> Result<Vec<RuntimeSignal>> {
        let _mailbox_lock = acquire_runtime_control_lock(&self.directory)?;
        let now = unix_time_ms()?;
        let allowed_future = now.saturating_add(TICKET_CLOCK_SKEW.as_millis() as u64);
        let mut messages = Vec::new();
        for path in self.matching_paths()? {
            let file = match open_private_ticket_file(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to open runtime signal {}", path.display())
                    })
                }
            };
            validate_private_ticket_file(&path, &file)?;
            remove_open_ticket_file(&path, &file)?;
            super::sync_parent_dir(&path)?;
            let mut bytes = Vec::new();
            file.take((MAX_RUNTIME_CONTROL_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .context("failed to read runtime signal")?;
            if bytes.len() > MAX_RUNTIME_CONTROL_BYTES {
                bail!("runtime signal exceeds its file limit");
            }
            let message: RuntimeControlMessage =
                serde_json::from_slice(&bytes).context("runtime signal is not strict JSON")?;
            if message.schema_version != RUNTIME_CONTROL_SCHEMA_VERSION
                || message.ticket_id != self.ticket_id
            {
                bail!("runtime signal binding is invalid");
            }
            if message.issued_at_unix_ms > allowed_future {
                bail!("runtime signal issue time is in the future");
            }
            if now.saturating_sub(message.issued_at_unix_ms)
                <= RUNTIME_CONTROL_MAX_AGE.as_millis() as u64
            {
                messages.push((message.issued_at_unix_ms, path, message.signal));
            }
        }
        messages.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        Ok(messages.into_iter().map(|(_, _, signal)| signal).collect())
    }

    fn discard(&self) -> Result<()> {
        let _mailbox_lock = acquire_runtime_control_lock(&self.directory)?;
        for path in self.matching_paths()? {
            match open_private_ticket_file(&path) {
                Ok(file) => {
                    validate_private_ticket_file(&path, &file)?;
                    remove_open_ticket_file(&path, &file)?;
                    super::sync_parent_dir(&path)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to discard runtime signal {}", path.display())
                    })
                }
            }
        }
        Ok(())
    }
}

fn validate_ticket(ticket: &RuntimeTicket) -> Result<()> {
    if ticket.schema_version != TICKET_SCHEMA_VERSION {
        bail!(
            "unsupported runtime ticket schema version {}",
            ticket.schema_version
        );
    }
    if ticket.workspace_key.len() != 24
        || !ticket
            .workspace_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("runtime ticket workspace key is invalid");
    }
    if ticket.agent.is_empty()
        || ticket.agent.chars().any(char::is_control)
        || ticket.agent.starts_with('-')
    {
        bail!("runtime ticket agent is invalid");
    }
    if !ticket.agent.contains(['/', '\\', ':']) {
        validate_managed_remote_agent_name(&ticket.agent)?;
    }
    if ticket.ssh_connect_timeout_seconds == 0
        || ticket.ssh_connect_timeout_seconds > MAX_SSH_CONNECT_TIMEOUT_SECONDS
    {
        bail!(
            "runtime ticket SSH connect timeout must be from 1 to {MAX_SSH_CONNECT_TIMEOUT_SECONDS} seconds"
        );
    }
    if ticket.request_timeout_ms == 0 || ticket.request_timeout_ms > MAX_RUNTIME_TIMEOUT_MS {
        bail!(
            "runtime ticket request timeout must be from 1 to {MAX_RUNTIME_TIMEOUT_MS} milliseconds"
        );
    }
    if ticket.capability == RuntimeCapability::WorkspaceWatchV1 {
        bail!("runtime process ticket cannot request workspace-watch capability");
    }

    let transport =
        RemoteTransport::from_ssh(ticket.ssh.clone(), ticket.ssh_connect_timeout_seconds)?;
    let remote_root = transport.normalize_remote_root(PathBuf::from(&ticket.remote_root))?;
    if let Some(host) = &ticket.remote_host {
        if !matches!(transport, RemoteTransport::Ssh(_)) {
            bail!("local runtime ticket must not include remote host metadata");
        }
        super::remote_host::validate_remote_host_info(host)?;
        super::validate_remote_root(host, &remote_root)?;
    }
    let expected_key = workspace_key(&transport, &remote_root);
    if ticket.workspace_key != expected_key {
        bail!("runtime ticket does not belong to the requested workspace");
    }

    let mut capabilities = CapabilitySet::v1_agent();
    capabilities.runtime_process_v1 = true;
    capabilities.runtime_pty_v1 = true;
    let mut machine = RuntimeStateMachine::new(RuntimePeerRole::Client, capabilities);
    let hello = RuntimeMessage::ClientHello {
        package_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION,
        capability: ticket.capability,
    };
    machine.observe_outbound(&hello)?;
    machine.observe_inbound(&RuntimeMessage::ServerHello {
        package_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: PROTOCOL_VERSION,
        capability: ticket.capability,
    })?;
    machine.observe_outbound(&RuntimeMessage::StartProcess {
        request_id: 1,
        spec: ticket.spec.clone(),
    })?;
    Ok(())
}

#[cfg(unix)]
struct PrivateDirectoryGuard;

#[cfg(unix)]
fn ensure_private_ticket_directory(directory: &Path) -> Result<PrivateDirectoryGuard> {
    super::ensure_secure_listener_directory(&directory.join("ticket-placeholder"))
        .context("failed to prepare private runtime ticket directory")?;
    Ok(PrivateDirectoryGuard)
}

#[cfg(windows)]
struct PrivateDirectoryGuard {
    _handles: Vec<File>,
}

#[cfg(windows)]
struct OwnedWindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedWindowsHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was returned by OpenProcessToken, remains
            // owned here, and is closed exactly once.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
struct LocalSecurityDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetSecurityInfo allocates the descriptor with LocalAlloc
            // and transfers ownership to the caller.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
        }
    }
}

#[cfg(windows)]
struct LocalWindowsAcl(*mut windows_sys::Win32::Security::ACL);

#[cfg(windows)]
impl Drop for LocalWindowsAcl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: SetEntriesInAclW allocates the ACL with LocalAlloc and
            // transfers ownership to the caller.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
        }
    }
}

#[cfg(windows)]
struct LocalWindowsSid(windows_sys::Win32::Security::PSID);

#[cfg(windows)]
impl Drop for LocalWindowsSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ConvertStringSidToSidW allocates the SID with LocalAlloc
            // and transfers ownership to the caller.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
        }
    }
}

#[cfg(windows)]
fn windows_status_error(status: u32) -> io::Error {
    io::Error::from_raw_os_error(status as i32)
}

#[cfg(windows)]
fn absolute_windows_private_directory(directory: &Path) -> Result<PathBuf> {
    use std::path::{Component, Prefix};

    if directory
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        bail!("runtime private directory must not contain dot components");
    }
    let absolute = std::path::absolute(directory).with_context(|| {
        format!(
            "failed to make runtime private directory absolute: {}",
            directory.display()
        )
    })?;
    let mut components = absolute.components();
    let valid_drive = matches!(
        components.next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    );
    if !valid_drive || !matches!(components.next(), Some(Component::RootDir)) {
        bail!("runtime private directory must use an absolute local drive path");
    }
    if components.any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir | Component::CurDir
        )
    }) {
        bail!("runtime private directory contains an invalid path component");
    }
    Ok(absolute)
}

#[cfg(windows)]
fn open_windows_directory_without_following(path: &Path, write_dacl: bool) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    let desired_access = READ_CONTROL | if write_dacl { WRITE_DAC } else { 0 };
    let file = OpenOptions::new()
        .access_mode(desired_access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("failed to securely open directory {}", path.display()))?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a valid handle and information is a writable structure
    // retained only for this call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to inspect directory handle {}", path.display()));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        bail!(
            "runtime private path is not a directory: {}",
            path.display()
        );
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "runtime private directory chain must not contain reparse points: {}",
            path.display()
        );
    }
    Ok(file)
}

#[cfg(windows)]
fn with_windows_process_user_sid<T>(
    callback: impl FnOnce(windows_sys::Win32::Security::PSID) -> Result<T>,
) -> Result<T> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle and token points
    // to writable storage for the newly owned token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error()).context("failed to open current process token");
    }
    let token = OwnedWindowsHandle(token);
    let mut required = 0;
    // SAFETY: a null buffer with length zero is the documented size query.
    let queried =
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut required) };
    // SAFETY: GetLastError has no pointer preconditions and is read
    // immediately after the size-query call whose failure it describes.
    let query_error = unsafe { GetLastError() };
    // The size query must fail with ERROR_INSUFFICIENT_BUFFER and publish a
    // nonzero required length.
    if queried != 0 || query_error != ERROR_INSUFFICIENT_BUFFER || required == 0 {
        return Err(io::Error::last_os_error())
            .context("failed to query current process token user size");
    }
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    // SAFETY: usize storage provides TOKEN_USER alignment and contains at
    // least required writable bytes for the duration of the call.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error())
            .context("failed to read current process token user");
    }
    // SAFETY: a successful TokenUser query initializes a TOKEN_USER at the
    // aligned start of storage and its SID remains valid while storage lives.
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if user.User.Sid.is_null() {
        bail!("current process token returned a null user SID");
    }
    callback(user.User.Sid)
}

#[cfg(windows)]
fn windows_broad_sid(
    kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> Result<[usize; 9]> {
    use std::mem::size_of;
    use windows_sys::Win32::Security::{CreateWellKnownSid, SECURITY_MAX_SID_SIZE};

    const WORDS: usize = (SECURITY_MAX_SID_SIZE as usize).div_ceil(size_of::<usize>());
    let mut storage = [0_usize; WORDS];
    let mut length = SECURITY_MAX_SID_SIZE;
    // SAFETY: the aligned storage has SECURITY_MAX_SID_SIZE writable bytes,
    // length points to its initialized capacity, and no domain SID is needed.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("failed to create Windows well-known SID");
    }
    Ok(storage)
}

#[cfg(windows)]
fn windows_trusted_installer_sid() -> Result<LocalWindowsSid> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::IsValidSid;

    // TrustedInstaller's service SID is stable and non-localized. Parsing the
    // canonical numeric form avoids account-name lookup and localization.
    const TRUSTED_INSTALLER_SID: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    let wide: Vec<u16> = TRUSTED_INSTALLER_SID
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sid = std::ptr::null_mut();
    // SAFETY: wide is NUL-terminated and sid points to writable storage for
    // the LocalAlloc result.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error())
            .context("failed to resolve the Windows TrustedInstaller SID");
    }
    let sid = LocalWindowsSid(sid);
    // SAFETY: a successful conversion returns a live SID owned by sid.
    if sid.0.is_null() || unsafe { IsValidSid(sid.0) } == 0 {
        bail!("Windows returned an invalid TrustedInstaller SID");
    }
    Ok(sid)
}

#[cfg(windows)]
fn with_windows_ancestor_trusted_sids<T>(
    callback: impl FnOnce(&[windows_sys::Win32::Security::PSID; 4]) -> Result<T>,
) -> Result<T> {
    use windows_sys::Win32::Security::{WinBuiltinAdministratorsSid, WinLocalSystemSid};

    with_windows_process_user_sid(|user| {
        let mut system = windows_broad_sid(WinLocalSystemSid)?;
        let mut administrators = windows_broad_sid(WinBuiltinAdministratorsSid)?;
        let trusted_installer = windows_trusted_installer_sid()?;
        let trusted = [
            user,
            system.as_mut_ptr().cast(),
            administrators.as_mut_ptr().cast(),
            trusted_installer.0,
        ];
        callback(&trusted)
    })
}

#[cfg(windows)]
fn windows_sid_is_trusted_mutator(
    sid: windows_sys::Win32::Security::PSID,
    trusted: &[windows_sys::Win32::Security::PSID],
) -> bool {
    use windows_sys::Win32::Security::EqualSid;

    trusted.iter().any(|candidate| {
        // SAFETY: callers validate sid and construct every trusted candidate
        // from a current-token or well-known valid SID retained by live data.
        (unsafe { EqualSid(sid, *candidate) }) != 0
    })
}

#[cfg(windows)]
fn with_windows_private_acl<T>(
    inherit_children: bool,
    callback: impl FnOnce(
        windows_sys::Win32::Security::PSID,
        *mut windows_sys::Win32::Security::ACL,
    ) -> Result<T>,
) -> Result<T> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{
        BuildTrusteeWithSidW, SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_IS_USER,
        TRUSTEE_IS_WELL_KNOWN_GROUP,
    };
    use windows_sys::Win32::Security::{
        WinLocalSystemSid, CONTAINER_INHERIT_ACE, NO_INHERITANCE, OBJECT_INHERIT_ACE,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    with_windows_process_user_sid(|user| {
        let mut system = windows_broad_sid(WinLocalSystemSid)?;
        let mut entries = [EXPLICIT_ACCESS_W::default(); 2];
        for entry in &mut entries {
            entry.grfAccessPermissions = FILE_ALL_ACCESS;
            entry.grfAccessMode = SET_ACCESS;
            entry.grfInheritance = if inherit_children {
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            } else {
                NO_INHERITANCE
            };
        }
        // SAFETY: both SIDs are valid and remain live until SetEntriesInAclW
        // has copied them into the returned ACL.
        unsafe {
            BuildTrusteeWithSidW(&mut entries[0].Trustee, user);
            BuildTrusteeWithSidW(&mut entries[1].Trustee, system.as_mut_ptr().cast());
        }
        entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

        let mut acl = std::ptr::null_mut();
        // SAFETY: entries contains two initialized trustees backed by live
        // SIDs; acl points to writable storage for the LocalAlloc result.
        let status = unsafe {
            SetEntriesInAclW(
                u32::try_from(entries.len()).expect("two ACL entries fit in u32"),
                entries.as_ptr(),
                std::ptr::null(),
                &mut acl,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(windows_status_error(status))
                .context("failed to build private Windows runtime ACL");
        }
        if acl.is_null() {
            bail!("Windows returned a null private runtime ACL");
        }
        let _acl = LocalWindowsAcl(acl);
        callback(user, acl)
    })
}

#[cfg(windows)]
fn with_windows_private_security_attributes<T>(
    inherit_children: bool,
    callback: impl FnOnce(&windows_sys::Win32::Security::SECURITY_ATTRIBUTES) -> Result<T>,
) -> Result<T> {
    use std::mem::size_of;
    use windows_sys::Win32::Security::{
        InitializeSecurityDescriptor, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
        SetSecurityDescriptorOwner, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    with_windows_private_acl(inherit_children, |user, acl| {
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor_pointer = (&raw mut descriptor).cast();
        // SAFETY: descriptor is writable, remains live through callback, and
        // revision 1 is the supported SECURITY_DESCRIPTOR revision.
        if unsafe { InitializeSecurityDescriptor(descriptor_pointer, SECURITY_DESCRIPTOR_REVISION) }
            == 0
        {
            return Err(io::Error::last_os_error())
                .context("failed to initialize private Windows security descriptor");
        }
        // SAFETY: user and acl remain live through callback; descriptor is an
        // initialized absolute security descriptor.
        if unsafe { SetSecurityDescriptorOwner(descriptor_pointer, user, 0) } == 0 {
            return Err(io::Error::last_os_error())
                .context("failed to set private Windows runtime owner");
        }
        // SAFETY: descriptor and acl satisfy the same lifetime constraints.
        if unsafe { SetSecurityDescriptorDacl(descriptor_pointer, 1, acl, 0) } == 0 {
            return Err(io::Error::last_os_error())
                .context("failed to set private Windows runtime DACL");
        }
        // SAFETY: descriptor is initialized and the requested control bit is
        // valid for an absolute security descriptor.
        if unsafe {
            SetSecurityDescriptorControl(descriptor_pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        } == 0
        {
            return Err(io::Error::last_os_error())
                .context("failed to protect private Windows runtime DACL");
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .expect("SECURITY_ATTRIBUTES size fits in u32"),
            lpSecurityDescriptor: descriptor_pointer,
            bInheritHandle: 0,
        };
        callback(&attributes)
    })
}

#[cfg(windows)]
fn windows_path_utf16(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        bail!("runtime private path contains NUL");
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
fn create_windows_private_directory(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let wide = windows_path_utf16(path)?;
    with_windows_private_security_attributes(true, |attributes| {
        // SAFETY: wide is NUL-terminated and attributes references a live
        // absolute security descriptor for the duration of the call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), attributes) } == 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("failed to create private directory {}", path.display()));
        }
        Ok(())
    })
}

#[cfg(windows)]
fn windows_simple_allow_ace_parts(
    raw_ace: *mut core::ffi::c_void,
) -> Result<(u32, windows_sys::Win32::Security::PSID)> {
    use std::mem::offset_of;
    use windows_sys::Win32::Security::{GetLengthSid, IsValidSid, ACCESS_ALLOWED_ACE, ACE_HEADER};

    // SAFETY: callers obtain raw_ace from GetAce on a validated live ACL.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    let ace_size = usize::from(header.AceSize);
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    const SID_FIXED_BYTES: usize = 8;
    if ace_size < sid_offset + SID_FIXED_BYTES {
        bail!("runtime directory ACL contains a truncated allow ACE SID header");
    }
    // SAFETY: the minimum-size check establishes the fixed allow-ACE layout.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    // SAFETY: sid_offset plus the fixed SID header was proven within AceSize.
    let sid_bytes = unsafe {
        std::slice::from_raw_parts(raw_ace.cast::<u8>().add(sid_offset), ace_size - sid_offset)
    };
    let sid_length = SID_FIXED_BYTES
        .checked_add(
            usize::from(sid_bytes[1])
                .checked_mul(4)
                .ok_or_else(|| anyhow!("runtime directory ACL SID length overflow"))?,
        )
        .ok_or_else(|| anyhow!("runtime directory ACL SID length overflow"))?;
    if sid_length > sid_bytes.len() {
        bail!("runtime directory ACL contains an out-of-bounds SID");
    }
    let sid = sid_bytes.as_ptr().cast_mut().cast();
    // SAFETY: the complete computed SID is bounded by the live ACE.
    if unsafe { IsValidSid(sid) } == 0 {
        bail!("runtime directory ACL contains an invalid SID");
    }
    // SAFETY: sid was validated and remains live in the ACL.
    if unsafe { GetLengthSid(sid) } as usize != sid_length {
        bail!("runtime directory ACL contains a non-canonical SID length");
    }
    Ok((ace.Mask, sid))
}

#[cfg(windows)]
fn validate_windows_ancestor_security(
    owner: windows_sys::Win32::Security::PSID,
    dacl: *mut windows_sys::Win32::Security::ACL,
) -> Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, IsValidAcl, IsValidSid, MapGenericMask,
        ACL_SIZE_INFORMATION, GENERIC_MAPPING, INHERIT_ONLY_ACE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ALL_ACCESS, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, WRITE_DAC, WRITE_OWNER,
    };

    // ACE type values are stable Win32 ABI constants. windows-sys exposes
    // these in a broader feature module that this crate otherwise does not use.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
    const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
    const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
    const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;
    const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;
    const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 12;

    if owner.is_null() || dacl.is_null() {
        bail!("runtime directory ancestor has a missing owner or null DACL");
    }
    // SAFETY: owner is retained by the live descriptor returned by
    // GetSecurityInfo.
    if unsafe { IsValidSid(owner) } == 0 {
        bail!("runtime directory ancestor has an invalid owner SID");
    }
    // SAFETY: dacl is retained by that same live descriptor.
    if unsafe { IsValidAcl(dacl) } == 0 {
        bail!("runtime directory ancestor has an invalid DACL");
    }

    let mut acl_info = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid and acl_info is writable with its exact size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .expect("ACL_SIZE_INFORMATION size fits in u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error())
            .context("failed to enumerate runtime directory ancestor DACL");
    }

    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    // FILE_ADD_SUBDIRECTORY alone can only race creation of a missing child,
    // which is opened no-follow and validated before traversal continues.
    // FILE_WRITE_DATA (FILE_ADD_FILE for directories) and
    // FILE_WRITE_ATTRIBUTES are different: either one can authorize
    // FSCTL_SET_REPARSE_POINT on an empty existing directory. Reject those
    // rights, along with rights that can delete or retake an existing path.
    let existing_chain_takeover = DELETE
        | FILE_DELETE_CHILD
        | FILE_WRITE_DATA
        | FILE_WRITE_ATTRIBUTES
        | WRITE_DAC
        | WRITE_OWNER;
    with_windows_ancestor_trusted_sids(|trusted| {
        if !windows_sid_is_trusted_mutator(owner, trusted) {
            bail!("runtime directory ancestor has an unsafe owner");
        }
        for index in 0..acl_info.AceCount {
            let mut raw_ace = std::ptr::null_mut();
            // SAFETY: dacl is valid and index is bounded by its ACE count.
            if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!("failed to read runtime directory ancestor DACL entry {index}")
                });
            }
            // SAFETY: every ACE begins with ACE_HEADER and remains live in dacl.
            let header = unsafe { &*raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
            if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
                continue;
            }
            match header.AceType {
                ACCESS_ALLOWED_ACE_TYPE => {
                    let (mut rights, sid) = windows_simple_allow_ace_parts(raw_ace)?;
                    // SAFETY: rights is writable and mapping is initialized
                    // with directory-specific generic access expansions.
                    unsafe { MapGenericMask(&mut rights, &mapping) };
                    if !windows_sid_is_trusted_mutator(sid, trusted)
                        && rights & existing_chain_takeover != 0
                    {
                        bail!(
                            "runtime directory ancestor grants an untrusted trustee unsafe access rights ({rights:#010x})"
                        );
                    }
                }
                ACCESS_DENIED_ACE_TYPE
                | ACCESS_DENIED_OBJECT_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_ACE_TYPE
                | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => {}
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE
                | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                    bail!(
                        "runtime directory ancestor contains an unsupported applicable access-allowed ACE type {}",
                        header.AceType
                    );
                }
                _ => {
                    bail!(
                        "runtime directory ancestor contains an unsupported applicable ACE type {}",
                        header.AceType
                    );
                }
            }
        }
        Ok(())
    })
}

#[cfg(windows)]
fn validate_windows_object_owner(file: &File, object: &str) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{EqualSid, OWNER_SECURITY_INFORMATION};

    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: file owns a valid object handle and all requested output
    // pointers refer to writable storage retained for this call.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(windows_status_error(status))
            .with_context(|| format!("failed to inspect private runtime {object} owner"));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if descriptor.is_null() || owner.is_null() {
        bail!("private runtime {object} has a missing owner");
    }
    with_windows_process_user_sid(|user| {
        // SAFETY: owner and user are valid SIDs retained by their live
        // descriptor/token buffers for this comparison.
        if unsafe { EqualSid(owner, user) } == 0 {
            bail!("private runtime {object} is not owned by the current token user");
        }
        Ok(())
    })
}

#[cfg(windows)]
fn apply_windows_private_dacl(file: &File, object: &str, inherit_children: bool) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    validate_windows_object_owner(file, object)?;
    with_windows_private_acl(inherit_children, |_user, acl| {
        // SAFETY: file owns a handle opened with WRITE_DAC and acl remains
        // valid for the duration of SetSecurityInfo.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(windows_status_error(status))
                .with_context(|| format!("failed to protect private runtime {object} DACL"));
        }
        Ok(())
    })
}

#[cfg(windows)]
fn validate_windows_private_object_security(
    file: &File,
    object: &str,
    inherit_children: bool,
) -> Result<()> {
    use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

    let expected_ace_flags = if inherit_children {
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
    } else {
        0
    };
    validate_windows_allowlist_security(file, object, expected_ace_flags, true)
}

#[cfg(windows)]
fn validate_windows_allowlist_security(
    file: &File,
    object: &str,
    expected_ace_flags: u8,
    require_protected: bool,
) -> Result<()> {
    use std::mem::{offset_of, size_of};
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, IsValidAcl, IsValidSid, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: file owns a valid object handle and all requested output
    // pointers refer to writable storage retained for this call.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(windows_status_error(status))
            .with_context(|| format!("failed to inspect private runtime {object} security"));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if descriptor.is_null() || owner.is_null() || dacl.is_null() {
        bail!("private runtime {object} has a missing owner or null DACL");
    }

    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor is the live descriptor returned by GetSecurityInfo;
    // control and revision point to writable stack storage.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to inspect private runtime {object} DACL control"));
    }
    if control & SE_DACL_PRESENT == 0 || (require_protected && control & SE_DACL_PROTECTED == 0) {
        bail!("private runtime {object} must have the required protected DACL");
    }
    // SAFETY: dacl is retained by the live descriptor.
    if unsafe { IsValidAcl(dacl) } == 0 {
        bail!("private runtime {object} has an invalid DACL");
    }
    let mut acl_info = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid, acl_info is writable and its exact size is given.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
                .expect("ACL_SIZE_INFORMATION size fits in u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to enumerate private runtime {object} DACL"));
    }
    if !(1..=2).contains(&acl_info.AceCount) {
        bail!(
            "private runtime {object} DACL must contain only the current user and optional SYSTEM"
        );
    }

    with_windows_process_user_sid(|user| {
        // The aligned storage owns this SID through the complete ACE walk.
        let mut system = windows_broad_sid(WinLocalSystemSid)?;
        let system_sid = system.as_mut_ptr().cast();
        let mut saw_user = false;
        let mut saw_system = false;
        for index in 0..acl_info.AceCount {
            let mut raw_ace = std::ptr::null_mut();
            // SAFETY: dacl is valid and index is bounded by its reported ACE
            // count; raw_ace points to writable pointer storage.
            if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!("failed to read private runtime {object} DACL entry {index}")
                });
            }
            // SAFETY: GetAce returned a pointer to a live ACE in dacl. The
            // header is common to all ACE types and is safe to inspect first.
            let header = unsafe { &*raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE || header.AceFlags != expected_ace_flags {
                bail!("private runtime {object} DACL contains a non-canonical ACE");
            }
            let ace_size = usize::from(header.AceSize);
            let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            const SID_FIXED_BYTES: usize = 8;
            if ace_size < sid_offset + SID_FIXED_BYTES {
                bail!("private runtime {object} DACL contains a truncated SID header");
            }
            // SAFETY: the type and minimum size checks establish the common
            // ACCESS_ALLOWED_ACE layout for Mask and SidStart.
            let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
            if ace.Mask != FILE_ALL_ACCESS {
                bail!("private runtime {object} DACL contains unexpected access rights");
            }
            // SAFETY: sid_offset plus the fixed SID header was proven within
            // AceSize, and dacl retains the complete ACE for this inspection.
            let sid_bytes = unsafe {
                std::slice::from_raw_parts(
                    raw_ace.cast::<u8>().add(sid_offset),
                    ace_size - sid_offset,
                )
            };
            let sid_length =
                SID_FIXED_BYTES
                    .checked_add(usize::from(sid_bytes[1]).checked_mul(4).ok_or_else(|| {
                        anyhow!("private runtime {object} DACL SID length overflow")
                    })?)
                    .ok_or_else(|| anyhow!("private runtime {object} DACL SID length overflow"))?;
            if sid_length > sid_bytes.len() {
                bail!("private runtime {object} DACL contains an out-of-bounds SID");
            }
            let sid = sid_bytes.as_ptr().cast_mut().cast();
            // SAFETY: sid points into the ACE; IsValidSid only reads it.
            if unsafe { IsValidSid(sid) } == 0 {
                bail!("private runtime {object} DACL contains an invalid SID");
            }
            // SAFETY: sid was just validated and remains live in dacl.
            if unsafe { GetLengthSid(sid) } as usize != sid_length {
                bail!("private runtime {object} DACL contains a non-canonical SID length");
            }
            // SAFETY: both compared pointers refer to valid live SIDs.
            let is_user = unsafe { EqualSid(sid, user) } != 0;
            // SAFETY: both compared pointers refer to valid live SIDs.
            let is_system = unsafe { EqualSid(sid, system_sid) } != 0;
            if is_user {
                if saw_user {
                    bail!("private runtime {object} DACL repeats the current user");
                }
                saw_user = true;
            } else if is_system {
                if saw_system {
                    bail!("private runtime {object} DACL repeats SYSTEM");
                }
                saw_system = true;
            } else {
                bail!("private runtime {object} DACL grants access to another trustee");
            }
        }
        if !saw_user {
            bail!("private runtime {object} DACL does not grant the current user access");
        }
        // SAFETY: both SIDs are valid and retained by live buffers.
        if unsafe { EqualSid(owner, user) } == 0 {
            bail!("private runtime {object} is not owned by the current token user");
        }
        Ok(())
    })
}

#[cfg(windows)]
fn validate_windows_directory_security(file: &File, final_directory: bool) -> Result<()> {
    if final_directory {
        return validate_windows_private_object_security(file, "directory", true);
    }

    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};

    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: file owns a valid directory handle and all requested output
    // pointers refer to writable storage retained for this call.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(windows_status_error(status))
            .context("failed to inspect runtime private directory security");
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if descriptor.is_null() || owner.is_null() || dacl.is_null() {
        bail!("runtime private directory ancestor has a missing owner or null DACL");
    }
    validate_windows_ancestor_security(owner, dacl)
}

#[cfg(windows)]
fn ensure_private_ticket_directory(directory: &Path) -> Result<PrivateDirectoryGuard> {
    let absolute = absolute_windows_private_directory(directory)?;
    let mut missing = Vec::new();
    let mut anchor = absolute.clone();
    loop {
        match fs::symlink_metadata(&anchor) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(anchor.clone());
                anchor = anchor.parent().map(Path::to_path_buf).ok_or_else(|| {
                    anyhow!(
                        "runtime private directory has no existing ancestor: {}",
                        directory.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect runtime private directory ancestor {}",
                        anchor.display()
                    )
                })
            }
        }
    }

    let mut paths: Vec<_> = anchor
        .ancestors()
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect();
    paths.reverse();
    let mut handles = Vec::with_capacity(paths.len() + missing.len());
    for path in &paths {
        let final_directory = path == &absolute;
        let handle = open_windows_directory_without_following(path, final_directory)?;
        // Validate each live existing component before opening a descendant or
        // creating anything below it. Holding the no-delete-sharing handle
        // then prevents an untrusted rename/delete race for that component.
        validate_windows_directory_security(&handle, false)?;
        if final_directory {
            apply_windows_private_dacl(&handle, "directory", true)?;
            validate_windows_directory_security(&handle, true)?;
        }
        handles.push(handle);
    }
    for component in missing.iter().rev() {
        match create_windows_private_directory(component) {
            Ok(()) => {}
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
                }) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create runtime private directory component {}",
                        component.display()
                    )
                })
            }
        }
        let handle = open_windows_directory_without_following(component, false)?;
        // A component created with our protected security descriptor must be
        // exact. The same check rejects an attacker (or incompatible process)
        // that wins the AlreadyExists race before any deeper path is touched.
        validate_windows_private_object_security(&handle, "directory component", true)?;
        handles.push(handle);
    }
    if handles.is_empty() {
        bail!("runtime private directory has no securely opened components");
    }
    Ok(PrivateDirectoryGuard { _handles: handles })
}

#[cfg(unix)]
fn create_private_ticket_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(windows)]
fn create_private_ticket_file(path: &Path) -> io::Result<File> {
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let result = (|| -> Result<File> {
        let wide = windows_path_utf16(path)?;
        with_windows_private_security_attributes(false, |attributes| {
            // SAFETY: wide is NUL-terminated, attributes references a live
            // absolute security descriptor, and the returned handle is
            // transferred into exactly one File on success.
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    attributes,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!("failed to create private runtime record {}", path.display())
                });
            }
            // SAFETY: handle is a newly owned valid file handle and ownership
            // is transferred to File exactly once.
            Ok(unsafe { File::from_raw_handle(handle) })
        })
    })();
    result.map_err(|error| {
        let kind = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<io::Error>().map(io::Error::kind))
            .unwrap_or(io::ErrorKind::Other);
        io::Error::new(kind, error.to_string())
    })
}

#[cfg(target_os = "linux")]
fn publish_private_record_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
    })?;
    // SAFETY: both paths are live NUL-terminated strings and `renameat2` does
    // not retain their pointers. RENAME_NOREPLACE makes publication atomic and
    // preserves any independently published destination.
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn replace_private_record(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(target_os = "macos")]
fn publish_private_record_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
    })?;
    // SAFETY: both paths are live NUL-terminated strings and `renamex_np`
    // does not retain them. RENAME_EXCL is the atomic no-replace operation.
    if unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn publish_private_record_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    // The supported POSIX release targets use renameat2/renamex_np above.
    // Retain fail-closed behavior on other Unix ports instead of silently
    // using an overwriting rename.
    let _ = (source, destination);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace publication is unavailable on this Unix platform",
    ))
}

#[cfg(windows)]
fn publish_private_record_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source = windows_path_utf16(source)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let destination = windows_path_utf16(destination)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    // SAFETY: both paths are live NUL-terminated buffers. Omitting
    // MOVEFILE_REPLACE_EXISTING gives atomic no-replace publication.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn replace_private_record(source: &Path, destination: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = windows_path_utf16(source)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let destination = windows_path_utf16(destination)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    // SAFETY: both paths are live NUL-terminated buffers. The replacement and
    // write-through flags provide one atomic activation point for readers.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn open_private_ticket_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_private_ticket_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
    };

    OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
fn remove_open_ticket_file(path: &Path, _file: &File) -> io::Result<()> {
    fs::remove_file(path)
}

#[cfg(windows)]
fn remove_open_ticket_file(_path: &Path, file: &File) -> io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfoEx, SetFileInformationByHandle, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX,
    };

    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: the file handle is valid and was opened with DELETE access. The
    // disposition structure remains live and has the exact documented size.
    let removed = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&raw const disposition).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if removed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_ticket_file(path: &Path, file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect runtime ticket {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        bail!("runtime ticket must be a regular, singly-linked file");
    }
    if metadata.uid() != super::effective_uid() {
        bail!("runtime ticket must be owned by the current uid");
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != 0o600 {
        bail!("runtime ticket must have mode 0600 (mode={mode:04o})");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_private_ticket_file(path: &Path, file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect runtime ticket {}", path.display()))?;
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect runtime ticket path {}", path.display()))?;
    if !metadata.is_file() || path_metadata.file_type().is_symlink() {
        bail!("runtime ticket must be a regular file and not a symlink");
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a valid handle and information is a writable
    // structure whose pointer is retained only for this call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error()).context("failed to inspect runtime ticket handle");
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("runtime ticket must not be a Windows reparse point");
    }
    if information.nNumberOfLinks != 1 {
        bail!("runtime ticket must be singly linked");
    }
    validate_windows_private_object_security(file, "record file", false)
}

#[cfg(unix)]
fn protect_ticket_content(
    content: &[u8],
    _ticket_id: &str,
    _workspace_key: &str,
) -> Result<ProtectedRuntimeContent> {
    Ok(ProtectedRuntimeContent {
        protection: RuntimeContentProtection::PosixMode,
        bytes: content.to_vec(),
    })
}

#[cfg(unix)]
fn unprotect_ticket_content(
    content: &[u8],
    _ticket_id: &str,
    _workspace_key: &str,
    protection: RuntimeContentProtection,
) -> Result<Vec<u8>> {
    if protection != RuntimeContentProtection::PosixMode {
        bail!("runtime ticket protection does not match this platform");
    }
    Ok(content.to_vec())
}

#[cfg(unix)]
fn protect_result_content(content: &[u8], _ticket_id: &str) -> Result<ProtectedRuntimeContent> {
    Ok(ProtectedRuntimeContent {
        protection: RuntimeContentProtection::PosixMode,
        bytes: content.to_vec(),
    })
}

#[cfg(unix)]
fn unprotect_result_content(
    content: &[u8],
    _ticket_id: &str,
    protection: RuntimeContentProtection,
) -> Result<Vec<u8>> {
    if protection != RuntimeContentProtection::PosixMode {
        bail!("runtime result protection does not match this platform");
    }
    Ok(content.to_vec())
}

#[cfg(windows)]
fn protect_ticket_content(
    content: &[u8],
    ticket_id: &str,
    workspace_key: &str,
) -> Result<ProtectedRuntimeContent> {
    let binding = format!("runtime-ticket/v1\0{ticket_id}\0{workspace_key}");
    protect_windows_runtime_content(content, &binding)
}

#[cfg(windows)]
fn unprotect_ticket_content(
    content: &[u8],
    ticket_id: &str,
    workspace_key: &str,
    protection: RuntimeContentProtection,
) -> Result<Vec<u8>> {
    match protection {
        RuntimeContentProtection::WindowsDpapi => {
            let binding = format!("runtime-ticket/v1\0{ticket_id}\0{workspace_key}");
            crypt_runtime_content(content, &binding, false)
        }
        RuntimeContentProtection::WindowsAcl => Ok(content.to_vec()),
        RuntimeContentProtection::PosixMode => {
            bail!("runtime ticket protection does not match this platform")
        }
    }
}

#[cfg(windows)]
fn protect_result_content(content: &[u8], ticket_id: &str) -> Result<ProtectedRuntimeContent> {
    let binding = format!("runtime-result/v1\0{ticket_id}");
    protect_windows_runtime_content(content, &binding)
}

#[cfg(windows)]
fn unprotect_result_content(
    content: &[u8],
    ticket_id: &str,
    protection: RuntimeContentProtection,
) -> Result<Vec<u8>> {
    match protection {
        RuntimeContentProtection::WindowsDpapi => {
            let binding = format!("runtime-result/v1\0{ticket_id}");
            crypt_runtime_content(content, &binding, false)
        }
        RuntimeContentProtection::WindowsAcl => Ok(content.to_vec()),
        RuntimeContentProtection::PosixMode => {
            bail!("runtime result protection does not match this platform")
        }
    }
}

#[cfg(windows)]
fn protect_windows_runtime_content(
    content: &[u8],
    binding: &str,
) -> Result<ProtectedRuntimeContent> {
    match crypt_runtime_content(content, binding, true) {
        Ok(bytes) => Ok(ProtectedRuntimeContent {
            protection: RuntimeContentProtection::WindowsDpapi,
            bytes,
        }),
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
            }) =>
        {
            Ok(ProtectedRuntimeContent {
                protection: RuntimeContentProtection::WindowsAcl,
                bytes: content.to_vec(),
            })
        }
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn crypt_runtime_content(content: &[u8], binding: &str, protect: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let entropy = format!("nvim-remote-mirror/{binding}");
    let content_len = u32::try_from(content.len()).context("runtime ticket input is too large")?;
    let entropy_len =
        u32::try_from(entropy.len()).context("runtime ticket binding is too large")?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: content_len,
        pbData: content.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy_len,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: all input blobs point to live byte slices, output is writable,
    // optional UI/reserved pointers are null as required, and the returned
    // LocalAlloc buffer is copied then released exactly once below.
    let succeeded = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error()).context(if protect {
            "failed to protect runtime ticket with Windows DPAPI"
        } else {
            "failed to unprotect runtime ticket with Windows DPAPI"
        });
    }
    let output_len = output.cbData as usize;
    // SAFETY: a successful DPAPI call returns output.cbData initialized bytes
    // at output.pbData until LocalFree is called.
    let protected = unsafe { std::slice::from_raw_parts(output.pbData, output_len) }.to_vec();
    // SAFETY: DPAPI allocated this buffer with LocalAlloc and ownership is
    // transferred to the caller on success.
    let free_result = unsafe { LocalFree(output.pbData.cast()) };
    if !free_result.is_null() {
        bail!("failed to release Windows DPAPI runtime ticket buffer");
    }
    Ok(protected)
}

enum RuntimeWriterCommand {
    Frame(
        RuntimeMessage,
        mpsc::SyncSender<std::result::Result<(), String>>,
    ),
    Bytes(Vec<u8>, mpsc::SyncSender<std::result::Result<(), String>>),
    Finish(mpsc::SyncSender<()>),
}

struct RuntimeWriter {
    machine: RuntimeStateMachine,
    sender: mpsc::SyncSender<RuntimeWriterCommand>,
    worker: Option<thread::JoinHandle<()>>,
    failure: Option<String>,
    timeout: Duration,
}

impl RuntimeWriter {
    fn new<W>(machine: RuntimeStateMachine, mut writer: W, timeout: Duration) -> Result<Self>
    where
        W: Write + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(RUNTIME_WRITER_QUEUE_DEPTH);
        let worker = thread::Builder::new()
            .name("nrm-runtime-outbound".to_owned())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    match command {
                        RuntimeWriterCommand::Frame(message, completed) => {
                            let result = write_runtime_frame(&mut writer, &message)
                                .map_err(|error| error.to_string());
                            let failed = result.is_err();
                            let _ = completed.send(result);
                            if failed {
                                return;
                            }
                        }
                        RuntimeWriterCommand::Bytes(bytes, completed) => {
                            let result = writer
                                .write_all(&bytes)
                                .and_then(|()| writer.flush())
                                .map_err(|error| error.to_string());
                            let failed = result.is_err();
                            let _ = completed.send(result);
                            if failed {
                                return;
                            }
                        }
                        RuntimeWriterCommand::Finish(completed) => {
                            let _ = completed.send(());
                            return;
                        }
                    }
                }
            })
            .context("failed to start runtime protocol writer")?;
        Ok(Self {
            machine,
            sender,
            worker: Some(worker),
            failure: None,
            timeout,
        })
    }

    fn send(&mut self, message: &RuntimeMessage) -> Result<()> {
        self.send_with_timeout(message, self.timeout)
    }

    fn send_with_timeout(&mut self, message: &RuntimeMessage, timeout: Duration) -> Result<()> {
        self.ensure_healthy()?;
        if timeout.is_zero() {
            return self.fail("runtime transport write deadline expired".to_owned());
        }
        self.machine
            .observe_outbound(message)
            .context("runtime client rejected an outbound message")?;
        let (completed, result) = mpsc::sync_channel(1);
        match self
            .sender
            .try_send(RuntimeWriterCommand::Frame(message.clone(), completed))
        {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                return self.fail("runtime outbound queue is full".to_owned())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return self.fail("runtime transport input is closed".to_owned())
            }
        }
        match result.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => self.fail(format!("failed to write runtime message: {error}")),
            Err(mpsc::RecvTimeoutError::Timeout) => self.fail(format!(
                "runtime transport write timed out after {} ms",
                timeout.as_millis()
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.fail("runtime protocol writer stopped unexpectedly".to_owned())
            }
        }
    }

    fn send_prefix(&mut self, bytes: &[u8], timeout: Duration) -> Result<()> {
        self.ensure_healthy()?;
        if timeout.is_zero() {
            return self.fail("runtime launch prefix deadline expired".to_owned());
        }
        let (completed, result) = mpsc::sync_channel(1);
        match self
            .sender
            .try_send(RuntimeWriterCommand::Bytes(bytes.to_vec(), completed))
        {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                return self.fail("runtime outbound queue is full".to_owned())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return self.fail("runtime transport input is closed".to_owned())
            }
        }
        match result.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => self.fail(format!("failed to write runtime launch prefix: {error}")),
            Err(mpsc::RecvTimeoutError::Timeout) => self.fail(format!(
                "runtime launch prefix write timed out after {} ms",
                timeout.as_millis()
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.fail("runtime protocol writer stopped during launch prefix".to_owned())
            }
        }
    }

    fn observe_inbound(&mut self, message: &RuntimeMessage) -> Result<()> {
        self.ensure_healthy()?;
        self.machine
            .observe_inbound(message)
            .context("runtime client rejected an inbound message")
    }

    fn close(&mut self) -> Result<()> {
        let Some(worker) = self.worker.take() else {
            return self.ensure_healthy();
        };
        let (completed, finished) = mpsc::sync_channel(1);
        let sent = self
            .sender
            .try_send(RuntimeWriterCommand::Finish(completed));
        let should_join = match sent {
            Ok(()) => match finished.recv_timeout(self.timeout) {
                Ok(()) => true,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.record_failure(format!(
                        "runtime protocol writer shutdown timed out after {} ms",
                        self.timeout.as_millis()
                    ));
                    false
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => true,
            },
            Err(mpsc::TrySendError::Disconnected(_)) => true,
            Err(mpsc::TrySendError::Full(_)) => {
                self.record_failure(
                    "runtime outbound queue remained full during shutdown".to_owned(),
                );
                false
            }
        };
        if should_join && worker.join().is_err() {
            self.record_failure("runtime protocol writer panicked".to_owned());
        }
        self.ensure_healthy()
    }

    fn record_failure(&mut self, message: String) {
        if self.failure.is_none() {
            self.failure = Some(message);
        }
    }

    fn fail<T>(&mut self, message: String) -> Result<T> {
        self.record_failure(message);
        self.ensure_healthy()?;
        unreachable!("recorded runtime writer failure must be returned")
    }

    fn ensure_healthy(&self) -> Result<()> {
        match self.failure.as_deref() {
            Some(message) => bail!("runtime transport writer failed: {message}"),
            None => Ok(()),
        }
    }
}

impl Drop for RuntimeWriter {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

struct RuntimeOutputChunk {
    process_id: RuntimeProcessId,
    stream: RuntimeOutputStream,
    offset: u64,
    data: Vec<u8>,
}

enum RuntimeOutputCommand {
    Write(RuntimeOutputChunk),
    Finish,
}

#[derive(Debug, PartialEq, Eq)]
enum RuntimeOutputEvent {
    Written {
        process_id: RuntimeProcessId,
        stream: RuntimeOutputStream,
        next_offset: u64,
    },
    WriteError(String),
    Finished,
}

struct RuntimeOutputPump {
    sender: mpsc::SyncSender<RuntimeOutputCommand>,
    events: mpsc::Receiver<RuntimeOutputEvent>,
    worker: Option<thread::JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
}

impl RuntimeOutputPump {
    fn new<Stdout, Stderr>(mut stdout: Stdout, mut stderr: Stderr) -> Result<Self>
    where
        Stdout: Write + Send + 'static,
        Stderr: Write + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(RUNTIME_OUTPUT_QUEUE_DEPTH);
        let (event_sender, events) = mpsc::sync_channel(RUNTIME_OUTPUT_QUEUE_DEPTH + 1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker = thread::Builder::new()
            .name("nrm-runtime-local-output".to_owned())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    if worker_cancelled.load(Ordering::Acquire) {
                        return;
                    }
                    match command {
                        RuntimeOutputCommand::Write(chunk) => {
                            let RuntimeOutputChunk {
                                process_id,
                                stream,
                                offset,
                                data,
                            } = chunk;
                            let next_offset = match offset.checked_add(data.len() as u64) {
                                Some(next_offset) => next_offset,
                                None => {
                                    let _ = event_sender.send(RuntimeOutputEvent::WriteError(
                                        "runtime output offset overflow".to_owned(),
                                    ));
                                    return;
                                }
                            };
                            let output: &mut dyn Write = match stream {
                                RuntimeOutputStream::Stdout | RuntimeOutputStream::Pty => {
                                    &mut stdout
                                }
                                RuntimeOutputStream::Stderr => &mut stderr,
                            };
                            if let Err(error) = output.write_all(&data) {
                                let _ = event_sender.send(RuntimeOutputEvent::WriteError(format!(
                                    "failed to write remote runtime output: {error}"
                                )));
                                return;
                            }
                            if worker_cancelled.load(Ordering::Acquire) {
                                return;
                            }
                            if let Err(error) = output.flush() {
                                let _ = event_sender.send(RuntimeOutputEvent::WriteError(format!(
                                    "failed to flush remote runtime output: {error}"
                                )));
                                return;
                            }
                            if worker_cancelled.load(Ordering::Acquire) {
                                return;
                            }
                            if event_sender
                                .send(RuntimeOutputEvent::Written {
                                    process_id,
                                    stream,
                                    next_offset,
                                })
                                .is_err()
                            {
                                return;
                            }
                        }
                        RuntimeOutputCommand::Finish => {
                            let _ = event_sender.send(RuntimeOutputEvent::Finished);
                            return;
                        }
                    }
                }
            })
            .context("failed to start local runtime output relay")?;
        Ok(Self {
            sender,
            events,
            worker: Some(worker),
            cancelled,
        })
    }

    fn try_write(&self, chunk: RuntimeOutputChunk) -> Result<Option<RuntimeOutputChunk>> {
        match self.sender.try_send(RuntimeOutputCommand::Write(chunk)) {
            Ok(()) => Ok(None),
            Err(mpsc::TrySendError::Full(RuntimeOutputCommand::Write(chunk))) => Ok(Some(chunk)),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                bail!("local runtime output relay stopped unexpectedly")
            }
            Err(mpsc::TrySendError::Full(RuntimeOutputCommand::Finish)) => {
                unreachable!("try_write only sends output chunks")
            }
        }
    }

    fn try_finish(&self) -> Result<bool> {
        match self.sender.try_send(RuntimeOutputCommand::Finish) {
            Ok(()) => Ok(true),
            Err(mpsc::TrySendError::Full(RuntimeOutputCommand::Finish)) => Ok(false),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                bail!("local runtime output relay stopped before shutdown")
            }
            Err(mpsc::TrySendError::Full(RuntimeOutputCommand::Write(_))) => {
                unreachable!("try_finish only sends the finish command")
            }
        }
    }

    fn try_event(&self) -> Result<Option<RuntimeOutputEvent>> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                bail!("local runtime output relay closed without a completion event")
            }
        }
    }

    fn wait_event(&self, timeout: Duration) -> Result<Option<RuntimeOutputEvent>> {
        match self.events.recv_timeout(timeout) {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("local runtime output relay closed without a completion event")
            }
        }
    }

    fn join_finished(&mut self) -> Result<()> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker
            .join()
            .map_err(|_| anyhow!("local runtime output relay panicked"))
    }
}

impl Drop for RuntimeOutputPump {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

enum RuntimeReaderEvent {
    Message(RuntimeMessage),
    LaunchFailure(super::RemoteAgentLaunchFailure),
    ReadError(String),
}

enum RuntimeLocalEvent {
    InputError(String),
}

#[derive(Default)]
struct RuntimeInputFlowState {
    sent: u64,
    acknowledged: u64,
    stopped: bool,
}

#[derive(Clone, Default)]
struct RuntimeInputFlow {
    state: Arc<(Mutex<RuntimeInputFlowState>, Condvar)>,
}

impl RuntimeInputFlow {
    fn reserve_chunk(&self, length: usize) -> Result<Option<(u64, u64)>> {
        let (state, ready) = &*self.state;
        let mut state = state
            .lock()
            .map_err(|_| anyhow!("runtime input flow lock poisoned"))?;
        while !state.stopped && state.acknowledged != state.sent {
            state = ready
                .wait(state)
                .map_err(|_| anyhow!("runtime input flow lock poisoned"))?;
        }
        if state.stopped {
            return Ok(None);
        }
        let offset = state.sent;
        let next_offset = offset
            .checked_add(length as u64)
            .ok_or_else(|| anyhow!("runtime input offset overflow"))?;
        state.sent = next_offset;
        Ok(Some((offset, next_offset)))
    }

    fn drained_offset(&self) -> Result<Option<u64>> {
        let (state, ready) = &*self.state;
        let mut state = state
            .lock()
            .map_err(|_| anyhow!("runtime input flow lock poisoned"))?;
        while !state.stopped && state.acknowledged != state.sent {
            state = ready
                .wait(state)
                .map_err(|_| anyhow!("runtime input flow lock poisoned"))?;
        }
        Ok((!state.stopped).then_some(state.sent))
    }

    fn acknowledge(&self, next_offset: u64) -> Result<()> {
        let (state, ready) = &*self.state;
        let mut state = state
            .lock()
            .map_err(|_| anyhow!("runtime input flow lock poisoned"))?;
        if next_offset < state.acknowledged || next_offset > state.sent {
            bail!("runtime input acknowledgement is outside the in-flight window");
        }
        state.acknowledged = next_offset;
        ready.notify_all();
        Ok(())
    }

    fn stop(&self) {
        let (state, ready) = &*self.state;
        if let Ok(mut state) = state.lock() {
            state.stopped = true;
            ready.notify_all();
        }
    }
}

struct RuntimeInputFlowGuard(RuntimeInputFlow);

impl Drop for RuntimeInputFlowGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}

struct RuntimeChild(Child);

impl Deref for RuntimeChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RuntimeChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for RuntimeChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            super::kill_child_tree(&mut self.0);
            let _ = self.0.wait();
        }
    }
}

#[derive(Default)]
struct BridgeDiagnosticState {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Clone, Default)]
struct BridgeDiagnostics(Arc<Mutex<BridgeDiagnosticState>>);

impl BridgeDiagnostics {
    fn append(&self, chunk: &[u8]) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if chunk.len() >= MAX_RUNTIME_DIAGNOSTIC_BYTES {
            state.bytes.clear();
            state
                .bytes
                .extend_from_slice(&chunk[chunk.len() - MAX_RUNTIME_DIAGNOSTIC_BYTES..]);
            state.truncated = true;
            return;
        }
        let overflow = state
            .bytes
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(MAX_RUNTIME_DIAGNOSTIC_BYTES);
        if overflow != 0 {
            state.bytes.drain(..overflow);
            state.truncated = true;
        }
        state.bytes.extend_from_slice(chunk);
    }

    fn text(&self) -> Option<String> {
        let state = self.0.lock().ok()?;
        if state.bytes.is_empty() {
            return None;
        }
        let text = super::sanitize_agent_error_text(&String::from_utf8_lossy(&state.bytes));
        if state.truncated {
            const PREFIX: &str = "[truncated] ";
            let available = MAX_RUNTIME_DIAGNOSTIC_BYTES - PREFIX.len();
            let mut start = text.len().saturating_sub(available);
            while start < text.len() && !text.is_char_boundary(start) {
                start += 1;
            }
            return Some(format!("{PREFIX}{}", &text[start..]));
        }
        Some(bounded_diagnostic(&text))
    }
}

fn spawn_bridge_diagnostic_reader<R>(stderr: R) -> Result<BridgeDiagnosticReader>
where
    R: Read + Send + 'static,
{
    let diagnostics = BridgeDiagnostics::default();
    let sink = diagnostics.clone();
    let worker = thread::Builder::new()
        .name("nrm-runtime-bridge-stderr".to_owned())
        .spawn(move || {
            let mut stderr = stderr;
            let mut buffer = [0_u8; 4 * 1024];
            loop {
                match stderr.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(read) => sink.append(&buffer[..read]),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return,
                }
            }
        })
        .context("failed to start runtime bridge diagnostic reader")?;
    Ok(BridgeDiagnosticReader {
        diagnostics,
        worker,
    })
}

struct BridgeDiagnosticReader {
    diagnostics: BridgeDiagnostics,
    worker: thread::JoinHandle<()>,
}

impl BridgeDiagnosticReader {
    fn finish(self) -> Option<String> {
        // The runtime bridge has been reaped before every call. Its owned
        // stderr pipe is therefore closed, so joining observes every final
        // diagnostic byte without leaving an unbounded teardown wait.
        let _ = self.worker.join();
        self.diagnostics.text()
    }
}

fn run_proxy(
    ticket: RuntimeTicket,
    state_dir: Option<&Path>,
    ticket_id: &str,
) -> Result<RuntimeProxyResult> {
    let launch_started = Instant::now();
    let transport =
        RemoteTransport::from_ssh(ticket.ssh.clone(), ticket.ssh_connect_timeout_seconds)?;
    let remote_root = transport.normalize_remote_root(PathBuf::from(&ticket.remote_root))?;
    let timeout = Duration::from_millis(ticket.request_timeout_ms);
    let host = match &ticket.remote_host {
        Some(host) => {
            super::remote_host::validate_remote_host_info(host)?;
            host.clone()
        }
        None => super::detect_remote_host_info(&transport, timeout)
            .context("failed to detect the runtime host")?,
    };
    if launch_started.elapsed() >= timeout {
        bail!(
            "runtime host detection exceeded the {} ms launch deadline",
            timeout.as_millis()
        );
    }
    let attempt = |host: &super::RemoteHostInfo,
                   process_request_sent: &mut bool|
     -> Result<RuntimeProxyResult> {
        let plan = transport.runtime_plan(&ticket.agent, &remote_root, host)?;
        let mut command = plan.command();
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        super::configure_agent_process(&mut command);
        let mut child = RuntimeChild(command.spawn().with_context(|| {
            format!(
                "failed to launch runtime agent{}",
                transport.launch_context_suffix()
            )
        })?);
        let child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("runtime agent stdin was not piped"))?;
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("runtime agent stdout was not piped"))?;
        let child_stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("runtime agent stderr was not piped"))?;
        let bridge_diagnostics = spawn_bridge_diagnostic_reader(child_stderr)?;
        let mut capabilities = CapabilitySet::v1_agent();
        capabilities.runtime_process_v1 = true;
        capabilities.runtime_pty_v1 = true;
        let writer = Arc::new(Mutex::new(RuntimeWriter::new(
            RuntimeStateMachine::new(RuntimePeerRole::Client, capabilities),
            child_stdin,
            RUNTIME_WRITER_TIMEOUT,
        )?));
        if !plan.stdin_prefix.is_empty() {
            let remaining = timeout.saturating_sub(launch_started.elapsed());
            let prefix_timeout = remaining.min(RUNTIME_WRITER_TIMEOUT);
            let prefix_result = writer
                .lock()
                .map_err(|_| anyhow!("runtime writer lock poisoned"))?
                .send_prefix(&plan.stdin_prefix, prefix_timeout);
            if let Err(error) = prefix_result {
                stop_runtime_bridge(&mut child);
                return Err(error).context("failed to write runtime launch prefix");
            }
        }

        let (reader_tx, reader_rx) = mpsc::sync_channel(RUNTIME_READER_QUEUE_DEPTH);
        spawn_runtime_reader(
            child_stdout,
            matches!(transport, RemoteTransport::Ssh(_)),
            reader_tx,
        )?;

        let remaining = timeout.saturating_sub(launch_started.elapsed());
        if remaining.is_zero() {
            stop_runtime_bridge(&mut child);
            bail!(
                "runtime agent launch exceeded its {} ms deadline",
                timeout.as_millis()
            );
        }
        if let Err(error) = send_shared_with_timeout(
            &writer,
            &RuntimeMessage::ClientHello {
                package_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: PROTOCOL_VERSION,
                capability: ticket.capability,
            },
            remaining.min(RUNTIME_WRITER_TIMEOUT),
        ) {
            stop_runtime_bridge(&mut child);
            return Err(error).context("failed to send runtime client hello");
        }

        let remaining = timeout.saturating_sub(launch_started.elapsed());
        if remaining.is_zero() {
            stop_runtime_bridge(&mut child);
            bail!(
                "runtime agent launch exceeded its {} ms deadline",
                timeout.as_millis()
            );
        }
        let server_hello =
            receive_runtime_message(&reader_rx, remaining, "runtime server hello", &mut child)?;
        observe_shared(&writer, &server_hello)?;
        if let RuntimeMessage::Error(error) = server_hello {
            stop_runtime_bridge(&mut child);
            return Ok(runtime_error_result(&error, bridge_diagnostics.finish()));
        }
        if !matches!(server_hello, RuntimeMessage::ServerHello { .. }) {
            stop_runtime_bridge(&mut child);
            bail!("runtime agent did not send server_hello after client_hello");
        }

        // Fence retry before writing: an I/O error can occur after the complete
        // frame reached the agent, so any attempted StartProcess is potentially
        // accepted and must never be replayed.
        let remaining = timeout.saturating_sub(launch_started.elapsed());
        if remaining.is_zero() {
            stop_runtime_bridge(&mut child);
            bail!(
                "runtime process startup exceeded its {} ms timeout",
                timeout.as_millis()
            );
        }
        *process_request_sent = true;
        if let Err(error) = send_shared_with_timeout(
            &writer,
            &RuntimeMessage::StartProcess {
                request_id: 1,
                spec: ticket.spec.clone(),
            },
            remaining.min(RUNTIME_WRITER_TIMEOUT),
        ) {
            stop_runtime_bridge(&mut child);
            return Err(error).context("failed to send runtime process request");
        }
        let remaining = timeout.saturating_sub(launch_started.elapsed());
        if remaining.is_zero() {
            stop_runtime_bridge(&mut child);
            bail!(
                "runtime process startup exceeded its {} ms timeout",
                timeout.as_millis()
            );
        }
        let started =
            receive_runtime_message(&reader_rx, remaining, "runtime process startup", &mut child)?;
        observe_shared(&writer, &started)?;
        let process_id = match started {
            RuntimeMessage::ProcessStarted { process_id, .. } => process_id,
            RuntimeMessage::Error(error) => {
                stop_runtime_bridge(&mut child);
                return Ok(runtime_error_result(&error, bridge_diagnostics.finish()));
            }
            _ => {
                stop_runtime_bridge(&mut child);
                bail!("runtime agent did not acknowledge process startup");
            }
        };
        let control_mailbox = RuntimeControlMailbox::open(state_dir, ticket_id)?;

        let (local_tx, local_rx) = mpsc::sync_channel(1);
        let input_flow = RuntimeInputFlow::default();
        let _input_flow_guard = RuntimeInputFlowGuard(input_flow.clone());
        spawn_runtime_input(
            process_id,
            ticket.capability == RuntimeCapability::ProcessPtyV1,
            ticket.spec.persistence,
            Arc::clone(&writer),
            input_flow.clone(),
            local_tx,
        )?;

        let mut output_pump = RuntimeOutputPump::new(io::stdout(), io::stderr())?;
        let mut pending_output = None;
        let mut terminal_message = None;
        let mut output_finish_sent = false;
        let mut output_shutdown_deadline: Option<Instant> = None;
        let mut last_terminal_size = ticket.spec.terminal_size;
        let is_pty = ticket.capability == RuntimeCapability::ProcessPtyV1;
        let mut next_resize_poll = Instant::now();
        let mut result = 'runtime: loop {
            if terminal_message.is_none() {
                forward_runtime_controls(&control_mailbox, &writer, process_id)?;
                if is_pty && Instant::now() >= next_resize_poll {
                    if let Some(size) = local_terminal_size() {
                        if Some(size) != last_terminal_size {
                            send_shared(&writer, &RuntimeMessage::Resize { process_id, size })?;
                            last_terminal_size = Some(size);
                        }
                    }
                    next_resize_poll = Instant::now() + RUNTIME_EVENT_POLL_INTERVAL;
                }
                if let Ok(RuntimeLocalEvent::InputError(error)) = local_rx.try_recv() {
                    stop_runtime_bridge(&mut child);
                    return Err(anyhow!(error)).context("failed to relay local runtime input");
                }
            }

            while let Some(event) = output_pump.try_event()? {
                if forward_runtime_output_event(&writer, event)? {
                    let terminal = terminal_message.take().ok_or_else(|| {
                        anyhow!("local runtime output relay stopped before remote completion")
                    })?;
                    output_pump.join_finished()?;
                    observe_shared(&writer, &terminal)?;
                    break 'runtime runtime_terminal_result(terminal)?;
                }
            }

            if let Some(chunk) = pending_output.take() {
                pending_output = output_pump.try_write(chunk)?;
                if pending_output.is_some() {
                    if let Some(event) = output_pump.wait_event(RUNTIME_EVENT_POLL_INTERVAL)? {
                        if forward_runtime_output_event(&writer, event)? {
                            bail!("local runtime output relay stopped while output was pending");
                        }
                    }
                    continue;
                }
            }

            if terminal_message.is_some() {
                let deadline = *output_shutdown_deadline
                    .get_or_insert_with(|| Instant::now() + RUNTIME_OUTPUT_SHUTDOWN_TIMEOUT);
                if !output_finish_sent {
                    output_finish_sent = output_pump.try_finish()?;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    stop_runtime_bridge(&mut child);
                    bail!(
                        "local runtime output did not drain within {} ms after remote completion",
                        RUNTIME_OUTPUT_SHUTDOWN_TIMEOUT.as_millis()
                    );
                }
                if let Some(event) =
                    output_pump.wait_event(remaining.min(RUNTIME_EVENT_POLL_INTERVAL))?
                {
                    if forward_runtime_output_event(&writer, event)? {
                        let terminal = terminal_message.take().ok_or_else(|| {
                            anyhow!("local runtime output relay stopped before remote completion")
                        })?;
                        output_pump.join_finished()?;
                        observe_shared(&writer, &terminal)?;
                        break 'runtime runtime_terminal_result(terminal)?;
                    }
                }
                continue;
            }

            match reader_rx.recv_timeout(RUNTIME_EVENT_POLL_INTERVAL) {
                Ok(RuntimeReaderEvent::Message(message)) => {
                    if matches!(
                        &message,
                        RuntimeMessage::Exited { .. }
                            | RuntimeMessage::Detached { .. }
                            | RuntimeMessage::Error(_)
                    ) {
                        input_flow.stop();
                        terminal_message = Some(message);
                        output_shutdown_deadline =
                            Some(Instant::now() + RUNTIME_OUTPUT_SHUTDOWN_TIMEOUT);
                        continue;
                    }
                    observe_shared(&writer, &message)?;
                    match message {
                        RuntimeMessage::Output {
                            process_id,
                            stream,
                            offset,
                            data,
                        } => {
                            pending_output = output_pump.try_write(RuntimeOutputChunk {
                                process_id,
                                stream,
                                offset,
                                data,
                            })?;
                        }
                        RuntimeMessage::InputAck { next_offset, .. } => {
                            input_flow.acknowledge(next_offset)?;
                        }
                        _ => {
                            stop_runtime_bridge(&mut child);
                            bail!("runtime agent sent an unexpected process message");
                        }
                    }
                }
                Ok(RuntimeReaderEvent::LaunchFailure(failure)) => {
                    stop_runtime_bridge(&mut child);
                    bail!("runtime agent launch failed: {}", failure.detail());
                }
                Ok(RuntimeReaderEvent::ReadError(error)) => {
                    stop_runtime_bridge(&mut child);
                    bail!(
                        "runtime agent stream failed: {}",
                        super::sanitize_agent_error_text(&error)
                    );
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(status) =
                        child.try_wait().context("failed to poll runtime bridge")?
                    {
                        bail!(
                        "runtime bridge exited with {status} before the remote process completed"
                    );
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    stop_runtime_bridge(&mut child);
                    bail!("runtime agent stream closed before the remote process completed");
                }
            }
        };

        control_mailbox.discard()?;
        close_shared(&writer)?;
        let bridge_status = wait_runtime_bridge(&mut child, RUNTIME_BRIDGE_EXIT_GRACE)?;
        let bridge_stderr = bridge_diagnostics.finish();
        if !bridge_status.success()
            && !matches!(
                result.kind,
                RuntimeResultKind::RuntimeError | RuntimeResultKind::TransportError
            )
        {
            return Ok(RuntimeProxyResult {
                schema_version: RUNTIME_RESULT_SCHEMA_VERSION,
                exit_code: RUNTIME_TRANSPORT_EXIT_CODE,
                kind: RuntimeResultKind::TransportError,
                error_code: Some("bridge_exit".to_owned()),
                message: Some(bounded_diagnostic(&format!(
                    "runtime bridge exited with {bridge_status} after remote completion"
                ))),
                output_truncated: result.output_truncated,
                bridge_stderr,
            });
        }
        result.bridge_stderr = bridge_stderr;
        Ok(result)
    };

    let mut process_request_sent = false;
    match attempt(&host, &mut process_request_sent) {
        Ok(result) => Ok(result),
        Err(first_error) if ticket.remote_host.is_some() && !process_request_sent => {
            let remaining = timeout.saturating_sub(launch_started.elapsed());
            if remaining.is_zero() {
                return Err(first_error).context(
                    "cached runtime host launch failed after the absolute launch deadline",
                );
            }
            let refreshed =
                super::detect_remote_host_info(&transport, remaining).with_context(|| {
                    format!("cached runtime host launch failed and refresh failed: {first_error:#}")
                })?;
            let mut retry_request_sent = false;
            attempt(&refreshed, &mut retry_request_sent).with_context(|| {
                format!(
                    "runtime launch still failed after refreshing cached host metadata; initial failure: {first_error:#}"
                )
            })
        }
        Err(error) => Err(error),
    }
}

fn send_shared(writer: &Arc<Mutex<RuntimeWriter>>, message: &RuntimeMessage) -> Result<()> {
    writer
        .lock()
        .map_err(|_| anyhow!("runtime writer lock poisoned"))?
        .send(message)
}

fn send_shared_with_timeout(
    writer: &Arc<Mutex<RuntimeWriter>>,
    message: &RuntimeMessage,
    timeout: Duration,
) -> Result<()> {
    writer
        .lock()
        .map_err(|_| anyhow!("runtime writer lock poisoned"))?
        .send_with_timeout(message, timeout)
}

fn observe_shared(writer: &Arc<Mutex<RuntimeWriter>>, message: &RuntimeMessage) -> Result<()> {
    writer
        .lock()
        .map_err(|_| anyhow!("runtime writer lock poisoned"))?
        .observe_inbound(message)
}

fn close_shared(writer: &Arc<Mutex<RuntimeWriter>>) -> Result<()> {
    writer
        .lock()
        .map_err(|_| anyhow!("runtime writer lock poisoned"))?
        .close()
}

fn forward_runtime_controls(
    mailbox: &RuntimeControlMailbox,
    writer: &Arc<Mutex<RuntimeWriter>>,
    process_id: RuntimeProcessId,
) -> Result<()> {
    for signal in mailbox.drain()? {
        send_shared(writer, &RuntimeMessage::Signal { process_id, signal })?;
    }
    Ok(())
}

fn forward_runtime_output_event(
    writer: &Arc<Mutex<RuntimeWriter>>,
    event: RuntimeOutputEvent,
) -> Result<bool> {
    match event {
        RuntimeOutputEvent::Written {
            process_id,
            stream,
            next_offset,
        } => {
            send_shared(
                writer,
                &RuntimeMessage::OutputAck {
                    process_id,
                    stream,
                    next_offset,
                },
            )?;
            Ok(false)
        }
        RuntimeOutputEvent::WriteError(error) => bail!(error),
        RuntimeOutputEvent::Finished => Ok(true),
    }
}

fn runtime_terminal_result(message: RuntimeMessage) -> Result<RuntimeProxyResult> {
    match message {
        RuntimeMessage::Exited {
            status,
            output_truncated,
            ..
        } => Ok(process_result(status, output_truncated)),
        RuntimeMessage::Detached { .. } => Ok(RuntimeProxyResult {
            schema_version: RUNTIME_RESULT_SCHEMA_VERSION,
            exit_code: 0,
            kind: RuntimeResultKind::Detached,
            error_code: None,
            message: None,
            output_truncated: false,
            bridge_stderr: None,
        }),
        RuntimeMessage::Error(error) => Ok(runtime_error_result(&error, None)),
        _ => bail!("runtime output relay completed without a terminal process message"),
    }
}

fn spawn_runtime_reader(
    stdout: ChildStdout,
    launch_prelude_pending: bool,
    sender: mpsc::SyncSender<RuntimeReaderEvent>,
) -> Result<()> {
    thread::Builder::new()
        .name("nrm-runtime-reader".to_owned())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            if launch_prelude_pending {
                match super::read_agent_launch_prelude(&mut reader) {
                    Ok(Some(failure)) => {
                        let _ = sender.send(RuntimeReaderEvent::LaunchFailure(failure));
                        return;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = sender.send(RuntimeReaderEvent::ReadError(error.to_string()));
                        return;
                    }
                }
            }
            loop {
                match read_runtime_frame(&mut reader) {
                    Ok(message) => {
                        if sender.send(RuntimeReaderEvent::Message(message)).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(RuntimeReaderEvent::ReadError(error.to_string()));
                        return;
                    }
                }
            }
        })
        .context("failed to start runtime protocol reader")?;
    Ok(())
}

fn receive_runtime_message(
    receiver: &mpsc::Receiver<RuntimeReaderEvent>,
    timeout: Duration,
    context: &str,
    child: &mut Child,
) -> Result<RuntimeMessage> {
    match receiver.recv_timeout(timeout) {
        Ok(RuntimeReaderEvent::Message(message)) => Ok(message),
        Ok(RuntimeReaderEvent::LaunchFailure(failure)) => {
            stop_runtime_bridge(child);
            bail!("runtime agent launch failed: {}", failure.detail())
        }
        Ok(RuntimeReaderEvent::ReadError(error)) => {
            stop_runtime_bridge(child);
            bail!(
                "{context} failed: {}",
                super::sanitize_agent_error_text(&error)
            )
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            stop_runtime_bridge(child);
            bail!("{context} timed out after {} ms", timeout.as_millis())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            stop_runtime_bridge(child);
            bail!("runtime agent stream closed during {context}")
        }
    }
}

fn spawn_runtime_input(
    process_id: RuntimeProcessId,
    is_pty: bool,
    persistence: RuntimePersistence,
    writer: Arc<Mutex<RuntimeWriter>>,
    flow: RuntimeInputFlow,
    event_sender: mpsc::SyncSender<RuntimeLocalEvent>,
) -> Result<()> {
    thread::Builder::new()
        .name("nrm-runtime-input".to_owned())
        .spawn(move || {
            let stdin = io::stdin();
            let mut stdin = stdin.lock();
            let mut buffer = vec![0_u8; RUNTIME_MAX_DATA_CHUNK_LEN];
            loop {
                match stdin.read(&mut buffer) {
                    Ok(0) => {
                        let next_offset = match flow.drained_offset() {
                            Ok(Some(offset)) => offset,
                            Ok(None) => return,
                            Err(error) => {
                                let _ = event_sender
                                    .send(RuntimeLocalEvent::InputError(error.to_string()));
                                return;
                            }
                        };
                        let message =
                            runtime_eof_message(process_id, is_pty, persistence, next_offset);
                        if let Err(error) = send_shared(&writer, &message) {
                            let _ =
                                event_sender.send(RuntimeLocalEvent::InputError(error.to_string()));
                        }
                        return;
                    }
                    Ok(read) => {
                        let (offset, _) = match flow.reserve_chunk(read) {
                            Ok(Some(offsets)) => offsets,
                            Ok(None) => return,
                            Err(error) => {
                                let _ = event_sender
                                    .send(RuntimeLocalEvent::InputError(error.to_string()));
                                return;
                            }
                        };
                        let message = RuntimeMessage::Input {
                            process_id,
                            offset,
                            data: buffer[..read].to_vec(),
                        };
                        if let Err(error) = send_shared(&writer, &message) {
                            let _ =
                                event_sender.send(RuntimeLocalEvent::InputError(error.to_string()));
                            return;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        let _ = event_sender.send(RuntimeLocalEvent::InputError(error.to_string()));
                        return;
                    }
                }
            }
        })
        .context("failed to start runtime input relay")?;
    Ok(())
}

fn runtime_eof_message(
    process_id: RuntimeProcessId,
    is_pty: bool,
    persistence: RuntimePersistence,
    next_offset: u64,
) -> RuntimeMessage {
    match persistence {
        RuntimePersistence::Attached if is_pty => RuntimeMessage::Signal {
            process_id,
            signal: nrm_protocol::RuntimeSignal::Hangup,
        },
        RuntimePersistence::Attached => RuntimeMessage::CloseInput {
            process_id,
            next_offset,
        },
        RuntimePersistence::Detachable { .. } => RuntimeMessage::Detach { process_id },
    }
}

fn bounded_diagnostic(message: &str) -> String {
    let message = super::sanitize_agent_error_text(message);
    if message.len() <= MAX_RUNTIME_DIAGNOSTIC_BYTES {
        return message;
    }
    const SUFFIX: &str = " [truncated]";
    let mut boundary = MAX_RUNTIME_DIAGNOSTIC_BYTES - SUFFIX.len();
    while boundary != 0 && !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}{SUFFIX}", &message[..boundary])
}

fn transport_error_result(error: &anyhow::Error) -> RuntimeProxyResult {
    let message = bounded_diagnostic(&format!("{error:#}"));
    let error_code = if message.contains("ticket_expired:") {
        "ticket_expired"
    } else {
        "transport_error"
    };
    RuntimeProxyResult {
        schema_version: RUNTIME_RESULT_SCHEMA_VERSION,
        exit_code: RUNTIME_TRANSPORT_EXIT_CODE,
        kind: RuntimeResultKind::TransportError,
        error_code: Some(error_code.to_owned()),
        message: Some(message),
        output_truncated: false,
        bridge_stderr: None,
    }
}

fn runtime_error_code(code: &nrm_protocol::RuntimeErrorCode) -> &'static str {
    use nrm_protocol::RuntimeErrorCode;
    match code {
        RuntimeErrorCode::Protocol => "protocol",
        RuntimeErrorCode::Unsupported => "unsupported",
        RuntimeErrorCode::InvalidRequest => "invalid_request",
        RuntimeErrorCode::SpawnFailed => "spawn_failed",
        RuntimeErrorCode::SessionNotFound => "session_not_found",
        RuntimeErrorCode::SessionInUse => "session_in_use",
        RuntimeErrorCode::Unauthorized => "unauthorized",
        RuntimeErrorCode::WrongWorkspace => "wrong_workspace",
        RuntimeErrorCode::HistoryLost => "history_lost",
        RuntimeErrorCode::ResourceLimit => "resource_limit",
        RuntimeErrorCode::PersistenceUnavailable => "persistence_unavailable",
        RuntimeErrorCode::PermissionDenied => "permission_denied",
        RuntimeErrorCode::Internal => "internal",
    }
}

fn runtime_error_result(
    error: &nrm_protocol::RuntimeError,
    bridge_stderr: Option<String>,
) -> RuntimeProxyResult {
    RuntimeProxyResult {
        schema_version: RUNTIME_RESULT_SCHEMA_VERSION,
        exit_code: RUNTIME_TRANSPORT_EXIT_CODE,
        kind: RuntimeResultKind::RuntimeError,
        error_code: Some(runtime_error_code(&error.code).to_owned()),
        message: Some(bounded_diagnostic(&error.message)),
        output_truncated: false,
        bridge_stderr,
    }
}

fn process_result(status: RuntimeExitStatus, output_truncated: bool) -> RuntimeProxyResult {
    let kind = match &status {
        RuntimeExitStatus::Code(_) => RuntimeResultKind::ProcessExit,
        RuntimeExitStatus::Signal(_) => RuntimeResultKind::Signal,
        RuntimeExitStatus::TimedOut => RuntimeResultKind::TimedOut,
        RuntimeExitStatus::OutputLimit => RuntimeResultKind::OutputLimit,
        RuntimeExitStatus::Cancelled => RuntimeResultKind::Cancelled,
    };
    RuntimeProxyResult {
        schema_version: RUNTIME_RESULT_SCHEMA_VERSION,
        exit_code: runtime_exit_code(status),
        kind,
        error_code: match kind {
            RuntimeResultKind::TimedOut => Some("timed_out".to_owned()),
            RuntimeResultKind::OutputLimit => Some("output_limit".to_owned()),
            RuntimeResultKind::Cancelled => Some("cancelled".to_owned()),
            _ => None,
        },
        message: None,
        output_truncated,
        bridge_stderr: None,
    }
}

fn runtime_exit_code(status: RuntimeExitStatus) -> i32 {
    match status {
        RuntimeExitStatus::Code(0) => 0,
        RuntimeExitStatus::Code(code @ 1..=255) => code,
        RuntimeExitStatus::Code(_) => 1,
        RuntimeExitStatus::Signal(signal) => 128 + i32::try_from(signal.min(127)).unwrap_or(127),
        RuntimeExitStatus::TimedOut => 124,
        RuntimeExitStatus::OutputLimit => RUNTIME_TRANSPORT_EXIT_CODE,
        RuntimeExitStatus::Cancelled => 130,
    }
}

fn wait_runtime_bridge(child: &mut Child, timeout: Duration) -> Result<std::process::ExitStatus> {
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("failed to poll runtime bridge")? {
            return Ok(status);
        }
        if started.elapsed() >= timeout {
            super::kill_child_tree(child);
            return child.wait().context("failed to reap runtime bridge");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn stop_runtime_bridge(child: &mut Child) {
    super::kill_child_tree(child);
    let _ = child.wait();
}

#[cfg(unix)]
struct LocalRuntimeTerminalMode {
    fd: std::os::fd::RawFd,
    original: libc::termios,
}

#[cfg(unix)]
impl LocalRuntimeTerminalMode {
    fn enter(fd: std::os::fd::RawFd) -> io::Result<Option<Self>> {
        let original = match unix_terminal_attributes(fd) {
            Ok(attributes) => attributes,
            Err(error)
                if error.raw_os_error() == Some(libc::ENOTTY)
                    || error.kind() == io::ErrorKind::Unsupported =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let mut raw = original;
        // SAFETY: raw is an initialized caller-owned termios structure and
        // cfmakeraw mutates only that structure without retaining its pointer.
        unsafe { libc::cfmakeraw(&mut raw) };
        unix_set_terminal_attributes(fd, &raw)?;
        Ok(Some(Self { fd, original }))
    }
}

#[cfg(unix)]
impl Drop for LocalRuntimeTerminalMode {
    fn drop(&mut self) {
        let _ = unix_set_terminal_attributes(self.fd, &self.original);
    }
}

#[cfg(unix)]
fn unix_terminal_attributes(fd: std::os::fd::RawFd) -> io::Result<libc::termios> {
    let mut attributes = std::mem::MaybeUninit::<libc::termios>::uninit();
    loop {
        // SAFETY: attributes points to writable storage for one termios value
        // and tcgetattr does not retain the pointer.
        if unsafe { libc::tcgetattr(fd, attributes.as_mut_ptr()) } == 0 {
            // SAFETY: tcgetattr initialized the complete structure on success.
            return Ok(unsafe { attributes.assume_init() });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn unix_set_terminal_attributes(
    fd: std::os::fd::RawFd,
    attributes: &libc::termios,
) -> io::Result<()> {
    loop {
        // SAFETY: attributes is a live initialized termios structure retained
        // for this call only; TCSANOW does not flush pending bridge input.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, attributes) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn enter_local_runtime_terminal_mode() -> Result<Option<LocalRuntimeTerminalMode>> {
    use std::os::fd::AsRawFd as _;

    LocalRuntimeTerminalMode::enter(io::stdin().as_raw_fd())
        .context("failed to put the local runtime terminal bridge in raw mode")
}

#[cfg(windows)]
struct LocalRuntimeTerminalMode {
    handle: windows_sys::Win32::Foundation::HANDLE,
    original: u32,
}

#[cfg(windows)]
impl Drop for LocalRuntimeTerminalMode {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::SetConsoleMode;

        // SAFETY: handle is the borrowed standard-input console handle that
        // succeeded in GetConsoleMode and original is that exact saved mode.
        let _ = unsafe { SetConsoleMode(self.handle, self.original) };
    }
}

#[cfg(windows)]
fn windows_runtime_input_mode(mode: u32) -> u32 {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    };

    (mode | ENABLE_VIRTUAL_TERMINAL_INPUT)
        & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT)
}

#[cfg(windows)]
fn enter_local_runtime_terminal_mode() -> Result<Option<LocalRuntimeTerminalMode>> {
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INVALID_HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, STD_INPUT_HANDLE,
    };

    // SAFETY: GetStdHandle has no pointer preconditions and returns a borrowed
    // process handle which is not closed here.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() {
        return Ok(None);
    }
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: GetLastError has no pointer preconditions and is read after
        // GetStdHandle returned its documented failure sentinel.
        let error = unsafe { GetLastError() };
        return Err(io::Error::from_raw_os_error(error as i32))
            .context("failed to resolve the local runtime console input handle");
    }
    let mut original = 0;
    // SAFETY: original is writable for this call and handle was checked for
    // the documented invalid sentinels.
    if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
        // SAFETY: GetLastError has no pointer preconditions and is read
        // immediately after the failed console-mode query.
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_HANDLE {
            return Ok(None);
        }
        return Err(io::Error::from_raw_os_error(error as i32))
            .context("failed to inspect the local runtime console input mode");
    }
    let raw = windows_runtime_input_mode(original);
    // SAFETY: handle succeeded in GetConsoleMode and raw is a mode derived
    // from that valid mode by clearing only documented input-processing bits.
    if unsafe { SetConsoleMode(handle, raw) } == 0 {
        return Err(io::Error::last_os_error())
            .context("failed to put the local runtime console bridge in raw mode");
    }
    Ok(Some(LocalRuntimeTerminalMode { handle, original }))
}

#[cfg(unix)]
fn local_terminal_size() -> Option<TerminalSize> {
    use std::os::fd::AsRawFd as _;

    let stdin = io::stdin();
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes exactly one winsize structure to a valid
    // caller-owned pointer and does not retain it.
    if unsafe { libc::ioctl(stdin.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } != 0
        || size.ws_row == 0
        || size.ws_col == 0
    {
        return None;
    }
    let (pixel_width, pixel_height) = if size.ws_xpixel == 0 || size.ws_ypixel == 0 {
        (None, None)
    } else {
        (
            Some(u32::from(size.ws_xpixel)),
            Some(u32::from(size.ws_ypixel)),
        )
    };
    Some(TerminalSize {
        columns: size.ws_col,
        rows: size.ws_row,
        pixel_width,
        pixel_height,
    })
}

#[cfg(windows)]
fn local_terminal_size() -> Option<TerminalSize> {
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, COORD, SMALL_RECT,
        STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };

    for selector in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle has no pointer preconditions and returns a
        // borrowed process handle which is not closed here.
        let handle: HANDLE = unsafe { GetStdHandle(selector) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        let mut info = CONSOLE_SCREEN_BUFFER_INFO {
            dwSize: COORD { X: 0, Y: 0 },
            dwCursorPosition: COORD { X: 0, Y: 0 },
            wAttributes: 0,
            srWindow: SMALL_RECT {
                Left: 0,
                Top: 0,
                Right: 0,
                Bottom: 0,
            },
            dwMaximumWindowSize: COORD { X: 0, Y: 0 },
        };
        // SAFETY: info is a valid writable structure for the duration of the
        // call and handle is checked for the documented invalid sentinels.
        if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } == 0 {
            continue;
        }
        let columns = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
        let rows = i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
        let (Ok(columns), Ok(rows)) = (u16::try_from(columns), u16::try_from(rows)) else {
            continue;
        };
        if columns != 0 && rows != 0 {
            return Some(TerminalSize {
                columns,
                rows,
                pixel_width: None,
                pixel_height: None,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrm_protocol::{
        RuntimeCwd, RuntimeEnvironment, RuntimePersistence, RuntimeProcessSpec, TerminalSize,
    };
    #[cfg(not(windows))]
    use tempfile::TempDir;

    #[cfg(not(windows))]
    fn test_directory() -> TempDir {
        TempDir::new().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn local_runtime_terminal_mode_is_raw_and_restores_the_slave() {
        use std::os::fd::FromRawFd as _;

        let mut master = -1;
        let mut slave = -1;
        // SAFETY: master and slave are writable descriptor slots; null termios
        // and winsize pointers request the platform defaults.
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(opened, 0, "{}", io::Error::last_os_error());
        // SAFETY: successful openpty returned a uniquely owned master fd.
        let _master = unsafe { File::from_raw_fd(master) };
        // SAFETY: successful openpty returned a uniquely owned slave fd.
        let _slave = unsafe { File::from_raw_fd(slave) };

        let mut configured = unix_terminal_attributes(slave).unwrap();
        configured.c_lflag |= libc::ECHO | libc::ICANON | libc::ISIG;
        unix_set_terminal_attributes(slave, &configured).unwrap();
        let original = unix_terminal_attributes(slave).unwrap();
        {
            let guard = LocalRuntimeTerminalMode::enter(slave).unwrap();
            assert!(guard.is_some());
            let raw = unix_terminal_attributes(slave).unwrap();
            assert_eq!(raw.c_lflag & (libc::ECHO | libc::ICANON | libc::ISIG), 0);
        }
        let restored = unix_terminal_attributes(slave).unwrap();
        let input_mask = libc::IGNBRK
            | libc::BRKINT
            | libc::PARMRK
            | libc::ISTRIP
            | libc::INLCR
            | libc::IGNCR
            | libc::ICRNL
            | libc::IXON;
        let local_mask = libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN;
        let control_mask = libc::CSIZE | libc::PARENB;
        assert_eq!(restored.c_iflag & input_mask, original.c_iflag & input_mask);
        assert_eq!(
            restored.c_oflag & libc::OPOST,
            original.c_oflag & libc::OPOST
        );
        assert_eq!(
            restored.c_cflag & control_mask,
            original.c_cflag & control_mask
        );
        // Darwin may set kernel-managed PENDIN after a canonical/raw mode
        // transition, so compare only the local flags cfmakeraw controls.
        assert_eq!(restored.c_lflag & local_mask, original.c_lflag & local_mask);
        assert_eq!(restored.c_cc[libc::VMIN], original.c_cc[libc::VMIN]);
        assert_eq!(restored.c_cc[libc::VTIME], original.c_cc[libc::VTIME]);
    }

    #[cfg(unix)]
    #[test]
    fn local_runtime_terminal_mode_ignores_non_terminal_stdin() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::net::UnixStream;

        let (reader, _writer) = UnixStream::pair().unwrap();
        assert!(LocalRuntimeTerminalMode::enter(reader.as_raw_fd())
            .unwrap()
            .is_none());
    }

    #[cfg(windows)]
    #[test]
    fn local_runtime_console_mode_forwards_echo_lines_and_control_keys() {
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
            ENABLE_VIRTUAL_TERMINAL_INPUT,
        };

        let original = ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
        let raw = windows_runtime_input_mode(original);
        assert_eq!(
            raw & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
            0
        );
        assert_ne!(raw & ENABLE_VIRTUAL_TERMINAL_INPUT, 0);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "runtime ConPTY subprocess fixture"]
    fn subprocess_checks_local_runtime_console_mode() {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
            ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, STD_INPUT_HANDLE,
        };

        // SAFETY: GetStdHandle has no pointer preconditions and returns a
        // borrowed handle which remains owned by the ConPTY process.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        assert!(!handle.is_null() && handle != INVALID_HANDLE_VALUE);
        let mut original = 0;
        // SAFETY: original is writable and handle is a live console input
        // handle supplied by the ConPTY subprocess.
        assert_ne!(unsafe { GetConsoleMode(handle, &mut original) }, 0);
        let fixture_mode =
            (original | ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT)
                & !ENABLE_VIRTUAL_TERMINAL_INPUT;
        // SAFETY: handle succeeded in GetConsoleMode and fixture_mode changes
        // only documented input-mode bits.
        assert_ne!(unsafe { SetConsoleMode(handle, fixture_mode) }, 0);

        let guard = enter_local_runtime_terminal_mode().unwrap().unwrap();
        let mut during = 0;
        // SAFETY: during is writable and the guard retains the live handle.
        assert_ne!(unsafe { GetConsoleMode(handle, &mut during) }, 0);
        assert_eq!(
            during & (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT),
            0
        );
        assert_ne!(during & ENABLE_VIRTUAL_TERMINAL_INPUT, 0);
        println!("NRM_CONPTY_MODE_READY");
        io::stdout().flush().unwrap();

        let mut input = [0_u8; 4];
        io::stdin().lock().read_exact(&mut input).unwrap();
        assert_eq!(&input, b"\x1b[A\x03");
        drop(guard);

        let mut restored = 0;
        // SAFETY: restored is writable and handle remains live.
        assert_ne!(unsafe { GetConsoleMode(handle, &mut restored) }, 0);
        assert_eq!(restored, fixture_mode);
        // SAFETY: handle remains live and original is the exact saved mode.
        assert_ne!(unsafe { SetConsoleMode(handle, original) }, 0);
        println!("NRM_CONPTY_MODE_OK");
        io::stdout().flush().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn local_runtime_console_mode_changes_and_restores_a_real_conpty() {
        let executable = std::env::current_exe().unwrap();
        let mut command = nrm_pty::PtyCommand::new(executable);
        command.args([
            "--ignored",
            "--exact",
            "runtime_proxy::tests::subprocess_checks_local_runtime_console_mode",
            "--nocapture",
            "--test-threads=1",
        ]);
        let mut process =
            nrm_pty::PtyProcess::spawn(&command, nrm_pty::PtySize::default()).unwrap();
        let mut input = process.take_input().unwrap();
        let mut output = process.take_output().unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !bytes
            .windows(b"NRM_CONPTY_MODE_READY".len())
            .any(|window| window == b"NRM_CONPTY_MODE_READY")
        {
            let read = output.read(&mut chunk).unwrap();
            assert_ne!(
                read,
                0,
                "ConPTY fixture exited before readiness: {}",
                String::from_utf8_lossy(&bytes)
            );
            bytes.extend_from_slice(&chunk[..read]);
        }
        input.write_all(b"\x1b[A\x03").unwrap();
        input.flush().unwrap();
        let reader = thread::spawn(move || {
            output.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let status = process.wait().unwrap();
        drop(input);
        let output = reader.join().unwrap();
        assert!(
            status.success(),
            "{status:?}: {}",
            String::from_utf8_lossy(&output)
        );
        assert!(
            output
                .windows(b"NRM_CONPTY_MODE_OK".len())
                .any(|window| window == b"NRM_CONPTY_MODE_OK"),
            "{}",
            String::from_utf8_lossy(&output)
        );
    }

    #[cfg(windows)]
    struct WindowsProtectedTestDirectory {
        path: PathBuf,
    }

    #[cfg(windows)]
    impl WindowsProtectedTestDirectory {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    #[cfg(windows)]
    impl Drop for WindowsProtectedTestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(windows)]
    fn test_directory() -> WindowsProtectedTestDirectory {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
        assert_eq!(drive.len(), 2, "SystemDrive must be a drive-letter path");
        assert!(
            drive.as_bytes()[0].is_ascii_alphabetic() && drive.as_bytes()[1] == b':',
            "SystemDrive must be a drive-letter path"
        );
        let drive_root = PathBuf::from(format!("{drive}\\"));
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for attempt in 0..128_u64 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = drive_root.join(format!(
                "nrm-runtime-security-test-{}-{timestamp}-{sequence}-{attempt}",
                std::process::id()
            ));
            match create_windows_private_directory(&path) {
                Ok(()) => return WindowsProtectedTestDirectory { path },
                Err(error)
                    if error.chain().any(|cause| {
                        cause
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
                    }) => {}
                Err(error) => panic!(
                    "failed to provision protected Windows test state root {}: {error:#}",
                    path.display()
                ),
            }
        }
        panic!("failed to allocate a unique protected Windows test state root");
    }

    fn ticket(root: &Path) -> RuntimeTicket {
        let transport = RemoteTransport::Local;
        RuntimeTicket {
            schema_version: TICKET_SCHEMA_VERSION,
            workspace_key: workspace_key(&transport, root),
            remote_root: root.to_string_lossy().into_owned(),
            ssh: None,
            agent: "nrm-agent".to_owned(),
            ssh_connect_timeout_seconds: 10,
            request_timeout_ms: 30_000,
            capability: RuntimeCapability::ProcessPtyV1,
            spec: RuntimeProcessSpec {
                argv: vec!["sh".to_owned()],
                cwd: RuntimeCwd::WorkspaceRoot,
                env: RuntimeEnvironment::default(),
                persistence: RuntimePersistence::Attached,
                terminal_size: Some(TerminalSize {
                    columns: 80,
                    rows: 24,
                    pixel_width: None,
                    pixel_height: None,
                }),
                timeout_ms: None,
                max_output_bytes: None,
            },
            remote_host: None,
        }
    }

    #[derive(Clone, Default)]
    struct CapturedRuntimeFrames(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedRuntimeFrames {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn running_pipe_writer(frames: CapturedRuntimeFrames) -> Arc<Mutex<RuntimeWriter>> {
        let mut capabilities = CapabilitySet::v1_agent();
        capabilities.runtime_process_v1 = true;
        let writer = Arc::new(Mutex::new(
            RuntimeWriter::new(
                RuntimeStateMachine::new(RuntimePeerRole::Client, capabilities),
                frames,
                Duration::from_secs(1),
            )
            .unwrap(),
        ));
        send_shared(
            &writer,
            &RuntimeMessage::ClientHello {
                package_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            },
        )
        .unwrap();
        observe_shared(
            &writer,
            &RuntimeMessage::ServerHello {
                package_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            },
        )
        .unwrap();
        send_shared(
            &writer,
            &RuntimeMessage::StartProcess {
                request_id: 1,
                spec: RuntimeProcessSpec {
                    argv: vec!["test-command".to_owned()],
                    cwd: RuntimeCwd::WorkspaceRoot,
                    env: RuntimeEnvironment::default(),
                    persistence: RuntimePersistence::Attached,
                    terminal_size: None,
                    timeout_ms: None,
                    max_output_bytes: Some(1024),
                },
            },
        )
        .unwrap();
        observe_shared(
            &writer,
            &RuntimeMessage::ProcessStarted {
                request_id: 1,
                process_id: 7,
                session: None,
                output_offset: 0,
            },
        )
        .unwrap();
        writer
    }

    fn captured_runtime_messages(frames: &CapturedRuntimeFrames) -> Vec<RuntimeMessage> {
        let bytes = frames.0.lock().unwrap().clone();
        let length = bytes.len() as u64;
        let mut cursor = io::Cursor::new(bytes);
        let mut messages = Vec::new();
        while cursor.position() < length {
            messages.push(read_runtime_frame(&mut cursor).unwrap());
        }
        messages
    }

    #[derive(Default)]
    struct BlockingOutputState {
        entered: bool,
        released: bool,
        flushes: usize,
    }

    #[derive(Clone, Default)]
    struct BlockingOutput(Arc<(Mutex<BlockingOutputState>, Condvar)>);

    impl BlockingOutput {
        fn wait_until_blocked(&self) {
            let (state, ready) = &*self.0;
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut state = state.lock().unwrap();
            while !state.entered {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "output worker did not enter write");
                let (next, timeout) = ready.wait_timeout(state, remaining).unwrap();
                state = next;
                assert!(!timeout.timed_out(), "output worker did not enter write");
            }
        }

        fn release(&self) {
            let (state, ready) = &*self.0;
            let mut state = state.lock().unwrap();
            state.released = true;
            ready.notify_all();
        }

        fn flushes(&self) -> usize {
            self.0 .0.lock().unwrap().flushes
        }
    }

    impl Write for BlockingOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let (state, ready) = &*self.0;
            let mut state = state.lock().unwrap();
            state.entered = true;
            ready.notify_all();
            while !state.released {
                state = ready.wait(state).unwrap();
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0 .0.lock().unwrap().flushes += 1;
            Ok(())
        }
    }

    type TaggedWrites = Arc<Mutex<Vec<(&'static str, Vec<u8>)>>>;

    struct TaggedOutput {
        tag: &'static str,
        writes: TaggedWrites,
    }

    impl Write for TaggedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes.lock().unwrap().push((self.tag, bytes.to_vec()));
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn windows_test_sid(value: &str) -> LocalWindowsSid {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

        let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = std::ptr::null_mut();
        // SAFETY: wide is NUL-terminated and sid is writable for the
        // LocalAlloc result owned by LocalWindowsSid.
        let converted = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) };
        assert_ne!(converted, 0);
        LocalWindowsSid(sid)
    }

    #[cfg(windows)]
    fn with_windows_test_allow_acl<T>(
        sid: windows_sys::Win32::Security::PSID,
        rights: u32,
        inheritance: u32,
        callback: impl FnOnce(*mut windows_sys::Win32::Security::ACL) -> T,
    ) -> T {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::Security::Authorization::{
            BuildTrusteeWithSidW, SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_IS_USER,
        };

        let mut entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: rights,
            grfAccessMode: SET_ACCESS,
            grfInheritance: inheritance,
            ..EXPLICIT_ACCESS_W::default()
        };
        // SAFETY: sid is a live valid SID retained through the ACL build.
        unsafe { BuildTrusteeWithSidW(&mut entry.Trustee, sid) };
        entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
        let mut acl = std::ptr::null_mut();
        // SAFETY: entry and its SID remain live and acl is writable.
        let status = unsafe { SetEntriesInAclW(1, &raw const entry, std::ptr::null(), &mut acl) };
        assert_eq!(status, ERROR_SUCCESS);
        assert!(!acl.is_null());
        let _acl = LocalWindowsAcl(acl);
        callback(acl)
    }

    #[cfg(windows)]
    fn apply_windows_test_directory_allow_acl(
        path: &Path,
        extra_sid: windows_sys::Win32::Security::PSID,
        extra_rights: u32,
    ) -> Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::Security::Authorization::{
            BuildTrusteeWithSidW, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, SET_ACCESS,
            SE_FILE_OBJECT, TRUSTEE_IS_USER,
        };
        use windows_sys::Win32::Security::{
            CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, NO_INHERITANCE, OBJECT_INHERIT_ACE,
            PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

        let file = open_windows_directory_without_following(path, true)?;
        with_windows_process_user_sid(|user| {
            let mut entries = [EXPLICIT_ACCESS_W::default(); 2];
            entries[0].grfAccessPermissions = FILE_ALL_ACCESS;
            entries[0].grfAccessMode = SET_ACCESS;
            entries[0].grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
            entries[1].grfAccessPermissions = extra_rights;
            entries[1].grfAccessMode = SET_ACCESS;
            entries[1].grfInheritance = NO_INHERITANCE;
            // SAFETY: both SIDs remain live through the ACL construction.
            unsafe {
                BuildTrusteeWithSidW(&mut entries[0].Trustee, user);
                BuildTrusteeWithSidW(&mut entries[1].Trustee, extra_sid);
            }
            entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
            entries[1].Trustee.TrusteeType = TRUSTEE_IS_USER;

            let mut acl = std::ptr::null_mut();
            // SAFETY: entries and their SID buffers remain live through this
            // call and acl points to writable result storage.
            let status = unsafe {
                SetEntriesInAclW(
                    u32::try_from(entries.len()).expect("two ACL entries fit in u32"),
                    entries.as_ptr(),
                    std::ptr::null_mut(),
                    &mut acl,
                )
            };
            if status != ERROR_SUCCESS {
                return Err(windows_status_error(status)).context("failed to build test DACL");
            }
            let _acl = LocalWindowsAcl(acl);
            // SAFETY: file was opened with WRITE_DAC and acl remains live for
            // the duration of SetSecurityInfo.
            let status = unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null_mut(),
                )
            };
            if status != ERROR_SUCCESS {
                return Err(windows_status_error(status)).context("failed to apply test DACL");
            }
            Ok(())
        })
    }

    #[test]
    fn workspace_trust_updates_are_serialized_and_digest_only() {
        let state = test_directory();
        let mut workers = Vec::new();
        for index in 1..=16_u64 {
            let state = state.path().to_path_buf();
            workers.push(thread::spawn(move || {
                let digest = format!("{index:064x}");
                set_workspace_trust(Some(state), &digest, true)
            }));
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }

        let directory = runtime_state_directory(Some(state.path()));
        let _guard = ensure_private_ticket_directory(&directory).unwrap();
        let _lock = acquire_private_runtime_lock(
            &directory,
            RUNTIME_TRUST_LOCK_FILE,
            "test workspace trust store",
        )
        .unwrap();
        let store = read_runtime_trust_store(&directory).unwrap();
        assert_eq!(store.schema_version, RUNTIME_TRUST_SCHEMA_VERSION);
        assert_eq!(store.trusted.len(), 16);
        assert!(store.trusted.keys().all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }));
        drop(_lock);

        let removed = format!("{:064x}", 7);
        set_workspace_trust(Some(state.path().to_path_buf()), &removed, false).unwrap();
        let _lock = acquire_private_runtime_lock(
            &directory,
            RUNTIME_TRUST_LOCK_FILE,
            "test workspace trust store",
        )
        .unwrap();
        assert!(!read_runtime_trust_store(&directory)
            .unwrap()
            .trusted
            .contains_key(&removed));
    }

    #[test]
    fn workspace_trust_store_rejects_malformed_or_nonprivate_state() {
        for invalid in [
            String::new(),
            "A".to_owned(),
            "a".repeat(63),
            "g".repeat(64),
        ] {
            assert!(validate_trust_digest(&invalid).is_err());
        }

        let state = test_directory();
        let directory = runtime_state_directory(Some(state.path()));
        let _guard = ensure_private_ticket_directory(&directory).unwrap();
        let path = directory.join(RUNTIME_TRUST_STORE_FILE);
        let mut file = create_private_ticket_file(&path).unwrap();
        file.write_all(br#"{"schema_version":1,"trusted":{},"extra":true}"#)
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(read_runtime_trust_store(&directory).is_err());

        fs::remove_file(&path).unwrap();
        let mut file = create_private_ticket_file(&path).unwrap();
        file.write_all(br#"{"schema_version":1,"schema_version":1,"trusted":{}}"#)
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(read_runtime_trust_store(&directory).is_err());

        #[cfg(unix)]
        {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(prepare_runtime_state(Some(state.path().to_path_buf())).is_err());
        }
    }

    #[test]
    fn workspace_trust_prepare_removes_strict_private_crash_temps_only() {
        let state = test_directory();
        let directory = runtime_state_directory(Some(state.path()));
        let first = directory.join(format!(
            ".trust-pending-{}.tmp",
            "1".repeat(RUNTIME_CONTROL_NONCE_BYTES * 2)
        ));
        let second = directory.join(format!(
            ".trust-pending-{}.tmp",
            "2".repeat(RUNTIME_CONTROL_NONCE_BYTES * 2)
        ));
        let unrelated = directory.join(".trust-pending-not-a-nonce.tmp");
        {
            let _guard = ensure_private_ticket_directory(&directory).unwrap();
            let _lock = acquire_private_runtime_lock(
                &directory,
                RUNTIME_TRUST_LOCK_FILE,
                "test workspace trust store",
            )
            .unwrap();
            for path in [&first, &second, &unrelated] {
                let mut file = create_private_ticket_file(path).unwrap();
                file.write_all(b"crash residue").unwrap();
            }
        }

        prepare_runtime_state(Some(state.path().to_path_buf())).unwrap();
        assert!(!first.exists());
        assert!(!second.exists());
        assert!(unrelated.exists(), "an unrelated state file was deleted");
    }

    #[cfg(unix)]
    #[test]
    fn workspace_trust_cleanup_never_follows_or_deletes_a_pending_symlink() {
        use std::os::unix::fs::symlink;

        let state = test_directory();
        let outside = test_directory();
        let target = outside.path().join("must-survive");
        fs::write(&target, b"outside").unwrap();
        let directory = runtime_state_directory(Some(state.path()));
        let _guard = ensure_private_ticket_directory(&directory).unwrap();
        let _lock = acquire_private_runtime_lock(
            &directory,
            RUNTIME_TRUST_LOCK_FILE,
            "test workspace trust store",
        )
        .unwrap();
        let pending = directory.join(format!(
            ".trust-pending-{}.tmp",
            "3".repeat(RUNTIME_CONTROL_NONCE_BYTES * 2)
        ));
        symlink(&target, &pending).unwrap();

        assert!(cleanup_orphan_trust_pending_files(&directory).is_err());
        assert!(pending.symlink_metadata().is_ok());
        assert_eq!(fs::read(&target).unwrap(), b"outside");
    }

    #[test]
    fn private_ticket_is_single_use() {
        let state = test_directory();
        let root = test_directory();
        let expected = ticket(root.path());
        let id = create_ticket(Some(state.path()), &expected).unwrap();
        let path = ticket_path(Some(state.path()), &id).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let actual = consume_ticket(Some(state.path()), &id).unwrap();
        assert_eq!(actual, expected);
        assert!(!path.exists());
        assert!(consume_ticket(Some(state.path()), &id).is_err());
    }

    #[test]
    fn runtime_record_capacity_bounds_entries_and_total_bytes() {
        let at_entry_limit = RuntimeStateUsage {
            entries: MAX_RUNTIME_RECORD_ENTRIES,
            bytes: 0,
        };
        let error = ensure_runtime_state_capacity(
            "test records",
            at_entry_limit,
            1,
            MAX_RUNTIME_RECORD_ENTRIES,
            MAX_RUNTIME_RECORD_TOTAL_BYTES,
        )
        .unwrap_err();
        assert!(error.to_string().contains("entry limit"));

        let at_byte_limit = RuntimeStateUsage {
            entries: 0,
            bytes: MAX_RUNTIME_RECORD_TOTAL_BYTES,
        };
        let error = ensure_runtime_state_capacity(
            "test records",
            at_byte_limit,
            1,
            MAX_RUNTIME_RECORD_ENTRIES,
            MAX_RUNTIME_RECORD_TOTAL_BYTES,
        )
        .unwrap_err();
        assert!(error.to_string().contains("byte limit"));

        ensure_runtime_state_capacity(
            "test records",
            RuntimeStateUsage {
                entries: MAX_RUNTIME_RECORD_ENTRIES - 1,
                bytes: MAX_RUNTIME_RECORD_TOTAL_BYTES - 1,
            },
            1,
            MAX_RUNTIME_RECORD_ENTRIES,
            MAX_RUNTIME_RECORD_TOTAL_BYTES,
        )
        .unwrap();
    }

    #[test]
    fn bounded_record_cleanup_makes_progress_across_overflow_batches() {
        let state = test_directory();
        let directory = ticket_directory(Some(state.path()));
        let _guard = ensure_private_ticket_directory(&directory).unwrap();
        let _lock = acquire_runtime_record_lock(&directory).unwrap();
        let excluded = format!("{:064x}", 17);
        for index in 0..18_u64 {
            let id = format!("{index:064x}");
            let path = directory.join(format!("{id}.json"));
            let mut file = create_private_ticket_file(&path).unwrap();
            file.write_all(b"stale").unwrap();
        }

        let mut overflow_batches = 0;
        let usage = loop {
            match cleanup_orphan_runtime_records_with_policy(
                &directory,
                Some(&excluded),
                Duration::ZERO,
                4,
            ) {
                Ok(usage) => break usage,
                Err(error) if error.to_string().contains("batch limit") => {
                    overflow_batches += 1;
                    assert!(overflow_batches < 18, "cleanup made no bounded progress");
                }
                Err(error) => panic!("unexpected cleanup failure: {error:#}"),
            }
        };

        assert!(overflow_batches > 0);
        assert_eq!(usage.entries, 1);
        assert_eq!(usage.bytes, 5);
        assert!(directory.join(format!("{excluded}.json")).exists());
    }

    #[test]
    fn concurrent_ticket_publishers_are_serialized_and_leave_bounded_state() {
        let state = test_directory();
        let root = test_directory();
        let expected = ticket(root.path());
        let mut workers = Vec::new();
        for _ in 0..12 {
            let state = state.path().to_path_buf();
            let expected = expected.clone();
            workers.push(thread::spawn(move || {
                create_ticket(Some(&state), &expected)
            }));
        }
        let mut ids = Vec::new();
        for worker in workers {
            ids.push(worker.join().unwrap().unwrap());
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 12);

        let directory = ticket_directory(Some(state.path()));
        let _guard = ensure_private_ticket_directory(&directory).unwrap();
        let _lock = acquire_runtime_record_lock(&directory).unwrap();
        let usage = runtime_record_usage(&directory).unwrap();
        assert_eq!(usage.entries, 12);
        assert!(usage.bytes <= MAX_RUNTIME_RECORD_TOTAL_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn record_cleanup_never_follows_or_deletes_a_record_symlink() {
        use std::os::unix::fs::symlink;

        let state = test_directory();
        let outside = test_directory();
        let target = outside.path().join("must-survive");
        fs::write(&target, b"outside").unwrap();
        let directory = result_directory(Some(state.path()));
        let _guard = ensure_private_ticket_directory(&directory).unwrap();
        let _lock = acquire_runtime_record_lock(&directory).unwrap();
        let record = directory.join(format!("{}.json", "4".repeat(TICKET_ID_HEX_LEN)));
        symlink(&target, &record).unwrap();

        assert!(cleanup_orphan_runtime_records_with_policy(
            &directory,
            None,
            Duration::ZERO,
            MAX_RUNTIME_RECORD_SCAN_ENTRIES,
        )
        .is_err());
        assert!(record.symlink_metadata().is_ok());
        assert_eq!(fs::read(&target).unwrap(), b"outside");
    }

    #[test]
    fn stored_ticket_lifetime_is_short_bounded_and_explicitly_expires() {
        let root = test_directory();
        let expected = ticket(root.path());
        let ticket_id = "ab".repeat(TICKET_ID_BYTES);
        let ttl_ms = TICKET_TTL.as_millis() as u64;
        let mut stored = StoredRuntimeTicket {
            schema_version: TICKET_SCHEMA_VERSION,
            ticket_id: ticket_id.clone(),
            issued_at_unix_ms: 10_000,
            expires_at_unix_ms: 10_000 + ttl_ms,
            ticket: expected.clone(),
        };

        validate_stored_ticket_at(
            &stored,
            &ticket_id,
            &expected.workspace_key,
            10_000 + ttl_ms,
        )
        .unwrap();
        let expired = validate_stored_ticket_at(
            &stored,
            &ticket_id,
            &expected.workspace_key,
            10_000 + ttl_ms + 1,
        )
        .unwrap_err();
        assert!(expired.to_string().contains("ticket_expired"));

        stored.expires_at_unix_ms += 1;
        assert!(
            validate_stored_ticket_at(&stored, &ticket_id, &expected.workspace_key, 10_000)
                .is_err()
        );
        stored.expires_at_unix_ms -= 1;
        assert!(validate_stored_ticket_at(&stored, &ticket_id, &"0".repeat(24), 10_000).is_err());
        assert!(validate_stored_ticket_at(
            &stored,
            &"cd".repeat(TICKET_ID_BYTES),
            &expected.workspace_key,
            10_000,
        )
        .is_err());

        stored.issued_at_unix_ms = 10_000 + TICKET_CLOCK_SKEW.as_millis() as u64 + 1;
        stored.expires_at_unix_ms = stored.issued_at_unix_ms + ttl_ms;
        assert!(
            validate_stored_ticket_at(&stored, &ticket_id, &expected.workspace_key, 10_000)
                .is_err()
        );
    }

    #[test]
    fn private_runtime_result_round_trips_once() {
        let state = test_directory();
        let id = "ab".repeat(TICKET_ID_BYTES);
        let expected = process_result(RuntimeExitStatus::Code(23), false);
        write_runtime_result(Some(state.path()), &id, &expected).unwrap();
        let path = result_path(Some(state.path()), &id).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let actual = consume_runtime_result(Some(state.path()), &id).unwrap();
        assert_eq!(actual, expected);
        assert!(!path.exists());
        assert!(consume_runtime_result(Some(state.path()), &id).is_err());
    }

    #[test]
    fn result_publication_failure_cannot_report_child_success() {
        let state = test_directory();
        fs::write(state.path().join("runtime"), b"not a directory").unwrap();
        let id = "ef".repeat(TICKET_ID_BYTES);
        let result = process_result(RuntimeExitStatus::Code(0), false);

        assert_eq!(
            publish_runtime_result(Some(state.path()), &id, &result),
            RUNTIME_TRANSPORT_EXIT_CODE
        );
    }

    #[test]
    fn private_signal_mailbox_is_bounded_single_use_and_strict() {
        let state = test_directory();
        let id = "cd".repeat(TICKET_ID_BYTES);
        enqueue_signal(Some(state.path().to_path_buf()), &id, "interrupt").unwrap();
        enqueue_signal(Some(state.path().to_path_buf()), &id, "kill").unwrap();
        assert!(enqueue_signal(Some(state.path().to_path_buf()), &id, "unknown").is_err());

        let mailbox = RuntimeControlMailbox::open(Some(state.path()), &id).unwrap();
        let signals = mailbox.drain().unwrap();
        assert_eq!(signals.len(), 2);
        assert!(signals.contains(&RuntimeSignal::Interrupt));
        assert!(signals.contains(&RuntimeSignal::Kill));
        assert!(mailbox.drain().unwrap().is_empty());

        let bad_path = control_directory(Some(state.path())).join(format!(
            "{}-{}.json",
            id,
            "0".repeat(RUNTIME_CONTROL_NONCE_BYTES * 2)
        ));
        let mut bad = create_private_ticket_file(&bad_path).unwrap();
        bad.write_all(br#"{"schema_version":1,"ticket_id":"wrong"}"#)
            .unwrap();
        drop(bad);
        assert!(mailbox.drain().is_err());
        assert!(!bad_path.exists());
    }

    #[test]
    fn control_publication_is_atomic_noreplace() {
        let directory = test_directory();
        let source = directory.path().join(".pending-source.tmp");
        let destination = directory.path().join("published.json");
        fs::write(&source, b"new").unwrap();
        fs::write(&destination, b"existing").unwrap();

        let error = publish_private_record_noreplace(&source, &destination).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"existing");
        assert_eq!(fs::read(&source).unwrap(), b"new");
    }

    #[test]
    fn signal_publication_and_drain_can_run_concurrently() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let state = test_directory();
        let state_path = state.path().to_path_buf();
        let id = "12".repeat(TICKET_ID_BYTES);
        let producer_id = id.clone();
        let producer_done = Arc::new(AtomicBool::new(false));
        let producer_flag = Arc::clone(&producer_done);
        let producer = thread::spawn(move || {
            for index in 0..64 {
                let signal = if index % 2 == 0 { "interrupt" } else { "kill" };
                enqueue_signal(Some(state_path.clone()), &producer_id, signal).unwrap();
            }
            producer_flag.store(true, Ordering::Release);
        });

        let mailbox = RuntimeControlMailbox::open(Some(state.path()), &id).unwrap();
        let mut signals = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while signals.len() < 64 {
            signals.extend(mailbox.drain().unwrap());
            assert!(
                !producer_done.load(Ordering::Acquire) || signals.len() <= 64,
                "signal mailbox returned duplicate records"
            );
            assert!(Instant::now() < deadline, "timed out draining signals");
            thread::sleep(Duration::from_millis(1));
        }
        producer.join().unwrap();
        assert_eq!(signals.len(), 64);
        assert!(mailbox.drain().unwrap().is_empty());
    }

    #[test]
    fn bounded_control_scan_fails_instead_of_starving_later_entries() {
        let directory = test_directory();
        fs::write(directory.path().join(RUNTIME_CONTROL_LOCK_FILE), b"").unwrap();
        for index in 0..3 {
            fs::write(directory.path().join(format!("unknown-{index}")), b"x").unwrap();
        }
        let error = bounded_control_paths_at_limit(directory.path(), 2).unwrap_err();
        assert!(error.to_string().contains("2-entry limit"));
        assert_eq!(
            bounded_control_paths_at_limit(directory.path(), 3)
                .unwrap()
                .len(),
            3,
            "the persistent lock file must not consume mailbox capacity"
        );
    }

    #[test]
    fn runtime_control_lock_serializes_mailbox_mutation() {
        let state = test_directory();
        let directory = control_directory(Some(state.path()));
        let _directory_guard = ensure_private_ticket_directory(&directory).unwrap();
        let first = acquire_runtime_control_lock(&directory).unwrap();
        let contender_directory = directory.clone();
        let contender = thread::spawn(move || acquire_runtime_control_lock(&contender_directory));
        thread::sleep(Duration::from_millis(25));
        assert!(
            !contender.is_finished(),
            "a second publisher entered the mailbox critical section"
        );
        drop(first);
        drop(contender.join().unwrap().unwrap());
    }

    #[test]
    fn bridge_diagnostics_are_bounded_sanitized_and_tail_preserving() {
        let diagnostics = BridgeDiagnostics::default();
        diagnostics.append(b"discarded-prefix\n");
        diagnostics.append(&vec![b'x'; MAX_RUNTIME_DIAGNOSTIC_BYTES]);
        diagnostics.append(b"tail\0message");
        let text = diagnostics.text().unwrap();
        assert!(text.len() <= MAX_RUNTIME_DIAGNOSTIC_BYTES);
        assert!(text.starts_with("[truncated] "));
        assert!(text.ends_with("tail message"));
        assert!(!text.contains("discarded-prefix"));

        let bounded = bounded_diagnostic(&"é".repeat(MAX_RUNTIME_DIAGNOSTIC_BYTES));
        assert!(bounded.len() <= MAX_RUNTIME_DIAGNOSTIC_BYTES);
        assert!(bounded.ends_with(" [truncated]"));
    }

    #[test]
    fn bridge_diagnostic_reader_joins_before_returning_final_bytes() {
        let reader = spawn_bridge_diagnostic_reader(std::io::Cursor::new(
            b"last bridge diagnostic".to_vec(),
        ))
        .unwrap();
        assert_eq!(reader.finish().as_deref(), Some("last bridge diagnostic"));
    }

    #[test]
    fn outbound_runtime_write_timeout_is_bounded_and_authoritative() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SlowFirstWrite(Arc<AtomicBool>);

        impl Write for SlowFirstWrite {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if !self.0.swap(true, Ordering::AcqRel) {
                    thread::sleep(Duration::from_millis(200));
                }
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut capabilities = CapabilitySet::v1_agent();
        capabilities.runtime_process_v1 = true;
        let mut prefix_writer = RuntimeWriter::new(
            RuntimeStateMachine::new(RuntimePeerRole::Client, capabilities.clone()),
            SlowFirstWrite(Arc::new(AtomicBool::new(false))),
            Duration::from_millis(50),
        )
        .unwrap();
        let started = Instant::now();
        let prefix_error = prefix_writer
            .send_prefix(b"larger-than-a-stalled-pipe", Duration::from_millis(50))
            .unwrap_err();
        assert!(prefix_error.to_string().contains("prefix write timed out"));
        assert!(started.elapsed() < Duration::from_millis(150));
        thread::sleep(Duration::from_millis(200));
        assert!(prefix_writer.close().is_err());

        let machine = RuntimeStateMachine::new(RuntimePeerRole::Client, capabilities);
        let mut writer = RuntimeWriter::new(
            machine,
            SlowFirstWrite(Arc::new(AtomicBool::new(false))),
            Duration::from_secs(1),
        )
        .unwrap();
        let hello = RuntimeMessage::ClientHello {
            package_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: PROTOCOL_VERSION,
            capability: RuntimeCapability::ProcessPipeV1,
        };

        let started = Instant::now();
        let error = writer
            .send_with_timeout(&hello, Duration::from_millis(50))
            .unwrap_err();
        assert!(error.to_string().contains("write timed out"));
        assert!(started.elapsed() < Duration::from_millis(150));
        assert!(
            writer
                .observe_inbound(&RuntimeMessage::ServerHello {
                    package_version: env!("CARGO_PKG_VERSION").to_owned(),
                    protocol_version: PROTOCOL_VERSION,
                    capability: RuntimeCapability::ProcessPipeV1,
                })
                .is_err(),
            "a timed-out write did not poison the transport"
        );

        thread::sleep(Duration::from_millis(200));
        assert!(writer.close().is_err());
    }

    #[test]
    fn blocked_local_output_does_not_starve_control_and_ack_waits_for_flush() {
        let frames = CapturedRuntimeFrames::default();
        let writer = running_pipe_writer(frames.clone());
        let blocking = BlockingOutput::default();
        let mut pump = RuntimeOutputPump::new(blocking.clone(), io::sink()).unwrap();
        let output = RuntimeMessage::Output {
            process_id: 7,
            stream: RuntimeOutputStream::Stdout,
            offset: 0,
            data: b"blocked output".to_vec(),
        };
        observe_shared(&writer, &output).unwrap();
        assert!(pump
            .try_write(RuntimeOutputChunk {
                process_id: 7,
                stream: RuntimeOutputStream::Stdout,
                offset: 0,
                data: b"blocked output".to_vec(),
            })
            .unwrap()
            .is_none());
        blocking.wait_until_blocked();
        assert!(pump.try_event().unwrap().is_none());

        let state = test_directory();
        let ticket_id = "a".repeat(TICKET_ID_HEX_LEN);
        let mailbox = RuntimeControlMailbox::open(Some(state.path()), &ticket_id).unwrap();
        enqueue_signal(Some(state.path().to_path_buf()), &ticket_id, "kill").unwrap();
        let started = Instant::now();
        forward_runtime_controls(&mailbox, &writer, 7).unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a blocked local output sink delayed mailbox control"
        );
        assert_eq!(blocking.flushes(), 0);
        assert!(pump.try_event().unwrap().is_none());

        blocking.release();
        let event = pump
            .wait_event(Duration::from_secs(1))
            .unwrap()
            .expect("output completion event");
        assert_eq!(blocking.flushes(), 1);
        assert!(!forward_runtime_output_event(&writer, event).unwrap());
        assert!(pump.try_finish().unwrap());
        assert_eq!(
            pump.wait_event(Duration::from_secs(1)).unwrap(),
            Some(RuntimeOutputEvent::Finished)
        );
        pump.join_finished().unwrap();
        close_shared(&writer).unwrap();

        let messages = captured_runtime_messages(&frames);
        let signal = messages
            .iter()
            .position(|message| {
                matches!(
                    message,
                    RuntimeMessage::Signal {
                        process_id: 7,
                        signal: RuntimeSignal::Kill,
                    }
                )
            })
            .unwrap();
        let acknowledgement = messages
            .iter()
            .position(|message| matches!(message, RuntimeMessage::OutputAck { .. }))
            .unwrap();
        assert!(signal < acknowledgement);
        assert!(matches!(
            &messages[acknowledgement],
            RuntimeMessage::OutputAck {
                process_id: 7,
                stream: RuntimeOutputStream::Stdout,
                next_offset: 14,
            }
        ));
    }

    #[test]
    fn local_output_pump_preserves_protocol_and_ack_order_across_streams() {
        let frames = CapturedRuntimeFrames::default();
        let writer = running_pipe_writer(frames.clone());
        let writes = Arc::new(Mutex::new(Vec::new()));
        let stdout = TaggedOutput {
            tag: "stdout",
            writes: Arc::clone(&writes),
        };
        let stderr = TaggedOutput {
            tag: "stderr",
            writes: Arc::clone(&writes),
        };
        let mut pump = RuntimeOutputPump::new(stdout, stderr).unwrap();
        let chunks = [
            (RuntimeOutputStream::Stdout, 0, b"a".as_slice()),
            (RuntimeOutputStream::Stderr, 0, b"b".as_slice()),
            (RuntimeOutputStream::Stdout, 1, b"cd".as_slice()),
        ];
        for (stream, offset, data) in chunks {
            observe_shared(
                &writer,
                &RuntimeMessage::Output {
                    process_id: 7,
                    stream,
                    offset,
                    data: data.to_vec(),
                },
            )
            .unwrap();
            assert!(pump
                .try_write(RuntimeOutputChunk {
                    process_id: 7,
                    stream,
                    offset,
                    data: data.to_vec(),
                })
                .unwrap()
                .is_none());
        }
        assert!(pump.try_finish().unwrap());
        loop {
            let event = pump
                .wait_event(Duration::from_secs(1))
                .unwrap()
                .expect("output pump event");
            if forward_runtime_output_event(&writer, event).unwrap() {
                break;
            }
        }
        pump.join_finished().unwrap();
        close_shared(&writer).unwrap();

        assert_eq!(
            *writes.lock().unwrap(),
            vec![
                ("stdout", b"a".to_vec()),
                ("stderr", b"b".to_vec()),
                ("stdout", b"cd".to_vec()),
            ]
        );
        let acknowledgements: Vec<_> = captured_runtime_messages(&frames)
            .into_iter()
            .filter_map(|message| match message {
                RuntimeMessage::OutputAck {
                    stream,
                    next_offset,
                    ..
                } => Some((stream, next_offset)),
                _ => None,
            })
            .collect();
        assert_eq!(
            acknowledgements,
            vec![
                (RuntimeOutputStream::Stdout, 1),
                (RuntimeOutputStream::Stderr, 1),
                (RuntimeOutputStream::Stdout, 3),
            ]
        );
    }

    #[test]
    fn blocked_local_output_pump_shutdown_is_bounded() {
        let blocking = BlockingOutput::default();
        let pump = RuntimeOutputPump::new(blocking.clone(), io::sink()).unwrap();
        assert!(pump
            .try_write(RuntimeOutputChunk {
                process_id: 7,
                stream: RuntimeOutputStream::Stdout,
                offset: 0,
                data: b"blocked".to_vec(),
            })
            .unwrap()
            .is_none());
        blocking.wait_until_blocked();

        let started = Instant::now();
        drop(pump);
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "output pump teardown waited for a blocked operating-system write"
        );
        blocking.release();
    }

    #[test]
    fn rejects_ticket_traversal_wrong_workspace_and_unknown_fields() {
        let state = test_directory();
        assert!(ticket_path(Some(state.path()), "../ticket").is_err());
        assert!(ticket_path(Some(state.path()), &"A".repeat(TICKET_ID_HEX_LEN)).is_err());

        let root = test_directory();
        let mut wrong = ticket(root.path());
        wrong.workspace_key = "0".repeat(24);
        assert!(validate_ticket(&wrong).is_err());

        let mut value = serde_json::to_value(ticket(root.path())).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<RuntimeTicket>(value).is_err());
    }

    #[test]
    fn input_flow_waits_for_ack_and_rejects_invalid_offsets() {
        let flow = RuntimeInputFlow::default();
        assert_eq!(flow.reserve_chunk(7).unwrap(), Some((0, 7)));
        assert!(flow.acknowledge(8).is_err());

        let waiting = flow.clone();
        let worker = thread::spawn(move || waiting.reserve_chunk(5).unwrap());
        thread::sleep(Duration::from_millis(20));
        assert!(!worker.is_finished());
        flow.acknowledge(7).unwrap();
        assert_eq!(worker.join().unwrap(), Some((7, 12)));
        flow.acknowledge(12).unwrap();
        assert_eq!(flow.drained_offset().unwrap(), Some(12));
    }

    #[test]
    fn process_exit_codes_never_turn_failures_into_success() {
        assert_eq!(runtime_exit_code(RuntimeExitStatus::Code(0)), 0);
        assert_eq!(runtime_exit_code(RuntimeExitStatus::Code(23)), 23);
        assert_eq!(runtime_exit_code(RuntimeExitStatus::Code(-1)), 1);
        assert_eq!(runtime_exit_code(RuntimeExitStatus::Code(300)), 1);
        assert_eq!(runtime_exit_code(RuntimeExitStatus::TimedOut), 124);
    }

    #[test]
    fn local_eof_closes_pipes_hangs_up_ptys_and_detaches_persistent_sessions() {
        assert!(matches!(
            runtime_eof_message(7, false, RuntimePersistence::Attached, 11),
            RuntimeMessage::CloseInput {
                process_id: 7,
                next_offset: 11
            }
        ));
        assert!(matches!(
            runtime_eof_message(7, true, RuntimePersistence::Attached, 11),
            RuntimeMessage::Signal {
                process_id: 7,
                signal: nrm_protocol::RuntimeSignal::Hangup
            }
        ));
        assert!(matches!(
            runtime_eof_message(7, true, RuntimePersistence::Detachable { ttl_ms: 1 }, 11),
            RuntimeMessage::Detach { process_id: 7 }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_protected_state_root_supports_sequential_private_creation() {
        let state = test_directory();
        let runtime = state.path().join("nested").join("runtime");
        let guard = ensure_private_ticket_directory(&runtime).unwrap();
        drop(guard);
        assert!(runtime.is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn windows_ancestor_acl_rejects_named_takeover_and_unsafe_owner() {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::GENERIC_ALL;
        use windows_sys::Win32::Security::{GetAce, INHERITED_ACE, INHERIT_ONLY_ACE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_GENERIC_READ, FILE_WRITE_ATTRIBUTES,
            FILE_WRITE_DATA,
        };

        let arbitrary_user = windows_test_sid("S-1-5-21-111111111-222222222-333333333-1001");
        with_windows_process_user_sid(|owner| {
            // Read/traverse and creating a missing subdirectory do not permit
            // mutation of a pinned existing component.
            with_windows_test_allow_acl(arbitrary_user.0, FILE_GENERIC_READ, 0, |acl| {
                validate_windows_ancestor_security(owner, acl)
            })?;
            with_windows_test_allow_acl(arbitrary_user.0, FILE_ADD_SUBDIRECTORY, 0, |acl| {
                validate_windows_ancestor_security(owner, acl)
            })?;

            // For a directory, FILE_WRITE_DATA is FILE_ADD_FILE. Either it or
            // FILE_WRITE_ATTRIBUTES can authorize FSCTL_SET_REPARSE_POINT on
            // an empty directory and must therefore fail closed.
            for rights in [FILE_WRITE_DATA, FILE_WRITE_ATTRIBUTES] {
                let reparse_takeover =
                    with_windows_test_allow_acl(arbitrary_user.0, rights, 0, |acl| {
                        validate_windows_ancestor_security(owner, acl)
                    })
                    .unwrap_err();
                assert!(reparse_takeover.to_string().contains("untrusted trustee"));
            }

            let named_takeover =
                with_windows_test_allow_acl(arbitrary_user.0, GENERIC_ALL, 0, |acl| {
                    validate_windows_ancestor_security(owner, acl)
                })
                .unwrap_err();
            assert!(named_takeover.to_string().contains("untrusted trustee"));

            let inherited_takeover =
                with_windows_test_allow_acl(arbitrary_user.0, GENERIC_ALL, 0, |acl| {
                    let mut raw_ace = std::ptr::null_mut();
                    // SAFETY: the test ACL has exactly one live writable ACE.
                    assert_ne!(unsafe { GetAce(acl, 0, &mut raw_ace) }, 0);
                    // SAFETY: GetAce returned the sole live writable ACE and
                    // its header is common to every ACE representation.
                    unsafe {
                        (*raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>()).AceFlags =
                            INHERITED_ACE as u8;
                    }
                    validate_windows_ancestor_security(owner, acl)
                })
                .unwrap_err();
            assert!(inherited_takeover.to_string().contains("untrusted trustee"));

            // Inherit-only entries do not apply to the ancestor object itself.
            with_windows_test_allow_acl(arbitrary_user.0, GENERIC_ALL, INHERIT_ONLY_ACE, |acl| {
                validate_windows_ancestor_security(owner, acl)
            })?;

            let unsafe_owner = with_windows_test_allow_acl(owner, FILE_ALL_ACCESS, 0, |acl| {
                validate_windows_ancestor_security(arbitrary_user.0, acl)
            })
            .unwrap_err();
            assert!(unsafe_owner.to_string().contains("unsafe owner"));

            let unsupported_allow = with_windows_test_allow_acl(owner, FILE_ALL_ACCESS, 0, |acl| {
                let mut raw_ace = std::ptr::null_mut();
                // SAFETY: the test ACL has exactly one live writable ACE.
                assert_ne!(unsafe { GetAce(acl, 0, &mut raw_ace) }, 0);
                assert!(!raw_ace.is_null());
                // ACCESS_ALLOWED_CALLBACK_ACE_TYPE is a granting form the
                // ancestor validator intentionally refuses to parse.
                // SAFETY: GetAce returned the sole live writable ACE and its
                // header is common to every ACE representation.
                unsafe {
                    (*raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>()).AceType = 9;
                }
                validate_windows_ancestor_security(owner, acl)
            })
            .unwrap_err();
            assert!(unsupported_allow
                .to_string()
                .contains("unsupported applicable access-allowed"));

            // Exercise the same handle form used by production to ensure the
            // test does not accidentally rely on a path-only security query.
            let state = test_directory();
            let handle = open_windows_directory_without_following(state.path(), false)?;
            assert!(!handle.as_raw_handle().is_null());
            Ok(())
        })
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_unsafe_ancestor_before_creating_a_child() {
        use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES;

        let state = test_directory();
        let unsafe_ancestor = state.path().join("unsafe-ancestor");
        create_windows_private_directory(&unsafe_ancestor).unwrap();
        let arbitrary_user = windows_test_sid("S-1-5-21-111111111-222222222-333333333-1001");
        apply_windows_test_directory_allow_acl(
            &unsafe_ancestor,
            arbitrary_user.0,
            FILE_WRITE_ATTRIBUTES,
        )
        .unwrap();

        let missing_child = unsafe_ancestor.join("must-not-be-created");
        let error = ensure_private_ticket_directory(&missing_child.join("runtime"))
            .err()
            .expect("unsafe ancestor must be rejected");
        assert!(error.to_string().contains("untrusted trustee"));
        assert!(
            !missing_child.exists(),
            "validation must finish before path creation begins"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_runtime_state_and_records_use_protected_allowlist_dacls() {
        use windows_sys::Win32::Security::INHERITED_ACE;

        let state = test_directory();
        let runtime_directory = state.path().join("runtime");
        fs::create_dir(&runtime_directory).unwrap();
        prepare_runtime_state(Some(state.path().to_path_buf())).unwrap();
        let runtime_handle =
            open_windows_directory_without_following(&runtime_directory, false).unwrap();
        validate_windows_private_object_security(&runtime_handle, "test runtime directory", true)
            .unwrap();
        drop(runtime_handle);

        let inherited_path = runtime_directory.join("trusted-workspaces-v1.json");
        fs::write(&inherited_path, b"{}").unwrap();
        let inherited_file = File::open(&inherited_path).unwrap();
        validate_windows_allowlist_security(
            &inherited_file,
            "inherited test trust file",
            INHERITED_ACE as u8,
            false,
        )
        .unwrap();
        drop(inherited_file);

        let root = test_directory();
        let expected = ticket(root.path());
        let id = create_ticket(Some(state.path()), &expected).unwrap();
        let path = ticket_path(Some(state.path()), &id).unwrap();
        let file = open_private_ticket_file(&path).unwrap();
        validate_private_ticket_file(&path, &file).unwrap();
        drop(file);
        assert_eq!(consume_ticket(Some(state.path()), &id).unwrap(), expected);
    }

    #[cfg(windows)]
    #[test]
    fn windows_runtime_record_rejects_an_arbitrary_extra_trustee() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::Security::Authorization::{
            BuildTrusteeWithSidW, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, SET_ACCESS,
            SE_FILE_OBJECT, TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP,
        };
        use windows_sys::Win32::Security::{
            WinWorldSid, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
            PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ALL_ACCESS, FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_DAC,
        };

        let state = test_directory();
        let root = test_directory();
        let id = create_ticket(Some(state.path()), &ticket(root.path())).unwrap();
        let path = ticket_path(Some(state.path()), &id).unwrap();
        let file = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .unwrap();

        with_windows_process_user_sid(|user| {
            let mut everyone = windows_broad_sid(WinWorldSid)?;
            let mut entries = [EXPLICIT_ACCESS_W::default(); 2];
            for entry in &mut entries {
                entry.grfAccessPermissions = FILE_ALL_ACCESS;
                entry.grfAccessMode = SET_ACCESS;
                entry.grfInheritance = NO_INHERITANCE;
            }
            // SAFETY: both live buffers contain valid SIDs for the ACL build.
            unsafe {
                BuildTrusteeWithSidW(&mut entries[0].Trustee, user);
                BuildTrusteeWithSidW(&mut entries[1].Trustee, everyone.as_mut_ptr().cast());
            }
            entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
            entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            let mut acl = std::ptr::null_mut();
            // SAFETY: entries and its SID buffers remain live through the call.
            let status =
                unsafe { SetEntriesInAclW(2, entries.as_ptr(), std::ptr::null(), &mut acl) };
            if status != ERROR_SUCCESS {
                return Err(windows_status_error(status)).context("build test ACL");
            }
            let _acl = LocalWindowsAcl(acl);
            // SAFETY: file was opened with WRITE_DAC and acl remains live.
            let status = unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null(),
                )
            };
            if status != ERROR_SUCCESS {
                return Err(windows_status_error(status)).context("apply test ACL");
            }
            Ok(())
        })
        .unwrap();

        let error = validate_private_ticket_file(&path, &file).unwrap_err();
        assert!(error.to_string().contains("another trustee"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_readable_or_hard_linked_ticket_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let state = test_directory();
        let root = test_directory();
        let expected = ticket(root.path());
        let id = create_ticket(Some(state.path()), &expected).unwrap();
        let path = ticket_path(Some(state.path()), &id).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(consume_ticket(Some(state.path()), &id).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = path.with_extension("link");
        fs::hard_link(&path, &link).unwrap();
        assert!(consume_ticket(Some(state.path()), &id).is_err());
    }
}
