use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
mod agent_install;
mod bom_reader;
mod lsp_rewrite;
mod remote_host;
mod windows_agent_install;
use bom_reader::LeadingBomReader;
use lsp_rewrite::rewrite_lsp_body;
use nrm_protocol::{
    read_frame, write_frame, BatchReadFile, BatchValidateFile, FileMeta, Request, RequestId,
    Response, RpcError, RpcMessage, SaveOutcome, WriteStartOutcome, MAX_FRAME_LEN,
    PROTOCOL_VERSION,
};
use nrm_registry::{
    fetch_verified_artifact, AgentTarget, ArtifactSource, FetchConfig, FetchError, FetchErrorCode,
    FetchedArtifact, ManifestSource, RegistryUrlTemplate, TrustedKeySet,
};
use remote_host::{
    local_host_info, parse_posix_probe, parse_powershell_probe, posix_probe_command,
    powershell_agent_process_command, powershell_probe_command, powershell_process_command,
    validate_remote_root, PowerShellProcessCommand, RemoteHostInfo, RemotePathStyle,
};
use rusqlite::Row;
use rusqlite::{params, Connection, OptionalExtension};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Condvar, Mutex, OnceLock,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_CHUNK_SIZE: u64 = 1024 * 1024;
const SAVE_UPLOAD_CHUNK_BYTES: usize = 1024 * 1024;
const DEFAULT_BATCH_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_BATCH_MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_GREP_CACHE_MAX_FILES: usize = 2_000;
const DEFAULT_GREP_CACHE_MAX_FILE_BYTES: u64 = 512 * 1024;
const DEFAULT_GREP_CACHE_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
const SEARCH_INDEX_MAX_FILE_BYTES: u64 = DEFAULT_BATCH_MAX_FILE_BYTES;
const SEARCH_TRIGRAM_BYTES: usize = 3;
const DEFAULT_GIT_OUTPUT_MAX_BYTES: u64 = 1024 * 1024;
const REMOTE_UNAVAILABLE_BACKOFF_BASE_MS: u64 = 2_000;
const REMOTE_UNAVAILABLE_BACKOFF_MAX_MS: u64 = 60_000;
const LSP_PROXY_EXIT_GRACE_MS: u64 = 500;
const LSP_PROXY_SSH_EXIT_GRACE_MS: u64 = 3_000;
const REMOTE_HOST_PROBE_TIMEOUT_MS: u64 = 15_000;
const MAX_SAVE_PAYLOAD_BYTES: u64 = (MAX_FRAME_LEN - (1024 * 1024)) as u64;
const SAVE_INLINE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const FAST_FLUSH_SNAPSHOT_MAX_BYTES: u64 = 1024 * 1024;
const REMOTE_INTERACTIVE_QUEUE_CAPACITY: usize = 128;
const REMOTE_BACKGROUND_QUEUE_CAPACITY: usize = 128;
const REMOTE_AGENT_MANAGED_PATH: &str = "$HOME/.local/bin/nrm-agent";
const DEFAULT_REGISTRY_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_REGISTRY_TIMEOUT_MS: u64 = 120_000;
const REGISTRY_POLICY_DISABLED: &str = "disabled";
const BOOTSTRAP_RECOVERY_RESERVE_MIN_MS: u64 = 250;
const BOOTSTRAP_RECOVERY_RESERVE_MAX_MS: u64 = 10_000;
const PROCESS_CAPTURE_MAX_STREAM_BYTES: usize = 1024 * 1024;
const AGENT_STDERR_TAIL_MAX_BYTES: usize = 64 * 1024;
const AGENT_EXIT_DIAGNOSTIC_GRACE: Duration = Duration::from_millis(250);
const AGENT_LAUNCH_PRELUDE_MAX_BYTES: usize = 128;
const AGENT_LAUNCH_READY_RECORD: &[u8] = b"NRM_AGENT_LAUNCH_V1\tREADY\n";
const AGENT_LAUNCH_FAILURE_PREFIX: &[u8] = b"NRM_AGENT_LAUNCH_V1\tFAILURE\t";
const BACKGROUND_SCAN_CURSOR_KEY: &str = "background_scan_cursor";
const BACKGROUND_SCAN_COMPLETED_AT_KEY: &str = "background_scan_completed_at_ms";
const SIDECAR_COMMAND_SPECS: &[SidecarCommandSpec] = &[
    SidecarCommandSpec::public("hello", "local", None, false, true, false),
    SidecarCommandSpec::public("workspace_info", "local", None, false, true, false),
    SidecarCommandSpec::public("status", "local", None, false, true, false),
    SidecarCommandSpec::public("save_queue", "local", None, false, true, false),
    SidecarCommandSpec::public("find_paths", "local", None, false, true, false),
    SidecarCommandSpec::public("remote_probe", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public("remote_health", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public(
        "remote_agent_install",
        "remote",
        Some("write"),
        true,
        false,
        false,
    ),
    SidecarCommandSpec::public(
        "remote_agent_update",
        "remote",
        Some("write"),
        true,
        false,
        false,
    ),
    SidecarCommandSpec::public("scan", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public("open", "hybrid", Some("read_or_write"), false, true, true),
    SidecarCommandSpec::public("prefetch", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public("prefetch_known", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public(
        "prefetch_related",
        "remote",
        Some("read"),
        false,
        false,
        true,
    ),
    SidecarCommandSpec::public("grep", "hybrid", Some("read_or_write"), false, false, true),
    SidecarCommandSpec::public("grep_cache", "local", None, false, true, false),
    SidecarCommandSpec::public("git_status", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public("git_diff", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public("git_blame", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public("recover_local_edits", "local", None, false, false, false),
    SidecarCommandSpec::public("adopt", "hybrid", Some("write"), true, false, false),
    SidecarCommandSpec::public("flush", "hybrid", Some("write"), true, false, false),
    SidecarCommandSpec::internal("flush_queued", "remote", Some("write"), true, false, false),
    SidecarCommandSpec::public("flush_queue", "remote", Some("write"), true, false, false),
    SidecarCommandSpec::public(
        "accept_local_conflict",
        "remote",
        Some("write"),
        true,
        false,
        false,
    ),
    SidecarCommandSpec::public("accept_remote_conflict", "local", None, false, false, false),
    SidecarCommandSpec::public(
        "validate",
        "hybrid",
        Some("read_or_write"),
        false,
        false,
        true,
    ),
    SidecarCommandSpec::public("refresh", "remote", Some("read"), false, false, true),
    SidecarCommandSpec::public("cancel", "control", None, false, false, false),
    SidecarCommandSpec::public("disconnect", "control", None, false, false, false),
    SidecarCommandSpec::public("shutdown", "control", None, false, false, false),
];
const SIDECAR_NOTIFICATIONS: &[&str] = &["workspace/remote_health"];

#[derive(Debug, Clone, Copy)]
struct SidecarCommandSpec {
    name: &'static str,
    visibility: &'static str,
    execution: &'static str,
    remote_lane: Option<&'static str>,
    mutates_remote: bool,
    fast_path: bool,
    preemptible: bool,
}

impl SidecarCommandSpec {
    const fn public(
        name: &'static str,
        execution: &'static str,
        remote_lane: Option<&'static str>,
        mutates_remote: bool,
        fast_path: bool,
        preemptible: bool,
    ) -> Self {
        Self {
            name,
            visibility: "public",
            execution,
            remote_lane,
            mutates_remote,
            fast_path,
            preemptible,
        }
    }

    const fn internal(
        name: &'static str,
        execution: &'static str,
        remote_lane: Option<&'static str>,
        mutates_remote: bool,
        fast_path: bool,
        preemptible: bool,
    ) -> Self {
        Self {
            name,
            visibility: "internal",
            execution,
            remote_lane,
            mutates_remote,
            fast_path,
            preemptible,
        }
    }

    fn to_value(self) -> Value {
        json!({
            "name": self.name,
            "visibility": self.visibility,
            "execution": self.execution,
            "remote_lane": self.remote_lane,
            "mutates_remote": self.mutates_remote,
            "fast_path": self.fast_path,
            "preemptible": self.preemptible
        })
    }
}

#[derive(Debug, Parser)]
#[command(version, about = "Local sidecar for nvim-remote-mirror")]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    Serve {
        #[arg(long)]
        remote_root: PathBuf,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long, default_value = "nrm-agent")]
        agent: String,
        #[arg(long)]
        local_agent: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 30_000)]
        request_timeout_ms: u64,
        #[arg(long, default_value_t = 10)]
        ssh_connect_timeout_seconds: u64,
        #[command(flatten)]
        registry: RegistryCliArgs,
    },
    Listen {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        remote_root: PathBuf,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long, default_value = "nrm-agent")]
        agent: String,
        #[arg(long)]
        local_agent: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 30_000)]
        request_timeout_ms: u64,
        #[arg(long, default_value_t = 10)]
        ssh_connect_timeout_seconds: u64,
        #[command(flatten)]
        registry: RegistryCliArgs,
    },
    LspProxy {
        #[arg(long)]
        remote_root: PathBuf,
        #[arg(long)]
        local_root: PathBuf,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long, default_value_t = 10)]
        ssh_connect_timeout_seconds: u64,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Clone, Args)]
struct RegistryCliArgs {
    #[arg(long)]
    remote_agent_registry_url: Option<String>,
    #[arg(
        long = "remote-agent-registry-public-key",
        value_name = "KEY_ID=BASE64",
        action = clap::ArgAction::Append
    )]
    remote_agent_registry_public_keys: Vec<String>,
    #[arg(long, default_value_t = 1)]
    remote_agent_registry_signature_threshold: usize,
    #[arg(long)]
    remote_agent_registry_cache_dir: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_REGISTRY_CACHE_MAX_BYTES)]
    remote_agent_registry_cache_max_bytes: u64,
    #[arg(long, default_value_t = DEFAULT_REGISTRY_TIMEOUT_MS)]
    remote_agent_registry_timeout_ms: u64,
}

impl RegistryCliArgs {
    fn into_config(self) -> Result<Option<RegistryLaunchConfig>> {
        let Some(url) = self.remote_agent_registry_url else {
            if !self.remote_agent_registry_public_keys.is_empty()
                || self.remote_agent_registry_cache_dir.is_some()
                || self.remote_agent_registry_signature_threshold != 1
                || self.remote_agent_registry_cache_max_bytes != DEFAULT_REGISTRY_CACHE_MAX_BYTES
                || self.remote_agent_registry_timeout_ms != DEFAULT_REGISTRY_TIMEOUT_MS
            {
                bail!("remote agent registry options require --remote-agent-registry-url");
            }
            return Ok(None);
        };
        if self.remote_agent_registry_cache_max_bytes == 0 {
            bail!("remote agent registry cache limit must be positive");
        }
        if self.remote_agent_registry_timeout_ms == 0 {
            bail!("remote agent registry timeout must be positive");
        }
        let url_template = RegistryUrlTemplate::parse(&url)
            .context("invalid remote agent registry URL template")?;
        let mut entries = Vec::with_capacity(self.remote_agent_registry_public_keys.len());
        for entry in self.remote_agent_registry_public_keys {
            let (key_id, encoded) = entry
                .split_once('=')
                .ok_or_else(|| anyhow!("registry public keys must use KEY_ID=BASE64 syntax"))?;
            entries.push((key_id.to_string(), encoded.to_string()));
        }
        let cache_dir_identity = self
            .remote_agent_registry_cache_dir
            .as_deref()
            .map(|path| {
                path.to_str().ok_or_else(|| {
                    anyhow!("remote agent registry cache directory must be valid UTF-8")
                })
            })
            .transpose()?
            .unwrap_or("");
        let mut policy_entries = entries.clone();
        policy_entries.sort_by(|left, right| left.0.cmp(&right.0));
        let mut policy_parts = vec![
            "nrm-registry-policy-v1".to_string(),
            url.clone(),
            self.remote_agent_registry_signature_threshold.to_string(),
            cache_dir_identity.to_string(),
            self.remote_agent_registry_cache_max_bytes.to_string(),
            self.remote_agent_registry_timeout_ms.to_string(),
        ];
        policy_parts.extend(
            policy_entries
                .iter()
                .map(|(key_id, encoded)| format!("{key_id}={}", sha256_bytes(encoded.as_bytes()))),
        );
        let policy_fingerprint = sha256_bytes(policy_parts.join("\x1f").as_bytes());
        let trusted_keys = TrustedKeySet::from_base64(entries)
            .context("invalid remote agent registry public keys")?;
        if self.remote_agent_registry_signature_threshold == 0
            || self.remote_agent_registry_signature_threshold > trusted_keys.len()
        {
            bail!(
                "remote agent registry signature threshold must be between 1 and {}",
                trusted_keys.len()
            );
        }
        Ok(Some(RegistryLaunchConfig {
            url_template,
            trusted_keys,
            signature_threshold: self.remote_agent_registry_signature_threshold,
            cache_dir: self.remote_agent_registry_cache_dir,
            cache_max_bytes: self.remote_agent_registry_cache_max_bytes,
            timeout: Duration::from_millis(self.remote_agent_registry_timeout_ms),
            policy_fingerprint,
        }))
    }
}

#[derive(Clone, Debug)]
struct RegistryLaunchConfig {
    url_template: RegistryUrlTemplate,
    trusted_keys: TrustedKeySet,
    signature_threshold: usize,
    cache_dir: Option<PathBuf>,
    cache_max_bytes: u64,
    timeout: Duration,
    policy_fingerprint: String,
}

#[derive(Debug)]
struct ResolvedAgentSource {
    path: PathBuf,
    file: File,
    expected_sha256: Option<String>,
    details: Value,
    _registry_artifact: Option<FetchedArtifact>,
}

struct AgentInstallPreflight {
    before: Value,
    target_path: String,
    effective_force: bool,
    skip_reason: Option<String>,
    automatic: bool,
}

#[derive(Debug)]
struct AgentInstallDecision {
    effective_force: bool,
    skip_reason: Option<String>,
}

enum RemoteAgentInstallLeaseOutcome {
    Skipped(Value),
    Transaction {
        result: std::result::Result<agent_install::ActivatedInstall, AgentInstallTransactionError>,
        effective_force: bool,
    },
}

fn agent_install_decision(
    before_status: &str,
    update: bool,
    force: bool,
    automatic: bool,
) -> Result<AgentInstallDecision> {
    if automatic {
        if !update {
            bail!("automatic remote agent bootstrap requires update/repair semantics");
        }
        if force {
            bail!("automatic remote agent bootstrap does not accept force=true");
        }
        return Ok(match before_status {
            "ok" => AgentInstallDecision {
                effective_force: false,
                skip_reason: Some("remote agent is already compatible".to_string()),
            },
            "missing_agent" => AgentInstallDecision {
                effective_force: false,
                skip_reason: None,
            },
            "agent_not_executable" | "version_mismatch" | "protocol_mismatch" => {
                AgentInstallDecision {
                    effective_force: true,
                    skip_reason: None,
                }
            }
            other => AgentInstallDecision {
                effective_force: false,
                skip_reason: Some(format!(
                    "automatic bootstrap left remote agent unchanged for status `{other}`"
                )),
            },
        });
    }

    Ok(AgentInstallDecision {
        effective_force: force || (update && before_status != "missing_agent"),
        skip_reason: (update && !force && before_status == "ok")
            .then(|| "remote agent is already compatible".to_string()),
    })
}

struct PreparedAgentInstall {
    source: ResolvedAgentSource,
    upload: File,
    source_hash: String,
    source_sha256: String,
    source_size: u64,
    ssh: SshTransport,
    plan: PreparedAgentInstallPlan,
}

enum PreparedAgentInstallPlan {
    Posix(agent_install::PosixInstallPlan),
    Windows(windows_agent_install::WindowsInstallPlan),
}

impl PreparedAgentInstallPlan {
    fn lease_command(&self, token: &str, watchdog: Duration) -> Result<String> {
        match self {
            Self::Posix(plan) => plan
                .lease_command(token)
                .context("invalid POSIX remote-agent lease plan"),
            Self::Windows(plan) => plan
                .lease_command(token, watchdog)
                .context("invalid Windows remote-agent lease plan"),
        }
    }

    fn lease_release_signal(
        &self,
        ssh: &SshTransport,
        token: &str,
    ) -> Result<Option<RemoteInstallLeaseReleaseSignal>> {
        match self {
            Self::Posix(_) => Ok(None),
            Self::Windows(plan) => Ok(Some(RemoteInstallLeaseReleaseSignal {
                ssh: ssh.clone(),
                remote_command: plan
                    .lease_release_command(token)
                    .context("invalid Windows remote-agent lease release plan")?,
                expected_record: plan
                    .expected_lease_release_record(token)
                    .context("invalid Windows remote-agent lease release record")?,
            })),
        }
    }

    fn parse_lease_ready_stdout(&self, token: &str, stdout: &str) -> Result<String> {
        match self {
            Self::Posix(plan) => plan
                .parse_lease_ready_stdout(token, stdout)
                .context("POSIX remote-agent lease returned an invalid readiness record"),
            Self::Windows(plan) => plan
                .parse_lease_ready_stdout(token, stdout)
                .context("Windows remote-agent lease returned an invalid readiness record"),
        }
    }

    fn set_force(&mut self, force: bool) {
        match self {
            Self::Posix(plan) => plan.set_force(force),
            Self::Windows(plan) => plan.set_force(force),
        }
    }

    fn set_expected_sha256(&mut self, digest: &str) -> Result<()> {
        match self {
            Self::Posix(plan) => plan
                .set_expected_sha256(digest)
                .context("invalid POSIX remote-agent artifact digest"),
            Self::Windows(plan) => plan
                .set_expected_sha256(digest)
                .context("invalid Windows remote-agent artifact digest"),
        }
    }

    fn set_lease_token(&mut self, token: &str) -> Result<()> {
        match self {
            Self::Posix(plan) => plan
                .set_lease_token(token)
                .context("invalid POSIX remote-agent lease token"),
            Self::Windows(plan) => plan
                .set_lease_token(token)
                .context("invalid Windows remote-agent lease token"),
        }
    }

    fn bind_lease_target(&mut self, target: &str) -> Result<()> {
        match self {
            Self::Posix(plan) => plan
                .bind_resolved_lease_target(target)
                .context("invalid resolved POSIX remote-agent lease target"),
            // Windows readiness parsing already requires the exact normalized
            // target stored in the plan.
            Self::Windows(_) => Ok(()),
        }
    }
}

static INSTALL_LEASE_NONCE: AtomicU64 = AtomicU64::new(0);
const INSTALL_LEASE_READY_MAX_BYTES: usize = 4096;
const INSTALL_LEASE_STDERR_GRACE: Duration = Duration::from_secs(1);
const INSTALL_LEASE_DETACHED_STDERR_GRACE: Duration = Duration::from_secs(1);

fn new_install_lease_token(target: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    hasher.update(
        INSTALL_LEASE_NONCE
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    hasher.update(target.as_bytes());
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct RemoteInstallLease {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stderr: Option<ProcessOutputReader>,
    release_signal: Option<RemoteInstallLeaseReleaseSignal>,
    released: bool,
}

struct RemoteInstallLeaseReleaseSignal {
    ssh: SshTransport,
    remote_command: String,
    expected_record: String,
}

impl RemoteInstallLeaseReleaseSignal {
    fn send(self, timeout: Duration) -> Result<()> {
        if timeout.is_zero() {
            bail!(ProcessTimeoutError {
                context: "remote agent installation lease release signal".to_owned(),
                timeout,
                status: None,
            });
        }
        let context = "remote agent installation lease release signal";
        let output = run_command_capture(
            self.ssh.command(self.remote_command),
            None,
            timeout,
            context,
        )?;
        if !output.status.success() {
            let failure =
                agent_install::classify_install_failure(output.status.code(), &output.stderr);
            bail!("{}: {}", install_failure_code(failure.kind), failure.detail);
        }
        let expected_lf = format!("{}\n", self.expected_record);
        let expected_crlf = format!("{}\r\n", self.expected_record);
        if output.stdout != expected_lf && output.stdout != expected_crlf {
            bail!(
                "invalid_state: remote agent installation lease release returned an invalid record"
            );
        }
        Ok(())
    }
}

fn detach_install_lease_stderr(stderr: ProcessOutputReader) {
    let _ = thread::Builder::new()
        .name("nrm-install-lease-stderr-reaper".to_owned())
        .spawn(move || {
            let started = Instant::now();
            while !stderr.is_finished() && started.elapsed() < INSTALL_LEASE_DETACHED_STDERR_GRACE {
                let remaining =
                    INSTALL_LEASE_DETACHED_STDERR_GRACE.saturating_sub(started.elapsed());
                thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            if stderr.is_finished() {
                let _ = join_process_output_reader(
                    stderr,
                    "remote agent installation lease detached cleanup",
                    "stderr",
                );
            }
            // If a daemonized descendant retains the pipe beyond the bounded
            // grace, dropping the join handle detaches the already-bounded
            // reader rather than extending the bootstrap caller's deadline.
        });
}

impl RemoteInstallLease {
    fn acquire(
        ssh: &SshTransport,
        remote_command: String,
        release_signal: Option<RemoteInstallLeaseReleaseSignal>,
        timeout: Duration,
    ) -> Result<(Self, String)> {
        let context = "remote agent installation lease";
        let mut command = ssh.command(remote_command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_agent_process(&mut command);
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to start {context} holder"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("{context} stdin was not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("{context} stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .map(spawn_process_output_reader)
            .ok_or_else(|| anyhow!("{context} stderr was not piped"))?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let ready_reader = thread::Builder::new()
            .name("nrm-install-lease-ready".to_owned())
            .spawn(move || {
                    let limited = LeadingBomReader::new(stdout)
                        .take((INSTALL_LEASE_READY_MAX_BYTES + 1) as u64);
                    let mut reader = BufReader::new(limited);
                    let mut bytes = Vec::new();
                    let result = match reader.read_until(b'\n', &mut bytes) {
                        Ok(0) => Err(anyhow!(
                            "remote agent installation lease closed stdout before readiness"
                        )),
                        Ok(_)
                            if bytes.len() > INSTALL_LEASE_READY_MAX_BYTES
                                || bytes.last() != Some(&b'\n') =>
                        {
                            Err(anyhow!(
                                "remote agent installation lease readiness exceeded its limit or lacked a newline"
                            ))
                        }
                        Ok(_) => String::from_utf8(bytes).context(
                            "remote agent installation lease readiness was not UTF-8",
                        ),
                        Err(error) => Err(error)
                            .context("failed to read remote agent installation lease readiness"),
                    };
                    let _ = ready_tx.send(result);
                });
        let mut ready_reader = match ready_reader {
            Ok(reader) => Some(reader),
            Err(error) => {
                drop(stdin);
                kill_child_tree(&mut child);
                reap_child_in_background(child);
                return Err(error).context("failed to start remote-agent lease readiness reader");
            }
        };

        let started = Instant::now();
        let mut readiness = None;
        let mut readiness_error = None;
        loop {
            if readiness.is_none() && ready_reader.is_some() {
                match ready_rx.try_recv() {
                    Ok(result) => readiness = Some(result),
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        readiness = Some(Err(anyhow!(
                            "remote agent installation lease readiness reader stopped"
                        )));
                    }
                }
            }
            if let Some(result) = readiness.take() {
                if let Some(reader) = ready_reader.take() {
                    if reader.is_finished() {
                        let _ = reader.join();
                    }
                }
                match result {
                    Ok(stdout) => match child.try_wait() {
                        Ok(None) => {
                            return Ok((
                                Self {
                                    child: Some(child),
                                    stdin: Some(stdin),
                                    stderr: Some(stderr),
                                    release_signal,
                                    released: false,
                                },
                                stdout,
                            ));
                        }
                        Ok(Some(status)) => {
                            return Err(Self::exited_error(
                                status,
                                stderr,
                                context,
                                timeout.saturating_sub(started.elapsed()),
                            ));
                        }
                        Err(error) => {
                            kill_child_tree(&mut child);
                            reap_child_in_background(child);
                            return Err(error).context(format!("failed to poll {context} holder"));
                        }
                    },
                    Err(error) => readiness_error = Some(error),
                }
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    if let Some(reader) = ready_reader.take() {
                        if reader.is_finished() {
                            let _ = reader.join();
                        }
                    }
                    if status.success() {
                        if let Some(error) = readiness_error.take() {
                            return Err(error);
                        }
                    }
                    return Err(Self::exited_error(
                        status,
                        stderr,
                        context,
                        timeout.saturating_sub(started.elapsed()),
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    kill_child_tree(&mut child);
                    reap_child_in_background(child);
                    return Err(error).context(format!("failed to poll {context} holder"));
                }
            }
            if started.elapsed() >= timeout {
                kill_child_tree(&mut child);
                let status = child.try_wait().ok().flatten();
                if status.is_none() {
                    reap_child_in_background(child);
                }
                let timeout_error = anyhow!(ProcessTimeoutError {
                    context: format!("{context} acquisition"),
                    timeout,
                    status,
                });
                return Err(match readiness_error {
                    Some(error) => timeout_error.context(error.to_string()),
                    None => timeout_error,
                });
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn exited_error(
        status: ExitStatus,
        stderr: ProcessOutputReader,
        context: &str,
        timeout: Duration,
    ) -> anyhow::Error {
        let started = Instant::now();
        let timeout = timeout.min(INSTALL_LEASE_STDERR_GRACE);
        while !stderr.is_finished() && started.elapsed() < timeout {
            let remaining = timeout.saturating_sub(started.elapsed());
            thread::sleep(remaining.min(Duration::from_millis(1)));
        }
        if !stderr.is_finished() {
            detach_install_lease_stderr(stderr);
            return anyhow!(
                "command_failed: {context} holder exited with {status}; stderr did not close"
            );
        }
        let stderr = join_process_output_reader(stderr, context, "stderr")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|error| error.to_string());
        let failure = agent_install::classify_install_failure(status.code(), &stderr);
        anyhow!("{}: {}", install_failure_code(failure.kind), failure.detail)
    }

    fn ensure_held(&mut self, phase: &str) -> Result<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| anyhow!("remote agent installation lease was already released"))?;
        match child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => {
                let stderr = self.stderr.take().ok_or_else(|| {
                    anyhow!("remote agent installation lease stderr was unavailable")
                })?;
                Err(Self::exited_error(status, stderr, phase, Duration::ZERO))
                    .context("remote agent installation lease holder exited before mutation")
            }
            Err(error) => Err(error)
                .with_context(|| format!("failed to poll installation lease before {phase}")),
        }
    }

    fn release(&mut self, timeout: Duration) -> Result<()> {
        if self.released {
            return Ok(());
        }
        // From this point every owned process/pipe is either reaped here or
        // handed to a detached reaper. Drop must never start a second wait
        // that can outlive the caller's bootstrap deadline.
        self.released = true;
        let started = Instant::now();
        let mut release_signal_error = self
            .release_signal
            .take()
            .and_then(|signal| signal.send(timeout).err());
        self.stdin.take();
        let mut stderr = self.stderr.take();
        let Some(mut child) = self.child.take() else {
            if let Some(stderr) = stderr.take() {
                detach_install_lease_stderr(stderr);
            }
            return match release_signal_error.take() {
                Some(error) => Err(error),
                None => Ok(()),
            };
        };
        if stderr.is_none() {
            kill_child_tree(&mut child);
            reap_child_in_background(child);
            let error =
                anyhow!("remote agent installation lease stderr was unavailable during release");
            return Err(match release_signal_error.take() {
                Some(signal_error) => error.context(format!(
                    "install lease release signal also failed: {signal_error:#}"
                )),
                None => error,
            });
        }
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < timeout => {
                    let remaining = timeout.saturating_sub(started.elapsed());
                    thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Ok(None) => {
                    kill_child_tree(&mut child);
                    let (status, reap_error) = match child.try_wait() {
                        Ok(Some(status)) => (Some(status), None),
                        Ok(None) => {
                            reap_child_in_background(child);
                            (None, None)
                        }
                        Err(error) => {
                            reap_child_in_background(child);
                            (None, Some(error))
                        }
                    };
                    detach_install_lease_stderr(stderr.take().unwrap());
                    let timeout_error = anyhow!(ProcessTimeoutError {
                        context: "remote agent installation lease release".to_owned(),
                        timeout,
                        status,
                    });
                    let timeout_error = match reap_error {
                        Some(error) => timeout_error.context(format!(
                            "failed to reap remote agent installation lease holder: {error}"
                        )),
                        None => timeout_error,
                    };
                    return Err(match release_signal_error.take() {
                        Some(signal_error) => timeout_error.context(format!(
                            "install lease release signal failed: {signal_error:#}"
                        )),
                        None => timeout_error,
                    });
                }
                Err(error) => {
                    kill_child_tree(&mut child);
                    reap_child_in_background(child);
                    detach_install_lease_stderr(stderr.take().unwrap());
                    let error = anyhow!(error)
                        .context("failed to poll remote agent installation lease holder");
                    return Err(match release_signal_error.take() {
                        Some(signal_error) => error.context(format!(
                            "install lease release signal also failed: {signal_error:#}"
                        )),
                        None => error,
                    });
                }
            }
        };
        let stderr = stderr.take().unwrap();
        let stderr_started = Instant::now();
        let stderr_timeout = timeout.saturating_sub(started.elapsed());
        while !stderr.is_finished() && stderr_started.elapsed() < stderr_timeout {
            let remaining = stderr_timeout.saturating_sub(stderr_started.elapsed());
            thread::sleep(remaining.min(Duration::from_millis(1)));
        }
        if !stderr.is_finished() {
            detach_install_lease_stderr(stderr);
            bail!("remote agent installation lease stderr did not close during release");
        }
        let stderr =
            join_process_output_reader(stderr, "remote agent installation lease", "stderr")?;
        if status.success() {
            // OpenSSH can emit host-key notices or a remote login banner on
            // stderr even though the fixed lease holder exited cleanly. The
            // stream is still bounded and drained, but success is determined
            // by the holder's exit status.
            if started.elapsed() >= timeout {
                let error = anyhow!(ProcessTimeoutError {
                    context: "remote agent installation lease release".to_owned(),
                    timeout,
                    status: Some(status),
                });
                return Err(match release_signal_error.take() {
                    Some(signal_error) => error.context(format!(
                        "install lease release signal also failed: {signal_error:#}"
                    )),
                    None => error,
                });
            }
            if let Some(error) = release_signal_error.take() {
                eprintln!(
                    "remote agent installation lease release signal lost its acknowledgement after the holder released cleanly: {error:#}"
                );
            }
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&stderr);
        let failure = agent_install::classify_install_failure(status.code(), &stderr);
        let error = anyhow!("{}: {}", install_failure_code(failure.kind), failure.detail);
        Err(match release_signal_error.take() {
            Some(signal_error) => error.context(format!(
                "install lease release signal also failed: {signal_error:#}"
            )),
            None => error,
        })
    }
}

impl Drop for RemoteInstallLease {
    fn drop(&mut self) {
        if !self.released {
            let _ = self.release(Duration::ZERO);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapBudget {
    Forward,
    Recovery,
}

#[derive(Clone, Copy, Debug)]
struct BootstrapDeadline {
    started: Instant,
    total: Duration,
    recovery_reserve: Duration,
}

#[derive(Debug)]
struct BootstrapTimeoutError {
    phase: String,
}

impl fmt::Display for BootstrapTimeoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bootstrap_timeout: {}", self.phase)
    }
}

impl std::error::Error for BootstrapTimeoutError {}

#[derive(Debug)]
struct ProcessTimeoutError {
    context: String,
    timeout: Duration,
    status: Option<ExitStatus>,
}

impl fmt::Display for ProcessTimeoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} timed out after {} ms; process-tree termination requested",
            self.context,
            self.timeout.as_millis()
        )?;
        if let Some(status) = self.status {
            write!(formatter, "; reaped with {status}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ProcessTimeoutError {}

#[derive(Debug)]
struct AgentRequestTimeoutError {
    id: RequestId,
    timeout: Duration,
    phase: &'static str,
}

impl fmt::Display for AgentRequestTimeoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "agent request {} timed out after {} ms {}",
            self.id,
            self.timeout.as_millis(),
            self.phase
        )
    }
}

impl std::error::Error for AgentRequestTimeoutError {}

#[derive(Debug)]
struct AgentWorkerExitTimeoutError {
    context: String,
}

impl fmt::Display for AgentWorkerExitTimeoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "timed out waiting for agent worker exit during {}",
            self.context
        )
    }
}

impl std::error::Error for AgentWorkerExitTimeoutError {}

impl BootstrapDeadline {
    fn new(total: Duration) -> Self {
        let quarter = total / 4;
        let desired = quarter.clamp(
            Duration::from_millis(BOOTSTRAP_RECOVERY_RESERVE_MIN_MS),
            Duration::from_millis(BOOTSTRAP_RECOVERY_RESERVE_MAX_MS),
        );
        Self {
            started: Instant::now(),
            total,
            recovery_reserve: desired.min(total / 2),
        }
    }

    fn remaining(self) -> Duration {
        self.total.saturating_sub(self.started.elapsed())
    }

    fn timeout(self, budget: BootstrapBudget, phase: &str) -> Result<Duration> {
        let remaining = self.remaining();
        let available = match budget {
            BootstrapBudget::Forward => remaining.saturating_sub(self.recovery_reserve),
            BootstrapBudget::Recovery => remaining,
        };
        if available.is_zero() {
            return Err(anyhow!(BootstrapTimeoutError {
                phase: format!("whole-bootstrap deadline expired during {phase}"),
            }));
        }
        Ok(available)
    }

    fn forward_timeout(self, phase: &str) -> Result<Duration> {
        self.timeout(BootstrapBudget::Forward, phase)
    }

    fn recovery_timeout(self, phase: &str) -> Result<Duration> {
        self.timeout(BootstrapBudget::Recovery, phase)
    }

    fn map_budgeted_error(
        self,
        budget: BootstrapBudget,
        phase: &str,
        error: anyhow::Error,
    ) -> anyhow::Error {
        if is_bootstrap_timeout(&error)
            || error.chain().any(|cause| {
                cause.downcast_ref::<ProcessTimeoutError>().is_some()
                    || cause.downcast_ref::<AgentRequestTimeoutError>().is_some()
                    || cause
                        .downcast_ref::<AgentWorkerExitTimeoutError>()
                        .is_some()
                    || cause.downcast_ref::<FetchError>().is_some_and(|error| {
                        matches!(
                            error.code(),
                            FetchErrorCode::OperationDeadline
                                | FetchErrorCode::NetworkTimeout
                                | FetchErrorCode::CacheLockTimeout
                        )
                    })
            })
            || self.timeout(budget, phase).is_err()
        {
            return anyhow!(BootstrapTimeoutError {
                phase: format!("whole-bootstrap deadline expired during {phase}: {error}"),
            });
        }
        error
    }

    #[cfg(test)]
    fn with_elapsed(total: Duration, elapsed: Duration) -> Self {
        let mut deadline = Self::new(total);
        deadline.started = Instant::now()
            .checked_sub(elapsed)
            .unwrap_or_else(Instant::now);
        deadline
    }
}

fn release_remote_install_lease_with_deadline(
    lease: &mut RemoteInstallLease,
    deadline: BootstrapDeadline,
    phase: &str,
) -> Result<()> {
    match deadline.recovery_timeout(phase) {
        Ok(release_timeout) => lease.release(release_timeout),
        Err(timeout_error) => {
            let forced_release = lease.release(Duration::ZERO);
            Err(match forced_release {
                Ok(()) => timeout_error,
                Err(release_error) => {
                    timeout_error.context(format!("install_lease_release_failed: {release_error}"))
                }
            })
        }
    }
}

fn is_bootstrap_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<BootstrapTimeoutError>().is_some()
            || cause
                .downcast_ref::<AgentInstallTransactionError>()
                .is_some_and(|error| error.bootstrap_timeout)
    })
}

fn normalize_bootstrap_error(error: anyhow::Error) -> anyhow::Error {
    if is_bootstrap_timeout(&error) {
        anyhow!("bootstrap_timeout: {error:#}")
    } else {
        error
    }
}

fn registry_fetch_timeout(
    configured_timeout: Duration,
    deadline: BootstrapDeadline,
) -> Result<Duration> {
    Ok(configured_timeout.min(deadline.forward_timeout("registry fetch")?))
}

fn remaining_timeout_since(started: Instant, total: Duration) -> Duration {
    total.saturating_sub(started.elapsed())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentInstallFinalState {
    TargetUnchanged,
    PreviousRestored,
    CandidateHealthy,
    LiveStateUnknown,
}

#[derive(Debug)]
struct AgentInstallTransactionError {
    final_state: AgentInstallFinalState,
    bootstrap_timeout: bool,
    message: String,
}

impl fmt::Display for AgentInstallTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AgentInstallTransactionError {}

#[cfg(test)]
fn install_transaction_error(
    final_state: AgentInstallFinalState,
    message: impl Into<String>,
) -> AgentInstallTransactionError {
    AgentInstallTransactionError {
        final_state,
        bootstrap_timeout: false,
        message: message.into(),
    }
}

fn install_transaction_error_with_timeout(
    final_state: AgentInstallFinalState,
    bootstrap_timeout: bool,
    message: impl Into<String>,
) -> AgentInstallTransactionError {
    AgentInstallTransactionError {
        final_state,
        bootstrap_timeout,
        message: message.into(),
    }
}

trait AgentInstallOps {
    fn stage(&mut self) -> Result<agent_install::StagedInstall>;
    fn validate_staged(&mut self, staged: &agent_install::StagedInstall) -> Result<()>;
    fn ensure_activation_budget(&mut self) -> Result<()> {
        Ok(())
    }
    fn activate(
        &mut self,
        staged: &agent_install::StagedInstall,
    ) -> Result<agent_install::ActivatedInstall>;
    fn reconcile_activation(
        &mut self,
        staged: &agent_install::StagedInstall,
    ) -> Result<agent_install::ActivationRecovery>;
    fn validate_reconciliation(
        &mut self,
        recovery: &agent_install::ActivationRecovery,
    ) -> Result<()>;
    fn validate_activated(&mut self, activated: &agent_install::ActivatedInstall) -> Result<()>;
    fn rollback(
        &mut self,
        activated: &agent_install::ActivatedInstall,
    ) -> Result<agent_install::RollbackOutcome>;
    fn validate_rollback(&mut self, rollback: &agent_install::RollbackOutcome) -> Result<()>;
    fn cleanup(&mut self, staged: &agent_install::StagedInstall) -> Result<()>;
}

fn install_phase_failure(prefix: &str, error: &anyhow::Error) -> String {
    if is_bootstrap_timeout(error) {
        format!("bootstrap_timeout: {prefix}: {error}")
    } else {
        format!("{prefix}: {error}")
    }
}

fn run_agent_install_transaction(
    operations: &mut dyn AgentInstallOps,
) -> std::result::Result<agent_install::ActivatedInstall, AgentInstallTransactionError> {
    let staged = operations.stage().map_err(|error| {
        install_transaction_error_with_timeout(
            AgentInstallFinalState::TargetUnchanged,
            is_bootstrap_timeout(&error),
            install_phase_failure("staging_failed: failed to stage remote agent", &error),
        )
    })?;
    if let Err(error) = operations.validate_staged(&staged) {
        let cleanup = operations.cleanup(&staged).err();
        let timed_out =
            is_bootstrap_timeout(&error) || cleanup.as_ref().is_some_and(is_bootstrap_timeout);
        return Err(install_transaction_error_with_timeout(
            AgentInstallFinalState::TargetUnchanged,
            timed_out,
            format!(
                "{}{}",
                install_phase_failure("staged_validation_failed", &error),
                cleanup
                    .map(|cleanup| format!("; cleanup_failed: {cleanup}"))
                    .unwrap_or_default()
            ),
        ));
    }
    if let Err(error) = operations.ensure_activation_budget() {
        let cleanup = operations.cleanup(&staged).err();
        let timed_out =
            is_bootstrap_timeout(&error) || cleanup.as_ref().is_some_and(is_bootstrap_timeout);
        return Err(install_transaction_error_with_timeout(
            AgentInstallFinalState::TargetUnchanged,
            timed_out,
            format!(
                "{}{}",
                install_phase_failure("activation budget exhausted before target mutation", &error),
                cleanup
                    .map(|cleanup| format!("; cleanup_failed: {cleanup}"))
                    .unwrap_or_default()
            ),
        ));
    }
    let activated = match operations.activate(&staged) {
        Ok(activated) => activated,
        Err(error) => {
            let activation_timed_out = is_bootstrap_timeout(&error);
            let recovery = operations.reconcile_activation(&staged).map_err(|recovery| {
                install_transaction_error_with_timeout(
                    AgentInstallFinalState::LiveStateUnknown,
                    activation_timed_out || is_bootstrap_timeout(&recovery),
                    format!(
                        "rollback_failed: activation reconciliation failed: {recovery}; original activation failure: {error}"
                    ),
                )
            })?;
            operations.validate_reconciliation(&recovery).map_err(
                |recovery_error| {
                    install_transaction_error_with_timeout(
                        AgentInstallFinalState::LiveStateUnknown,
                        activation_timed_out || is_bootstrap_timeout(&recovery_error),
                        format!(
                            "rollback_failed: reconciled target reprobe failed: {recovery_error}; original activation failure: {error}"
                        ),
                    )
                },
            )?;
            let final_state = match recovery.kind {
                agent_install::ActivationRecoveryKind::ActivationUnchangedPresent
                | agent_install::ActivationRecoveryKind::ActivationUnchangedMissing => {
                    AgentInstallFinalState::TargetUnchanged
                }
                agent_install::ActivationRecoveryKind::RestoredPrevious
                | agent_install::ActivationRecoveryKind::RemovedCandidate => {
                    AgentInstallFinalState::PreviousRestored
                }
            };
            return Err(install_transaction_error_with_timeout(
                final_state,
                activation_timed_out,
                format!(
                    "{}; reconciliation={:?}",
                    install_phase_failure("activation_failed", &error),
                    recovery.kind
                ),
            ));
        }
    };
    if let Err(error) = operations.validate_activated(&activated) {
        let validation_timed_out = is_bootstrap_timeout(&error);
        let rollback = operations.rollback(&activated).map_err(|rollback| {
            install_transaction_error_with_timeout(
                AgentInstallFinalState::LiveStateUnknown,
                validation_timed_out || is_bootstrap_timeout(&rollback),
                format!("rollback_failed: {rollback}; original postactivation failure: {error}"),
            )
        })?;
        operations.validate_rollback(&rollback).map_err(|rollback| {
            install_transaction_error_with_timeout(
                AgentInstallFinalState::LiveStateUnknown,
                validation_timed_out || is_bootstrap_timeout(&rollback),
                format!(
                    "rollback_failed: restored agent reprobe failed: {rollback}; original postactivation failure: {error}"
                ),
            )
        })?;
        return Err(install_transaction_error_with_timeout(
            AgentInstallFinalState::PreviousRestored,
            validation_timed_out,
            format!(
                "{}; rollback=restored",
                install_phase_failure("post_activation_validation_failed", &error)
            ),
        ));
    }
    operations.cleanup(&activated.staged).map_err(|error| {
        install_transaction_error_with_timeout(
            AgentInstallFinalState::CandidateHealthy,
            is_bootstrap_timeout(&error),
            format!(
                "cleanup_failed: activated agent is healthy but backup cleanup failed: {error}"
            ),
        )
    })?;
    Ok(activated)
}

struct PosixSshInstallOps<'a> {
    plan: agent_install::PosixInstallPlan,
    ssh: SshTransport,
    source: Option<File>,
    launch: AgentLaunch,
    normal_agent: &'a mut AgentClient,
    lease: &'a mut RemoteInstallLease,
    deadline: BootstrapDeadline,
}

impl PosixSshInstallOps<'_> {
    fn command_output(
        &self,
        command: String,
        budget: BootstrapBudget,
        context: &str,
    ) -> Result<CapturedProcessOutput> {
        let timeout = self.deadline.timeout(budget, context)?;
        run_command_capture(self.ssh.command(command), None, timeout, context)
            .map_err(|error| self.deadline.map_budgeted_error(budget, context, error))
    }

    fn require_success(output: CapturedProcessOutput) -> Result<String> {
        if output.status.success() {
            return Ok(output.stdout);
        }
        let failure =
            agent_install::classify_install_failure(output.status.code(), output.stderr.as_str());
        bail!("{}: {}", install_failure_code(failure.kind), failure.detail);
    }

    fn confirm_target_absent(&self, hook: &agent_install::PosixValidationHook) -> Result<()> {
        let command = self
            .plan
            .absence_check_command(hook)
            .context("invalid absent-target validation hook")?;
        let output = self.command_output(
            command,
            BootstrapBudget::Recovery,
            "remote agent absence check",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_absence_check_stdout(hook, &stdout)
            .context("remote agent absence check returned an invalid record")
    }

    fn stop_normal_agent(&mut self, budget: BootstrapBudget, context: &str) -> Result<()> {
        let timeout = self.deadline.timeout(budget, context)?;
        self.normal_agent
            .kill_worker_with_timeout(timeout, context)
            .map_err(|error| self.deadline.map_budgeted_error(budget, context, error))?;
        self.deadline.timeout(budget, context).map(drop)
    }
}

impl AgentInstallOps for PosixSshInstallOps<'_> {
    fn stage(&mut self) -> Result<agent_install::StagedInstall> {
        self.lease.ensure_held("remote agent staging")?;
        let source = self
            .source
            .take()
            .ok_or_else(|| anyhow!("agent source was already consumed"))?;
        let output = run_command_capture(
            self.ssh.command(self.plan.stage_command()),
            Some(Box::new(source)),
            self.deadline.forward_timeout("remote agent staging")?,
            "remote agent staging",
        )
        .map_err(|error| {
            self.deadline.map_budgeted_error(
                BootstrapBudget::Forward,
                "remote agent staging",
                error,
            )
        })?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_stage_stdout(&stdout)
            .context("remote agent staging returned an invalid record")
    }

    fn validate_staged(&mut self, staged: &agent_install::StagedInstall) -> Result<()> {
        self.lease.ensure_held("staged agent exact Hello")?;
        let hook = self.plan.staged_validation(staged);
        let timeout = self.deadline.forward_timeout("staged agent exact Hello")?;
        probe_agent_at(&self.launch, &hook.executable_path, timeout)
            .map_err(|error| {
                self.deadline.map_budgeted_error(
                    BootstrapBudget::Forward,
                    "staged agent exact Hello",
                    error,
                )
            })
            .context("staged agent Hello failed")?;
        self.deadline
            .forward_timeout("staged agent exact Hello completion")
            .map(drop)
    }

    fn ensure_activation_budget(&mut self) -> Result<()> {
        self.lease
            .ensure_held("remote agent activation budget check")?;
        self.deadline
            .forward_timeout("remote agent activation")
            .map(drop)
    }

    fn activate(
        &mut self,
        staged: &agent_install::StagedInstall,
    ) -> Result<agent_install::ActivatedInstall> {
        self.lease.ensure_held("remote agent activation")?;
        let output = self.command_output(
            self.plan.activate_command(staged),
            BootstrapBudget::Forward,
            "remote agent activation",
        )?;
        let stdout = Self::require_success(output)?;
        self.deadline
            .forward_timeout("remote agent activation response")?;
        self.plan
            .parse_activation_stdout(staged, &stdout)
            .context("remote agent activation returned an invalid record")
    }

    fn validate_activated(&mut self, activated: &agent_install::ActivatedInstall) -> Result<()> {
        self.lease.ensure_held("normal-path agent Hello")?;
        let _hook = self.plan.post_activation_validation(activated);
        let timeout = self.deadline.forward_timeout("normal-path agent Hello")?;
        probe_normal_agent_with_timeout(self.normal_agent, timeout)
            .map_err(|error| {
                self.deadline.map_budgeted_error(
                    BootstrapBudget::Forward,
                    "normal-path agent Hello",
                    error,
                )
            })
            .context("normal-path agent Hello failed")?;
        self.deadline
            .forward_timeout("normal-path agent Hello completion")
            .map(drop)
    }

    fn reconcile_activation(
        &mut self,
        staged: &agent_install::StagedInstall,
    ) -> Result<agent_install::ActivationRecovery> {
        self.stop_normal_agent(
            BootstrapBudget::Recovery,
            "normal-path agent exit before activation reconciliation",
        )?;
        self.lease
            .ensure_held("remote agent activation reconciliation")?;
        let output = self.command_output(
            self.plan.reconcile_activation_command(staged),
            BootstrapBudget::Recovery,
            "remote agent activation reconciliation",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_reconciliation_stdout(staged, &stdout)
            .context("remote agent activation reconciliation returned an invalid record")
    }

    fn validate_reconciliation(
        &mut self,
        recovery: &agent_install::ActivationRecovery,
    ) -> Result<()> {
        self.lease.ensure_held("reconciled agent validation")?;
        let hook = self.plan.reconciliation_validation(recovery);
        match hook.mode {
            agent_install::ValidationMode::Reprobe => {
                let timeout = self.deadline.recovery_timeout("reconciled agent Hello")?;
                probe_restored_agent_at(&self.launch, &hook.executable_path, timeout)
                    .map_err(|error| {
                        self.deadline.map_budgeted_error(
                            BootstrapBudget::Recovery,
                            "reconciled agent Hello",
                            error,
                        )
                    })
                    .context("reconciled agent Hello failed")?;
                self.deadline
                    .recovery_timeout("reconciled agent Hello completion")?;
                self.normal_agent.clear_all_remote_unavailable();
                Ok(())
            }
            agent_install::ValidationMode::ExpectMissing => {
                self.confirm_target_absent(&hook)?;
                self.normal_agent.clear_all_remote_unavailable();
                Ok(())
            }
            agent_install::ValidationMode::FullHelloExact => {
                bail!("reconciliation returned an invalid validation mode")
            }
        }
    }

    fn rollback(
        &mut self,
        activated: &agent_install::ActivatedInstall,
    ) -> Result<agent_install::RollbackOutcome> {
        self.stop_normal_agent(
            BootstrapBudget::Recovery,
            "normal-path agent exit before rollback",
        )?;
        self.lease.ensure_held("remote agent rollback")?;
        let output = self.command_output(
            self.plan.rollback_command(activated),
            BootstrapBudget::Recovery,
            "remote agent rollback",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_rollback_stdout(activated, &stdout)
            .context("remote agent rollback returned an invalid record")
    }

    fn validate_rollback(&mut self, rollback: &agent_install::RollbackOutcome) -> Result<()> {
        self.lease.ensure_held("restored agent validation")?;
        let hook = self.plan.rollback_validation(rollback);
        match hook.mode {
            agent_install::ValidationMode::Reprobe => {
                let timeout = self.deadline.recovery_timeout("restored agent Hello")?;
                probe_restored_agent_at(&self.launch, &hook.executable_path, timeout)
                    .map_err(|error| {
                        self.deadline.map_budgeted_error(
                            BootstrapBudget::Recovery,
                            "restored agent Hello",
                            error,
                        )
                    })
                    .context("restored agent Hello failed")?;
                self.deadline
                    .recovery_timeout("restored agent Hello completion")?;
                self.normal_agent.clear_all_remote_unavailable();
                Ok(())
            }
            agent_install::ValidationMode::ExpectMissing => {
                self.confirm_target_absent(&hook)?;
                self.normal_agent.clear_all_remote_unavailable();
                Ok(())
            }
            agent_install::ValidationMode::FullHelloExact => {
                bail!("rollback returned an invalid validation mode")
            }
        }
    }

    fn cleanup(&mut self, staged: &agent_install::StagedInstall) -> Result<()> {
        self.lease.ensure_held("remote agent cleanup")?;
        let output = self.command_output(
            self.plan.cleanup_command(staged),
            BootstrapBudget::Recovery,
            "remote agent cleanup",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_cleanup_stdout(staged, &stdout)
            .context("remote agent cleanup returned an invalid record")
    }
}

struct WindowsSshInstallOps<'a> {
    plan: windows_agent_install::WindowsInstallPlan,
    ssh: SshTransport,
    source_path: Option<PathBuf>,
    source_size: u64,
    source_sha256: String,
    launch: AgentLaunch,
    normal_agent: &'a mut AgentClient,
    lease: &'a mut RemoteInstallLease,
    deadline: BootstrapDeadline,
}

impl WindowsSshInstallOps<'_> {
    fn recover_stale_transaction(
        &mut self,
    ) -> Result<windows_agent_install::WindowsInstallRecovery> {
        self.lease
            .ensure_held("remote agent interrupted-install recovery")?;
        let output = self.action_output(
            self.plan.recovery_script(),
            None,
            BootstrapBudget::Recovery,
            "remote agent interrupted-install recovery",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_recovery_stdout(&stdout)
            .context("remote agent interrupted-install recovery returned an invalid record")
    }

    fn command_output(
        &self,
        command: String,
        budget: BootstrapBudget,
        context: &str,
    ) -> Result<CapturedProcessOutput> {
        let timeout = self.deadline.timeout(budget, context)?;
        run_command_capture(self.ssh.command(command), None, timeout, context)
            .map_err(|error| self.deadline.map_budgeted_error(budget, context, error))
    }

    fn require_success(output: CapturedProcessOutput) -> Result<String> {
        if output.status.success() {
            return Ok(output.stdout);
        }
        let failure =
            agent_install::classify_install_failure(output.status.code(), output.stderr.as_str());
        bail!("{}: {}", install_failure_code(failure.kind), failure.detail);
    }

    fn cleanup_action_script(&self, path: &str, budget: BootstrapBudget) -> Result<()> {
        let output = self.command_output(
            self.plan.action_script_cleanup_command(path),
            budget,
            "remote installer action-script cleanup",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_action_script_cleanup_stdout(path, &stdout)
            .context("remote installer action-script cleanup returned an invalid record")
    }

    fn abort_stage(
        &mut self,
        prepared: &windows_agent_install::PreparedWindowsStage,
    ) -> Result<()> {
        self.lease.ensure_held("remote agent stage abort")?;
        let output = self.action_output(
            self.plan.abort_stage_script(prepared),
            None,
            BootstrapBudget::Recovery,
            "remote agent stage abort",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_abort_stage_stdout(prepared, &stdout)
            .context("remote agent stage abort returned an invalid record")
    }

    fn upload_stage(&self, source: &Path, remote_path: &str) -> Result<()> {
        let command = self
            .ssh
            .scp_upload_command(source, remote_path)
            .context("upload_failed: invalid scp upload plan")?;
        let output = run_command_capture(
            command,
            None,
            self.deadline
                .forward_timeout("remote agent artifact scp upload")?,
            "remote agent artifact scp upload",
        )
        .map_err(|error| {
            self.deadline.map_budgeted_error(
                BootstrapBudget::Forward,
                "remote agent artifact scp upload",
                error,
            )
        })
        .context("upload_failed")?;
        if output.status.success() {
            return Ok(());
        }
        let detail = output.stderr.trim();
        if detail.is_empty() {
            bail!(
                "upload_failed: scp exited with {}",
                output
                    .status
                    .code()
                    .map_or_else(|| "no status".to_owned(), |code| code.to_string())
            );
        }
        bail!("upload_failed: scp failed: {detail}")
    }

    fn action_output(
        &self,
        script: String,
        input: Option<Box<dyn Read + Send>>,
        budget: BootstrapBudget,
        context: &str,
    ) -> Result<CapturedProcessOutput> {
        let script = self
            .plan
            .guard_action_script(&script)
            .context("failed to apply the Windows installation lease guard")?;
        let upload_timeout = self
            .deadline
            .timeout(budget, "remote installer action-script upload")?;
        let upload = run_command_capture(
            self.ssh.command(self.plan.action_script_upload_command()),
            Some(Box::new(io::Cursor::new(script.as_bytes().to_vec()))),
            upload_timeout,
            "remote installer action-script upload",
        )
        .map_err(|error| {
            self.deadline
                .map_budgeted_error(budget, "remote installer action-script upload", error)
        })?;
        let stdout = Self::require_success(upload)?;
        let path = self
            .plan
            .parse_action_script_upload_stdout(&script, &stdout)
            .context("remote installer action-script upload returned an invalid record")?;
        let action_timeout = match self.deadline.timeout(budget, context) {
            Ok(timeout) => timeout,
            Err(error) => {
                return Err(
                    match self.cleanup_action_script(&path, BootstrapBudget::Recovery) {
                        Ok(()) => error,
                        Err(cleanup) => {
                            error.context(format!("action_script_cleanup_failed: {cleanup}"))
                        }
                    },
                );
            }
        };
        let action = run_command_capture(
            self.ssh
                .command(self.plan.action_script_run_command(&path, &script)),
            input,
            action_timeout,
            context,
        )
        .map_err(|error| self.deadline.map_budgeted_error(budget, context, error));
        let cleanup = self.cleanup_action_script(&path, budget);
        match action {
            Ok(output) => {
                if let Err(error) = cleanup {
                    eprintln!(
                        "remote installer action completed but its temporary script could not be removed: {error}"
                    );
                }
                Ok(output)
            }
            Err(error) => Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => error.context(format!("action_script_cleanup_failed: {cleanup}")),
            }),
        }
    }

    fn confirm_target_absent(&self, hook: &agent_install::PosixValidationHook) -> Result<()> {
        let command = self
            .plan
            .absence_check_script(hook)
            .context("invalid absent-target validation hook")?;
        let output = self.action_output(
            command,
            None,
            BootstrapBudget::Recovery,
            "remote agent absence check",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_absence_check_stdout(hook, &stdout)
            .context("remote agent absence check returned an invalid record")
    }

    fn stop_normal_agent(&mut self, budget: BootstrapBudget, context: &str) -> Result<()> {
        let timeout = self.deadline.timeout(budget, context)?;
        self.normal_agent
            .kill_worker_with_timeout(timeout, context)
            .map_err(|error| self.deadline.map_budgeted_error(budget, context, error))?;
        self.deadline.timeout(budget, context).map(drop)
    }
}

impl AgentInstallOps for WindowsSshInstallOps<'_> {
    fn stage(&mut self) -> Result<agent_install::StagedInstall> {
        self.lease.ensure_held("remote agent stage preparation")?;
        let source_path = self
            .source_path
            .take()
            .ok_or_else(|| anyhow!("agent source was already consumed"))?;
        let prepare = self.action_output(
            self.plan.prepare_stage_script(),
            None,
            BootstrapBudget::Forward,
            "remote agent stage preparation",
        )?;
        let stdout = Self::require_success(prepare)?;
        let prepared = self
            .plan
            .parse_prepare_stage_stdout(&stdout)
            .context("remote agent stage preparation returned an invalid record")?;
        let result = (|| {
            self.lease.ensure_held("remote agent artifact scp upload")?;
            self.upload_stage(&source_path, &prepared.staged.stage_path)?;
            self.lease.ensure_held("remote agent stage finalization")?;
            let output = self.action_output(
                self.plan
                    .finalize_stage_script(&prepared, self.source_size, &self.source_sha256),
                None,
                BootstrapBudget::Forward,
                "remote agent stage finalization",
            )?;
            let stdout = Self::require_success(output)?;
            self.plan
                .parse_finalize_stage_stdout(&prepared, &stdout)
                .context("remote agent stage finalization returned an invalid record")
        })();
        match result {
            Ok(staged) => Ok(staged),
            Err(error) => Err(match self.abort_stage(&prepared) {
                Ok(()) => error,
                Err(abort) => error.context(format!("stage_abort_failed: {abort}")),
            }),
        }
    }

    fn validate_staged(&mut self, staged: &agent_install::StagedInstall) -> Result<()> {
        self.lease.ensure_held("staged agent exact Hello")?;
        let hook = self.plan.staged_validation(staged);
        let timeout = self.deadline.forward_timeout("staged agent exact Hello")?;
        probe_agent_at(&self.launch, &hook.executable_path, timeout)
            .map_err(|error| {
                self.deadline.map_budgeted_error(
                    BootstrapBudget::Forward,
                    "staged agent exact Hello",
                    error,
                )
            })
            .context("staged agent Hello failed")?;
        self.deadline
            .forward_timeout("staged agent exact Hello completion")
            .map(drop)
    }

    fn ensure_activation_budget(&mut self) -> Result<()> {
        self.lease
            .ensure_held("remote agent activation budget check")?;
        self.deadline
            .forward_timeout("remote agent activation")
            .map(drop)
    }

    fn activate(
        &mut self,
        staged: &agent_install::StagedInstall,
    ) -> Result<agent_install::ActivatedInstall> {
        self.lease.ensure_held("remote agent activation")?;
        let output = self.action_output(
            self.plan.activate_script(staged),
            None,
            BootstrapBudget::Forward,
            "remote agent activation",
        )?;
        let stdout = Self::require_success(output)?;
        self.deadline
            .forward_timeout("remote agent activation response")?;
        self.plan
            .parse_activation_stdout(staged, &stdout)
            .context("remote agent activation returned an invalid record")
    }

    fn reconcile_activation(
        &mut self,
        staged: &agent_install::StagedInstall,
    ) -> Result<agent_install::ActivationRecovery> {
        self.stop_normal_agent(
            BootstrapBudget::Recovery,
            "normal-path agent exit before activation reconciliation",
        )?;
        self.lease
            .ensure_held("remote agent activation reconciliation")?;
        let output = self.action_output(
            self.plan.reconcile_activation_script(staged),
            None,
            BootstrapBudget::Recovery,
            "remote agent activation reconciliation",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_reconciliation_stdout(staged, &stdout)
            .context("remote agent activation reconciliation returned an invalid record")
    }

    fn validate_reconciliation(
        &mut self,
        recovery: &agent_install::ActivationRecovery,
    ) -> Result<()> {
        self.lease.ensure_held("reconciled agent validation")?;
        let hook = self.plan.reconciliation_validation(recovery);
        match hook.mode {
            agent_install::ValidationMode::Reprobe => {
                let timeout = self.deadline.recovery_timeout("reconciled agent Hello")?;
                probe_restored_agent_at(&self.launch, &hook.executable_path, timeout)
                    .map_err(|error| {
                        self.deadline.map_budgeted_error(
                            BootstrapBudget::Recovery,
                            "reconciled agent Hello",
                            error,
                        )
                    })
                    .context("reconciled agent Hello failed")?;
                self.deadline
                    .recovery_timeout("reconciled agent Hello completion")?;
                self.normal_agent.clear_all_remote_unavailable();
                Ok(())
            }
            agent_install::ValidationMode::ExpectMissing => {
                self.confirm_target_absent(&hook)?;
                self.normal_agent.clear_all_remote_unavailable();
                Ok(())
            }
            agent_install::ValidationMode::FullHelloExact => {
                bail!("reconciliation returned an invalid validation mode")
            }
        }
    }

    fn validate_activated(&mut self, activated: &agent_install::ActivatedInstall) -> Result<()> {
        self.lease.ensure_held("normal-path agent Hello")?;
        let _hook = self.plan.post_activation_validation(activated);
        let timeout = self.deadline.forward_timeout("normal-path agent Hello")?;
        probe_normal_agent_with_timeout(self.normal_agent, timeout)
            .map_err(|error| {
                self.deadline.map_budgeted_error(
                    BootstrapBudget::Forward,
                    "normal-path agent Hello",
                    error,
                )
            })
            .context("normal-path agent Hello failed")?;
        self.deadline
            .forward_timeout("normal-path agent Hello completion")
            .map(drop)
    }

    fn rollback(
        &mut self,
        activated: &agent_install::ActivatedInstall,
    ) -> Result<agent_install::RollbackOutcome> {
        self.stop_normal_agent(
            BootstrapBudget::Recovery,
            "normal-path agent exit before rollback",
        )?;
        self.lease.ensure_held("remote agent rollback")?;
        let output = self.action_output(
            self.plan.rollback_script(activated),
            None,
            BootstrapBudget::Recovery,
            "remote agent rollback",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_rollback_stdout(activated, &stdout)
            .context("remote agent rollback returned an invalid record")
    }

    fn validate_rollback(&mut self, rollback: &agent_install::RollbackOutcome) -> Result<()> {
        self.lease.ensure_held("restored agent validation")?;
        let hook = self.plan.rollback_validation(rollback);
        match hook.mode {
            agent_install::ValidationMode::Reprobe => {
                let timeout = self.deadline.recovery_timeout("restored agent Hello")?;
                probe_restored_agent_at(&self.launch, &hook.executable_path, timeout)
                    .map_err(|error| {
                        self.deadline.map_budgeted_error(
                            BootstrapBudget::Recovery,
                            "restored agent Hello",
                            error,
                        )
                    })
                    .context("restored agent Hello failed")?;
                self.deadline
                    .recovery_timeout("restored agent Hello completion")?;
                self.normal_agent.clear_all_remote_unavailable();
                Ok(())
            }
            agent_install::ValidationMode::ExpectMissing => {
                self.confirm_target_absent(&hook)?;
                self.normal_agent.clear_all_remote_unavailable();
                Ok(())
            }
            agent_install::ValidationMode::FullHelloExact => {
                bail!("rollback returned an invalid validation mode")
            }
        }
    }

    fn cleanup(&mut self, staged: &agent_install::StagedInstall) -> Result<()> {
        self.lease.ensure_held("remote agent cleanup")?;
        let output = self.action_output(
            self.plan.cleanup_script(staged),
            None,
            BootstrapBudget::Recovery,
            "remote agent cleanup",
        )?;
        let stdout = Self::require_success(output)?;
        self.plan
            .parse_cleanup_stdout(staged, &stdout)
            .context("remote agent cleanup returned an invalid record")
    }
}

fn install_failure_code(kind: agent_install::InstallFailureKind) -> &'static str {
    use agent_install::InstallFailureKind;
    match kind {
        InstallFailureKind::AlreadyExists => "already_exists",
        InstallFailureKind::InstallInProgress => "install_in_progress",
        InstallFailureKind::InvalidTarget => "invalid_target",
        InstallFailureKind::StageCreateFailed => "stage_create_failed",
        InstallFailureKind::UploadFailed => "upload_failed",
        InstallFailureKind::ChmodFailed => "chmod_failed",
        InstallFailureKind::VersionExecutionFailed => "version_exec_failed",
        InstallFailureKind::VersionMismatch => "version_mismatch",
        InstallFailureKind::InvalidState => "invalid_state",
        InstallFailureKind::ActivationFailed => "activation_failed",
        InstallFailureKind::ProcessInUse => "process_in_use",
        InstallFailureKind::RollbackFailed => "rollback_failed",
        InstallFailureKind::CleanupFailed => "cleanup_failed",
        InstallFailureKind::CommandFailed => "command_failed",
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ClientRequest {
    id: u64,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct ClientResponse {
    id: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClientNotification {
    method: String,
    params: Value,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ServerMessage {
    Response(ClientResponse),
    Notification(ClientNotification),
}

#[derive(Debug, Clone)]
struct MirrorEntry {
    relative_path: String,
    local_path: PathBuf,
    size: u64,
    remote_hash: Option<String>,
    local_hash: Option<String>,
    state: String,
    dirty: bool,
    validated_at_ms: i64,
    validation_state: String,
    last_error: Option<String>,
}

fn mirror_entry_from_row(row: &Row<'_>) -> rusqlite::Result<MirrorEntry> {
    Ok(MirrorEntry {
        relative_path: row.get(0)?,
        local_path: PathBuf::from(row.get::<_, String>(1)?),
        size: row.get::<_, i64>(2)? as u64,
        remote_hash: row.get(3)?,
        local_hash: row.get(4)?,
        state: row.get(5)?,
        dirty: row.get::<_, i64>(6)? != 0,
        validated_at_ms: row.get(7)?,
        validation_state: row.get(8)?,
        last_error: row.get(9)?,
    })
}

#[derive(Debug, Clone)]
struct SaveQueueEntry {
    id: i64,
    relative_path: String,
    expected_hash: Option<String>,
    local_hash: String,
    snapshot_path: PathBuf,
}

#[derive(Debug, Clone)]
struct ConflictQueueEntry {
    id: i64,
    relative_path: String,
    local_hash: String,
    snapshot_path: Option<PathBuf>,
    remote_conflict_path: Option<PathBuf>,
    conflict_actual_hash: Option<String>,
    remote_conflict_truncated: bool,
}

#[derive(Debug)]
struct SearchIndexMeta {
    local_hash: String,
    state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchIndexReadiness {
    Ready,
    Legacy,
}

#[derive(Debug)]
enum SaveAttempt {
    Applied {
        path: String,
        hash: String,
        size: u64,
    },
    Conflict {
        path: String,
        expected_hash: Option<String>,
        actual_hash: Option<String>,
        remote_path: PathBuf,
        remote_content_truncated: bool,
        remote_size: Option<u64>,
        remote_content_bytes: usize,
    },
    Queued {
        path: String,
        reason: String,
        remote_failure: bool,
    },
}

impl SaveAttempt {
    fn should_stop_queue_replay(&self) -> bool {
        matches!(
            self,
            SaveAttempt::Queued {
                remote_failure: true,
                ..
            }
        )
    }
}

enum HydrationMode {
    Batch,
    Chunked,
}

impl HydrationMode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Batch => "batch",
            Self::Chunked => "chunked",
        }
    }
}

#[cfg_attr(windows, allow(clippy::large_enum_variant))]
enum HydrateOutcome {
    Hydrated {
        entry: MirrorEntry,
        mode: HydrationMode,
    },
    Preempted,
}

enum HydrationInstall {
    ReplaceWithPart,
    AdoptExisting { local_hash: String },
}

#[derive(Debug, Clone)]
struct ProcessLaunchPlan {
    program: String,
    args: Vec<String>,
    current_dir: Option<PathBuf>,
    stdin_prefix: Vec<u8>,
}

impl ProcessLaunchPlan {
    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }
        command
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SshTransport {
    program: PathBuf,
    target: String,
    connect_timeout_seconds: u64,
}

impl SshTransport {
    fn command_args(&self, remote_command: String) -> Vec<String> {
        vec![
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            format!("ConnectTimeout={}", self.connect_timeout_seconds),
            "-o".to_string(),
            "ServerAliveInterval=15".to_string(),
            "-o".to_string(),
            "ServerAliveCountMax=2".to_string(),
            "-o".to_string(),
            "ControlMaster=no".to_string(),
            "-o".to_string(),
            "ControlPath=none".to_string(),
            "--".to_string(),
            self.target.clone(),
            remote_command,
        ]
    }

    fn command(&self, remote_command: String) -> Command {
        let mut command = Command::new(&self.program);
        command.args(self.command_args(remote_command));
        command
    }

    fn scp_program(&self) -> Result<PathBuf> {
        let filename = self
            .program
            .file_name()
            .and_then(|filename| filename.to_str())
            .ok_or_else(|| anyhow!("ssh program path does not have a UTF-8 filename"))?;
        let scp = if filename.eq_ignore_ascii_case("ssh.exe") {
            "scp.exe"
        } else if filename == "ssh" {
            "scp"
        } else {
            bail!(
                "cannot derive the scp companion from ssh program {}",
                self.program.display()
            );
        };
        Ok(self.program.with_file_name(scp))
    }

    fn scp_upload_command(&self, source: &Path, remote_path: &str) -> Result<Command> {
        let remote_path = windows_scp_remote_path(remote_path)?;
        let destination = format!("{}:{remote_path}", self.target);
        let mut command = Command::new(self.scp_program()?);
        command
            .args([
                "-s",
                "-q",
                "-o",
                "BatchMode=yes",
                "-o",
                &format!("ConnectTimeout={}", self.connect_timeout_seconds),
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=none",
                "--",
            ])
            .arg(source)
            .arg(destination);
        Ok(command)
    }
}

fn windows_scp_remote_path(path: &str) -> Result<String> {
    if path.chars().any(char::is_control) || path.starts_with(['/', '\\']) {
        bail!("Windows scp destination must be an absolute drive path without controls");
    }
    let normalized = path.replace('\\', "/");
    let bytes = normalized.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'/'
        || normalized[3..].contains(':')
    {
        bail!("Windows scp destination must use absolute drive-path syntax");
    }
    if normalized[3..]
        .split('/')
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        bail!("Windows scp destination contains an invalid path segment");
    }
    Ok(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteTransport {
    Local,
    Ssh(SshTransport),
}

impl RemoteTransport {
    fn from_ssh(ssh: Option<String>, connect_timeout_seconds: u64) -> Result<Self> {
        match ssh {
            Some(target) => {
                validate_ssh_destination(&target)?;
                Ok(Self::Ssh(SshTransport {
                    program: PathBuf::from("ssh"),
                    target,
                    connect_timeout_seconds,
                }))
            }
            None => Ok(Self::Local),
        }
    }

    fn workspace_identity(&self) -> String {
        match self {
            Self::Local => "local".to_string(),
            Self::Ssh(ssh) => ssh.target.clone(),
        }
    }

    fn normalize_remote_root(&self, remote_root: PathBuf) -> Result<PathBuf> {
        if matches!(self, Self::Local) {
            return Ok(remote_root);
        }
        let remote_root = remote_root
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow!("SSH remote root must be valid UTF-8"))?;
        if remote_root.chars().any(char::is_control) {
            bail!("SSH remote root must not contain control characters");
        }
        let bytes = remote_root.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'/'
        {
            let mut canonical = bytes.to_vec();
            canonical[0] = canonical[0].to_ascii_uppercase();
            return Ok(PathBuf::from(
                String::from_utf8(canonical).expect("uppercasing ASCII preserves UTF-8"),
            ));
        }
        Ok(PathBuf::from(remote_root))
    }

    fn agent_plan(
        &self,
        agent: &str,
        remote_root: &Path,
        host: &RemoteHostInfo,
    ) -> Result<ProcessLaunchPlan> {
        match self {
            Self::Local => Ok(ProcessLaunchPlan {
                program: agent.to_string(),
                args: vec![
                    "serve".to_string(),
                    "--root".to_string(),
                    remote_root.to_string_lossy().to_string(),
                ],
                current_dir: None,
                stdin_prefix: Vec::new(),
            }),
            Self::Ssh(ssh) => {
                if remote_agent_uses_managed_path(agent) {
                    validate_managed_remote_agent_name(agent)?;
                }
                validate_remote_root(host, remote_root)?;
                let (remote_command, stdin_prefix) = match host.path_style {
                    RemotePathStyle::Posix => {
                        (posix_agent_remote_command(agent, remote_root), Vec::new())
                    }
                    RemotePathStyle::Windows => {
                        let launch = powershell_agent_remote_command(agent, remote_root, host)?;
                        (launch.command, launch.stdin_prefix)
                    }
                };
                Ok(ProcessLaunchPlan {
                    program: ssh.program.to_string_lossy().to_string(),
                    args: ssh.command_args(remote_command),
                    current_dir: None,
                    stdin_prefix,
                })
            }
        }
    }

    fn lsp_plan(
        &self,
        remote_root: PathBuf,
        command: Vec<String>,
        host: &RemoteHostInfo,
    ) -> Result<ProcessLaunchPlan> {
        match self {
            Self::Local => Ok(ProcessLaunchPlan {
                program: command[0].clone(),
                args: command[1..].to_vec(),
                current_dir: Some(remote_root),
                stdin_prefix: Vec::new(),
            }),
            Self::Ssh(ssh) => {
                validate_remote_root(host, &remote_root)?;
                let (remote_command, stdin_prefix) = match host.path_style {
                    RemotePathStyle::Posix => {
                        (posix_lsp_remote_command(remote_root, command), Vec::new())
                    }
                    RemotePathStyle::Windows => {
                        let launch = powershell_lsp_remote_command(remote_root, command)?;
                        (launch.command, launch.stdin_prefix)
                    }
                };
                Ok(ProcessLaunchPlan {
                    program: ssh.program.to_string_lossy().to_string(),
                    args: ssh.command_args(remote_command),
                    current_dir: None,
                    stdin_prefix,
                })
            }
        }
    }

    fn launch_context_suffix(&self) -> String {
        match self {
            Self::Local => String::new(),
            Self::Ssh(ssh) => format!(" through ssh target `{}`", ssh.target),
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Local => json!({
                "kind": "local",
                "endpoint": Value::Null,
                "connect_timeout_ms": Value::Null,
                "agent_io": "stdio"
            }),
            Self::Ssh(ssh) => json!({
                "kind": "ssh",
                "endpoint": ssh.target,
                "connect_timeout_ms": ssh.connect_timeout_seconds.saturating_mul(1000),
                "agent_io": "stdio",
                "target": ssh.target,
                "ssh_connect_timeout_seconds": ssh.connect_timeout_seconds
            }),
        }
    }
}

fn validate_ssh_destination(destination: &str) -> Result<()> {
    if destination.is_empty() {
        bail!("ssh destination must not be empty");
    }
    if destination.starts_with('-') {
        bail!("ssh destination must not begin with `-`");
    }
    if destination
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        bail!("ssh destination must not contain whitespace or control characters");
    }
    if destination.contains(['/', '\\']) {
        bail!("ssh destination must not contain path separators");
    }

    let mut parts = destination.split('@');
    let first = parts.next().unwrap_or_default();
    let second = parts.next();
    if parts.next().is_some() {
        bail!("ssh destination must contain at most one `@`");
    }
    let (user, host) = match second {
        Some(host) => (Some(first), host),
        None => (None, first),
    };
    if user.is_some_and(|user| {
        user.is_empty()
            || !user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }) {
        bail!("ssh destination contains an invalid user name");
    }
    if host.is_empty() || host.starts_with('-') {
        bail!("ssh destination contains an invalid host name");
    }

    if host.starts_with('[') || host.ends_with(']') {
        if !(host.starts_with('[') && host.ends_with(']')) || host.len() <= 2 {
            bail!("ssh destination contains an invalid bracketed host");
        }
        let address = &host[1..host.len() - 1];
        if !address.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'%' | b'_' | b'-')
        }) {
            bail!("ssh destination contains an invalid bracketed host");
        }
    } else if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("ssh destination contains an invalid host name");
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AgentCompatibilityFailure {
    VersionMismatch { agent_version: String },
    ProtocolMismatch { protocol_version: u16 },
}

impl AgentCompatibilityFailure {
    fn as_str(&self) -> &'static str {
        match self {
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::ProtocolMismatch { .. } => "protocol_mismatch",
        }
    }

    fn insert_observed_version(&self, object: &mut Map<String, Value>) {
        match self {
            Self::VersionMismatch { agent_version } => {
                object.insert("agent_version".to_owned(), json!(agent_version));
            }
            Self::ProtocolMismatch { protocol_version } => {
                object.insert("protocol_version".to_owned(), json!(protocol_version));
            }
        }
    }
}

#[derive(Debug)]
struct AgentCompatibilityError {
    failure: Option<AgentCompatibilityFailure>,
    message: String,
}

impl std::fmt::Display for AgentCompatibilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AgentCompatibilityError {}

fn validate_agent_hello(
    agent_version: &str,
    protocol_version: u16,
) -> std::result::Result<(), AgentCompatibilityError> {
    if protocol_version != PROTOCOL_VERSION {
        return Err(AgentCompatibilityError {
            failure: Some(AgentCompatibilityFailure::ProtocolMismatch { protocol_version }),
            message: format!(
                "protocol version mismatch: sidecar={PROTOCOL_VERSION} agent={protocol_version}"
            ),
        });
    }
    if agent_version != env!("CARGO_PKG_VERSION") {
        let valid_agent_version = Version::parse(agent_version)
            .ok()
            .filter(|version| version.to_string() == agent_version)
            .map(|_| sanitize_agent_error_text(agent_version));
        let message = if valid_agent_version.is_some() {
            format!(
                "package version mismatch: sidecar={} agent={agent_version}",
                env!("CARGO_PKG_VERSION")
            )
        } else {
            "agent Hello reported a malformed package version".to_owned()
        };
        return Err(AgentCompatibilityError {
            failure: valid_agent_version
                .map(|agent_version| AgentCompatibilityFailure::VersionMismatch { agent_version }),
            message,
        });
    }
    Ok(())
}

fn detect_remote_host_info(
    transport: &RemoteTransport,
    request_timeout: Duration,
) -> Result<RemoteHostInfo> {
    let RemoteTransport::Ssh(ssh) = transport else {
        return local_host_info();
    };
    let probe_budget = request_timeout.min(Duration::from_millis(REMOTE_HOST_PROBE_TIMEOUT_MS));
    let started = Instant::now();

    let powershell_error = match run_remote_host_probe(
        ssh,
        powershell_probe_command(),
        probe_budget,
        "PowerShell remote host probe",
    ) {
        Ok(stdout) => match parse_powershell_probe(&stdout) {
            Ok(info) => return Ok(info),
            Err(error) => error,
        },
        Err(error) => error,
    };
    let remaining = probe_budget.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(powershell_error).context(format!(
            "failed to detect remote host within {} ms after the PowerShell probe failed",
            probe_budget.as_millis()
        ));
    }

    match run_remote_host_probe(
        ssh,
        posix_probe_command(),
        remaining,
        "POSIX remote host probe",
    ) {
        Ok(stdout) => parse_posix_probe(&stdout).with_context(|| {
            format!("failed to detect remote host (PowerShell probe failed: {powershell_error})")
        }),
        Err(posix_error) => Err(posix_error).context(format!(
            "failed to detect remote host after the PowerShell probe failed: {powershell_error}"
        )),
    }
}

fn run_remote_host_probe(
    ssh: &SshTransport,
    remote_command: String,
    timeout: Duration,
    context: &str,
) -> Result<String> {
    let output = run_command_capture(ssh.command(remote_command), None, timeout, context)?;
    if !output.status.success() {
        let stderr = output.stderr.trim();
        bail!(
            "{context} exited with {}{}",
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    Ok(output.stdout)
}

#[derive(Debug, Clone)]
struct AgentLaunch {
    agent: String,
    local_agent: Option<PathBuf>,
    registry: Option<RegistryLaunchConfig>,
    remote_root: PathBuf,
    request_timeout: Duration,
    transport: RemoteTransport,
    remote_host_info: Arc<Mutex<Option<RemoteHostInfo>>>,
    worker_generation: Arc<AtomicU64>,
}

impl AgentLaunch {
    #[cfg(test)]
    fn remote_host_info(&self) -> Result<RemoteHostInfo> {
        self.remote_host_info_with_timeout(self.request_timeout)
    }

    fn remote_host_info_with_timeout(&self, timeout: Duration) -> Result<RemoteHostInfo> {
        match self.remote_host_info.try_lock() {
            Ok(cached) => {
                if let Some(info) = cached.as_ref() {
                    return Ok(info.clone());
                }
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                bail!("remote host information cache lock poisoned")
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        let info = detect_remote_host_info(&self.transport, timeout)?;
        if matches!(self.transport, RemoteTransport::Ssh(_)) {
            validate_remote_root(&info, &self.remote_root)?;
        }
        match self.remote_host_info.try_lock() {
            Ok(mut cached) => *cached = Some(info.clone()),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                bail!("remote host information cache lock poisoned")
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        Ok(info)
    }

    fn invalidate_remote_host_info(&self) {
        if let Ok(mut cached) = self.remote_host_info.lock() {
            *cached = None;
        }
    }

    fn cached_remote_host_info(&self) -> Option<RemoteHostInfo> {
        self.remote_host_info
            .try_lock()
            .ok()
            .and_then(|cached| cached.clone())
    }
}

#[derive(Clone, Default)]
struct AgentInterrupt {
    // Keep every worker registered until its worker thread exits. A request
    // timeout may retire a worker without joining it, and maintenance must
    // still be able to terminate that older worker before replacing an agent.
    current_abort: Arc<Mutex<Vec<Arc<dyn AgentAbortHandle>>>>,
    shutdown_requested: Arc<AtomicBool>,
}

trait AgentAbortHandle: Send + Sync {
    /// Abort the current lane worker. This must be idempotent, safe to call from
    /// preemption and shutdown paths, and strong enough to unblock an in-flight
    /// AgentSession::request for the lane.
    fn abort(&self);

    /// Report whether the process resource has been reaped. This operation must
    /// never block: request timeout and maintenance paths poll it against their
    /// own deadline.
    fn is_stopped(&self) -> bool;
}

struct ProcessAgentAbort {
    child: Arc<Mutex<Child>>,
}

impl AgentAbortHandle for ProcessAgentAbort {
    fn abort(&self) {
        match self.child.try_lock() {
            Ok(mut child) => kill_child_tree(&mut child),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                kill_child_tree(&mut poisoned.into_inner());
            }
            // Another abort/status probe owns the child briefly. That owner is
            // already progressing teardown, so a timeout path must not block.
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
    }

    fn is_stopped(&self) -> bool {
        match self.child.try_lock() {
            Ok(mut child) => child.try_wait().ok().flatten().is_some(),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                poisoned.into_inner().try_wait().ok().flatten().is_some()
            }
            Err(std::sync::TryLockError::WouldBlock) => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct AgentPreempt {
    epoch: Arc<AtomicU64>,
}

impl AgentInterrupt {
    fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.kill_current();
    }

    fn set_abort_handle(&self, handle: Arc<dyn AgentAbortHandle>) {
        if let Ok(mut current) = self.current_abort.lock() {
            current.push(Arc::clone(&handle));
        }
        // Close the registration race with request_shutdown(): shutdown can
        // snapshot an empty handle list after a worker's initial shutdown
        // check but before that worker publishes its process handle. Checking
        // again after publication guarantees that either request_shutdown()
        // observes the handle or this registration aborts it directly.
        if self.is_shutdown_requested() {
            handle.abort();
        }
    }

    fn clear_abort_handle(&self, handle: &Arc<dyn AgentAbortHandle>) {
        if let Ok(mut current) = self.current_abort.lock() {
            current.retain(|current_handle| !Arc::ptr_eq(current_handle, handle));
        }
    }

    fn abort_handles_snapshot(&self) -> Option<Vec<Arc<dyn AgentAbortHandle>>> {
        match self.current_abort.try_lock() {
            Ok(current) => Some(current.iter().cloned().collect()),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                Some(poisoned.into_inner().iter().cloned().collect())
            }
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    fn kill_current(&self) {
        let Some(handles) = self.abort_handles_snapshot() else {
            return;
        };
        for handle in handles {
            handle.abort();
        }
    }

    fn kill_current_and_wait(&self, timeout: Duration, context: &str) -> Result<()> {
        let started = Instant::now();
        loop {
            if let Some(handles) = self.abort_handles_snapshot() {
                for handle in &handles {
                    handle.abort();
                }
                if handles.iter().all(|handle| handle.is_stopped()) {
                    return Ok(());
                }
            }
            let remaining = remaining_timeout_since(started, timeout);
            if remaining.is_zero() {
                return Err(anyhow!(AgentWorkerExitTimeoutError {
                    context: context.to_string(),
                }));
            }
            thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }

    #[cfg(test)]
    fn has_current_abort(&self) -> bool {
        self.current_abort
            .lock()
            .map(|current| !current.is_empty())
            .unwrap_or(false)
    }
}

impl AgentPreempt {
    fn request_preemption(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    fn changed_since(&self, epoch: u64) -> bool {
        self.epoch() != epoch
    }
}

struct AgentWorker {
    tx: mpsc::Sender<AgentWorkerCommand>,
    abort: Arc<dyn AgentAbortHandle>,
    join: Option<thread::JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteAgentLaunchFailure {
    Missing,
    NotExecutable,
    RootMissing,
}

impl RemoteAgentLaunchFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::NotExecutable => "not_executable",
            Self::RootMissing => "root_missing",
        }
    }

    fn agent_status(self) -> &'static str {
        match self {
            Self::Missing => "missing_agent",
            Self::NotExecutable => "agent_not_executable",
            Self::RootMissing => "remote_root_missing",
        }
    }

    fn detail(self) -> &'static str {
        match self {
            Self::Missing => "remote agent launcher reported a missing executable",
            Self::NotExecutable => {
                "remote agent launcher reported a non-executable or invalid executable"
            }
            Self::RootMissing => "remote agent launcher reported a missing remote root",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustedAgentFailure {
    Launch(RemoteAgentLaunchFailure),
    Compatibility(AgentCompatibilityFailure),
}

impl TrustedAgentFailure {
    fn insert_into(&self, object: &mut Map<String, Value>) {
        match self {
            Self::Launch(failure) => {
                object.insert("agent_launch_failure".to_owned(), json!(failure.as_str()));
            }
            Self::Compatibility(failure) => {
                object.insert(
                    "agent_compatibility_failure".to_owned(),
                    json!(failure.as_str()),
                );
                failure.insert_observed_version(object);
            }
        }
    }

    fn trace_value(&self) -> &'static str {
        match self {
            Self::Launch(failure) => failure.as_str(),
            Self::Compatibility(failure) => failure.as_str(),
        }
    }
}

#[derive(Debug, Default)]
struct AgentStderrTailState {
    bytes: VecDeque<u8>,
    truncated: bool,
    read_error: Option<String>,
}

struct AgentStderrCapture {
    state: Arc<Mutex<AgentStderrTailState>>,
    join: Option<thread::JoinHandle<()>>,
}

impl AgentStderrCapture {
    fn spawn<R>(mut stderr: R) -> Result<Self>
    where
        R: Read + Send + 'static,
    {
        let state = Arc::new(Mutex::new(AgentStderrTailState::default()));
        let reader_state = Arc::clone(&state);
        let join = thread::Builder::new()
            .name("nrm-agent-stderr".to_owned())
            .spawn(move || {
                let mut buffer = [0_u8; 8 * 1024];
                loop {
                    match stderr.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(read) => {
                            if let Ok(mut state) = reader_state.lock() {
                                append_agent_stderr_tail(&mut state, &buffer[..read]);
                            }
                        }
                        Err(error) => {
                            if let Ok(mut state) = reader_state.lock() {
                                state.read_error = Some(error.to_string());
                            }
                            break;
                        }
                    }
                }
            })
            .context("failed to start remote-agent stderr drainer")?;
        Ok(Self {
            state,
            join: Some(join),
        })
    }

    fn is_finished(&self) -> bool {
        self.join
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
    }

    fn wait_for_finish(&self, timeout: Duration) {
        let started = Instant::now();
        while !self.is_finished() && started.elapsed() < timeout {
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn snapshot(&self) -> AgentStderrSnapshot {
        match self.state.lock() {
            Ok(state) => AgentStderrSnapshot {
                bytes: state.bytes.iter().copied().collect(),
                truncated: state.truncated,
                read_error: state.read_error.clone(),
            },
            Err(poisoned) => {
                let state = poisoned.into_inner();
                AgentStderrSnapshot {
                    bytes: state.bytes.iter().copied().collect(),
                    truncated: state.truncated,
                    read_error: state.read_error.clone(),
                }
            }
        }
    }

    fn finish_bounded(mut self, timeout: Duration) -> bool {
        self.wait_for_finish(timeout);
        let Some(join) = self.join.take() else {
            return true;
        };
        if join.is_finished() {
            let _ = join.join();
            true
        } else {
            // A remote descendant can inherit the SSH stderr pipe after the
            // launcher itself has exited. Dropping the join handle detaches the
            // bounded diagnostic drainer so worker teardown never waits on an
            // untrusted pipe lifetime.
            drop(join);
            false
        }
    }
}

#[derive(Debug)]
struct AgentStderrSnapshot {
    bytes: Vec<u8>,
    truncated: bool,
    read_error: Option<String>,
}

fn append_agent_stderr_tail(state: &mut AgentStderrTailState, bytes: &[u8]) {
    if bytes.len() >= AGENT_STDERR_TAIL_MAX_BYTES {
        state.bytes.clear();
        state.bytes.extend(
            bytes[bytes.len() - AGENT_STDERR_TAIL_MAX_BYTES..]
                .iter()
                .copied(),
        );
        state.truncated = true;
        return;
    }
    let excess = state
        .bytes
        .len()
        .saturating_add(bytes.len())
        .saturating_sub(AGENT_STDERR_TAIL_MAX_BYTES);
    if excess > 0 {
        state.bytes.drain(..excess);
        state.truncated = true;
    }
    state.bytes.extend(bytes.iter().copied());
}

fn agent_transport_error_reply(
    error: String,
    child: &Arc<Mutex<Child>>,
    stderr: &AgentStderrCapture,
) -> AgentWorkerReply {
    let Some(status) = poll_agent_exit_status(child, AGENT_EXIT_DIAGNOSTIC_GRACE) else {
        return AgentWorkerReply::TransportError(error);
    };
    stderr.wait_for_finish(AGENT_EXIT_DIAGNOSTIC_GRACE);
    let snapshot = stderr.snapshot();
    AgentWorkerReply::TransportError(format_agent_transport_error(error, status, &snapshot))
}

fn poll_agent_exit_status(child: &Arc<Mutex<Child>>, timeout: Duration) -> Option<ExitStatus> {
    let started = Instant::now();
    loop {
        let status = match child.try_lock() {
            Ok(mut child) => child.try_wait().ok().flatten(),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                poisoned.into_inner().try_wait().ok().flatten()
            }
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        if status.is_some() {
            return status;
        }
        if started.elapsed() >= timeout {
            return None;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn format_agent_transport_error(
    error: String,
    status: ExitStatus,
    stderr: &AgentStderrSnapshot,
) -> String {
    let error = sanitize_agent_error_text(&error);
    let mut message = format!("{error}; agent process exited with {status}");
    let stderr_text = String::from_utf8_lossy(&stderr.bytes);
    let stderr_text = stderr_text.trim();
    if !stderr_text.is_empty() {
        const MAX_DETAIL_CHARS: usize = 4096;
        let stderr_text = sanitize_agent_error_text(stderr_text);
        let chars: Vec<_> = stderr_text.chars().collect();
        let detail = if chars.len() > MAX_DETAIL_CHARS {
            chars[chars.len() - MAX_DETAIL_CHARS..].iter().collect()
        } else {
            stderr_text.to_owned()
        };
        let prefix = if stderr.truncated || chars.len() > MAX_DETAIL_CHARS {
            "truncated stderr tail"
        } else {
            "stderr"
        };
        message.push_str(&format!("; {prefix}: {detail}"));
    }
    if let Some(read_error) = &stderr.read_error {
        message.push_str(&format!(
            "; stderr capture failed: {}",
            sanitize_agent_error_text(read_error)
        ));
    }
    message
}

fn sanitize_agent_error_text(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

struct RetiredAgentWorker {
    abort: Arc<dyn AgentAbortHandle>,
    join: Option<thread::JoinHandle<()>>,
    reaper_join: Option<thread::JoinHandle<()>>,
}

trait AgentSession: Send {
    fn request(&mut self, id: RequestId, request: Request) -> Result<AgentWorkerReply>;
}

struct FramedAgentSession<W, R> {
    writer: W,
    reader: BufReader<R>,
    launch_prelude_pending: bool,
}

impl<W, R: Read> FramedAgentSession<W, R> {
    fn new(writer: W, reader: R) -> Self {
        Self {
            writer,
            reader: BufReader::new(reader),
            launch_prelude_pending: false,
        }
    }

    fn new_with_launch_prelude(writer: W, reader: R) -> Self {
        Self {
            writer,
            reader: BufReader::new(reader),
            launch_prelude_pending: true,
        }
    }

    #[cfg(test)]
    fn into_writer(self) -> W {
        self.writer
    }
}

impl<W, R> AgentSession for FramedAgentSession<W, R>
where
    W: Write + Send,
    R: Read + Send,
{
    fn request(&mut self, id: RequestId, request: Request) -> Result<AgentWorkerReply> {
        if self.launch_prelude_pending {
            self.launch_prelude_pending = false;
            if let Some(failure) = read_agent_launch_prelude(&mut self.reader)? {
                return Ok(AgentWorkerReply::LaunchError(failure));
            }
        }
        send_agent_frame(&mut self.writer, &mut self.reader, id, request)
    }
}

fn read_agent_launch_prelude<R: BufRead>(
    reader: &mut R,
) -> Result<Option<RemoteAgentLaunchFailure>> {
    let mut limited = reader.take((AGENT_LAUNCH_PRELUDE_MAX_BYTES + 1) as u64);
    let mut record = Vec::with_capacity(AGENT_LAUNCH_PRELUDE_MAX_BYTES);
    let read = limited
        .read_until(b'\n', &mut record)
        .context("failed to read SSH agent launch prelude")?;
    if read == 0 {
        bail!("SSH agent launch prelude was missing");
    }
    if record.len() > AGENT_LAUNCH_PRELUDE_MAX_BYTES {
        bail!("SSH agent launch prelude exceeded its {AGENT_LAUNCH_PRELUDE_MAX_BYTES}-byte limit");
    }
    if record.last() != Some(&b'\n') {
        bail!("SSH agent launch prelude was not newline terminated");
    }
    if record == AGENT_LAUNCH_READY_RECORD {
        return Ok(None);
    }
    let Some(kind) = record
        .strip_prefix(AGENT_LAUNCH_FAILURE_PREFIX)
        .and_then(|kind| kind.strip_suffix(b"\n"))
    else {
        bail!("SSH agent launch prelude was malformed");
    };
    let failure = match kind {
        b"missing" => RemoteAgentLaunchFailure::Missing,
        b"not_executable" => RemoteAgentLaunchFailure::NotExecutable,
        b"root_missing" => RemoteAgentLaunchFailure::RootMissing,
        _ => bail!("SSH agent launch prelude contained an unknown failure kind"),
    };
    Ok(Some(failure))
}

struct AgentWorkerCommand {
    id: RequestId,
    request: Request,
    reply: mpsc::Sender<AgentWorkerReply>,
}

#[derive(Debug)]
enum AgentWorkerReply {
    Response(Response),
    Error(RpcError),
    LaunchError(RemoteAgentLaunchFailure),
    TransportError(String),
}

#[derive(Debug)]
enum AgentRequestOutcome {
    Response(Response),
    Preempted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteHealthState {
    Unchecked,
    Connected,
    Unavailable,
}

#[derive(Debug, Clone)]
struct RemoteHealth {
    state: RemoteHealthState,
    unavailable_until: Option<Instant>,
    error: Option<String>,
    trusted_failure: Option<TrustedAgentFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryHealthState {
    Disabled,
    NotChecked,
    Fetching,
    Verified,
    Error,
}

impl RegistryHealthState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::NotChecked => "not_checked",
            Self::Fetching => "fetching",
            Self::Verified => "verified",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RegistryPlatform {
    os: String,
    arch: String,
    path_style: RemotePathStyle,
    target: String,
}

impl From<&RemoteHostInfo> for RegistryPlatform {
    fn from(host: &RemoteHostInfo) -> Self {
        Self {
            os: host.os.clone(),
            arch: host.arch.clone(),
            path_style: host.path_style,
            target: host.target.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryHealth {
    state: RegistryHealthState,
    source: &'static str,
    manifest_url: Option<String>,
    platform: Option<RegistryPlatform>,
    signing_key_ids: Vec<String>,
    manifest_sha256: Option<String>,
    artifact_sha256: Option<String>,
    manifest_source: Option<&'static str>,
    artifact_source: Option<&'static str>,
    cache_state: Option<nrm_registry::CacheState>,
    error_code: Option<String>,
    error: Option<String>,
}

impl RegistryHealth {
    fn from_registry(registry: Option<&RegistryLaunchConfig>) -> Self {
        let Some(registry) = registry else {
            return Self {
                state: RegistryHealthState::Disabled,
                source: "local",
                manifest_url: None,
                platform: None,
                signing_key_ids: Vec::new(),
                manifest_sha256: None,
                artifact_sha256: None,
                manifest_source: None,
                artifact_source: None,
                cache_state: None,
                error_code: None,
                error: None,
            };
        };
        let manifest_url = Version::parse(env!("CARGO_PKG_VERSION"))
            .ok()
            .and_then(|version| registry.url_template.expand(&version).ok())
            .map(|url| redact_registry_manifest_url(&url));
        Self {
            state: RegistryHealthState::NotChecked,
            source: "registry",
            manifest_url,
            platform: None,
            signing_key_ids: Vec::new(),
            manifest_sha256: None,
            artifact_sha256: None,
            manifest_source: None,
            artifact_source: None,
            cache_state: None,
            error_code: None,
            error: None,
        }
    }

    fn begin_fetch(&mut self, platform: Option<RegistryPlatform>) {
        self.state = RegistryHealthState::Fetching;
        self.source = "registry";
        self.platform = platform;
        self.signing_key_ids.clear();
        self.manifest_sha256 = None;
        self.artifact_sha256 = None;
        self.manifest_source = None;
        self.artifact_source = None;
        self.cache_state = None;
        self.error_code = None;
        self.error = None;
    }

    fn set_platform(&mut self, host: &RemoteHostInfo) {
        self.platform = Some(RegistryPlatform::from(host));
    }

    fn set_manifest_url(&mut self, manifest_url: &url::Url) {
        self.manifest_url = Some(redact_registry_manifest_url(manifest_url));
    }

    fn set_verified(&mut self, fetched: &FetchedArtifact, signing_key_ids: Vec<String>) {
        self.state = RegistryHealthState::Verified;
        self.signing_key_ids = signing_key_ids;
        self.manifest_sha256 = Some(fetched.verified_manifest.manifest_sha256.clone());
        self.artifact_sha256 = Some(fetched.sha256.clone());
        self.manifest_source = Some(manifest_source_name(fetched.manifest_source));
        self.artifact_source = Some(artifact_source_name(fetched.source));
        self.cache_state = Some(fetched.cache_state);
        self.error_code = None;
        self.error = None;
    }

    fn set_error(&mut self, code: &str, detail: &str) {
        self.state = RegistryHealthState::Error;
        self.signing_key_ids.clear();
        self.manifest_sha256 = None;
        self.artifact_sha256 = None;
        self.manifest_source = None;
        self.artifact_source = None;
        self.cache_state = None;
        self.error_code = Some(code.to_string());
        self.error = Some(detail.to_string());
    }

    fn to_value(&self) -> Value {
        let mut value = json!({
            "state": self.state.as_str(),
            "source": self.source,
            "signing_key_ids": self.signing_key_ids,
        });
        let Some(object) = value.as_object_mut() else {
            return value;
        };
        if let Some(manifest_url) = &self.manifest_url {
            object.insert("manifest_url".to_string(), json!(manifest_url));
        }
        if let Some(platform) = &self.platform {
            object.insert("platform".to_string(), json!(platform));
        }
        if let Some(digest) = &self.manifest_sha256 {
            object.insert("manifest_sha256".to_string(), json!(digest));
        }
        if let Some(digest) = &self.artifact_sha256 {
            object.insert("artifact_sha256".to_string(), json!(digest));
        }
        if let Some(source) = self.manifest_source {
            object.insert("manifest_source".to_string(), json!(source));
        }
        if let Some(source) = self.artifact_source {
            object.insert("artifact_source".to_string(), json!(source));
        }
        if let Some(cache_state) = self.cache_state {
            object.insert(
                "cache_state".to_string(),
                json!({
                    "manifest_fallback": cache_state.manifest_fallback,
                    "artifact_hit": cache_state.artifact_hit,
                }),
            );
        }
        if let Some(error_code) = &self.error_code {
            object.insert("error_code".to_string(), json!(error_code));
        }
        if let Some(error) = &self.error {
            object.insert("error".to_string(), json!(error));
        }
        value
    }

    fn insert_into(&self, value: &mut Value) {
        if let Some(object) = value.as_object_mut() {
            object.insert("registry_health".to_string(), self.to_value());
        }
    }
}

fn artifact_source_name(source: ArtifactSource) -> &'static str {
    match source {
        ArtifactSource::Network => "network",
        ArtifactSource::File => "file",
        ArtifactSource::Cache => "cache",
    }
}

fn manifest_source_name(source: ManifestSource) -> &'static str {
    match source {
        ManifestSource::Network => "network",
        ManifestSource::File => "file",
        ManifestSource::VerifiedCacheFallback => "verified_cache_fallback",
    }
}

fn redact_registry_manifest_url(url: &url::Url) -> String {
    match url.scheme() {
        "https" => {
            let Some(host) = url.host_str() else {
                return "https://<redacted>".to_string();
            };
            match url.port() {
                Some(port) => format!("https://{host}:{port}/<redacted>"),
                None => format!("https://{host}/<redacted>"),
            }
        }
        "file" => "file:///<redacted>".to_string(),
        _ => "<redacted>".to_string(),
    }
}

fn registry_error_code(error: &anyhow::Error) -> Option<FetchErrorCode> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<FetchError>())
        .map(FetchError::code)
}

impl Default for RemoteHealth {
    fn default() -> Self {
        Self {
            state: RemoteHealthState::Unchecked,
            unavailable_until: None,
            error: None,
            trusted_failure: None,
        }
    }
}

impl RemoteHealth {
    fn connected() -> Self {
        Self {
            state: RemoteHealthState::Connected,
            unavailable_until: None,
            error: None,
            trusted_failure: None,
        }
    }

    fn unavailable(
        unavailable_until: Option<Instant>,
        error: String,
        trusted_failure: Option<TrustedAgentFailure>,
    ) -> Self {
        Self {
            state: RemoteHealthState::Unavailable,
            unavailable_until,
            error: Some(error),
            trusted_failure,
        }
    }

    fn retry_after_ms(&self) -> Option<u64> {
        let until = self.unavailable_until?;
        let now = Instant::now();
        if now >= until {
            return Some(0);
        }
        Some(
            until
                .duration_since(now)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
        )
    }

    fn to_value(&self) -> Value {
        let mut value = json!({});
        self.insert_into(&mut value);
        value
    }

    fn insert_into(&self, value: &mut Value) {
        let Some(object) = value.as_object_mut() else {
            return;
        };
        match self.state {
            RemoteHealthState::Unchecked => {
                object.insert("remote_status".to_string(), json!("unchecked"));
                object.insert("remote_checked".to_string(), json!(false));
                object.insert("remote_available".to_string(), json!(false));
            }
            RemoteHealthState::Connected => {
                object.insert("remote_status".to_string(), json!("connected"));
                object.insert("remote_checked".to_string(), json!(true));
                object.insert("remote_available".to_string(), json!(true));
            }
            RemoteHealthState::Unavailable => {
                object.insert("remote_status".to_string(), json!("unavailable"));
                object.insert("remote_checked".to_string(), json!(true));
                object.insert("remote_available".to_string(), json!(false));
                if let Some(retry_after_ms) = self.retry_after_ms() {
                    object.insert("retry_after_ms".to_string(), json!(retry_after_ms));
                }
                if let Some(error) = &self.error {
                    object.insert("remote_error".to_string(), json!(error));
                }
                if let Some(failure) = &self.trusted_failure {
                    failure.insert_into(object);
                }
            }
        }
    }
}

struct AgentClient {
    launch: AgentLaunch,
    interrupt: AgentInterrupt,
    preempt: AgentPreempt,
    worker: Option<AgentWorker>,
    retired_workers: Vec<RetiredAgentWorker>,
    handshake_complete: bool,
    negotiated_hello: Option<NegotiatedAgentHello>,
    backoff_lane: AgentBackoffLane,
    remote_backoff: Arc<Mutex<RemoteBackoffState>>,
    next_id: RequestId,
    worker_generation: u64,
}

#[derive(Debug, Clone)]
struct NegotiatedAgentHello {
    agent_version: String,
    protocol_version: u16,
    capabilities: nrm_protocol::CapabilitySet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentBackoffLane {
    Read,
    Write,
}

impl AgentBackoffLane {
    fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Debug, Default, Clone)]
struct RemoteBackoffSlot {
    unavailable_until: Option<Instant>,
    last_remote_error: Option<String>,
    trusted_failure: Option<TrustedAgentFailure>,
    last_remote_error_at: Option<Instant>,
    consecutive_failures: u32,
}

#[derive(Debug, Default)]
struct RemoteBackoffState {
    read: RemoteBackoffSlot,
    write: RemoteBackoffSlot,
}

impl RemoteBackoffState {
    fn slot(&self, lane: AgentBackoffLane) -> &RemoteBackoffSlot {
        match lane {
            AgentBackoffLane::Read => &self.read,
            AgentBackoffLane::Write => &self.write,
        }
    }

    fn slot_mut(&mut self, lane: AgentBackoffLane) -> &mut RemoteBackoffSlot {
        match lane {
            AgentBackoffLane::Read => &mut self.read,
            AgentBackoffLane::Write => &mut self.write,
        }
    }

    fn lane_backoff(
        &self,
        lane: AgentBackoffLane,
    ) -> Option<(u64, String, Option<TrustedAgentFailure>)> {
        let slot = self.slot(lane);
        let until = slot.unavailable_until?;
        let now = Instant::now();
        if now >= until {
            return None;
        }
        let remaining_ms = until
            .duration_since(now)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let error = slot
            .last_remote_error
            .clone()
            .unwrap_or_else(|| "last remote attempt failed".to_string());
        Some((remaining_ms, error, slot.trusted_failure.clone()))
    }

    fn mark_unavailable(
        &mut self,
        lane: AgentBackoffLane,
        error: String,
        trusted_failure: Option<TrustedAgentFailure>,
    ) {
        let now = Instant::now();
        let slot = self.slot_mut(lane);
        slot.consecutive_failures = slot.consecutive_failures.saturating_add(1).max(1);
        let backoff_ms = remote_unavailable_backoff_ms(slot.consecutive_failures);
        slot.last_remote_error = Some(error);
        slot.trusted_failure = trusted_failure;
        slot.last_remote_error_at = Some(now);
        slot.unavailable_until = Some(now + Duration::from_millis(backoff_ms));
    }

    fn clear_lane(&mut self, lane: AgentBackoffLane) {
        let slot = self.slot_mut(lane);
        slot.unavailable_until = None;
        slot.last_remote_error = None;
        slot.trusted_failure = None;
        slot.last_remote_error_at = None;
        slot.consecutive_failures = 0;
    }

    fn clear_all(&mut self) {
        self.clear_lane(AgentBackoffLane::Read);
        self.clear_lane(AgentBackoffLane::Write);
    }

    fn health_error(&self) -> Option<(Option<Instant>, String, Option<TrustedAgentFailure>)> {
        let now = Instant::now();
        let slots = [&self.read, &self.write];
        let mut selected = None;
        for slot in slots {
            let Some(error) = slot.last_remote_error.clone() else {
                continue;
            };
            let error_at = slot.last_remote_error_at.unwrap_or(now);
            let replace = selected
                .as_ref()
                .map(|(selected_at, _, _, _)| error_at >= *selected_at)
                .unwrap_or(true);
            if replace {
                selected = Some((
                    error_at,
                    slot.unavailable_until,
                    error,
                    slot.trusted_failure.clone(),
                ));
            }
        }
        selected.map(|(_, unavailable_until, error, failure)| (unavailable_until, error, failure))
    }
}

fn remote_unavailable_backoff_ms(consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }
    let exponent = consecutive_failures.saturating_sub(1).min(20);
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
    REMOTE_UNAVAILABLE_BACKOFF_BASE_MS
        .saturating_mul(multiplier)
        .min(REMOTE_UNAVAILABLE_BACKOFF_MAX_MS)
}

impl AgentClient {
    #[cfg(test)]
    fn new(
        agent: String,
        local_agent: Option<PathBuf>,
        transport: RemoteTransport,
        remote_root: PathBuf,
        request_timeout: Duration,
        interrupt: AgentInterrupt,
    ) -> Self {
        Self::new_with_registry(
            agent,
            local_agent,
            None,
            transport,
            remote_root,
            request_timeout,
            interrupt,
        )
    }

    fn new_with_registry(
        agent: String,
        local_agent: Option<PathBuf>,
        registry: Option<RegistryLaunchConfig>,
        transport: RemoteTransport,
        remote_root: PathBuf,
        request_timeout: Duration,
        interrupt: AgentInterrupt,
    ) -> Self {
        Self {
            launch: AgentLaunch {
                agent,
                local_agent,
                registry,
                remote_root,
                request_timeout,
                transport,
                remote_host_info: Arc::new(Mutex::new(None)),
                worker_generation: Arc::new(AtomicU64::new(0)),
            },
            interrupt,
            preempt: AgentPreempt::default(),
            worker: None,
            retired_workers: Vec::new(),
            handshake_complete: false,
            negotiated_hello: None,
            backoff_lane: AgentBackoffLane::Read,
            remote_backoff: Arc::new(Mutex::new(RemoteBackoffState::default())),
            next_id: 1,
            worker_generation: 0,
        }
    }

    fn clone_for_lane(&self, interrupt: AgentInterrupt) -> Self {
        Self {
            launch: self.launch.clone(),
            interrupt,
            preempt: AgentPreempt::default(),
            worker: None,
            retired_workers: Vec::new(),
            handshake_complete: false,
            negotiated_hello: None,
            backoff_lane: AgentBackoffLane::Write,
            remote_backoff: Arc::clone(&self.remote_backoff),
            next_id: 1,
            worker_generation: self.launch.worker_generation.load(Ordering::SeqCst),
        }
    }

    fn spawn_worker(
        launch: &AgentLaunch,
        interrupt: AgentInterrupt,
        timeout: Duration,
    ) -> Result<AgentWorker> {
        let host = launch.remote_host_info_with_timeout(timeout)?;
        let plan = launch
            .transport
            .agent_plan(&launch.agent, &launch.remote_root, &host)?;
        let mut command = plan.command();
        configure_agent_process(&mut command);

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to launch agent `{}`{}",
                    launch.agent,
                    launch.transport.launch_context_suffix()
                )
            })?;

        let mut stdin = child.stdin.take().context("agent stdin was not piped")?;
        let stdin_prefix = plan.stdin_prefix;
        let stdout = child.stdout.take().context("agent stdout was not piped")?;
        let stderr = child.stderr.take().context("agent stderr was not piped")?;
        let stderr_capture = match AgentStderrCapture::spawn(stderr) {
            Ok(capture) => capture,
            Err(error) => {
                kill_child_tree(&mut child);
                reap_child_in_background(child);
                return Err(error);
            }
        };
        let launch_prelude_required = matches!(launch.transport, RemoteTransport::Ssh(_));
        let child = Arc::new(Mutex::new(child));
        let abort: Arc<dyn AgentAbortHandle> = Arc::new(ProcessAgentAbort {
            child: Arc::clone(&child),
        });
        interrupt.set_abort_handle(Arc::clone(&abort));
        let (tx, rx) = mpsc::channel::<AgentWorkerCommand>();
        let worker_abort = Arc::clone(&abort);
        let diagnostic_child = Arc::clone(&child);
        let join = thread::spawn(move || {
            let bootstrap_error = stdin
                .write_all(&stdin_prefix)
                .and_then(|()| stdin.flush())
                .err()
                .map(|error| format!("failed to write Windows agent bootstrap: {error}"));
            let reader = LeadingBomReader::new(stdout);
            let mut session: Box<dyn AgentSession> = if launch_prelude_required {
                Box::new(FramedAgentSession::new_with_launch_prelude(stdin, reader))
            } else {
                Box::new(FramedAgentSession::new(stdin, reader))
            };
            while let Ok(command) = rx.recv() {
                let response = if let Some(error) = &bootstrap_error {
                    agent_transport_error_reply(error.clone(), &diagnostic_child, &stderr_capture)
                } else {
                    match session.request(command.id, command.request) {
                        Ok(reply) => reply,
                        Err(error) => agent_transport_error_reply(
                            error.to_string(),
                            &diagnostic_child,
                            &stderr_capture,
                        ),
                    }
                };
                let terminal = matches!(
                    response,
                    AgentWorkerReply::LaunchError(_) | AgentWorkerReply::TransportError(_)
                );
                let _ = command.reply.send(response);
                if terminal {
                    break;
                }
            }
            worker_abort.abort();
            // This cleanup loop is intentionally owned by the retiring worker
            // thread. Callers only poll/join it with their own deadline, while
            // this detached path keeps retrying process-tree termination until
            // the child is actually reaped.
            while !worker_abort.is_stopped() {
                worker_abort.abort();
                thread::sleep(Duration::from_millis(10));
            }
            let _ = stderr_capture.finish_bounded(AGENT_EXIT_DIAGNOSTIC_GRACE);
            interrupt.clear_abort_handle(&worker_abort);
        });

        Ok(AgentWorker {
            tx,
            abort,
            join: Some(join),
        })
    }

    fn request(&mut self, request: Request) -> Result<Response> {
        self.request_inner(request, false, self.launch.request_timeout)
    }

    fn request_with_timeout(&mut self, request: Request, timeout: Duration) -> Result<Response> {
        self.request_inner(request, false, timeout)
    }

    fn request_maybe_preemptible_since(
        &mut self,
        request: Request,
        preempt_epoch: u64,
    ) -> Result<AgentRequestOutcome> {
        self.request_outcome_inner(request, true, preempt_epoch, self.launch.request_timeout)
    }

    fn request_maybe_preemptible_since_with_timeout(
        &mut self,
        request: Request,
        preempt_epoch: u64,
        timeout: Duration,
    ) -> Result<AgentRequestOutcome> {
        self.request_outcome_inner(request, true, preempt_epoch, timeout)
    }

    fn preempt_handle(&self) -> AgentPreempt {
        self.preempt.clone()
    }

    fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    fn negotiated_hello(&self) -> Option<&NegotiatedAgentHello> {
        self.negotiated_hello.as_ref()
    }

    fn remote_backoff_guard(&self) -> std::sync::MutexGuard<'_, RemoteBackoffState> {
        match self.remote_backoff.lock() {
            Ok(backoff) => backoff,
            Err(poisoned) => {
                // Backoff is advisory shared state. A panic must not make it
                // impossible to clear a stale trusted failure and can safely
                // be recovered from the data left in the poisoned guard.
                self.remote_backoff.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    fn remote_health(&self) -> RemoteHealth {
        let backoff = self.remote_backoff_guard();
        if let Some((unavailable_until, error, failure)) = backoff.health_error() {
            return RemoteHealth::unavailable(unavailable_until, error, failure);
        }
        drop(backoff);
        if self.handshake_complete {
            return RemoteHealth::connected();
        }
        RemoteHealth::default()
    }

    fn remote_backoff(&self) -> Option<(u64, String, Option<TrustedAgentFailure>)> {
        let backoff = self.remote_backoff_guard();
        backoff.lane_backoff(self.backoff_lane)
    }

    fn check_remote_backoff(&mut self) -> Result<()> {
        if let Some((remaining_ms, error, _)) = self.remote_backoff() {
            bail!("remote unavailable; retry after {remaining_ms} ms: {error}");
        }
        self.remote_backoff_guard()
            .slot_mut(self.backoff_lane)
            .unavailable_until = None;
        Ok(())
    }

    fn mark_remote_unavailable(&mut self, error: impl Into<String>) -> anyhow::Error {
        self.mark_remote_unavailable_with_trusted_failure(error, None)
    }

    fn mark_remote_unavailable_with_launch_failure(
        &mut self,
        error: impl Into<String>,
        failure: RemoteAgentLaunchFailure,
    ) -> anyhow::Error {
        self.mark_remote_unavailable_with_trusted_failure(
            error,
            Some(TrustedAgentFailure::Launch(failure)),
        )
    }

    fn mark_remote_unavailable_with_compatibility_failure(
        &mut self,
        error: impl Into<String>,
        failure: AgentCompatibilityFailure,
    ) -> anyhow::Error {
        self.mark_remote_unavailable_with_trusted_failure(
            error,
            Some(TrustedAgentFailure::Compatibility(failure)),
        )
    }

    fn mark_remote_unavailable_with_trusted_failure(
        &mut self,
        error: impl Into<String>,
        trusted_failure: Option<TrustedAgentFailure>,
    ) -> anyhow::Error {
        self.handshake_complete = false;
        self.negotiated_hello = None;
        let error = sanitize_agent_error_text(&error.into());
        self.remote_backoff_guard().mark_unavailable(
            self.backoff_lane,
            error.clone(),
            trusted_failure.clone(),
        );
        let retry_after_ms = self
            .remote_backoff()
            .map(|(remaining_ms, _, _)| remaining_ms)
            .unwrap_or(0);
        trace_event(
            "remote_backoff",
            json!({
                "lane": self.backoff_lane.label(),
                "retry_after_ms": retry_after_ms,
                "error": error.as_str(),
                "trusted_agent_failure": trusted_failure.as_ref().map(TrustedAgentFailure::trace_value)
            }),
        );
        anyhow!(error)
    }

    fn mark_request_timeout(
        &mut self,
        id: RequestId,
        timeout: Duration,
        phase: &'static str,
    ) -> anyhow::Error {
        let error = AgentRequestTimeoutError { id, timeout, phase };
        let _ = self.mark_remote_unavailable(error.to_string());
        anyhow!(error)
    }

    fn clear_remote_unavailable(&mut self) {
        self.remote_backoff_guard().clear_lane(self.backoff_lane);
    }

    fn clear_all_remote_unavailable(&mut self) {
        self.remote_backoff_guard().clear_all();
    }

    #[cfg(all(test, unix))]
    fn preempt_epoch(&self) -> u64 {
        self.preempt.epoch()
    }

    fn request_inner(
        &mut self,
        request: Request,
        preemptible: bool,
        timeout: Duration,
    ) -> Result<Response> {
        let preempt_epoch = self.preempt.epoch();
        match self.request_outcome_inner(request, preemptible, preempt_epoch, timeout)? {
            AgentRequestOutcome::Response(response) => Ok(response),
            AgentRequestOutcome::Preempted => bail!("agent request preempted by interactive work"),
        }
    }

    fn request_outcome_inner(
        &mut self,
        request: Request,
        preemptible: bool,
        preempt_epoch: u64,
        timeout: Duration,
    ) -> Result<AgentRequestOutcome> {
        let started = Instant::now();
        self.check_remote_backoff()?;
        if !matches!(request, Request::Hello { .. }) && !self.handshake_complete {
            if let Some(outcome) = self.ensure_handshake(preemptible, preempt_epoch, timeout)? {
                return Ok(outcome);
            }
        }
        let is_hello = matches!(request, Request::Hello { .. });
        let remaining = remaining_timeout_since(started, timeout);
        if remaining.is_zero() {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            self.kill_worker();
            self.launch.invalidate_remote_host_info();
            return Err(self.mark_request_timeout(
                id,
                timeout,
                "after completing its compatibility handshake",
            ));
        }
        let outcome = self.send_request_outcome(request, preemptible, preempt_epoch, remaining)?;
        if is_hello {
            self.record_handshake_outcome(&outcome)?;
        }
        Ok(outcome)
    }

    fn ensure_handshake(
        &mut self,
        preemptible: bool,
        preempt_epoch: u64,
        timeout: Duration,
    ) -> Result<Option<AgentRequestOutcome>> {
        let outcome = self.send_request_outcome(
            Request::Hello {
                client_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION,
            },
            preemptible,
            preempt_epoch,
            timeout,
        )?;
        match outcome {
            AgentRequestOutcome::Response(Response::Hello {
                agent_version,
                protocol_version,
                capabilities,
            }) => match validate_agent_hello(&agent_version, protocol_version) {
                Ok(()) => {
                    self.handshake_complete = true;
                    self.negotiated_hello = Some(NegotiatedAgentHello {
                        agent_version,
                        protocol_version,
                        capabilities,
                    });
                    self.clear_remote_unavailable();
                    Ok(None)
                }
                Err(error) => {
                    self.kill_worker();
                    let message = error.to_string();
                    Err(match error.failure {
                        Some(failure) => self
                            .mark_remote_unavailable_with_compatibility_failure(message, failure),
                        None => self.mark_remote_unavailable(message),
                    })
                }
            },
            AgentRequestOutcome::Response(other) => {
                self.kill_worker();
                Err(self.mark_remote_unavailable(format!(
                    "unexpected hello response from agent: {other:?}"
                )))
            }
            AgentRequestOutcome::Preempted => Ok(Some(AgentRequestOutcome::Preempted)),
        }
    }

    fn record_handshake_outcome(&mut self, outcome: &AgentRequestOutcome) -> Result<()> {
        match outcome {
            AgentRequestOutcome::Response(Response::Hello {
                agent_version,
                protocol_version,
                capabilities,
            }) => match validate_agent_hello(agent_version, *protocol_version) {
                Ok(()) => {
                    self.handshake_complete = true;
                    self.negotiated_hello = Some(NegotiatedAgentHello {
                        agent_version: agent_version.clone(),
                        protocol_version: *protocol_version,
                        capabilities: capabilities.clone(),
                    });
                    self.clear_remote_unavailable();
                    Ok(())
                }
                Err(error) => {
                    self.kill_worker();
                    let message = error.to_string();
                    Err(match error.failure {
                        Some(failure) => self
                            .mark_remote_unavailable_with_compatibility_failure(message, failure),
                        None => self.mark_remote_unavailable(message),
                    })
                }
            },
            AgentRequestOutcome::Response(other) => {
                self.kill_worker();
                Err(self.mark_remote_unavailable(format!(
                    "unexpected hello response from agent: {other:?}"
                )))
            }
            AgentRequestOutcome::Preempted => Ok(()),
        }
    }

    fn send_request_outcome(
        &mut self,
        request: Request,
        preemptible: bool,
        preempt_epoch: u64,
        timeout: Duration,
    ) -> Result<AgentRequestOutcome> {
        if self.interrupt.is_shutdown_requested() {
            bail!("agent request cancelled by shutdown");
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let method = agent_request_name(&request);
        let started = Instant::now();
        let (reply, reply_rx) = mpsc::channel();
        for attempt in 0..2 {
            let remaining = remaining_timeout_since(started, timeout);
            if remaining.is_zero() {
                self.kill_worker();
                self.launch.invalidate_remote_host_info();
                return Err(self.mark_request_timeout(id, timeout, "while launching its worker"));
            }
            let tx = match self.ensure_worker(remaining) {
                Ok(worker) => worker.tx.clone(),
                Err(error) => {
                    self.launch.invalidate_remote_host_info();
                    return Err(self.mark_remote_unavailable(error.to_string()));
                }
            };
            let command = AgentWorkerCommand {
                id,
                request: request.clone(),
                reply: reply.clone(),
            };
            if tx.send(command).is_ok() {
                break;
            }
            self.kill_worker();
            self.launch.invalidate_remote_host_info();
            if attempt == 1 {
                return Err(self.mark_remote_unavailable(format!(
                    "agent worker exited before request {id} could be sent"
                )));
            }
        }

        let remaining = remaining_timeout_since(started, timeout);
        let outcome = if remaining.is_zero() {
            self.kill_worker();
            self.launch.invalidate_remote_host_info();
            Err(self.mark_request_timeout(id, timeout, "while launching its worker"))
        } else {
            self.wait_for_reply(
                id,
                &request,
                reply_rx,
                preemptible,
                preempt_epoch,
                remaining,
            )
        };
        trace_event(
            "agent_request",
            json!({
                "agent_request_id": id,
                "method": method,
                "lane": self.backoff_lane.label(),
                "agent_rtt_ms": duration_ms(started.elapsed()),
                "ok": outcome.is_ok(),
                "preempted": matches!(&outcome, Ok(AgentRequestOutcome::Preempted)),
                "error": outcome.as_ref().err().map(ToString::to_string)
            }),
        );
        outcome
    }

    fn wait_for_reply(
        &mut self,
        id: RequestId,
        request: &Request,
        reply_rx: mpsc::Receiver<AgentWorkerReply>,
        preemptible: bool,
        preempt_epoch: u64,
        timeout: Duration,
    ) -> Result<AgentRequestOutcome> {
        let started = Instant::now();
        loop {
            if preemptible && self.preempt.changed_since(preempt_epoch) {
                self.kill_worker();
                return Ok(AgentRequestOutcome::Preempted);
            }

            let elapsed = started.elapsed();
            if elapsed >= timeout {
                self.kill_worker();
                self.launch.invalidate_remote_host_info();
                return Err(self.mark_request_timeout(id, timeout, "while waiting for its reply"));
            }
            let remaining = timeout.saturating_sub(elapsed);
            let wait = remaining.min(Duration::from_millis(25));

            match reply_rx.recv_timeout(wait) {
                Ok(reply) => return self.handle_worker_reply(reply, request),
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.kill_worker();
                    self.launch.invalidate_remote_host_info();
                    return Err(self.mark_remote_unavailable(format!(
                        "agent worker exited while request {id} was pending"
                    )));
                }
            }
        }
    }

    fn handle_worker_reply(
        &mut self,
        reply: AgentWorkerReply,
        request: &Request,
    ) -> Result<AgentRequestOutcome> {
        match reply {
            AgentWorkerReply::Response(Response::Error { message }) => Err(anyhow!(message)),
            AgentWorkerReply::Response(response) => Ok(AgentRequestOutcome::Response(response)),
            AgentWorkerReply::Error(error) => {
                if let Some(failure) = parse_agent_compatibility_rpc_error(&error, request) {
                    self.kill_worker();
                    return Err(self.mark_remote_unavailable_with_compatibility_failure(
                        format_rpc_error(error),
                        failure,
                    ));
                }
                if error.retryable {
                    self.kill_worker();
                    Err(self.mark_remote_unavailable(format_rpc_error(error)))
                } else {
                    Err(anyhow!(format_rpc_error(error)))
                }
            }
            AgentWorkerReply::LaunchError(failure) => {
                self.kill_worker();
                self.launch.invalidate_remote_host_info();
                Err(self.mark_remote_unavailable_with_launch_failure(failure.detail(), failure))
            }
            AgentWorkerReply::TransportError(message) => {
                self.kill_worker();
                self.launch.invalidate_remote_host_info();
                Err(self.mark_remote_unavailable(message))
            }
        }
    }

    fn ensure_worker(&mut self, timeout: Duration) -> Result<&AgentWorker> {
        if self.interrupt.is_shutdown_requested() {
            bail!("agent worker is shut down");
        }
        let shared_generation = self.launch.worker_generation.load(Ordering::SeqCst);
        if self.worker.is_some() && self.worker_generation != shared_generation {
            self.kill_worker();
        }
        if self.worker.is_none() {
            self.worker = Some(Self::spawn_worker(
                &self.launch,
                self.interrupt.clone(),
                timeout,
            )?);
            self.worker_generation = shared_generation;
        }
        Ok(self.worker.as_ref().expect("worker was just initialized"))
    }

    fn shutdown(&mut self) {
        if self.worker.is_some() {
            let _ = self.request(Request::Shutdown);
        }
        self.kill_worker();
    }

    fn retire_active_worker(&mut self) {
        self.handshake_complete = false;
        self.negotiated_hello = None;
        let Some(worker) = self.worker.take() else {
            return;
        };
        let AgentWorker { tx, abort, join } = worker;
        drop(tx);
        abort.abort();
        let reaper_abort = Arc::clone(&abort);
        let reaper_join = thread::Builder::new()
            .name("nrm-agent-reaper".to_string())
            .spawn(move || {
                while !reaper_abort.is_stopped() {
                    reaper_abort.abort();
                    thread::sleep(Duration::from_millis(10));
                }
            })
            .ok();
        self.retired_workers.push(RetiredAgentWorker {
            abort,
            join,
            reaper_join,
        });
    }

    fn reap_finished_workers(&mut self) -> Result<()> {
        let mut index = 0;
        while index < self.retired_workers.len() {
            let stopped = self.retired_workers[index].abort.is_stopped();
            let thread_finished = self.retired_workers[index]
                .join
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished);
            let reaper_finished = self.retired_workers[index]
                .reaper_join
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished);
            if !stopped || !thread_finished || !reaper_finished {
                index += 1;
                continue;
            }
            let mut worker = self.retired_workers.swap_remove(index);
            if let Some(join) = worker.join.take() {
                // `is_finished` above makes this join nonblocking.
                if join.join().is_err() {
                    bail!("agent worker panicked during teardown");
                }
            }
            if let Some(join) = worker.reaper_join.take() {
                // The child was reaped and `is_finished` was checked above.
                if join.join().is_err() {
                    bail!("agent process reaper panicked during teardown");
                }
            }
        }
        Ok(())
    }

    fn kill_worker(&mut self) {
        self.retire_active_worker();
        for worker in &self.retired_workers {
            worker.abort.abort();
        }
        // Request timeout, preemption, and Drop paths must not wait. Finished
        // workers can still be joined immediately; unfinished ones remain
        // tracked for a later bounded maintenance barrier.
        let _ = self.reap_finished_workers();
    }

    fn kill_worker_with_timeout(&mut self, timeout: Duration, context: &str) -> Result<()> {
        self.retire_active_worker();
        let started = Instant::now();
        loop {
            for worker in &self.retired_workers {
                worker.abort.abort();
            }
            self.reap_finished_workers()?;
            if self.retired_workers.is_empty() {
                return Ok(());
            }
            let remaining = remaining_timeout_since(started, timeout);
            if remaining.is_zero() {
                return Err(anyhow!(AgentWorkerExitTimeoutError {
                    context: context.to_string(),
                }));
            }
            thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }

    #[cfg(test)]
    fn invalidate_shared_workers(&mut self) {
        self.launch.worker_generation.fetch_add(1, Ordering::SeqCst);
        self.kill_worker();
    }

    fn invalidate_shared_workers_with_timeout(
        &mut self,
        timeout: Duration,
        context: &str,
    ) -> Result<()> {
        self.launch.worker_generation.fetch_add(1, Ordering::SeqCst);
        self.kill_worker_with_timeout(timeout, context)
    }
}

impl Drop for AgentClient {
    fn drop(&mut self) {
        self.kill_worker();
    }
}

fn probe_agent_at(launch: &AgentLaunch, executable: &str, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    let mut candidate = AgentClient::new_with_registry(
        executable.to_string(),
        None,
        None,
        launch.transport.clone(),
        launch.remote_root.clone(),
        timeout,
        AgentInterrupt::default(),
    );
    candidate.launch.remote_host_info = Arc::clone(&launch.remote_host_info);
    let result = probe_normal_agent(&mut candidate);
    let cleanup = candidate.kill_worker_with_timeout(
        remaining_timeout_since(started, timeout),
        "staged agent probe cleanup",
    );
    cleanup.and(result)
}

fn probe_restored_agent_at(
    launch: &AgentLaunch,
    executable: &str,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    let mut candidate = AgentClient::new_with_registry(
        executable.to_string(),
        None,
        None,
        launch.transport.clone(),
        launch.remote_root.clone(),
        timeout,
        AgentInterrupt::default(),
    );
    candidate.launch.remote_host_info = Arc::clone(&launch.remote_host_info);
    let preempt_epoch = candidate.preempt.epoch();
    let result = match candidate.send_request_outcome(
        Request::Hello {
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
        },
        false,
        preempt_epoch,
        timeout,
    ) {
        Ok(AgentRequestOutcome::Response(Response::Hello { .. })) => Ok(()),
        Ok(AgentRequestOutcome::Response(other)) => {
            bail!("unexpected restored-agent Hello response: {other:?}")
        }
        Ok(AgentRequestOutcome::Preempted) => bail!("restored-agent Hello was preempted"),
        Err(error) => {
            let typed_compatibility_failure = candidate
                .remote_backoff()
                .and_then(|(_, _, failure)| failure)
                .is_some_and(|failure| matches!(failure, TrustedAgentFailure::Compatibility(_)));
            if typed_compatibility_failure {
                Ok(())
            } else {
                Err(error)
            }
        }
    };
    let cleanup = candidate.kill_worker_with_timeout(
        remaining_timeout_since(started, timeout),
        "restored agent probe cleanup",
    );
    cleanup.and(result)
}

fn probe_normal_agent(agent: &mut AgentClient) -> Result<()> {
    let timeout = agent.launch.request_timeout;
    probe_normal_agent_with_timeout(agent, timeout)
}

fn probe_normal_agent_with_timeout(agent: &mut AgentClient, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    agent.kill_worker_with_timeout(timeout, "normal-path agent probe reset")?;
    agent.clear_all_remote_unavailable();
    let remaining = remaining_timeout_since(started, timeout);
    if remaining.is_zero() {
        return Err(anyhow!(AgentWorkerExitTimeoutError {
            context: "normal-path agent probe reset".to_string(),
        }));
    }
    match agent.request_with_timeout(
        Request::Hello {
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
        },
        remaining,
    )? {
        Response::Hello { .. } => Ok(()),
        other => bail!("unexpected Hello response from agent: {other:?}"),
    }
}

#[cfg(unix)]
fn configure_agent_process(command: &mut Command) {
    // SAFETY: `pre_exec` only calls the async-signal-safe `setpgid` syscall
    // before exec so the spawned agent owns a process group we can terminate.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}

#[cfg(not(unix))]
fn configure_agent_process(_command: &mut Command) {}

fn kill_child_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as libc::pid_t;
        if pid > 0 {
            // SAFETY: a negative pid targets the process group created for
            // this child by `configure_agent_process`; errors are ignored
            // because child teardown falls back to killing the direct child.
            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
    }
    let _ = child.kill();
}

fn agent_request_name(request: &Request) -> &'static str {
    match request {
        Request::Hello { .. } => "hello",
        Request::Scan { .. } => "scan",
        Request::Stat { .. } => "stat",
        Request::Checksum { .. } => "checksum",
        Request::ValidateFiles { .. } => "validate_files",
        Request::ReadFile { .. } => "read_file",
        Request::ReadFiles { .. } => "read_files",
        Request::Grep { .. } => "grep",
        Request::GitStatus { .. } => "git_status",
        Request::GitDiff { .. } => "git_diff",
        Request::GitBlame { .. } => "git_blame",
        Request::WriteFileCas { .. } => "write_file_cas",
        Request::BeginWriteFileCas { .. } => "begin_write_file_cas",
        Request::WriteFileChunk { .. } => "write_file_chunk",
        Request::FinishWriteFileCas { .. } => "finish_write_file_cas",
        Request::AbortWriteFileCas { .. } => "abort_write_file_cas",
        Request::Shutdown => "shutdown",
    }
}

fn send_agent_frame<W: Write, R: Read>(
    stdin: &mut W,
    stdout: &mut BufReader<R>,
    id: RequestId,
    request: Request,
) -> Result<AgentWorkerReply> {
    write_frame(stdin, &RpcMessage::Request { id, request })
        .context("failed to write agent request")?;
    let message: RpcMessage = read_frame(stdout).context("failed to read agent response")?;
    match message {
        RpcMessage::Response {
            id: response_id,
            response,
        } if response_id == id => Ok(AgentWorkerReply::Response(response)),
        RpcMessage::Error {
            id: response_id,
            error,
        } if response_id == id => Ok(AgentWorkerReply::Error(error)),
        RpcMessage::Response {
            id: response_id, ..
        }
        | RpcMessage::Error {
            id: response_id, ..
        } => {
            bail!("agent response id mismatch: expected {id}, got {response_id}")
        }
        other => bail!("unexpected agent frame for request {id}: {other:?}"),
    }
}

fn format_rpc_error(error: RpcError) -> String {
    format!(
        "{:?}: {}{}",
        error.code,
        error.message,
        if error.retryable { " (retryable)" } else { "" }
    )
}

fn parse_agent_compatibility_rpc_error(
    error: &RpcError,
    request: &Request,
) -> Option<AgentCompatibilityFailure> {
    let Request::Hello {
        client_version,
        protocol_version,
    } = request
    else {
        return None;
    };
    if client_version != env!("CARGO_PKG_VERSION")
        || *protocol_version != PROTOCOL_VERSION
        || error.retryable
        || error.code != nrm_protocol::RpcErrorCode::Agent
    {
        return None;
    }

    let package_prefix = format!(
        "package version mismatch: client={} agent=",
        env!("CARGO_PKG_VERSION")
    );
    if let Some(agent_version) = error.message.strip_prefix(&package_prefix) {
        let parsed = Version::parse(agent_version).ok()?;
        if parsed.to_string() == agent_version && agent_version != env!("CARGO_PKG_VERSION") {
            return Some(AgentCompatibilityFailure::VersionMismatch {
                agent_version: agent_version.to_owned(),
            });
        }
        return None;
    }

    let protocol_prefix = format!("protocol version mismatch: client={PROTOCOL_VERSION} agent=");
    if let Some(agent_protocol) = error.message.strip_prefix(&protocol_prefix) {
        let agent_protocol = agent_protocol.parse::<u16>().ok()?;
        if agent_protocol.to_string() == error.message[protocol_prefix.len()..]
            && agent_protocol != PROTOCOL_VERSION
        {
            return Some(AgentCompatibilityFailure::ProtocolMismatch {
                protocol_version: agent_protocol,
            });
        }
    }
    None
}

fn indexed_text_lines(text: &str) -> Vec<(i64, String)> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split_inclusive('\n')
        .enumerate()
        .map(|(idx, line)| {
            (
                idx as i64 + 1,
                line.trim_end_matches(&['\r', '\n'][..]).to_string(),
            )
        })
        .collect()
}

fn indexed_line_trigrams(lines: &[(i64, String)]) -> Vec<(Vec<u8>, i64)> {
    let mut trigrams = Vec::new();
    for (line_number, line) in lines {
        for gram in unique_trigrams(line.as_bytes()) {
            trigrams.push((gram, *line_number));
        }
    }
    trigrams
}

fn unique_trigrams(bytes: &[u8]) -> Vec<Vec<u8>> {
    if bytes.len() < SEARCH_TRIGRAM_BYTES {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    let mut trigrams = Vec::new();
    for window in bytes.windows(SEARCH_TRIGRAM_BYTES) {
        let gram = window.to_vec();
        if seen.insert(gram.clone()) {
            trigrams.push(gram);
        }
    }
    trigrams
}

struct Mirror {
    root: PathBuf,
    files_root: PathBuf,
    conflicts_root: PathBuf,
    save_snapshots_root: PathBuf,
    db: Connection,
}

impl Mirror {
    fn open(state_dir: Option<PathBuf>, workspace_key: &str) -> Result<Self> {
        let state_dir = state_dir.unwrap_or_else(default_state_dir);
        let root = state_dir.join("workspaces").join(workspace_key);
        Self::open_root(root)
    }

    fn open_root(root: PathBuf) -> Result<Self> {
        let files_root = root.join("files");
        let conflicts_root = root.join("conflicts");
        let save_snapshots_root = root.join("save-snapshots");
        fs::create_dir_all(&files_root)?;
        fs::create_dir_all(&conflicts_root)?;
        fs::create_dir_all(&save_snapshots_root)?;
        let db = Connection::open(root.join("mirror.sqlite"))?;
        db.busy_timeout(Duration::from_millis(1_000))?;
        let mirror = Self {
            root,
            files_root,
            conflicts_root,
            save_snapshots_root,
            db,
        };
        mirror.init_schema()?;
        Ok(mirror)
    }

    fn init_schema(&self) -> Result<()> {
        self.db.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS files (
              relative_path TEXT PRIMARY KEY,
              local_path TEXT NOT NULL,
              size INTEGER NOT NULL,
              mtime_ms INTEGER NOT NULL,
              mode INTEGER NOT NULL,
              is_dir INTEGER NOT NULL DEFAULT 0,
              is_symlink INTEGER NOT NULL DEFAULT 0,
              metadata_kind_known INTEGER NOT NULL DEFAULT 0,
              remote_hash TEXT,
              local_hash TEXT,
              state TEXT NOT NULL,
              dirty INTEGER NOT NULL DEFAULT 0,
              validated_at_ms INTEGER NOT NULL DEFAULT 0,
              validation_state TEXT NOT NULL DEFAULT 'unknown',
              last_error TEXT,
              updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS save_queue (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              relative_path TEXT NOT NULL,
              expected_hash TEXT,
              local_hash TEXT NOT NULL,
              snapshot_path TEXT,
              state TEXT NOT NULL,
              attempts INTEGER NOT NULL DEFAULT 0,
              last_error TEXT,
              remote_conflict_path TEXT,
              conflict_actual_hash TEXT,
              remote_conflict_truncated INTEGER NOT NULL DEFAULT 0,
              created_at_ms INTEGER NOT NULL,
              updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS search_files (
              relative_path TEXT PRIMARY KEY,
              local_hash TEXT NOT NULL,
              indexed_bytes INTEGER NOT NULL,
              line_count INTEGER NOT NULL,
              index_state TEXT NOT NULL,
              last_error TEXT,
              updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS search_lines (
              relative_path TEXT NOT NULL,
              line_number INTEGER NOT NULL,
              text TEXT NOT NULL,
              PRIMARY KEY(relative_path, line_number)
            );
            CREATE TABLE IF NOT EXISTS search_trigrams (
              gram BLOB NOT NULL,
              relative_path TEXT NOT NULL,
              line_number INTEGER NOT NULL,
              PRIMARY KEY(gram, relative_path, line_number)
            );
            CREATE INDEX IF NOT EXISTS search_trigrams_path_idx
              ON search_trigrams(relative_path, line_number);
            CREATE TABLE IF NOT EXISTS workspace_state (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL,
              updated_at_ms INTEGER NOT NULL
            );
            ",
        )?;
        self.add_missing_column("files", "validated_at_ms", "INTEGER NOT NULL DEFAULT 0")?;
        self.add_missing_column("files", "is_dir", "INTEGER NOT NULL DEFAULT 0")?;
        self.add_missing_column("files", "is_symlink", "INTEGER NOT NULL DEFAULT 0")?;
        self.add_missing_column("files", "metadata_kind_known", "INTEGER NOT NULL DEFAULT 0")?;
        self.add_missing_column(
            "files",
            "validation_state",
            "TEXT NOT NULL DEFAULT 'unknown'",
        )?;
        self.add_missing_column("files", "last_error", "TEXT")?;
        self.add_missing_column("save_queue", "snapshot_path", "TEXT")?;
        self.add_missing_column("save_queue", "attempts", "INTEGER NOT NULL DEFAULT 0")?;
        self.add_missing_column("save_queue", "last_error", "TEXT")?;
        self.add_missing_column("save_queue", "remote_conflict_path", "TEXT")?;
        self.add_missing_column("save_queue", "conflict_actual_hash", "TEXT")?;
        self.add_missing_column(
            "save_queue",
            "remote_conflict_truncated",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        Ok(())
    }

    fn add_missing_column(&self, table: &str, column: &str, definition: &str) -> Result<()> {
        let mut statement = self.db.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        for existing in columns {
            if existing? == column {
                return Ok(());
            }
        }
        self.db.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
        Ok(())
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn files_root(&self) -> &Path {
        &self.files_root
    }

    fn workspace_state_value(&self, key: &str) -> Result<Option<String>> {
        self.db
            .query_row(
                "SELECT value FROM workspace_state WHERE key=?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn set_workspace_state_value(&self, key: &str, value: Option<&str>) -> Result<()> {
        if let Some(value) = value {
            self.db.execute(
                "
                INSERT INTO workspace_state (key, value, updated_at_ms)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(key) DO UPDATE SET
                  value=excluded.value,
                  updated_at_ms=excluded.updated_at_ms
                ",
                params![key, value, now_ms()],
            )?;
        } else {
            self.db
                .execute("DELETE FROM workspace_state WHERE key=?1", params![key])?;
        }
        Ok(())
    }

    fn background_scan_cursor(&self) -> Result<Option<String>> {
        self.workspace_state_value(BACKGROUND_SCAN_CURSOR_KEY)
    }

    fn set_background_scan_cursor(&self, cursor: Option<&str>) -> Result<()> {
        self.set_workspace_state_value(BACKGROUND_SCAN_CURSOR_KEY, cursor)
    }

    fn background_scan_completed_at_ms(&self) -> Result<Option<i64>> {
        self.workspace_state_value(BACKGROUND_SCAN_COMPLETED_AT_KEY)?
            .map(|value| {
                value.parse::<i64>().with_context(|| {
                    format!("invalid {BACKGROUND_SCAN_COMPLETED_AT_KEY} value `{value}`")
                })
            })
            .transpose()
    }

    fn set_background_scan_completed_at_ms(&self, completed_at_ms: Option<i64>) -> Result<()> {
        let value = completed_at_ms.map(|value| value.to_string());
        self.set_workspace_state_value(BACKGROUND_SCAN_COMPLETED_AT_KEY, value.as_deref())
    }

    fn local_path(&self, relative_path: &str) -> Result<PathBuf> {
        Ok(self
            .files_root
            .join(normalize_relative_path(relative_path)?))
    }

    fn upsert_metadata(&self, meta: &FileMeta, state: &str) -> Result<()> {
        let local_path = self.local_path(&meta.path)?;
        self.db.execute(
            "
            INSERT INTO files (
              relative_path, local_path, size, mtime_ms, mode, is_dir, is_symlink,
              metadata_kind_known, remote_hash,
              local_hash, state, dirty, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, NULL, ?9, 0, ?10)
            ON CONFLICT(relative_path) DO UPDATE SET
              local_path=excluded.local_path,
              size=excluded.size,
              mtime_ms=excluded.mtime_ms,
              mode=excluded.mode,
              is_dir=excluded.is_dir,
              is_symlink=excluded.is_symlink,
              metadata_kind_known=1,
              remote_hash=CASE
                WHEN files.state = 'hydrated' THEN files.remote_hash
                ELSE COALESCE(excluded.remote_hash, files.remote_hash)
              END,
              state=CASE WHEN files.state = 'hydrated' THEN files.state ELSE excluded.state END,
              updated_at_ms=excluded.updated_at_ms
            ",
            params![
                meta.path,
                local_path.to_string_lossy(),
                meta.size as i64,
                meta.mtime_ms,
                meta.mode as i64,
                if meta.is_dir { 1_i64 } else { 0_i64 },
                if meta.is_symlink { 1_i64 } else { 0_i64 },
                meta.hash,
                state,
                now_ms()
            ],
        )?;
        Ok(())
    }

    fn upsert_metadata_batch(&self, entries: &[FileMeta], state: &str) -> Result<()> {
        self.immediate_transaction(|| {
            for entry in entries {
                self.upsert_metadata(entry, state)?;
            }
            Ok(())
        })
    }

    fn record_hydrated(&self, meta: &FileMeta, remote_hash: &str, local_hash: &str) -> Result<()> {
        let local_path = self.local_path(&meta.path)?;
        self.db.execute(
            "
            INSERT INTO files (
              relative_path, local_path, size, mtime_ms, mode, is_dir, is_symlink,
              metadata_kind_known, remote_hash,
              local_hash, state, dirty, validated_at_ms, validation_state, last_error, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, 'hydrated', 0, ?10, 'valid', NULL, ?10)
            ON CONFLICT(relative_path) DO UPDATE SET
              local_path=excluded.local_path,
              size=excluded.size,
              mtime_ms=excluded.mtime_ms,
              mode=excluded.mode,
              is_dir=excluded.is_dir,
              is_symlink=excluded.is_symlink,
              metadata_kind_known=1,
              remote_hash=excluded.remote_hash,
              local_hash=excluded.local_hash,
              state='hydrated',
              dirty=0,
              validated_at_ms=excluded.validated_at_ms,
              validation_state='valid',
              last_error=NULL,
              updated_at_ms=excluded.updated_at_ms
            ",
            params![
                meta.path,
                local_path.to_string_lossy(),
                meta.size as i64,
                meta.mtime_ms,
                meta.mode as i64,
                if meta.is_dir { 1_i64 } else { 0_i64 },
                if meta.is_symlink { 1_i64 } else { 0_i64 },
                remote_hash,
                local_hash,
                now_ms()
            ],
        )?;
        Ok(())
    }

    fn get(&self, relative_path: &str) -> Result<Option<MirrorEntry>> {
        let relative_path = normalize_relative_path(relative_path)?
            .to_string_lossy()
            .replace('\\', "/");
        self.db
            .query_row(
                "
                SELECT relative_path, local_path, size, remote_hash, local_hash, state, dirty,
                       validated_at_ms, validation_state, last_error
                FROM files WHERE relative_path = ?1
                ",
                params![relative_path],
                mirror_entry_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn search_index_meta(&self, relative_path: &str) -> Result<Option<SearchIndexMeta>> {
        self.db
            .query_row(
                "
                SELECT local_hash, index_state
                FROM search_files
                WHERE relative_path=?1
                ",
                params![relative_path],
                |row| {
                    Ok(SearchIndexMeta {
                        local_hash: row.get(0)?,
                        state: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn replace_search_index_from_bytes(
        &self,
        relative_path: &str,
        local_hash: &str,
        content: &[u8],
    ) -> Result<SearchIndexReadiness> {
        let relative_path = normalize_relative_path(relative_path)?
            .to_string_lossy()
            .replace('\\', "/");
        let indexed_bytes = content.len() as u64;
        if indexed_bytes > SEARCH_INDEX_MAX_FILE_BYTES {
            self.replace_search_index_rows(
                &relative_path,
                local_hash,
                indexed_bytes,
                "too_large",
                Some("file exceeds local search index byte cap"),
                &[],
                &[],
            )?;
            return Ok(SearchIndexReadiness::Legacy);
        }
        let text = match std::str::from_utf8(content) {
            Ok(text) => text,
            Err(error) => {
                self.replace_search_index_rows(
                    &relative_path,
                    local_hash,
                    indexed_bytes,
                    "binary",
                    Some(&error.to_string()),
                    &[],
                    &[],
                )?;
                return Ok(SearchIndexReadiness::Legacy);
            }
        };
        let lines = indexed_text_lines(text);
        let trigrams = indexed_line_trigrams(&lines);
        self.replace_search_index_rows(
            &relative_path,
            local_hash,
            indexed_bytes,
            "ready",
            None,
            &lines,
            &trigrams,
        )?;
        Ok(SearchIndexReadiness::Ready)
    }

    fn rebuild_search_index_from_local_file(
        &self,
        entry: &MirrorEntry,
        local_hash: &str,
        file_len: u64,
    ) -> Result<SearchIndexReadiness> {
        if file_len > SEARCH_INDEX_MAX_FILE_BYTES {
            self.replace_search_index_rows(
                &entry.relative_path,
                local_hash,
                file_len,
                "too_large",
                Some("file exceeds local search index byte cap"),
                &[],
                &[],
            )?;
            return Ok(SearchIndexReadiness::Legacy);
        }
        let content = fs::read(&entry.local_path).with_context(|| {
            format!(
                "failed to read local mirror file {} for search index",
                entry.local_path.display()
            )
        })?;
        self.replace_search_index_from_bytes(&entry.relative_path, local_hash, &content)
    }

    fn immediate_transaction(&self, action: impl FnOnce() -> Result<()>) -> Result<()> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = action();
        match result {
            Ok(()) => self.db.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn replace_search_index_rows(
        &self,
        relative_path: &str,
        local_hash: &str,
        indexed_bytes: u64,
        index_state: &str,
        last_error: Option<&str>,
        lines: &[(i64, String)],
        trigrams: &[(Vec<u8>, i64)],
    ) -> Result<()> {
        self.immediate_transaction(|| {
            self.db.execute(
                "DELETE FROM search_trigrams WHERE relative_path=?1",
                params![relative_path],
            )?;
            self.db.execute(
                "DELETE FROM search_lines WHERE relative_path=?1",
                params![relative_path],
            )?;
            for (line_number, text) in lines {
                self.db.execute(
                    "
                    INSERT INTO search_lines (relative_path, line_number, text)
                    VALUES (?1, ?2, ?3)
                    ",
                    params![relative_path, line_number, text],
                )?;
            }
            for (gram, line_number) in trigrams {
                self.db.execute(
                    "
                    INSERT OR IGNORE INTO search_trigrams (gram, relative_path, line_number)
                    VALUES (?1, ?2, ?3)
                    ",
                    params![gram, relative_path, line_number],
                )?;
            }
            self.db.execute(
                "
                INSERT INTO search_files (
                  relative_path, local_hash, indexed_bytes, line_count,
                  index_state, last_error, updated_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(relative_path) DO UPDATE SET
                  local_hash=excluded.local_hash,
                  indexed_bytes=excluded.indexed_bytes,
                  line_count=excluded.line_count,
                  index_state=excluded.index_state,
                  last_error=excluded.last_error,
                  updated_at_ms=excluded.updated_at_ms
                ",
                params![
                    relative_path,
                    local_hash,
                    indexed_bytes as i64,
                    lines.len() as i64,
                    index_state,
                    last_error,
                    now_ms()
                ],
            )?;
            Ok(())
        })
    }

    fn ensure_search_index_ready(
        &self,
        entry: &MirrorEntry,
        file_len: u64,
    ) -> Result<SearchIndexReadiness> {
        let Some(local_hash) = entry.local_hash.as_deref().or(entry.remote_hash.as_deref()) else {
            return Ok(SearchIndexReadiness::Legacy);
        };
        if let Some(meta) = self.search_index_meta(&entry.relative_path)? {
            if meta.local_hash == local_hash {
                return Ok(match meta.state.as_str() {
                    "ready" => SearchIndexReadiness::Ready,
                    "binary" => SearchIndexReadiness::Legacy,
                    "too_large" => SearchIndexReadiness::Legacy,
                    _ => SearchIndexReadiness::Legacy,
                });
            }
        }
        self.rebuild_search_index_from_local_file(entry, local_hash, file_len)
    }

    fn indexed_grep_hits(
        &self,
        entry: &MirrorEntry,
        query: &str,
        remaining: usize,
    ) -> Result<(Vec<Value>, bool)> {
        if query.len() >= SEARCH_TRIGRAM_BYTES {
            if let Some(gram) = self.rarest_query_trigram(&entry.relative_path, query)? {
                return self.indexed_grep_hits_for_gram(entry, query, remaining, &gram);
            }
            return Ok((Vec::new(), false));
        }

        let mut statement = self.db.prepare(
            "
            SELECT line_number, text
            FROM search_lines
            WHERE relative_path=?1
            ORDER BY line_number ASC
            ",
        )?;
        let rows = statement.query_map(params![&entry.relative_path], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        self.grep_indexed_rows(entry, query, remaining, rows)
    }

    fn indexed_grep_hits_for_gram(
        &self,
        entry: &MirrorEntry,
        query: &str,
        remaining: usize,
        gram: &[u8],
    ) -> Result<(Vec<Value>, bool)> {
        let mut statement = self.db.prepare(
            "
            SELECT l.line_number, l.text
            FROM search_trigrams g
            JOIN search_lines l
              ON l.relative_path = g.relative_path
             AND l.line_number = g.line_number
            WHERE g.relative_path=?1
              AND g.gram=?2
            ORDER BY l.line_number ASC
            ",
        )?;
        let rows = statement.query_map(params![&entry.relative_path, gram], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        self.grep_indexed_rows(entry, query, remaining, rows)
    }

    fn grep_indexed_rows<I>(
        &self,
        entry: &MirrorEntry,
        query: &str,
        remaining: usize,
        rows: I,
    ) -> Result<(Vec<Value>, bool)>
    where
        I: IntoIterator<Item = rusqlite::Result<(i64, String)>>,
    {
        let mut hits = Vec::new();
        for row in rows {
            let (line_number, text) = row?;
            if let Some(byte_idx) = text.find(query) {
                hits.push(json!({
                    "path": entry.relative_path,
                    "local_path": entry.local_path.to_string_lossy(),
                    "line": line_number as u64,
                    "column": byte_idx as u64 + 1,
                    "text": text,
                    "cached": true,
                    "dirty": entry.dirty,
                    "validation_state": entry.validation_state
                }));
                if hits.len() >= remaining {
                    return Ok((hits, true));
                }
            }
        }
        Ok((hits, false))
    }

    fn rarest_query_trigram(&self, relative_path: &str, query: &str) -> Result<Option<Vec<u8>>> {
        let trigrams = unique_trigrams(query.as_bytes());
        let mut best: Option<(Vec<u8>, i64)> = None;
        for gram in trigrams {
            let count: i64 = self.db.query_row(
                "
                SELECT COUNT(*)
                FROM search_trigrams
                WHERE relative_path=?1 AND gram=?2
                ",
                params![relative_path, &gram],
                |row| row.get(0),
            )?;
            if count == 0 {
                return Ok(Some(gram));
            }
            if best
                .as_ref()
                .map(|(_, best_count)| count < *best_count)
                .unwrap_or(true)
            {
                best = Some((gram, count));
            }
        }
        Ok(best.map(|(gram, _)| gram))
    }

    fn legacy_grep_file(
        &self,
        entry: &MirrorEntry,
        query: &str,
        remaining: usize,
    ) -> Result<(Vec<Value>, bool, bool)> {
        let file = File::open(&entry.local_path)?;
        let mut reader = BufReader::new(file);
        let mut hits = Vec::new();
        let mut line = String::new();
        let mut line_number = 0_u64;
        let mut invalid_text = false;
        loop {
            line.clear();
            let bytes_read = match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(bytes_read) => bytes_read,
                Err(_) => {
                    invalid_text = true;
                    break;
                }
            };
            if bytes_read == 0 {
                break;
            }
            line_number += 1;
            let line_text = line.trim_end_matches(&['\r', '\n'][..]);
            if let Some(byte_idx) = line_text.find(query) {
                hits.push(json!({
                    "path": entry.relative_path,
                    "local_path": entry.local_path.to_string_lossy(),
                    "line": line_number,
                    "column": byte_idx as u64 + 1,
                    "text": line_text,
                    "cached": true,
                    "dirty": entry.dirty,
                    "validation_state": entry.validation_state
                }));
                if hits.len() >= remaining {
                    return Ok((hits, invalid_text, true));
                }
            }
        }
        Ok((hits, invalid_text, false))
    }

    fn enqueue_save(
        &self,
        relative_path: &str,
        local_hash: &str,
        expected_hash: Option<&str>,
        content: &[u8],
    ) -> Result<SaveQueueEntry> {
        let relative_path = normalize_relative_path(relative_path)?
            .to_string_lossy()
            .replace('\\', "/");
        let local_path = self.local_path(&relative_path)?;
        let effective_expected_hash = self
            .latest_unresolved_save_hash(&relative_path)?
            .or_else(|| expected_hash.map(ToOwned::to_owned));
        let snapshot_path = self.write_save_snapshot(&relative_path, local_hash, content)?;
        let now = now_ms();
        self.immediate_transaction(|| {
            self.db.execute(
                "
                INSERT INTO files (
                  relative_path, local_path, size, mtime_ms, mode, is_dir, is_symlink,
                  metadata_kind_known, remote_hash, local_hash, state, dirty,
                  validated_at_ms, validation_state, last_error, updated_at_ms
                )
                VALUES (?1, ?2, ?3, 0, 0, 0, 0, 0, ?4, ?5, 'hydrated', 1, 0, 'dirty', NULL, ?6)
                ON CONFLICT(relative_path) DO UPDATE SET
                  size=excluded.size,
                  local_hash=excluded.local_hash,
                  dirty=1,
                  validation_state='dirty',
                  last_error=NULL,
                  updated_at_ms=excluded.updated_at_ms
                ",
                params![
                    relative_path,
                    local_path.to_string_lossy(),
                    content.len() as i64,
                    effective_expected_hash,
                    local_hash,
                    now
                ],
            )?;
            self.db.execute(
                "
                INSERT INTO save_queue (
                  relative_path, expected_hash, local_hash, snapshot_path, state,
                  attempts, created_at_ms, updated_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, ?5)
                ",
                params![
                    relative_path,
                    effective_expected_hash,
                    local_hash,
                    snapshot_path.to_string_lossy(),
                    now
                ],
            )?;
            Ok(())
        })?;
        let queue_id = self.db.last_insert_rowid();
        self.replace_search_index_from_bytes(&relative_path, local_hash, content)?;
        Ok(SaveQueueEntry {
            id: queue_id,
            relative_path: relative_path.to_string(),
            expected_hash: effective_expected_hash,
            local_hash: local_hash.to_string(),
            snapshot_path,
        })
    }

    fn enqueue_local_save(&self, relative_path: &str) -> Result<SaveQueueEntry> {
        self.enqueue_local_save_inner(relative_path, false)
    }

    fn enqueue_adopted_local_save(&self, relative_path: &str) -> Result<SaveQueueEntry> {
        self.enqueue_local_save_inner(relative_path, true)
    }

    fn enqueue_local_save_inner(
        &self,
        relative_path: &str,
        allow_adopt_or_recreate: bool,
    ) -> Result<SaveQueueEntry> {
        let relative_path = normalize_relative_path(relative_path)?
            .to_string_lossy()
            .replace('\\', "/");
        let entry = self.get(&relative_path)?;
        if entry.is_none() && !allow_adopt_or_recreate {
            bail!(
                "{} is not tracked in the mirror; use RemoteAdopt to create it remotely",
                relative_path
            );
        }
        if let Some(entry) = entry.as_ref() {
            let requires_explicit_recreate = entry.validation_state == "deleted"
                || (entry.validation_state == "conflict" && entry.remote_hash.is_none());
            if requires_explicit_recreate && !allow_adopt_or_recreate {
                bail!(
                    "{} was deleted remotely; use RemoteAdopt to recreate it",
                    relative_path
                );
            }
        }
        let local_path = entry
            .as_ref()
            .map(|entry| entry.local_path.clone())
            .unwrap_or(self.local_path(&relative_path)?);
        let content = fs::read(&local_path).with_context(|| {
            format!("failed to read local mirror file {}", local_path.display())
        })?;
        let local_hash = hash_bytes(&content);
        let expected_hash = entry.as_ref().and_then(|entry| {
            if allow_adopt_or_recreate && entry.validation_state == "deleted" {
                None
            } else {
                entry.remote_hash.as_deref()
            }
        });
        self.enqueue_save(&relative_path, &local_hash, expected_hash, &content)
    }

    fn sync_cached_file_integrity(&self, entry: &MirrorEntry) -> Result<(MirrorEntry, bool)> {
        if entry.state != "hydrated" || !entry.local_path.is_file() {
            return Ok((entry.clone(), false));
        }

        let actual_hash = hash_file(&entry.local_path).with_context(|| {
            format!(
                "failed to hash local mirror file {}",
                entry.local_path.display()
            )
        })?;
        let recorded_hash = entry.local_hash.as_deref().or(entry.remote_hash.as_deref());
        if recorded_hash == Some(actual_hash.as_str()) {
            if entry.local_hash.as_deref() == Some(actual_hash.as_str()) {
                return Ok((entry.clone(), false));
            }
            self.record_clean_local_hash(entry, &actual_hash)?;
            let updated = self
                .get(&entry.relative_path)?
                .ok_or_else(|| anyhow!("verified file lost mirror metadata"))?;
            return Ok((updated, false));
        }

        let content = fs::read(&entry.local_path).with_context(|| {
            format!(
                "failed to read modified local mirror file {}",
                entry.local_path.display()
            )
        })?;
        let content_hash = hash_bytes(&content);
        if recorded_hash == Some(content_hash.as_str()) {
            self.record_clean_local_hash(entry, &content_hash)?;
            let updated = self
                .get(&entry.relative_path)?
                .ok_or_else(|| anyhow!("verified file lost mirror metadata"))?;
            return Ok((updated, false));
        }

        let queued = self.enqueue_save(
            &entry.relative_path,
            &content_hash,
            entry.remote_hash.as_deref(),
            &content,
        )?;
        let updated = self
            .get(&queued.relative_path)?
            .ok_or_else(|| anyhow!("queued modified file lost mirror metadata"))?;
        Ok((updated, true))
    }

    fn recover_local_edits(&self, limit: usize, after: Option<&str>) -> Result<Value> {
        let limit = limit.clamp(1, 100_000);
        let db_limit = limit.saturating_add(1).min(i64::MAX as usize) as i64;
        let after = after.unwrap_or("");
        let mut entries = {
            let mut statement = self.db.prepare(
                "
                SELECT relative_path, local_path, size, remote_hash, local_hash, state, dirty,
                       validated_at_ms, validation_state, last_error
                FROM files
                WHERE state='hydrated'
                  AND is_dir=0
                  AND is_symlink=0
                  AND relative_path > ?1
                ORDER BY relative_path ASC
                LIMIT ?2
                ",
            )?;
            let rows = statement.query_map(params![after, db_limit], mirror_entry_from_row)?;
            let mut entries = Vec::new();
            for row in rows {
                entries.push(row?);
            }
            entries
        };

        let truncated = entries.len() > limit;
        if truncated {
            entries.truncate(limit);
        }
        let next_after = truncated
            .then(|| entries.last().map(|entry| entry.relative_path.clone()))
            .flatten();
        let scanned = entries.len();
        let mut queued = Vec::new();
        let mut errors = Vec::new();

        for entry in entries {
            let relative_path = entry.relative_path.clone();
            match self.sync_cached_file_integrity(&entry) {
                Ok((_, true)) => {
                    let save = self.latest_unresolved_save_entry(&relative_path)?;
                    queued.push(json!({
                        "path": relative_path,
                        "queue_id": save.map(|entry| entry.id)
                    }));
                }
                Ok((_, false)) => {}
                Err(error) => errors.push(json!({
                    "path": relative_path,
                    "error": error.to_string()
                })),
            }
        }

        Ok(json!({
            "scanned": scanned,
            "queued": queued,
            "errors": errors,
            "truncated": truncated,
            "next_after": next_after
        }))
    }

    fn record_clean_local_hash(&self, entry: &MirrorEntry, local_hash: &str) -> Result<()> {
        let size = fs::metadata(&entry.local_path)
            .map(|metadata| metadata.len() as i64)
            .unwrap_or(entry.size as i64);
        self.db.execute(
            "
            UPDATE files SET
              size=?2,
              local_hash=?3,
              updated_at_ms=?4
            WHERE relative_path=?1 AND dirty=0
            ",
            params![entry.relative_path, size, local_hash, now_ms()],
        )?;
        self.rebuild_search_index_from_local_file(entry, local_hash, size as u64)?;
        Ok(())
    }

    fn write_save_snapshot(
        &self,
        relative_path: &str,
        local_hash: &str,
        content: &[u8],
    ) -> Result<PathBuf> {
        let safe_name = relative_path.replace(['/', '\\'], "__");
        let path = self.save_snapshots_root.join(format!(
            "{safe_name}.{}.{}.snapshot",
            now_ms(),
            local_hash
        ));
        write_durable_file(&path, content)?;
        Ok(path)
    }

    fn latest_unresolved_save_hash(&self, relative_path: &str) -> Result<Option<String>> {
        self.db
            .query_row(
                "
                SELECT local_hash FROM save_queue
                WHERE relative_path=?1 AND state IN ('pending', 'failed') AND snapshot_path IS NOT NULL
                ORDER BY id DESC LIMIT 1
                ",
                params![relative_path],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn pending_save_entries(&self, limit: Option<usize>) -> Result<Vec<SaveQueueEntry>> {
        let limit = limit.unwrap_or(usize::MAX).min(i64::MAX as usize) as i64;
        let mut statement = self.db.prepare(
            "
            SELECT id, relative_path, expected_hash, local_hash, snapshot_path
            FROM save_queue
            WHERE state IN ('pending', 'failed') AND snapshot_path IS NOT NULL
            ORDER BY id ASC
            LIMIT ?1
            ",
        )?;
        let rows = statement.query_map(params![limit], |row| {
            Ok(SaveQueueEntry {
                id: row.get(0)?,
                relative_path: row.get(1)?,
                expected_hash: row.get(2)?,
                local_hash: row.get(3)?,
                snapshot_path: PathBuf::from(row.get::<_, String>(4)?),
            })
        })?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    fn pending_save_count(&self) -> Result<i64> {
        self.db
            .query_row(
                "
                SELECT COUNT(*) FROM save_queue
                WHERE state IN ('pending', 'failed') AND snapshot_path IS NOT NULL
                ",
                [],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    fn save_queue(&self, params: &Value) -> Result<Value> {
        let limit = optional_positive_usize_param(params, "limit").unwrap_or(256);
        let state_filter = optional_string_param(params, "state")
            .map(str::to_string)
            .filter(|state| !state.is_empty());
        if let Some(state) = state_filter.as_deref() {
            match state {
                "pending" | "failed" | "conflict" | "unreplayable" => {}
                other => bail!("unsupported save queue state filter `{other}`"),
            }
        }
        let db_limit = if limit >= i64::MAX as usize {
            i64::MAX
        } else {
            (limit + 1) as i64
        };
        let mut statement = self.db.prepare(
            "
            WITH visible_queue AS (
              SELECT id, relative_path, expected_hash, local_hash, snapshot_path,
                     CASE
                       WHEN state IN ('pending', 'failed') AND snapshot_path IS NULL THEN 'unreplayable'
                       ELSE state
                     END AS visible_state,
                     attempts, last_error, remote_conflict_path, conflict_actual_hash,
                     remote_conflict_truncated,
                     created_at_ms, updated_at_ms
              FROM save_queue
              WHERE state IN ('pending', 'failed', 'conflict')
            )
            SELECT id, relative_path, expected_hash, local_hash, snapshot_path,
                   visible_state, attempts, last_error, remote_conflict_path, conflict_actual_hash,
                   remote_conflict_truncated, created_at_ms, updated_at_ms
            FROM visible_queue
            WHERE (?2 IS NULL OR visible_state = ?2)
            ORDER BY id ASC
            LIMIT ?1
            ",
        )?;
        let mut rows = statement.query(params![db_limit, state_filter.as_deref()])?;
        let mut entries = Vec::new();
        let mut truncated = false;
        while let Some(row) = rows.next()? {
            if entries.len() >= limit {
                truncated = true;
                break;
            }

            let relative_path: String = row.get(1)?;
            let queue_id: i64 = row.get(0)?;
            let expected_hash: Option<String> = row.get(2)?;
            let local_hash: String = row.get(3)?;
            let snapshot_path: Option<String> = row.get(4)?;
            let state: String = row.get(5)?;
            let attempts: i64 = row.get(6)?;
            let last_error: Option<String> = row.get(7)?;
            let remote_conflict_path: Option<String> = row.get(8)?;
            let conflict_actual_hash: Option<String> = row.get(9)?;
            let remote_conflict_truncated = row.get::<_, i64>(10)? != 0;
            let created_at_ms: i64 = row.get(11)?;
            let updated_at_ms: i64 = row.get(12)?;
            let local_path = self
                .local_path(&relative_path)?
                .to_string_lossy()
                .to_string();
            entries.push(json!({
                "queue_id": queue_id,
                "path": relative_path,
                "expected_hash": expected_hash,
                "local_hash": local_hash,
                "snapshot_path": snapshot_path,
                "state": state,
                "attempts": attempts,
                "last_error": last_error,
                "remote_conflict_path": remote_conflict_path,
                "conflict_actual_hash": conflict_actual_hash,
                "remote_conflict_truncated": remote_conflict_truncated,
                "local_path": local_path,
                "created_at_ms": created_at_ms,
                "updated_at_ms": updated_at_ms,
            }));
        }

        let total: i64 = self.db.query_row(
            "
            WITH visible_queue AS (
              SELECT CASE
                       WHEN state IN ('pending', 'failed') AND snapshot_path IS NULL THEN 'unreplayable'
                       ELSE state
                     END AS visible_state
              FROM save_queue
              WHERE state IN ('pending', 'failed', 'conflict')
            )
            SELECT COUNT(*) FROM visible_queue
            WHERE (?1 IS NULL OR visible_state = ?1)
            ",
            params![state_filter.as_deref()],
            |row| row.get(0),
        )?;
        let pending: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM save_queue WHERE state='pending' AND snapshot_path IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let failed: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM save_queue WHERE state='failed' AND snapshot_path IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let conflict: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM save_queue WHERE state='conflict'",
            [],
            |row| row.get(0),
        )?;
        let unreplayable: i64 = self.db.query_row(
            "
            SELECT COUNT(*) FROM save_queue
            WHERE state IN ('pending', 'failed') AND snapshot_path IS NULL
            ",
            [],
            |row| row.get(0),
        )?;

        Ok(json!({
            "entries": entries,
            "limit": limit,
            "truncated": truncated,
            "total": total,
            "counts": {
                "pending": pending,
                "failed": failed,
                "conflict": conflict,
                "unreplayable": unreplayable
            }
        }))
    }

    fn latest_unresolved_save_entry(&self, relative_path: &str) -> Result<Option<SaveQueueEntry>> {
        self.db
            .query_row(
                "
                SELECT id, relative_path, expected_hash, local_hash, snapshot_path
                FROM save_queue
                WHERE relative_path=?1 AND state IN ('pending', 'failed') AND snapshot_path IS NOT NULL
                ORDER BY id DESC LIMIT 1
                ",
                params![relative_path],
                |row| {
                    Ok(SaveQueueEntry {
                        id: row.get(0)?,
                        relative_path: row.get(1)?,
                        expected_hash: row.get(2)?,
                        local_hash: row.get(3)?,
                        snapshot_path: PathBuf::from(row.get::<_, String>(4)?),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn save_queue_entry(&self, queue_id: i64) -> Result<SaveQueueEntry> {
        self.db
            .query_row(
                "
                SELECT id, relative_path, expected_hash, local_hash, snapshot_path
                FROM save_queue
                WHERE id=?1 AND state IN ('pending', 'failed') AND snapshot_path IS NOT NULL
                ",
                params![queue_id],
                |row| {
                    Ok(SaveQueueEntry {
                        id: row.get(0)?,
                        relative_path: row.get(1)?,
                        expected_hash: row.get(2)?,
                        local_hash: row.get(3)?,
                        snapshot_path: PathBuf::from(row.get::<_, String>(4)?),
                    })
                },
            )
            .optional()?
            .ok_or_else(|| anyhow!("queued save {queue_id} is not pending or failed"))
    }

    fn conflict_queue_entry(&self, queue_id: i64) -> Result<ConflictQueueEntry> {
        self.db
            .query_row(
                "
                SELECT id, relative_path, local_hash, snapshot_path, remote_conflict_path,
                       conflict_actual_hash, remote_conflict_truncated
                FROM save_queue
                WHERE id=?1 AND state='conflict'
                ",
                params![queue_id],
                |row| {
                    let snapshot_path: Option<String> = row.get(3)?;
                    let remote_conflict_path: Option<String> = row.get(4)?;
                    Ok(ConflictQueueEntry {
                        id: row.get(0)?,
                        relative_path: row.get(1)?,
                        local_hash: row.get(2)?,
                        snapshot_path: snapshot_path.map(PathBuf::from),
                        remote_conflict_path: remote_conflict_path.map(PathBuf::from),
                        conflict_actual_hash: row.get(5)?,
                        remote_conflict_truncated: row.get::<_, i64>(6)? != 0,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| anyhow!("queued save {queue_id} is not a conflict"))
    }

    fn newer_unresolved_save_count(&self, relative_path: &str, queue_id: i64) -> Result<i64> {
        self.db
            .query_row(
                "
                SELECT COUNT(*) FROM save_queue
                WHERE relative_path=?1
                  AND id > ?2
                  AND state IN ('pending', 'failed', 'conflict')
                ",
                params![relative_path, queue_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    fn ensure_no_newer_unresolved_save(&self, entry: &ConflictQueueEntry) -> Result<()> {
        let newer = self.newer_unresolved_save_count(&entry.relative_path, entry.id)?;
        if newer > 0 {
            bail!(
                "cannot resolve conflict #{} for {} because newer queued saves exist",
                entry.id,
                entry.relative_path
            );
        }
        Ok(())
    }

    fn prepare_accept_local_conflict(&self, queue_id: i64) -> Result<SaveQueueEntry> {
        let entry = self.conflict_queue_entry(queue_id)?;
        self.ensure_no_newer_unresolved_save(&entry)?;
        let snapshot_path = entry
            .snapshot_path
            .clone()
            .ok_or_else(|| anyhow!("conflict #{} has no durable local snapshot", entry.id))?;
        let snapshot_hash = hash_file(&snapshot_path).with_context(|| {
            format!(
                "failed to hash conflict snapshot {}",
                snapshot_path.display()
            )
        })?;
        if snapshot_hash != entry.local_hash {
            bail!(
                "conflict snapshot hash mismatch for {}: expected={} actual={snapshot_hash}",
                entry.relative_path,
                entry.local_hash
            );
        }
        self.immediate_transaction(|| {
            self.db.execute(
                "
                UPDATE save_queue SET
                  state='superseded',
                  last_error=?3,
                  updated_at_ms=?4
                WHERE relative_path=?1
                  AND id < ?2
                  AND state IN ('pending', 'failed', 'conflict')
                ",
                params![
                    entry.relative_path.as_str(),
                    entry.id,
                    format!("superseded by accepted local conflict #{}", entry.id),
                    now_ms()
                ],
            )?;
            self.db.execute(
                "
                UPDATE save_queue SET
                  state='pending',
                  expected_hash=?2,
                  last_error=NULL,
                  remote_conflict_path=NULL,
                  conflict_actual_hash=NULL,
                  remote_conflict_truncated=0,
                  updated_at_ms=?3
                WHERE id=?1 AND state='conflict'
                ",
                params![entry.id, entry.conflict_actual_hash.as_deref(), now_ms()],
            )?;
            Ok(())
        })?;
        Ok(SaveQueueEntry {
            id: entry.id,
            relative_path: entry.relative_path,
            expected_hash: entry.conflict_actual_hash,
            local_hash: entry.local_hash,
            snapshot_path,
        })
    }

    fn accept_remote_conflict(&self, queue_id: i64) -> Result<Value> {
        let entry = self.conflict_queue_entry(queue_id)?;
        self.ensure_no_newer_unresolved_save(&entry)?;
        let remote_conflict_path = entry
            .remote_conflict_path
            .clone()
            .ok_or_else(|| anyhow!("conflict #{} has no saved remote copy", entry.id))?;
        if entry.remote_conflict_truncated || conflict_copy_path_is_partial(&remote_conflict_path) {
            bail!(
                "cannot accept remote for conflict #{} because the saved remote copy is partial",
                entry.id
            );
        }
        let recorded_remote_hash = entry
            .conflict_actual_hash
            .as_deref()
            .ok_or_else(|| anyhow!("conflict #{} has no recorded remote hash", entry.id))?;
        let local_path = self.local_path(&entry.relative_path)?;
        let current_local_hash = hash_file(&local_path).with_context(|| {
            format!(
                "failed to hash local mirror file {} before accepting remote conflict",
                local_path.display()
            )
        })?;
        if current_local_hash != entry.local_hash {
            bail!(
                "local mirror file changed since conflict #{} for {}; refresh the conflict before accepting remote",
                entry.id,
                entry.relative_path
            );
        }

        let content = fs::read(&remote_conflict_path).with_context(|| {
            format!(
                "failed to read saved remote conflict copy {}",
                remote_conflict_path.display()
            )
        })?;
        let actual_hash = hash_bytes(&content);
        if recorded_remote_hash != actual_hash {
            bail!(
                "saved remote conflict copy hash mismatch for {}: expected={} actual={actual_hash}",
                entry.relative_path,
                recorded_remote_hash
            );
        }
        let remote_hash = recorded_remote_hash.to_string();
        write_durable_file(&local_path, &content)?;
        let size = content.len() as u64;
        let now = now_ms();
        self.immediate_transaction(|| {
            self.db.execute(
                "
                UPDATE save_queue SET
                  state='resolved_remote',
                  last_error=NULL,
                  updated_at_ms=?3
                WHERE relative_path=?1
                  AND id <= ?2
                  AND state IN ('pending', 'failed', 'conflict')
                ",
                params![entry.relative_path.as_str(), entry.id, now],
            )?;
            self.db.execute(
                "
                INSERT INTO files (
                  relative_path, local_path, size, mtime_ms, mode, is_dir, is_symlink,
                  metadata_kind_known, remote_hash, local_hash, state, dirty,
                  validated_at_ms, validation_state, last_error, updated_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, 0, 0, 0, 1, ?5, ?5, 'hydrated', 0, ?4, 'valid', NULL, ?4)
                ON CONFLICT(relative_path) DO UPDATE SET
                  local_path=excluded.local_path,
                  size=excluded.size,
                  mtime_ms=excluded.mtime_ms,
                  metadata_kind_known=1,
                  is_dir=0,
                  is_symlink=0,
                  remote_hash=excluded.remote_hash,
                  local_hash=excluded.local_hash,
                  state='hydrated',
                  dirty=0,
                  validated_at_ms=excluded.validated_at_ms,
                  validation_state='valid',
                  last_error=NULL,
                  updated_at_ms=excluded.updated_at_ms
                ",
                params![
                    entry.relative_path.as_str(),
                    local_path.to_string_lossy(),
                    size as i64,
                    now,
                    remote_hash.as_str()
                ],
            )?;
            Ok(())
        })?;
        self.replace_search_index_from_bytes(&entry.relative_path, &remote_hash, &content)?;
        Ok(json!({
            "status": "accepted_remote",
            "path": entry.relative_path,
            "hash": remote_hash,
            "size": size,
            "local_path": local_path.to_string_lossy()
        }))
    }

    fn restore_latest_dirty_snapshot(&self, entry: &MirrorEntry) -> Result<()> {
        let save = self
            .latest_unresolved_save_entry(&entry.relative_path)?
            .ok_or_else(|| {
                anyhow!(
                    "{} is dirty but the local file is missing and no save snapshot exists",
                    entry.relative_path
                )
            })?;
        let snapshot_hash = hash_file(&save.snapshot_path).with_context(|| {
            format!(
                "failed to hash queued save snapshot {}",
                save.snapshot_path.display()
            )
        })?;
        if snapshot_hash != save.local_hash {
            bail!(
                "queued save snapshot hash mismatch for {}: expected={} actual={snapshot_hash}",
                entry.relative_path,
                save.local_hash
            );
        }
        if let Some(parent) = entry.local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let part_path = entry.local_path.with_extension("nrm-restore-part");
        {
            let mut source = File::open(&save.snapshot_path).with_context(|| {
                format!(
                    "failed to open queued save snapshot {}",
                    save.snapshot_path.display()
                )
            })?;
            let mut part = File::create(&part_path)?;
            io::copy(&mut source, &mut part)?;
            part.sync_all()?;
        }
        rename_durable(&part_path, &entry.local_path)?;
        Ok(())
    }

    fn unresolved_save_count(&self, relative_path: &str) -> Result<i64> {
        self.db
            .query_row(
                "
                SELECT COUNT(*) FROM save_queue
                WHERE relative_path=?1 AND state IN ('pending', 'failed') AND snapshot_path IS NOT NULL
                ",
                params![relative_path],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    fn mark_save_applied(
        &self,
        queue_id: i64,
        relative_path: &str,
        new_hash: &str,
        size: u64,
        mtime_ms: i64,
    ) -> Result<()> {
        self.immediate_transaction(|| {
            self.db.execute(
                "
                UPDATE save_queue SET state='applied', last_error=NULL, updated_at_ms=?2
                WHERE id=?1
                ",
                params![queue_id, now_ms()],
            )?;
            let unresolved = self.unresolved_save_count(relative_path)?;
            if unresolved > 0 {
                self.db.execute(
                    "
                    UPDATE files SET
                      size=?2,
                      mtime_ms=?3,
                      metadata_kind_known=1,
                      is_dir=0,
                      is_symlink=0,
                      remote_hash=?4,
                      validation_state='dirty',
                      last_error=NULL,
                      updated_at_ms=?5
                    WHERE relative_path=?1
                    ",
                    params![relative_path, size as i64, mtime_ms, new_hash, now_ms()],
                )?;
                return Ok(());
            }

            self.db.execute(
                "
                UPDATE files SET
                  size=?2,
                  mtime_ms=?3,
                  metadata_kind_known=1,
                  is_dir=0,
                  is_symlink=0,
                  remote_hash=?4,
                  local_hash=?4,
                  dirty=0,
                  state='hydrated',
                  validated_at_ms=?5,
                  validation_state='valid',
                  last_error=NULL,
                  updated_at_ms=?5
                WHERE relative_path=?1
                ",
                params![relative_path, size as i64, mtime_ms, new_hash, now_ms()],
            )?;
            Ok(())
        })?;
        if let Some(entry) = self.get(relative_path)? {
            if entry.local_path.is_file() {
                let file_len = fs::metadata(&entry.local_path)
                    .map(|metadata| metadata.len())
                    .unwrap_or(size);
                self.rebuild_search_index_from_local_file(&entry, new_hash, file_len)?;
            }
        }
        Ok(())
    }

    fn mark_save_failed(&self, queue_id: i64, relative_path: &str, error: &str) -> Result<()> {
        self.immediate_transaction(|| {
            self.db.execute(
                "
                UPDATE save_queue SET
                  state='failed',
                  attempts=attempts+1,
                  last_error=?2,
                  updated_at_ms=?3
                WHERE id=?1
                ",
                params![queue_id, error, now_ms()],
            )?;
            self.db.execute(
                "
                UPDATE files SET last_error=?2, updated_at_ms=?3
                WHERE relative_path=?1
                ",
                params![relative_path, error, now_ms()],
            )?;
            Ok(())
        })
    }

    fn record_save_conflict(
        &self,
        queue_id: i64,
        relative_path: &str,
        actual_hash: Option<&str>,
        remote_content: &[u8],
        remote_content_truncated: bool,
        message: &str,
    ) -> Result<PathBuf> {
        let safe_name = relative_path.replace(['/', '\\'], "__");
        let suffix = if remote_content_truncated {
            "partial"
        } else {
            "full"
        };
        let path = self
            .conflicts_root
            .join(format!("{safe_name}.remote.{suffix}.{}", now_ms()));
        write_durable_file(&path, remote_content)?;
        self.immediate_transaction(|| {
            self.db.execute(
                "
                UPDATE save_queue SET
                  state='conflict',
                  attempts=attempts+1,
                  last_error=?2,
                  remote_conflict_path=?3,
                  conflict_actual_hash=?4,
                  remote_conflict_truncated=?5,
                  updated_at_ms=?6
                WHERE id=?1
                ",
                params![
                    queue_id,
                    message,
                    path.to_string_lossy(),
                    actual_hash,
                    if remote_content_truncated {
                        1_i64
                    } else {
                        0_i64
                    },
                    now_ms()
                ],
            )?;
            self.db.execute(
                "
                UPDATE files SET
                  remote_hash=?2,
                  validation_state='conflict',
                  last_error=?3,
                  updated_at_ms=?4
                WHERE relative_path=?1
                ",
                params![relative_path, actual_hash, message, now_ms()],
            )?;
            Ok(())
        })?;
        Ok(path)
    }

    fn status(&self) -> Result<Value> {
        let cached: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM files WHERE state='hydrated'",
            [],
            |row| row.get(0),
        )?;
        let indexed: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM search_files WHERE index_state='ready'",
            [],
            |row| row.get(0),
        )?;
        let known: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))?;
        let dirty: i64 =
            self.db
                .query_row("SELECT COUNT(*) FROM files WHERE dirty=1", [], |row| {
                    row.get(0)
                })?;
        let pending: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM save_queue WHERE state='pending' AND snapshot_path IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let failed: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM save_queue WHERE state='failed' AND snapshot_path IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let unreplayable: i64 = self.db.query_row(
            "
            SELECT COUNT(*) FROM save_queue
            WHERE state IN ('pending', 'failed') AND snapshot_path IS NULL
            ",
            [],
            |row| row.get(0),
        )?;
        let conflicted: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM save_queue WHERE state='conflict'",
            [],
            |row| row.get(0),
        )?;
        let stale: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM files WHERE validation_state='stale'",
            [],
            |row| row.get(0),
        )?;
        let deleted: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM files WHERE validation_state='deleted'",
            [],
            |row| row.get(0),
        )?;
        let background_scan_cursor = self.background_scan_cursor()?;
        let background_scan_completed_at_ms = self.background_scan_completed_at_ms()?;
        let background_scan_state = if background_scan_cursor.is_some() {
            "in_progress"
        } else if background_scan_completed_at_ms.is_some() {
            "completed"
        } else {
            "not_started"
        };
        Ok(json!({
            "mirror_root": self.root.to_string_lossy(),
            "known_files": known,
            "cached_files": cached,
            "indexed_files": indexed,
            "dirty_files": dirty,
            "pending_saves": pending,
            "failed_saves": failed,
            "unreplayable_saves": unreplayable,
            "conflicted_saves": conflicted,
            "stale_files": stale,
            "deleted_files": deleted,
            "background_scan_state": background_scan_state,
            "background_scan_cursor": background_scan_cursor,
            "background_scan_completed_at_ms": background_scan_completed_at_ms
        }))
    }

    fn find_paths(&self, params: &Value) -> Result<Value> {
        let query = optional_string_param(params, "query").unwrap_or("");
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
        let db_limit = limit.saturating_add(1).min(i64::MAX as usize) as i64;
        let mut statement = self.db.prepare(
            "
            SELECT relative_path, local_path, state, dirty, validation_state
            FROM files
            WHERE is_dir=0
              AND is_symlink=0
              AND metadata_kind_known=1
              AND (?1='' OR instr(relative_path, ?1) > 0)
            ORDER BY relative_path ASC
            LIMIT ?2
            ",
        )?;
        let rows = statement.query_map(params![query, db_limit], |row| {
            Ok(json!({
                "path": row.get::<_, String>(0)?,
                "local_path": row.get::<_, String>(1)?,
                "cached": row.get::<_, String>(2)? == "hydrated",
                "dirty": row.get::<_, i64>(3)? != 0,
                "validation_state": row.get::<_, String>(4)?
            }))
        })?;
        let mut hits = Vec::new();
        for row in rows {
            hits.push(row?);
        }
        let mut truncated = false;
        if hits.len() > limit {
            hits.truncate(limit);
            truncated = true;
        }
        Ok(json!({
            "query": query,
            "hits": hits,
            "truncated": truncated,
            "limit": limit,
            "cached": true
        }))
    }

    fn record_validation(
        &self,
        relative_path: &str,
        validation_state: &str,
        remote_hash: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        self.db.execute(
            "
            UPDATE files SET
              remote_hash=COALESCE(?2, remote_hash),
              validation_state=?3,
              validated_at_ms=?4,
              last_error=?5,
              updated_at_ms=?4
            WHERE relative_path=?1
            ",
            params![
                relative_path,
                remote_hash,
                validation_state,
                now_ms(),
                error
            ],
        )?;
        Ok(())
    }

    fn mark_validation_error(&self, relative_path: &str, error: &str) -> Result<()> {
        self.db.execute(
            "
            UPDATE files SET
              validation_state='error',
              validated_at_ms=?2,
              last_error=?3,
              updated_at_ms=?2
            WHERE relative_path=?1
            ",
            params![relative_path, now_ms(), error],
        )?;
        Ok(())
    }

    fn cached_clean_paths(&self, limit: usize) -> Result<Vec<String>> {
        let mut statement = self.db.prepare(
            "
            SELECT relative_path FROM files
            WHERE state='hydrated' AND dirty=0
            ORDER BY validated_at_ms ASC, relative_path ASC
            LIMIT ?1
            ",
        )?;
        let rows = statement.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;
        let mut paths = Vec::new();
        for row in rows {
            paths.push(row?);
        }
        Ok(paths)
    }

    fn hydrated_file_entries(&self, limit: usize) -> Result<Vec<MirrorEntry>> {
        let db_limit = limit.min(i64::MAX as usize) as i64;
        let mut statement = self.db.prepare(
            "
            SELECT relative_path, local_path, size, remote_hash, local_hash, state, dirty,
                   validated_at_ms, validation_state, last_error
            FROM files
            WHERE state='hydrated'
              AND is_dir=0
              AND is_symlink=0
            ORDER BY relative_path ASC
            LIMIT ?1
            ",
        )?;
        let rows = statement.query_map(params![db_limit], mirror_entry_from_row)?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    fn grep_cache(&self, params: &Value) -> Result<Value> {
        let query = required_string(params, "query")?;
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
        let max_files = params
            .get("max_files")
            .and_then(Value::as_u64)
            .map(|value| value.min(usize::MAX as u64) as usize)
            .unwrap_or(DEFAULT_GREP_CACHE_MAX_FILES);
        let max_file_bytes = params
            .get("max_file_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_FILE_BYTES);
        let max_total_bytes = params
            .get("max_total_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_TOTAL_BYTES);
        let mut hits = Vec::new();
        let mut searched_files = 0_usize;
        let mut searched_bytes = 0_u64;
        let mut skipped_files = 0_usize;
        let mut indexed_files = 0_usize;
        let mut legacy_files = 0_usize;
        let mut truncated = false;

        if query.is_empty() || limit == 0 {
            return Ok(json!({
                "hits": [],
                "truncated": false,
                "searched_files": 0,
                "searched_bytes": 0,
                "skipped_files": 0,
                "cached": true
            }));
        }

        let mut entries = self.hydrated_file_entries(max_files.saturating_add(1))?;
        if entries.len() > max_files {
            entries.truncate(max_files);
            truncated = true;
        }

        for entry in entries {
            if hits.len() >= limit {
                truncated = true;
                break;
            }
            let (entry, _) = self.sync_cached_file_integrity(&entry)?;
            if !entry.local_path.is_file() {
                continue;
            }
            let metadata = match fs::metadata(&entry.local_path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    skipped_files += 1;
                    continue;
                }
            };
            let file_len = metadata.len();
            if file_len > max_file_bytes {
                skipped_files += 1;
                truncated = true;
                continue;
            }
            if searched_bytes.saturating_add(file_len) > max_total_bytes {
                truncated = true;
                break;
            }
            searched_bytes = searched_bytes.saturating_add(file_len);

            match self.ensure_search_index_ready(&entry, file_len)? {
                SearchIndexReadiness::Ready => {
                    let remaining = limit.saturating_sub(hits.len());
                    let (mut file_hits, hit_limit) =
                        self.indexed_grep_hits(&entry, query, remaining)?;
                    searched_files += 1;
                    indexed_files += 1;
                    hits.append(&mut file_hits);
                    if hit_limit {
                        truncated = true;
                        break;
                    }
                }
                SearchIndexReadiness::Legacy => {
                    let remaining = limit.saturating_sub(hits.len());
                    let (mut file_hits, invalid_text, hit_limit) =
                        match self.legacy_grep_file(&entry, query, remaining) {
                            Ok(result) => result,
                            Err(_) => {
                                skipped_files += 1;
                                continue;
                            }
                        };
                    legacy_files += 1;
                    hits.append(&mut file_hits);
                    if invalid_text {
                        skipped_files += 1;
                    } else {
                        searched_files += 1;
                    }
                    if hit_limit {
                        truncated = true;
                        break;
                    }
                }
            }
        }

        Ok(json!({
            "hits": hits,
            "truncated": truncated,
            "searched_files": searched_files,
            "searched_bytes": searched_bytes,
            "skipped_files": skipped_files,
            "indexed_files": indexed_files,
            "legacy_files": legacy_files,
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
            "cached": true
        }))
    }

    fn related_prefetch_paths(&self, anchor: &str, limit: usize) -> Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = limit.min(100_000);
        let anchor = normalize_relative_path(anchor)?
            .to_string_lossy()
            .replace('\\', "/");
        let anchor_dir = parent_dir(&anchor);
        let anchor_ext = file_extension(&anchor);
        let dir_prefix = if anchor_dir.is_empty() {
            String::new()
        } else {
            format!("{}/", anchor_dir)
        };
        let dir_prefix_len = dir_prefix.len() as i64;
        let dir_like = if dir_prefix.is_empty() {
            String::new()
        } else {
            format!("{}%", escape_sql_like(&dir_prefix))
        };
        let ext_like = if anchor_ext.is_empty() {
            String::new()
        } else {
            format!("%.{}", escape_sql_like(&anchor_ext))
        };
        let mut paths = Vec::new();
        self.push_related_prefetch_bucket(
            &mut paths,
            limit,
            RelatedBucket::SameDirectoryAndExtension,
            &anchor,
            &dir_like,
            dir_prefix_len,
            &ext_like,
        )?;
        self.push_related_prefetch_bucket(
            &mut paths,
            limit,
            RelatedBucket::SameDirectory,
            &anchor,
            &dir_like,
            dir_prefix_len,
            &ext_like,
        )?;
        self.push_related_prefetch_bucket(
            &mut paths,
            limit,
            RelatedBucket::DescendantAndExtension,
            &anchor,
            &dir_like,
            dir_prefix_len,
            &ext_like,
        )?;
        self.push_related_prefetch_bucket(
            &mut paths,
            limit,
            RelatedBucket::SameExtension,
            &anchor,
            &dir_like,
            dir_prefix_len,
            &ext_like,
        )?;
        self.push_related_prefetch_bucket(
            &mut paths,
            limit,
            RelatedBucket::AnyMetadata,
            &anchor,
            &dir_like,
            dir_prefix_len,
            &ext_like,
        )?;
        Ok(paths)
    }

    fn known_prefetch_paths(&self, limit: usize) -> Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = limit.min(100_000);
        let mut statement = self.db.prepare(
            "
            SELECT relative_path FROM files
            WHERE state != 'hydrated'
              AND dirty = 0
              AND is_dir = 0
              AND is_symlink = 0
              AND metadata_kind_known = 1
              AND validation_state != 'deleted'
            ORDER BY validated_at_ms ASC, relative_path ASC
            LIMIT ?1
            ",
        )?;
        let rows = statement.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;
        let mut paths = Vec::new();
        for row in rows {
            paths.push(row?);
        }
        Ok(paths)
    }

    #[allow(clippy::too_many_arguments)]
    fn push_related_prefetch_bucket(
        &self,
        paths: &mut Vec<String>,
        limit: usize,
        bucket: RelatedBucket,
        anchor: &str,
        dir_like: &str,
        dir_prefix_len: i64,
        ext_like: &str,
    ) -> Result<()> {
        if paths.len() >= limit {
            return Ok(());
        }
        let query_limit = limit;
        let mut statement = self.db.prepare(&format!(
            "
            SELECT relative_path FROM files
            WHERE {}
              AND relative_path != ?1
              AND state != 'hydrated'
              AND dirty = 0
              AND is_dir = 0
              AND is_symlink = 0
              AND metadata_kind_known = 1
              AND validation_state != 'deleted'
            ORDER BY relative_path ASC
            LIMIT ?5
            ",
            bucket.sql_predicate()
        ))?;
        let rows = statement.query_map(
            params![
                anchor,
                dir_like,
                dir_prefix_len,
                ext_like,
                query_limit as i64
            ],
            |row| row.get::<_, String>(0),
        )?;
        let existing: HashSet<String> = paths.iter().cloned().collect();
        for row in rows {
            let path = row?;
            if !existing.contains(&path) && paths.len() < limit {
                paths.push(path);
            }
        }
        Ok(())
    }
}

fn status_with_remote_health(
    mut status: Value,
    remote_health: RemoteHealth,
    registry_health: RegistryHealth,
) -> Result<Value> {
    if !status.is_object() {
        bail!("mirror status was not a JSON object");
    }
    remote_health.insert_into(&mut status);
    registry_health.insert_into(&mut status);
    Ok(status)
}

fn sidecar_commands() -> Vec<&'static str> {
    SIDECAR_COMMAND_SPECS
        .iter()
        .map(|command| command.name)
        .collect()
}

fn sidecar_commands_by_visibility(visibility: &str) -> Vec<&'static str> {
    SIDECAR_COMMAND_SPECS
        .iter()
        .filter_map(|command| (command.visibility == visibility).then_some(command.name))
        .collect()
}

fn sidecar_command_specs_value() -> Vec<Value> {
    SIDECAR_COMMAND_SPECS
        .iter()
        .map(|command| command.to_value())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn workspace_info_value(
    workspace_key: &str,
    remote_root: &Path,
    mirror_root: &Path,
    files_root: &Path,
    transport: &RemoteTransport,
    remote_health: RemoteHealth,
    registry_health: RegistryHealth,
    remote_host: Option<&RemoteHostInfo>,
    registry_policy_fingerprint: &str,
) -> Value {
    let remote_health_value = remote_health.to_value();
    let registry_health_value = registry_health.to_value();
    let mut value = json!({
        "sidecar_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": PROTOCOL_VERSION,
        "workspace_key": workspace_key,
        "remote_root": remote_root.to_string_lossy(),
        "mirror_root": mirror_root.to_string_lossy(),
        "files_root": files_root.to_string_lossy(),
        "transport": transport.to_value(),
        "registry_policy_fingerprint": registry_policy_fingerprint,
        "client_mode": "single_writer",
        "client_policy": {
            "mode": "single_writer",
            "concurrency": "sequential",
            "write_owner": "current_session"
        },
        "commands": sidecar_commands(),
        "public_commands": sidecar_commands_by_visibility("public"),
        "internal_commands": sidecar_commands_by_visibility("internal"),
        "command_specs": sidecar_command_specs_value(),
        "notifications": SIDECAR_NOTIFICATIONS,
        "capabilities": {
            "command_responses": true,
            "command_metadata": true,
            "server_notifications": true,
            "durable_mirror": true,
            "checksum_validation": true,
            "batched_hydration": true,
            "conflict_safe_saves": true,
            "lazy_agent_handshake": true,
            "remote_agent": true,
            "lsp_proxy": true,
            "remote_git": true,
            "remote_agent_bootstrap": true,
            "remote_agent_automatic_bootstrap_v1": true,
            "transport_neutral_agent_frames": true,
            "agent_abort_handle": true,
            "agent_abort_scope": "lane_worker",
            "sidecar_socket_listener": cfg!(unix),
            "single_writer_sessions": true
        },
        "remote_health": remote_health_value,
        "registry_health": registry_health_value
    });
    if let (Some(object), Some(remote_host)) = (value.as_object_mut(), remote_host) {
        object.insert("remote_host".to_string(), json!(remote_host));
    }
    remote_health.insert_into(&mut value);
    value
}

fn save_should_use_chunked_upload(snapshot_size: u64) -> bool {
    snapshot_size > SAVE_INLINE_MAX_BYTES || snapshot_size > MAX_SAVE_PAYLOAD_BYTES
}

struct Sidecar {
    agent: AgentClient,
    mirror: Mirror,
    remote_root: PathBuf,
    workspace_key: String,
    remote_health: Arc<Mutex<RemoteHealth>>,
    registry_health: Arc<Mutex<RegistryHealth>>,
}

#[derive(Debug, Clone)]
struct FastState {
    mirror_root: PathBuf,
    files_root: PathBuf,
    remote_root: PathBuf,
    transport: RemoteTransport,
    workspace_key: String,
    pending_remote: Arc<Mutex<PendingRemote>>,
    remote_health: Arc<Mutex<RemoteHealth>>,
    registry_health: Arc<Mutex<RegistryHealth>>,
    registry_health_fallback: RegistryHealth,
    remote_host_info: Arc<Mutex<Option<RemoteHostInfo>>>,
    registry_policy_fingerprint: String,
}

enum FastHandle {
    Handled(Result<Value>),
    Defer,
}

#[derive(Debug, Default)]
struct PendingRemote {
    exact_paths: HashMap<String, usize>,
    unknown_content_mutations: usize,
}

#[derive(Debug, Clone, Default)]
struct PendingHazard {
    exact_paths: Vec<String>,
    unknown_content_mutation: bool,
}

#[derive(Debug, Default)]
struct RequestInterest {
    exact_paths: Vec<String>,
    unknown_content: bool,
}

#[derive(Debug)]
struct RemoteWork {
    request: ClientRequest,
    hazard: PendingHazard,
    priority: RemotePriority,
    lane: RemoteLane,
    write_hazard_registered: bool,
    enqueued_at: Instant,
}

struct StartedRemoteWork {
    work: RemoteWork,
    preempt_epoch: u64,
}

enum RemoteWorkerControl {
    ResetAgent {
        started: Instant,
        timeout: Duration,
        reply: mpsc::SyncSender<Result<()>>,
    },
}

enum RemoteWorkerItem {
    Work(StartedRemoteWork),
    Control(RemoteWorkerControl),
}

#[derive(Debug, Clone)]
struct ActiveRemoteWork {
    id: u64,
    method: String,
    lane: RemoteLane,
}

#[derive(Debug, Clone, Default)]
struct ActiveRemote {
    current: Arc<Mutex<HashMap<RemoteLane, ActiveRemoteWork>>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum RemoteLane {
    Read,
    Write,
}

#[derive(Debug, Clone)]
struct RemotePreempts {
    read: AgentPreempt,
    write: AgentPreempt,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RemotePriority {
    Interactive,
    Background,
}

impl RemoteLane {
    fn for_request(request: &ClientRequest, pending_writes: &PendingRemote) -> Self {
        if request_is_write_lane(request) {
            return Self::Write;
        }
        if request.method == "grep"
            && request
                .params
                .get("session_id")
                .and_then(Value::as_str)
                .is_some()
        {
            return Self::Read;
        }
        let interest = RequestInterest::for_request(request);
        if pending_writes.conflicts_with_interest(&interest) {
            Self::Write
        } else {
            Self::Read
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

impl RemotePreempts {
    fn for_lane(&self, lane: RemoteLane) -> &AgentPreempt {
        match lane {
            RemoteLane::Read => &self.read,
            RemoteLane::Write => &self.write,
        }
    }
}

fn request_is_write_lane(request: &ClientRequest) -> bool {
    matches!(
        request.method.as_str(),
        "recover_local_edits"
            | "adopt"
            | "flush"
            | "flush_queued"
            | "flush_queue"
            | "accept_local_conflict"
            | "accept_remote_conflict"
            | "remote_agent_install"
            | "remote_agent_update"
    )
}

fn request_replaces_remote_agent(request: &ClientRequest) -> bool {
    matches!(
        request.method.as_str(),
        "remote_agent_install" | "remote_agent_update"
    )
}

struct RemoteQueue {
    state: Mutex<RemoteQueueState>,
    ready: Condvar,
    quiescent: Condvar,
    interactive_capacity: usize,
    background_capacity: usize,
}

struct RemoteQueueState {
    queue: VecDeque<RemoteWork>,
    interactive_len: usize,
    background_len: usize,
    closed: bool,
    maintenance_paused: bool,
    in_flight: usize,
    controls: VecDeque<RemoteWorkerControl>,
}

impl RemotePriority {
    fn for_request(request: &ClientRequest) -> Self {
        match request.method.as_str() {
            "prefetch" | "prefetch_known" | "prefetch_related" | "refresh" | "scan"
            | "remote_probe" => Self::Background,
            "recover_local_edits" | "flush_queue" if request_background_flag(request) => {
                Self::Background
            }
            _ => Self::Interactive,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Background => "background",
        }
    }
}

impl ActiveRemote {
    fn set(&self, work: &RemoteWork) {
        if let Ok(mut current) = self.current.lock() {
            current.insert(
                work.lane,
                ActiveRemoteWork {
                    id: work.request.id,
                    method: work.request.method.clone(),
                    lane: work.lane,
                },
            );
        }
    }

    fn clear(&self, request_id: u64) {
        if let Ok(mut current) = self.current.lock() {
            let lane = current
                .iter()
                .find_map(|(lane, work)| (work.id == request_id).then_some(*lane));
            if let Some(lane) = lane {
                current.remove(&lane);
            }
        }
    }

    fn cancel_if_active(&self, request_id: u64, preempts: &RemotePreempts) -> Option<ActiveCancel> {
        self.current.lock().ok().and_then(|current| {
            let active = current.values().find(|work| work.id == request_id)?.clone();
            let canceled = active_request_is_preemptible(&active);
            if canceled {
                preempts.for_lane(active.lane).request_preemption();
            }
            Some(ActiveCancel { active, canceled })
        })
    }

    #[cfg(test)]
    fn get(&self, request_id: u64) -> Option<ActiveRemoteWork> {
        self.current
            .lock()
            .ok()
            .and_then(|current| current.values().find(|work| work.id == request_id).cloned())
    }
}

struct ActiveCancel {
    active: ActiveRemoteWork,
    canceled: bool,
}

impl RemoteQueue {
    fn new(interactive_capacity: usize, background_capacity: usize) -> Self {
        Self {
            state: Mutex::new(RemoteQueueState {
                queue: VecDeque::new(),
                interactive_len: 0,
                background_len: 0,
                closed: false,
                maintenance_paused: false,
                in_flight: 0,
                controls: VecDeque::new(),
            }),
            ready: Condvar::new(),
            quiescent: Condvar::new(),
            interactive_capacity,
            background_capacity,
        }
    }

    fn try_push(
        &self,
        work: RemoteWork,
        preempt: Option<&AgentPreempt>,
    ) -> Result<Vec<RemoteWork>, RemoteWork> {
        let priority = work.priority;
        let mut state = self.state.lock().expect("remote queue mutex poisoned");
        if state.closed || state.maintenance_paused {
            return Err(work);
        }

        match priority {
            RemotePriority::Interactive => {
                if state.interactive_len >= self.interactive_capacity {
                    Err(work)
                } else {
                    state.interactive_len += 1;
                    state.queue.push_back(work);
                    let interactive_index = state.queue.len() - 1;
                    let canceled = state.drain_background_blocking(interactive_index);
                    if let Some(preempt) = preempt {
                        preempt.request_preemption();
                    }
                    self.ready.notify_one();
                    Ok(canceled)
                }
            }
            RemotePriority::Background => {
                if state.background_len >= self.background_capacity {
                    Err(work)
                } else {
                    state.background_len += 1;
                    state.queue.push_back(work);
                    self.ready.notify_one();
                    Ok(Vec::new())
                }
            }
        }
    }

    #[cfg(test)]
    fn pop(&self) -> Option<RemoteWork> {
        let started = self.pop_started_with_epoch(None)?;
        self.finish_started();
        Some(started.work)
    }

    #[cfg(test)]
    fn pop_started(&self, preempt: &AgentPreempt) -> Option<StartedRemoteWork> {
        loop {
            match self.pop_worker_item(Some(preempt))? {
                RemoteWorkerItem::Work(started) => return Some(started),
                RemoteWorkerItem::Control(RemoteWorkerControl::ResetAgent { reply, .. }) => {
                    let _ = reply.send(Ok(()));
                }
            }
        }
    }

    #[cfg(test)]
    fn pop_started_with_epoch(&self, preempt: Option<&AgentPreempt>) -> Option<StartedRemoteWork> {
        loop {
            match self.pop_worker_item(preempt)? {
                RemoteWorkerItem::Work(started) => return Some(started),
                RemoteWorkerItem::Control(RemoteWorkerControl::ResetAgent { reply, .. }) => {
                    let _ = reply.send(Ok(()));
                }
            }
        }
    }

    fn pop_worker_item(&self, preempt: Option<&AgentPreempt>) -> Option<RemoteWorkerItem> {
        let mut state = self.state.lock().expect("remote queue mutex poisoned");
        loop {
            if let Some(control) = state.controls.pop_front() {
                return Some(RemoteWorkerItem::Control(control));
            }
            if !state.maintenance_paused {
                if let Some(index) = state.next_ready_index() {
                    state.in_flight = state.in_flight.saturating_add(1);
                    let preempt_epoch = preempt.map(AgentPreempt::epoch).unwrap_or(0);
                    return Some(RemoteWorkerItem::Work(StartedRemoteWork {
                        work: state.remove(index),
                        preempt_epoch,
                    }));
                }
            }
            if state.closed {
                return None;
            }
            state = self
                .ready
                .wait(state)
                .expect("remote queue mutex poisoned while waiting");
        }
    }

    fn shutdown_and_drain(&self) -> Vec<RemoteWork> {
        let mut state = self.state.lock().expect("remote queue mutex poisoned");
        state.closed = true;
        let drained = state.drain_all();
        self.ready.notify_all();
        drained
    }

    #[cfg(test)]
    fn drain_queued(&self) -> Vec<RemoteWork> {
        let mut state = self.state.lock().expect("remote queue mutex poisoned");
        let drained = state.drain_all();
        self.ready.notify_all();
        drained
    }

    fn begin_maintenance_and_drain(&self) -> Vec<RemoteWork> {
        let mut state = self.state.lock().expect("remote queue mutex poisoned");
        state.maintenance_paused = true;
        let drained = state.drain_all();
        self.ready.notify_all();
        drained
    }

    fn wait_quiescent_for(&self, timeout: Duration) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        if state.in_flight == 0 {
            return true;
        }
        self.quiescent
            .wait_timeout_while(state, timeout, |state| state.in_flight != 0)
            .map(|(state, _)| state.in_flight == 0)
            .unwrap_or(false)
    }

    fn end_maintenance(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.maintenance_paused = false;
            self.ready.notify_all();
        }
    }

    fn finish_started(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.in_flight = state.in_flight.saturating_sub(1);
            if state.in_flight == 0 {
                self.quiescent.notify_all();
            }
        }
    }

    fn reset_agent_worker(&self, timeout: Duration) -> Result<()> {
        let (reply, receiver) = mpsc::sync_channel(0);
        let started = Instant::now();
        {
            let mut state = self.state.lock().expect("remote queue mutex poisoned");
            if state.closed {
                bail!("remote worker queue closed during agent maintenance");
            }
            state.controls.push_back(RemoteWorkerControl::ResetAgent {
                started,
                timeout,
                reply,
            });
            self.ready.notify_one();
        }
        let remaining = remaining_timeout_since(started, timeout);
        if remaining.is_zero() {
            return Err(anyhow!(AgentWorkerExitTimeoutError {
                context: "remote lane reset dispatch".to_string(),
            }));
        }
        receiver.recv_timeout(remaining).map_err(|error| {
            anyhow!(AgentWorkerExitTimeoutError {
                context: format!("remote lane reset reply: {error}"),
            })
        })??;
        Ok(())
    }

    fn close_and_drain_background(&self) -> Vec<RemoteWork> {
        let mut state = self.state.lock().expect("remote queue mutex poisoned");
        state.closed = true;
        let mut kept = VecDeque::new();
        let mut drained = Vec::new();
        while let Some(work) = state.queue.pop_front() {
            if work.priority == RemotePriority::Background {
                drained.push(work);
            } else {
                kept.push_back(work);
            }
        }
        state.queue = kept;
        state.background_len = 0;
        state.interactive_len = state.queue.len();
        self.ready.notify_all();
        drained
    }

    fn cancel(&self, request_id: u64) -> Option<RemoteWork> {
        let mut state = self.state.lock().expect("remote queue mutex poisoned");
        let index = state
            .queue
            .iter()
            .position(|work| work.request.id == request_id)?;
        let work = state.remove(index);
        self.ready.notify_all();
        Some(work)
    }
}

impl RemoteQueueState {
    fn next_ready_index(&self) -> Option<usize> {
        let interactive_index = self
            .queue
            .iter()
            .position(|work| work.priority == RemotePriority::Interactive);
        let Some(interactive_index) = interactive_index else {
            return (!self.queue.is_empty()).then_some(0);
        };

        let interactive = &self.queue[interactive_index];
        let conflicting_background = self
            .queue
            .iter()
            .take(interactive_index)
            .position(|work| work.blocks_later(interactive));
        Some(conflicting_background.unwrap_or(interactive_index))
    }

    fn remove(&mut self, index: usize) -> RemoteWork {
        let work = self
            .queue
            .remove(index)
            .expect("remote queue index disappeared");
        self.decrement(work.priority);
        work
    }

    fn drain_all(&mut self) -> Vec<RemoteWork> {
        let drained = self.queue.drain(..).collect();
        self.interactive_len = 0;
        self.background_len = 0;
        drained
    }

    fn decrement(&mut self, priority: RemotePriority) {
        match priority {
            RemotePriority::Interactive => {
                self.interactive_len = self.interactive_len.saturating_sub(1)
            }
            RemotePriority::Background => {
                self.background_len = self.background_len.saturating_sub(1)
            }
        }
    }

    fn drain_background_blocking(&mut self, interactive_index: usize) -> Vec<RemoteWork> {
        let interest = RequestInterest::for_request(&self.queue[interactive_index].request);
        let mut drained = Vec::new();
        let mut index = 0;
        let mut limit = interactive_index;
        while index < limit {
            if self.queue[index].priority == RemotePriority::Background
                && self.queue[index].hazard.conflicts_with_interest(&interest)
            {
                drained.push(self.remove(index));
                limit -= 1;
            } else {
                index += 1;
            }
        }
        drained
    }
}

struct RemoteMaintenanceGuard {
    read_queue: Arc<RemoteQueue>,
    write_queue: Arc<RemoteQueue>,
}

impl RemoteMaintenanceGuard {
    fn begin(
        read_queue: Arc<RemoteQueue>,
        write_queue: Arc<RemoteQueue>,
    ) -> (Self, Vec<RemoteWork>) {
        let drained = read_queue
            .begin_maintenance_and_drain()
            .into_iter()
            .chain(write_queue.begin_maintenance_and_drain())
            .collect();
        (
            Self {
                read_queue,
                write_queue,
            },
            drained,
        )
    }
}

impl Drop for RemoteMaintenanceGuard {
    fn drop(&mut self) {
        self.read_queue.end_maintenance();
        self.write_queue.end_maintenance();
    }
}

fn wait_for_remote_queues_quiescent(
    read_queue: &RemoteQueue,
    write_queue: &RemoteQueue,
    read_interrupt: &AgentInterrupt,
    write_interrupt: &AgentInterrupt,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    loop {
        read_interrupt.kill_current();
        write_interrupt.kill_current();
        let read_remaining = remaining_timeout_since(started, timeout);
        if read_remaining.is_zero() {
            bail!("timed out waiting for remote agent lanes to quiesce");
        }
        let read_idle =
            read_queue.wait_quiescent_for(read_remaining.min(Duration::from_millis(10)));
        let write_remaining = remaining_timeout_since(started, timeout);
        if write_remaining.is_zero() {
            bail!("timed out waiting for remote agent lanes to quiesce");
        }
        let write_idle =
            write_queue.wait_quiescent_for(write_remaining.min(Duration::from_millis(10)));
        if read_idle && write_idle {
            read_interrupt.kill_current_and_wait(
                remaining_timeout_since(started, timeout),
                "remote read-lane process exit",
            )?;
            write_interrupt.kill_current_and_wait(
                remaining_timeout_since(started, timeout),
                "remote write-lane process exit",
            )?;
            return Ok(());
        }
    }
}

impl PendingRemote {
    fn register(&mut self, hazard: &PendingHazard) {
        if hazard.unknown_content_mutation {
            self.unknown_content_mutations = self.unknown_content_mutations.saturating_add(1);
        }
        for path in &hazard.exact_paths {
            *self.exact_paths.entry(path.clone()).or_insert(0) += 1;
        }
    }

    fn clear(&mut self, hazard: &PendingHazard) {
        if hazard.unknown_content_mutation {
            self.unknown_content_mutations = self.unknown_content_mutations.saturating_sub(1);
        }
        for path in &hazard.exact_paths {
            let should_remove = if let Some(count) = self.exact_paths.get_mut(path) {
                *count = count.saturating_sub(1);
                *count == 0
            } else {
                false
            };
            if should_remove {
                self.exact_paths.remove(path);
            }
        }
    }

    fn blocks_path(&self, path: &str) -> bool {
        self.unknown_content_mutations > 0 || self.exact_paths.contains_key(path)
    }

    fn conflicts_with_interest(&self, interest: &RequestInterest) -> bool {
        if !interest.has_content_interest() {
            return false;
        }
        if interest.unknown_content {
            return self.unknown_content_mutations > 0 || !self.exact_paths.is_empty();
        }
        self.unknown_content_mutations > 0
            || interest
                .exact_paths
                .iter()
                .any(|path| self.exact_paths.contains_key(path))
    }
}

impl PendingHazard {
    fn for_request(request: &ClientRequest) -> Self {
        match request.method.as_str() {
            "open" => {
                let force = request
                    .params
                    .get("force")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if force {
                    return path_hazard(request.params.get("path").and_then(Value::as_str));
                }
                Self::default()
            }
            "prefetch" => {
                let mut paths = Vec::new();
                if let Some(values) = request.params.get("paths").and_then(Value::as_array) {
                    for value in values {
                        if let Some(path) = value.as_str().and_then(normalized_path_string) {
                            paths.push(path);
                        }
                    }
                }
                Self {
                    exact_paths: paths,
                    unknown_content_mutation: false,
                }
            }
            "grep" => Self {
                exact_paths: Vec::new(),
                unknown_content_mutation: request
                    .params
                    .get("hydrate")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
            },
            "adopt" | "flush" | "flush_queued" => {
                path_hazard(request.params.get("path").and_then(Value::as_str))
            }
            "accept_local_conflict" | "accept_remote_conflict" => Self {
                exact_paths: Vec::new(),
                unknown_content_mutation: true,
            },
            "recover_local_edits" if request_background_flag(request) => Self::default(),
            "recover_local_edits" => Self {
                exact_paths: Vec::new(),
                unknown_content_mutation: true,
            },
            "flush_queue" if request_background_flag(request) => Self::default(),
            "flush_queue" => Self {
                exact_paths: Vec::new(),
                unknown_content_mutation: true,
            },
            _ => Self::default(),
        }
    }

    fn conflicts_with_interest(&self, interest: &RequestInterest) -> bool {
        if self.unknown_content_mutation && interest.has_content_interest() {
            return true;
        }
        if interest.unknown_content {
            return self.unknown_content_mutation || !self.exact_paths.is_empty();
        }
        self.exact_paths
            .iter()
            .any(|path| interest.exact_paths.iter().any(|other| other == path))
    }
}

impl RequestInterest {
    fn for_request(request: &ClientRequest) -> Self {
        match request.method.as_str() {
            "open" | "validate" => {
                request_path_interest(request.params.get("path").and_then(Value::as_str))
            }
            "prefetch" => {
                let mut paths = Vec::new();
                if let Some(values) = request.params.get("paths").and_then(Value::as_array) {
                    for value in values {
                        if let Some(path) = value.as_str().and_then(normalized_path_string) {
                            paths.push(path);
                        }
                    }
                }
                Self {
                    exact_paths: paths,
                    unknown_content: false,
                }
            }
            "grep" => Self {
                exact_paths: Vec::new(),
                unknown_content: request
                    .params
                    .get("hydrate")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
            },
            "git_status" | "git_diff" => Self {
                exact_paths: Vec::new(),
                unknown_content: true,
            },
            "git_blame" => {
                request_path_interest(request.params.get("path").and_then(Value::as_str))
            }
            _ => Self::default(),
        }
    }

    fn has_content_interest(&self) -> bool {
        self.unknown_content || !self.exact_paths.is_empty()
    }
}

impl RemoteWork {
    fn blocks_later(&self, later: &RemoteWork) -> bool {
        self.hazard
            .conflicts_with_interest(&RequestInterest::for_request(&later.request))
    }
}

fn path_hazard(path: Option<&str>) -> PendingHazard {
    PendingHazard {
        exact_paths: path.and_then(normalized_path_string).into_iter().collect(),
        unknown_content_mutation: false,
    }
}

fn request_path_interest(path: Option<&str>) -> RequestInterest {
    RequestInterest {
        exact_paths: path.and_then(normalized_path_string).into_iter().collect(),
        unknown_content: false,
    }
}

fn request_background_flag(request: &ClientRequest) -> bool {
    request
        .params
        .get("background")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn normalized_path_string(path: &str) -> Option<String> {
    normalize_relative_path(path)
        .ok()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
}

impl FastState {
    fn from_sidecar(sidecar: &Sidecar, pending_remote: Arc<Mutex<PendingRemote>>) -> Self {
        Self {
            mirror_root: sidecar.mirror.root().to_path_buf(),
            files_root: sidecar.mirror.files_root().to_path_buf(),
            remote_root: sidecar.remote_root.clone(),
            transport: sidecar.agent.launch.transport.clone(),
            workspace_key: sidecar.workspace_key.clone(),
            pending_remote,
            remote_health: Arc::clone(&sidecar.remote_health),
            registry_health: Arc::clone(&sidecar.registry_health),
            registry_health_fallback: sidecar.registry_health_snapshot(),
            remote_host_info: Arc::clone(&sidecar.agent.launch.remote_host_info),
            registry_policy_fingerprint: sidecar.registry_policy_fingerprint().to_string(),
        }
    }

    fn try_handle(&self, request: &ClientRequest) -> FastHandle {
        match request.method.as_str() {
            "hello" | "workspace_info" => FastHandle::Handled(Ok(self.workspace_info())),
            "status" => FastHandle::Handled(Mirror::open_root(self.mirror_root.clone()).and_then(
                |mirror| {
                    status_with_remote_health(
                        mirror.status()?,
                        self.remote_health_snapshot(),
                        self.registry_health_snapshot(),
                    )
                },
            )),
            "save_queue" => FastHandle::Handled(
                Mirror::open_root(self.mirror_root.clone())
                    .and_then(|mirror| mirror.save_queue(&request.params)),
            ),
            "find_paths" => FastHandle::Handled(
                Mirror::open_root(self.mirror_root.clone())
                    .and_then(|mirror| mirror.find_paths(&request.params)),
            ),
            "open" => self.try_open(&request.params),
            "grep_cache" => FastHandle::Handled(
                Mirror::open_root(self.mirror_root.clone())
                    .and_then(|mirror| mirror.grep_cache(&request.params)),
            ),
            _ => FastHandle::Defer,
        }
    }

    fn workspace_info(&self) -> Value {
        let remote_host = self
            .remote_host_info
            .try_lock()
            .ok()
            .and_then(|cached| cached.clone());
        workspace_info_value(
            &self.workspace_key,
            &self.remote_root,
            &self.mirror_root,
            &self.files_root,
            &self.transport,
            self.remote_health_snapshot(),
            self.registry_health_snapshot(),
            remote_host.as_ref(),
            &self.registry_policy_fingerprint,
        )
    }

    fn try_open(&self, params: &Value) -> FastHandle {
        let force = params
            .get("force")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let result = (|| -> Result<Option<Value>> {
            let path = required_string(params, "path")?;
            let normalized_path = normalize_relative_path(path)?
                .to_string_lossy()
                .replace('\\', "/");
            let mirror = Mirror::open_root(self.mirror_root.clone())?;
            let Some(mut entry) = mirror.get(&normalized_path)? else {
                return Ok(None);
            };
            if entry.state != "hydrated" {
                return Ok(None);
            }
            let mut restored_from_snapshot = false;
            if entry.dirty && !entry.local_path.exists() {
                mirror.restore_latest_dirty_snapshot(&entry)?;
                restored_from_snapshot = true;
                entry = mirror
                    .get(&normalized_path)?
                    .ok_or_else(|| anyhow!("restored file lost mirror metadata"))?;
            }
            if !entry.local_path.exists() {
                return Ok(None);
            }
            let (synced_entry, _) = mirror.sync_cached_file_integrity(&entry)?;
            entry = synced_entry;
            if entry.dirty {
                return Ok(Some(Sidecar::cached_open_response(
                    &entry,
                    "dirty",
                    force,
                    restored_from_snapshot,
                )));
            }
            if force {
                return Ok(None);
            }
            if self
                .pending_remote
                .lock()
                .map(|pending| pending.blocks_path(&normalized_path))
                .unwrap_or(true)
            {
                return Ok(None);
            }
            let reason = if entry.dirty {
                "dirty"
            } else {
                match entry.validation_state.as_str() {
                    "stale" | "deleted" | "conflict" => entry.validation_state.as_str(),
                    _ => "cached",
                }
            };
            Ok(Some(Sidecar::cached_open_response(
                &entry,
                reason,
                false,
                restored_from_snapshot,
            )))
        })();
        match result {
            Ok(Some(value)) => FastHandle::Handled(Ok(value)),
            Ok(None) => FastHandle::Defer,
            Err(error) => FastHandle::Handled(Err(error)),
        }
    }

    fn prepare_flush(&self, request: &ClientRequest, adopt: bool) -> Result<ClientRequest> {
        let path = required_string(&request.params, "path")?;
        let mirror = Mirror::open_root(self.mirror_root.clone())?;
        let local_path = mirror.local_path(path)?;
        if fs::metadata(&local_path)
            .map(|metadata| metadata.len() > FAST_FLUSH_SNAPSHOT_MAX_BYTES)
            .unwrap_or(false)
        {
            return Ok(request.clone());
        }
        let queued = if adopt {
            mirror.enqueue_adopted_local_save(path)?
        } else {
            mirror.enqueue_local_save(path)?
        };
        Ok(ClientRequest {
            id: request.id,
            method: "flush_queued".to_string(),
            params: json!({
                "queue_id": queued.id,
                "path": queued.relative_path
            }),
        })
    }

    fn remote_health_snapshot(&self) -> RemoteHealth {
        self.remote_health
            .lock()
            .map(|health| health.clone())
            .unwrap_or_default()
    }

    fn registry_health_snapshot(&self) -> RegistryHealth {
        self.registry_health
            .try_lock()
            .map(|health| health.clone())
            .unwrap_or_else(|_| self.registry_health_fallback.clone())
    }
}

impl Sidecar {
    fn registry_policy_fingerprint(&self) -> &str {
        self.agent
            .launch
            .registry
            .as_ref()
            .map(|registry| registry.policy_fingerprint.as_str())
            .unwrap_or(REGISTRY_POLICY_DISABLED)
    }

    fn remote_agent_bootstrap_timeout(&self) -> Duration {
        self.agent
            .launch
            .registry
            .as_ref()
            .map(|registry| registry.timeout)
            .unwrap_or(self.agent.launch.request_timeout)
    }

    #[cfg(test)]
    fn new(
        remote_root: PathBuf,
        transport: RemoteTransport,
        agent: String,
        local_agent: Option<PathBuf>,
        state_dir: Option<PathBuf>,
        request_timeout_ms: u64,
        agent_interrupt: AgentInterrupt,
    ) -> Result<Self> {
        Self::new_with_registry(
            remote_root,
            transport,
            agent,
            local_agent,
            None,
            state_dir,
            request_timeout_ms,
            agent_interrupt,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_registry(
        remote_root: PathBuf,
        transport: RemoteTransport,
        agent: String,
        local_agent: Option<PathBuf>,
        registry: Option<RegistryLaunchConfig>,
        state_dir: Option<PathBuf>,
        request_timeout_ms: u64,
        agent_interrupt: AgentInterrupt,
    ) -> Result<Self> {
        let state_dir = state_dir.unwrap_or_else(default_state_dir);
        let registry = registry.map(|mut config| {
            config
                .cache_dir
                .get_or_insert_with(|| state_dir.join("registry-cache"));
            config
        });
        let registry_health = RegistryHealth::from_registry(registry.as_ref());
        let workspace_key = workspace_key(&transport, &remote_root);
        let mirror = Mirror::open(Some(state_dir), &workspace_key)?;
        let agent = AgentClient::new_with_registry(
            agent,
            local_agent,
            registry,
            transport,
            remote_root.clone(),
            Duration::from_millis(request_timeout_ms),
            agent_interrupt,
        );
        let sidecar = Self {
            agent,
            mirror,
            remote_root,
            workspace_key,
            remote_health: Arc::new(Mutex::new(RemoteHealth::default())),
            registry_health: Arc::new(Mutex::new(registry_health)),
        };
        Ok(sidecar)
    }

    fn clone_for_lane(&self, agent_interrupt: AgentInterrupt) -> Result<Self> {
        Ok(Self {
            agent: self.agent.clone_for_lane(agent_interrupt),
            mirror: Mirror::open_root(self.mirror.root().to_path_buf())?,
            remote_root: self.remote_root.clone(),
            workspace_key: self.workspace_key.clone(),
            remote_health: Arc::clone(&self.remote_health),
            registry_health: Arc::clone(&self.registry_health),
        })
    }

    fn handle(&mut self, method: &str, params: Value, preempt_epoch: u64) -> Result<Value> {
        let result = self.handle_inner(method, params, preempt_epoch);
        let preserve_health =
            matches!(method, "remote_agent_install" | "remote_agent_update") && result.is_err();
        if !preserve_health {
            self.record_remote_health();
        }
        result
    }

    fn handle_inner(&mut self, method: &str, params: Value, preempt_epoch: u64) -> Result<Value> {
        match method {
            "hello" | "workspace_info" => Ok(self.workspace_info()),
            "status" => self.status(),
            "save_queue" => self.mirror.save_queue(&params),
            "find_paths" => self.mirror.find_paths(&params),
            "remote_probe" => Ok(self.remote_probe(preempt_epoch)),
            "remote_health" => Ok(self.remote_health(preempt_epoch)),
            "remote_agent_install" => self.remote_agent_install(params, false, preempt_epoch),
            "remote_agent_update" => self.remote_agent_install(params, true, preempt_epoch),
            "scan" => self.scan(params, preempt_epoch),
            "open" => self.open(params, preempt_epoch),
            "prefetch" => self.prefetch(params, preempt_epoch),
            "prefetch_known" => self.prefetch_known(params, preempt_epoch),
            "prefetch_related" => self.prefetch_related(params, preempt_epoch),
            "grep" => self.grep(params, preempt_epoch),
            "grep_cache" => self.mirror.grep_cache(&params),
            "git_status" => self.git_status(params, preempt_epoch),
            "git_diff" => self.git_diff(params, preempt_epoch),
            "git_blame" => self.git_blame(params, preempt_epoch),
            "recover_local_edits" => self.recover_local_edits(params),
            "adopt" => self.adopt(params),
            "flush" => self.flush(params),
            "flush_queued" => self.flush_queued(params),
            "flush_queue" => self.flush_queue(params),
            "accept_local_conflict" => self.accept_local_conflict(params),
            "accept_remote_conflict" => self.accept_remote_conflict(params),
            "validate" => self.validate(params, preempt_epoch),
            "refresh" => self.refresh(params, preempt_epoch),
            "shutdown" | "disconnect" => {
                self.agent.shutdown();
                Ok(json!({"shutdown": true}))
            }
            other => bail!("unknown method `{other}`"),
        }
    }

    fn workspace_info(&self) -> Value {
        let remote_host = self.agent.launch.cached_remote_host_info();
        workspace_info_value(
            &self.workspace_key,
            &self.remote_root,
            self.mirror.root(),
            self.mirror.files_root(),
            &self.agent.launch.transport,
            self.remote_health_snapshot(),
            self.registry_health_snapshot(),
            remote_host.as_ref(),
            self.registry_policy_fingerprint(),
        )
    }

    fn status(&self) -> Result<Value> {
        status_with_remote_health(
            self.mirror.status()?,
            self.remote_health_snapshot(),
            self.registry_health_snapshot(),
        )
    }

    fn record_remote_health(&self) {
        if let Ok(mut health) = self.remote_health.lock() {
            *health = self.agent.remote_health();
        }
    }

    fn remote_health_snapshot(&self) -> RemoteHealth {
        self.remote_health
            .lock()
            .map(|health| health.clone())
            .unwrap_or_default()
    }

    fn registry_health_snapshot(&self) -> RegistryHealth {
        self.registry_health
            .lock()
            .map(|health| health.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    fn update_registry_health(&self, update: impl FnOnce(&mut RegistryHealth)) {
        match self.registry_health.lock() {
            Ok(mut health) => update(&mut health),
            Err(poisoned) => update(&mut poisoned.into_inner()),
        }
    }

    fn record_agent_install_error_health(&mut self, error: &AgentInstallTransactionError) {
        match error.final_state {
            AgentInstallFinalState::TargetUnchanged | AgentInstallFinalState::PreviousRestored => {}
            AgentInstallFinalState::CandidateHealthy => self.record_remote_health(),
            AgentInstallFinalState::LiveStateUnknown => {
                self.agent.kill_worker();
                let _ = self.agent.mark_remote_unavailable(format!(
                    "remote agent live state is unknown after failed installation: {error}"
                ));
                self.record_remote_health();
            }
        }
    }

    fn remote_health_notification(&self) -> ClientNotification {
        let mut params = self
            .remote_health
            .lock()
            .map(|health| health.to_value())
            .unwrap_or_else(|_| RemoteHealth::default().to_value());
        if let Some(object) = params.as_object_mut() {
            object.insert("workspace_key".to_string(), json!(self.workspace_key));
            object.insert(
                "remote_root".to_string(),
                json!(self.remote_root.to_string_lossy()),
            );
        }
        self.registry_health_snapshot().insert_into(&mut params);
        ClientNotification {
            method: "workspace/remote_health".to_string(),
            params,
        }
    }

    fn remote_probe(&mut self, preempt_epoch: u64) -> Value {
        self.remote_probe_with_timeout(preempt_epoch, None)
    }

    fn remote_probe_with_timeout(
        &mut self,
        preempt_epoch: u64,
        timeout: Option<Duration>,
    ) -> Value {
        if let Some(hello) = self.agent.negotiated_hello() {
            return json!({
                "remote_status": "connected",
                "remote_checked": true,
                "remote_available": true,
                "agent_version": hello.agent_version,
                "protocol_version": hello.protocol_version,
                "capabilities": hello.capabilities
            });
        }
        // Some tests and transitional in-process callers may only retain the
        // legacy boolean. Production handshakes always retain the complete
        // negotiated response above.
        if self.agent.handshake_complete() {
            return json!({
                "remote_status": "connected",
                "remote_checked": true,
                "remote_available": true
            });
        }
        if let Some((retry_after_ms, error, trusted_failure)) = self.agent.remote_backoff() {
            let mut value = json!({
                "remote_status": "unavailable",
                "remote_checked": true,
                "remote_available": false,
                "retry_after_ms": retry_after_ms,
                "remote_error": error
            });
            if let (Some(object), Some(failure)) = (value.as_object_mut(), trusted_failure) {
                failure.insert_into(object);
            }
            return value;
        }

        let request = Request::Hello {
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
        };
        let outcome = match timeout {
            Some(timeout) => self.agent.request_maybe_preemptible_since_with_timeout(
                request,
                preempt_epoch,
                timeout,
            ),
            None => self
                .agent
                .request_maybe_preemptible_since(request, preempt_epoch),
        };
        match outcome {
            Ok(AgentRequestOutcome::Response(Response::Hello {
                agent_version,
                protocol_version,
                capabilities,
            })) => json!({
                "remote_status": "connected",
                "remote_checked": true,
                "remote_available": true,
                "agent_version": agent_version,
                "protocol_version": protocol_version,
                "capabilities": capabilities
            }),
            Ok(AgentRequestOutcome::Response(other)) => self.remote_probe_unavailable(format!(
                "unexpected hello response from agent: {other:?}"
            )),
            Ok(AgentRequestOutcome::Preempted) => json!({
                "remote_status": "unchecked",
                "remote_checked": false,
                "remote_available": false,
                "preempted": true
            }),
            Err(error) => self.remote_probe_unavailable(error.to_string()),
        }
    }

    fn remote_probe_unavailable(&mut self, error: String) -> Value {
        let error = sanitize_agent_error_text(&error);
        if self.agent.remote_backoff().is_none() {
            let _ = self.agent.mark_remote_unavailable(error.clone());
        }
        let backoff = self.agent.remote_backoff();
        let mut value = json!({
            "remote_status": "unavailable",
            "remote_checked": true,
            "remote_available": false,
            "retry_after_ms": backoff.as_ref().map(|(remaining, _, _)| *remaining).unwrap_or(0),
            "remote_error": error
        });
        if let (Some(object), Some(failure)) = (
            value.as_object_mut(),
            backoff.and_then(|(_, _, failure)| failure),
        ) {
            failure.insert_into(object);
        }
        value
    }

    fn remote_health(&mut self, preempt_epoch: u64) -> Value {
        let probe = self.remote_probe(preempt_epoch);
        let mut health = self.decorate_remote_agent_health(probe);
        self.registry_health_snapshot().insert_into(&mut health);
        health
    }

    fn remote_health_with_timeout(&mut self, preempt_epoch: u64, timeout: Duration) -> Value {
        let probe = self.remote_probe_with_timeout(preempt_epoch, Some(timeout));
        let mut health = self.decorate_remote_agent_health(probe);
        self.registry_health_snapshot().insert_into(&mut health);
        health
    }

    fn remote_agent_install_preflight(
        &mut self,
        params: &Value,
        update: bool,
        preempt_epoch: u64,
        deadline: BootstrapDeadline,
    ) -> Result<AgentInstallPreflight> {
        let force = match params.get("force") {
            None => false,
            Some(Value::Bool(force)) => *force,
            Some(_) => bail!("params.force must be a boolean"),
        };
        let automatic = match params.get("automatic") {
            None => false,
            Some(Value::Bool(automatic)) => *automatic,
            Some(_) => bail!("params.automatic must be a boolean"),
        };
        let requested_target = match params.get("install_path") {
            None => None,
            Some(Value::String(path)) if !path.trim().is_empty() => Some(path.clone()),
            Some(Value::String(_)) => bail!("params.install_path must not be empty"),
            Some(_) => bail!("params.install_path must be a string"),
        };
        if automatic {
            if !update {
                bail!("automatic remote agent bootstrap requires update/repair semantics");
            }
            if force {
                bail!("automatic remote agent bootstrap does not accept force=true");
            }
            if self.agent.launch.registry.is_none() {
                bail!("automatic remote agent bootstrap requires a configured signed registry");
            }
            if !matches!(&self.agent.launch.transport, RemoteTransport::Ssh(_)) {
                bail!("automatic remote agent bootstrap is only supported for ssh targets");
            }
            // A socket daemon may retain a prior launch failure in its shared
            // backoff state. Automatic mutation decisions must be based on a
            // fresh probe, not on a cached error from an earlier connection.
            self.agent.clear_all_remote_unavailable();
        }

        let before_timeout = deadline.forward_timeout("remote agent preflight health")?;
        let before = self.remote_health_with_timeout(preempt_epoch, before_timeout);
        deadline.forward_timeout("remote agent preflight health")?;
        let before_status = before
            .get("agent_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let decision = agent_install_decision(before_status, update, force, automatic)?;
        if decision.skip_reason.is_some() {
            let target_path = requested_target
                .or_else(|| {
                    before
                        .get("remote_agent_install_path")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .map(Ok)
                .unwrap_or_else(|| {
                    default_posix_remote_agent_install_path(&self.agent.launch.agent)
                })?;
            deadline.forward_timeout("remote agent preflight")?;
            return Ok(AgentInstallPreflight {
                effective_force: decision.effective_force,
                skip_reason: decision.skip_reason,
                automatic,
                before,
                target_path,
            });
        }
        let target_path = match requested_target {
            Some(target_path) => target_path,
            None => {
                let host_timeout = deadline.forward_timeout("remote host detection")?;
                let host = self
                    .agent
                    .launch
                    .remote_host_info_with_timeout(host_timeout)
                    .map_err(|error| {
                        deadline.map_budgeted_error(
                            BootstrapBudget::Forward,
                            "remote host detection",
                            error,
                        )
                    })
                    .context("failed to select the default remote agent install path")?;
                default_remote_agent_install_path(&self.agent.launch.agent, &host)?
            }
        };
        deadline.forward_timeout("remote agent preflight")?;
        Ok(AgentInstallPreflight {
            effective_force: decision.effective_force,
            skip_reason: decision.skip_reason,
            automatic,
            before,
            target_path,
        })
    }

    fn remote_agent_install(
        &mut self,
        params: Value,
        update: bool,
        preempt_epoch: u64,
    ) -> Result<Value> {
        let deadline = BootstrapDeadline::new(self.remote_agent_bootstrap_timeout());
        (|| {
            let preflight =
                self.remote_agent_install_preflight(&params, update, preempt_epoch, deadline)?;
            if let Some(reason) = preflight.skip_reason.as_deref() {
                return Ok(json!({
                    "status": "skipped",
                    "reason": reason,
                    "automatic": preflight.automatic,
                    "install_path": preflight.target_path,
                    "remote_health": preflight.before
                }));
            }
            self.record_remote_health();
            let prepared = self.prepare_remote_agent_install(&preflight, deadline)?;
            let invalidation_timeout =
                deadline.forward_timeout("control-lane agent worker exit")?;
            self.agent
                .invalidate_shared_workers_with_timeout(
                    invalidation_timeout,
                    "control-lane agent worker exit",
                )
                .map_err(|error| {
                    deadline.map_budgeted_error(
                        BootstrapBudget::Forward,
                        "control-lane agent worker exit",
                        error,
                    )
                })?;
            self.agent.clear_all_remote_unavailable();
            self.remote_agent_install_prepared(preflight, prepared, update, preempt_epoch, deadline)
        })()
        .map_err(|error| {
            if is_bootstrap_timeout(&error) {
                self.record_registry_bootstrap_timeout();
            }
            normalize_bootstrap_error(error)
        })
    }

    fn prepare_remote_agent_install(
        &self,
        preflight: &AgentInstallPreflight,
        deadline: BootstrapDeadline,
    ) -> Result<PreparedAgentInstall> {
        let ssh = match &self.agent.launch.transport {
            RemoteTransport::Ssh(ssh) => ssh.clone(),
            RemoteTransport::Local => {
                bail!("remote agent install/update is only supported for ssh targets")
            }
        };
        let host_timeout = deadline.forward_timeout("remote host detection")?;
        let host = self
            .agent
            .launch
            .remote_host_info_with_timeout(host_timeout)
            .map_err(|error| {
                deadline.map_budgeted_error(
                    BootstrapBudget::Forward,
                    "remote host detection",
                    error,
                )
            })?;
        let mut plan = match host.path_style {
            RemotePathStyle::Posix => PreparedAgentInstallPlan::Posix(
                agent_install::PosixInstallPlan::new(
                    &preflight.target_path,
                    env!("CARGO_PKG_VERSION"),
                    PROTOCOL_VERSION,
                    preflight.effective_force,
                )
                .context("invalid POSIX remote agent install plan")?,
            ),
            RemotePathStyle::Windows => PreparedAgentInstallPlan::Windows(
                windows_agent_install::WindowsInstallPlan::new(
                    &preflight.target_path,
                    env!("CARGO_PKG_VERSION"),
                    PROTOCOL_VERSION,
                    preflight.effective_force,
                )
                .context("invalid Windows remote agent install plan")?,
            ),
        };
        let mut source = self.resolve_agent_source(deadline)?;
        let registry_source = source._registry_artifact.is_some();
        let (source_hash, source_sha256, source_size) =
            match hash_agent_source(&mut source.file, deadline)
                .with_context(|| format!("failed to hash agent source {}", source.path.display()))
            {
                Ok(hashed) => hashed,
                Err(error) => {
                    if registry_source {
                        if is_bootstrap_timeout(&error) {
                            self.record_registry_bootstrap_timeout();
                        } else {
                            self.record_registry_error_code(FetchErrorCode::LocalIo);
                        }
                    }
                    return Err(error);
                }
            };
        if source
            .expected_sha256
            .as_deref()
            .is_some_and(|expected| expected != source_sha256)
        {
            self.record_registry_error_code(FetchErrorCode::ArtifactDigestMismatch);
            bail!(
                "verified registry artifact changed before upload: expected={} actual={source_sha256}",
                source.expected_sha256.as_deref().unwrap_or_default()
            );
        }
        plan.set_expected_sha256(&source_sha256)?;
        let upload = match source
            .file
            .try_clone()
            .context("failed to clone agent source for streaming upload")
        {
            Ok(upload) => upload,
            Err(error) => {
                if registry_source {
                    self.record_registry_error_code(FetchErrorCode::LocalIo);
                }
                return Err(error);
            }
        };
        Ok(PreparedAgentInstall {
            source,
            upload,
            source_hash,
            source_sha256,
            source_size,
            ssh,
            plan,
        })
    }

    fn remote_agent_install_prepared(
        &mut self,
        preflight: AgentInstallPreflight,
        prepared: PreparedAgentInstall,
        update: bool,
        preempt_epoch: u64,
        deadline: BootstrapDeadline,
    ) -> Result<Value> {
        let AgentInstallPreflight {
            before: _,
            target_path,
            mut effective_force,
            skip_reason: _,
            automatic,
        } = preflight;
        let PreparedAgentInstall {
            source,
            upload,
            source_hash,
            source_sha256,
            source_size,
            ssh,
            mut plan,
        } = prepared;
        let lease_token = new_install_lease_token(&target_path);
        let lease_timeout = deadline.forward_timeout("remote agent installation lease")?;
        let lease_command = plan.lease_command(&lease_token, deadline.remaining())?;
        let release_signal = plan.lease_release_signal(&ssh, &lease_token)?;
        let (mut lease, lease_stdout) =
            RemoteInstallLease::acquire(&ssh, lease_command, release_signal, lease_timeout)
                .map_err(|error| {
                    deadline.map_budgeted_error(
                        BootstrapBudget::Forward,
                        "remote agent installation lease",
                        error,
                    )
                })?;
        let lease_work = (|| -> Result<RemoteAgentInstallLeaseOutcome> {
            let leased_target = plan.parse_lease_ready_stdout(&lease_token, &lease_stdout)?;
            plan.bind_lease_target(&leased_target)?;
            plan.set_lease_token(&lease_token)?;

            if let PreparedAgentInstallPlan::Windows(windows_plan) = &plan {
                let recovery = {
                    let mut recovery_ops = WindowsSshInstallOps {
                        plan: windows_plan.clone(),
                        ssh: ssh.clone(),
                        source_path: None,
                        source_size: 0,
                        source_sha256: source_sha256.clone(),
                        launch: self.agent.launch.clone(),
                        normal_agent: &mut self.agent,
                        lease: &mut lease,
                        deadline,
                    };
                    recovery_ops.recover_stale_transaction()?
                };
                if recovery.kind != windows_agent_install::WindowsInstallRecoveryKind::None {
                    eprintln!(
                        "recovered interrupted remote-agent transaction at {}: {:?}",
                        recovery.target_path, recovery.kind
                    );
                }
            }

            if automatic {
                lease.ensure_held("automatic remote agent post-lease health probe")?;
                self.agent.clear_all_remote_unavailable();
                let fresh_timeout =
                    deadline.forward_timeout("automatic remote agent post-lease health probe")?;
                let fresh = self.remote_health_with_timeout(preempt_epoch, fresh_timeout);
                deadline.forward_timeout("automatic remote agent post-lease health probe")?;
                let fresh_status = fresh
                    .get("agent_status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let fresh_decision = agent_install_decision(fresh_status, update, false, true)?;
                if let Some(reason) = fresh_decision.skip_reason {
                    let mut result = json!({
                        "status": "skipped",
                        "reason": reason,
                        "automatic": true,
                        "install_path": leased_target,
                        "requested_install_path": target_path,
                        "remote_health": fresh
                    });
                    if let (Some(result), Some(details)) =
                        (result.as_object_mut(), source.details.as_object())
                    {
                        result.extend(details.clone());
                    }
                    return Ok(RemoteAgentInstallLeaseOutcome::Skipped(result));
                }
                effective_force = fresh_decision.effective_force;
                plan.set_force(effective_force);

                // The fresh probe may have started the normal control-lane agent.
                // Stop it again before any staging or target mutation while the
                // remote lease is still held.
                let reset_timeout =
                    deadline.forward_timeout("post-lease control-lane agent worker exit")?;
                self.agent
                    .invalidate_shared_workers_with_timeout(
                        reset_timeout,
                        "post-lease control-lane agent worker exit",
                    )
                    .map_err(|error| {
                        deadline.map_budgeted_error(
                            BootstrapBudget::Forward,
                            "post-lease control-lane agent worker exit",
                            error,
                        )
                    })?;
                self.agent.clear_all_remote_unavailable();
                lease.ensure_held("automatic remote agent staging")?;
            }

            let launch = self.agent.launch.clone();
            let mut operations: Box<dyn AgentInstallOps + '_> = match plan {
                PreparedAgentInstallPlan::Posix(plan) => Box::new(PosixSshInstallOps {
                    plan,
                    ssh,
                    source: Some(upload),
                    launch,
                    normal_agent: &mut self.agent,
                    lease: &mut lease,
                    deadline,
                }),
                PreparedAgentInstallPlan::Windows(plan) => {
                    drop(upload);
                    Box::new(WindowsSshInstallOps {
                        plan,
                        ssh,
                        source_path: Some(source.path.clone()),
                        source_size,
                        source_sha256: source_sha256.clone(),
                        launch,
                        normal_agent: &mut self.agent,
                        lease: &mut lease,
                        deadline,
                    })
                }
            };
            let result = run_agent_install_transaction(operations.as_mut());
            drop(operations);
            Ok(RemoteAgentInstallLeaseOutcome::Transaction {
                result,
                effective_force,
            })
        })();
        let release = release_remote_install_lease_with_deadline(
            &mut lease,
            deadline,
            "remote agent installation lease release",
        );
        let (transaction, effective_force) = match lease_work {
            Ok(RemoteAgentInstallLeaseOutcome::Skipped(result)) => {
                release.context("failed to release remote agent installation lease")?;
                return Ok(result);
            }
            Ok(RemoteAgentInstallLeaseOutcome::Transaction {
                result,
                effective_force,
            }) => (result, effective_force),
            Err(error) => {
                let error = match release {
                    Ok(()) => error,
                    Err(release_error) if is_bootstrap_timeout(&release_error) => release_error
                        .context(format!(
                            "lease-protected remote agent work also failed: {error:#}"
                        )),
                    Err(release_error) => {
                        error.context(format!("install_lease_release_failed: {release_error:#}"))
                    }
                };
                return Err(error);
            }
        };
        let activated = match transaction {
            Ok(activated) => activated,
            Err(mut error) => {
                if let Err(release) = release {
                    error.bootstrap_timeout |= is_bootstrap_timeout(&release);
                    error
                        .message
                        .push_str(&format!("; install_lease_release_failed: {release}"));
                }
                self.record_agent_install_error_health(&error);
                return Err(anyhow!(error));
            }
        };
        if let Err(error) = release {
            let timed_out = is_bootstrap_timeout(&error);
            let error = install_transaction_error_with_timeout(
                AgentInstallFinalState::CandidateHealthy,
                timed_out,
                format!(
                    "cleanup_failed: activated agent is healthy but installation lease release failed: {error}"
                ),
            );
            self.record_agent_install_error_health(&error);
            return Err(anyhow!(error));
        }
        let after_timeout = deadline.recovery_timeout("post-install remote agent health probe")?;
        let after = self.remote_health_with_timeout(preempt_epoch, after_timeout);
        deadline.recovery_timeout("post-install remote agent health probe")?;
        let mut result = json!({
            "status": if update { "updated" } else { "installed" },
            "install_path": activated.staged.target_path,
            "requested_install_path": target_path,
            "source_path": source.path.to_string_lossy(),
            "source_hash": source_hash,
            "source_sha256": source_sha256,
            "bytes": source_size,
            "force": effective_force,
            "automatic": automatic,
            "remote_health": after
        });
        if let (Some(result), Some(details)) = (result.as_object_mut(), source.details.as_object())
        {
            result.extend(details.clone());
        }
        Ok(result)
    }

    fn resolve_agent_source(&self, deadline: BootstrapDeadline) -> Result<ResolvedAgentSource> {
        deadline.forward_timeout("agent source resolution")?;
        if let Some(registry) = &self.agent.launch.registry {
            let cached_platform = self
                .agent
                .launch
                .cached_remote_host_info()
                .as_ref()
                .map(RegistryPlatform::from);
            self.update_registry_health(|health| health.begin_fetch(cached_platform));
            let result = self.resolve_registry_agent_source(registry, deadline);
            if let Err(error) = &result {
                if is_bootstrap_timeout(error) {
                    self.record_registry_bootstrap_timeout();
                } else {
                    self.record_registry_source_error(error);
                }
            }
            return result;
        }

        let source = self
            .agent
            .launch
            .local_agent
            .clone()
            .unwrap_or_else(|| PathBuf::from(&self.agent.launch.agent));
        let file = File::open(&source)
            .with_context(|| format!("local agent source is not readable: {}", source.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("failed to stat local agent source: {}", source.display()))?;
        if !metadata.is_file() {
            bail!("local agent source is not a file: {}", source.display());
        }
        deadline.forward_timeout("local agent source inspection")?;
        Ok(ResolvedAgentSource {
            details: json!({ "agent_source": "local" }),
            path: source,
            file,
            expected_sha256: None,
            _registry_artifact: None,
        })
    }

    fn resolve_registry_agent_source(
        &self,
        registry: &RegistryLaunchConfig,
        deadline: BootstrapDeadline,
    ) -> Result<ResolvedAgentSource> {
        let host_timeout = deadline.forward_timeout("remote host detection")?;
        let host = self
            .agent
            .launch
            .remote_host_info_with_timeout(host_timeout)
            .map_err(|error| {
                deadline.map_budgeted_error(
                    BootstrapBudget::Forward,
                    "remote host detection",
                    error,
                )
            })?;
        self.update_registry_health(|health| health.set_platform(&host));
        let target = host.target.parse::<AgentTarget>().map_err(|()| {
            anyhow!(
                "remote host selected unsupported registry target {:?}",
                host.target
            )
        })?;
        let version = Version::parse(env!("CARGO_PKG_VERSION"))
            .context("sidecar package version is not valid semantic versioning")?;
        let manifest_url = registry
            .url_template
            .expand(&version)
            .context("failed to expand remote agent registry URL")?;
        self.update_registry_health(|health| health.set_manifest_url(&manifest_url));
        let cache_dir = registry
            .cache_dir
            .as_deref()
            .ok_or_else(|| anyhow!("remote agent registry cache directory was not initialized"))?;
        let fetch_timeout = registry_fetch_timeout(registry.timeout, deadline)?;
        let fetched = fetch_verified_artifact(&FetchConfig {
            manifest_url: &manifest_url,
            target,
            expected_version: &version,
            expected_protocol_version: u32::from(PROTOCOL_VERSION),
            trusted_keys: &registry.trusted_keys,
            signature_threshold: registry.signature_threshold,
            cache_dir,
            cache_max_bytes: registry.cache_max_bytes,
            timeout: fetch_timeout,
        })
        .map_err(|error| {
            let error = anyhow!(error).context("failed to retrieve a verified remote agent build");
            deadline.map_budgeted_error(BootstrapBudget::Forward, "registry fetch", error)
        })?;
        deadline.forward_timeout("registry artifact preparation")?;
        let mut signing_key_ids: Vec<_> = fetched
            .verified_manifest
            .verified_signers
            .iter()
            .map(|signer| signer.key_id.clone())
            .collect();
        signing_key_ids.sort();
        let file = fetched
            .try_clone_file()
            .context("failed to clone verified registry artifact handle")?;
        let artifact_source = artifact_source_name(fetched.source);
        let manifest_source = manifest_source_name(fetched.manifest_source);
        let redacted_manifest_url = redact_registry_manifest_url(&manifest_url);
        let details = json!({
            "agent_source": "registry",
            "registry_manifest_url": redacted_manifest_url,
            "registry_target": target.to_string(),
            "registry_manifest_sha256": fetched.verified_manifest.manifest_sha256,
            "registry_signing_key_ids": signing_key_ids,
            "registry_artifact_source": artifact_source,
            "registry_manifest_source": manifest_source,
            "registry_cache_state": {
                "manifest_fallback": fetched.cache_state.manifest_fallback,
                "artifact_hit": fetched.cache_state.artifact_hit,
            }
        });
        self.update_registry_health(|health| {
            health.set_verified(&fetched, signing_key_ids.clone());
        });
        Ok(ResolvedAgentSource {
            path: fetched.local_path.clone(),
            file,
            expected_sha256: Some(fetched.sha256.clone()),
            details,
            _registry_artifact: Some(fetched),
        })
    }

    fn record_registry_source_error(&self, error: &anyhow::Error) {
        let (code, detail) = registry_error_code(error).map_or_else(
            || {
                (
                    "source_resolution_failed".to_string(),
                    "registry source resolution failed".to_string(),
                )
            },
            |code| {
                (
                    code.as_str().to_string(),
                    format!("signed registry retrieval failed ({code})"),
                )
            },
        );
        self.update_registry_health(|health| health.set_error(&code, &detail));
    }

    fn record_registry_error_code(&self, code: FetchErrorCode) {
        let detail = format!("signed registry artifact preparation failed ({code})");
        self.update_registry_health(|health| health.set_error(code.as_str(), &detail));
    }

    fn record_registry_bootstrap_timeout(&self) {
        if self.agent.launch.registry.is_some() {
            self.update_registry_health(|health| {
                health.set_error(
                    "bootstrap_timeout",
                    "signed registry bootstrap exceeded its whole-request deadline",
                );
            });
        }
    }

    fn decorate_remote_agent_health(&self, mut value: Value) -> Value {
        let cached_host = self.agent.launch.cached_remote_host_info();
        let install_path = cached_host
            .as_ref()
            .and_then(|host| default_remote_agent_install_path(&self.agent.launch.agent, host).ok())
            .or_else(|| default_posix_remote_agent_install_path(&self.agent.launch.agent).ok())
            .unwrap_or_else(|| self.agent.launch.agent.clone());
        let managed_install_path = cached_host
            .as_ref()
            .and_then(|host| default_remote_agent_install_path("nrm-agent", host).ok())
            .unwrap_or_else(|| REMOTE_AGENT_MANAGED_PATH.to_string());
        let source = self
            .agent
            .launch
            .local_agent
            .clone()
            .unwrap_or_else(|| PathBuf::from(&self.agent.launch.agent));
        let local_agent_available = fs::metadata(&source)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false);
        let local_agent_error = (!local_agent_available)
            .then(|| format!("local agent source is not readable: {}", source.display()));
        let agent_status = classify_remote_agent_status(&value);
        let is_ssh = matches!(self.agent.launch.transport, RemoteTransport::Ssh(_));
        let registry_configured = self.agent.launch.registry.is_some();
        let install_source_available = registry_configured || local_agent_available;
        let update_available = is_ssh
            && install_source_available
            && matches!(
                agent_status.as_str(),
                "missing_agent" | "agent_not_executable" | "protocol_mismatch" | "version_mismatch"
            );
        if let Some(object) = value.as_object_mut() {
            object.insert("agent_status".to_string(), json!(agent_status));
            object.insert(
                "expected_agent_version".to_string(),
                json!(env!("CARGO_PKG_VERSION")),
            );
            object.insert(
                "expected_protocol_version".to_string(),
                json!(PROTOCOL_VERSION),
            );
            object.insert("remote_agent".to_string(), json!(self.agent.launch.agent));
            object.insert("remote_agent_install_path".to_string(), json!(install_path));
            object.insert(
                "managed_remote_agent_path".to_string(),
                json!(managed_install_path),
            );
            object.insert(
                "local_agent_path".to_string(),
                json!(source.to_string_lossy()),
            );
            object.insert(
                "local_agent_available".to_string(),
                json!(local_agent_available),
            );
            object.insert(
                "registry_configured".to_string(),
                json!(registry_configured),
            );
            if !registry_configured {
                object.insert("agent_source".to_string(), json!("local"));
            } else {
                object.insert("agent_source".to_string(), json!("registry"));
            }
            if !registry_configured {
                if let Some(error) = local_agent_error {
                    object.insert("local_agent_error".to_string(), json!(error));
                }
            }
            object.insert(
                "install_available".to_string(),
                json!(is_ssh && install_source_available),
            );
            object.insert("update_available".to_string(), json!(update_available));
            if update_available {
                object.insert("repair_command".to_string(), json!("RemoteUpdateAgent"));
            } else if is_ssh && !install_source_available {
                object.insert(
                    "repair_command".to_string(),
                    json!("configure local agent path"),
                );
            }
        }
        value
    }

    fn scan(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(10_000) as usize;
        let resume = params
            .get("resume")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let explicit_after = optional_string_param(&params, "after").is_some();
        let rescan_after_ms = params.get("rescan_after_ms").and_then(Value::as_u64);
        let after = self.scan_after_param(&params, resume)?;
        if resume && after.is_none() && !explicit_after {
            if let Some(skipped) = self.completed_scan_skip_response(rescan_after_ms)? {
                return Ok(skipped);
            }
        }
        let response = match self.agent.request_maybe_preemptible_since(
            Request::Scan {
                limit,
                after: after.clone(),
            },
            preempt_epoch,
        )? {
            AgentRequestOutcome::Response(response) => response,
            AgentRequestOutcome::Preempted => {
                return Ok(json!({
                    "entries": [],
                    "truncated": true,
                    "next_after": after,
                    "preempted": true
                }));
            }
        };
        match response {
            Response::Scan { entries, truncated } => {
                let next_after = entries.last().map(|entry| entry.path.clone());
                self.mirror.upsert_metadata_batch(&entries, "metadata")?;
                self.record_scan_progress(resume, truncated, next_after.as_deref())?;
                Ok(json!({
                    "entries": entries,
                    "truncated": truncated,
                    "next_after": next_after,
                    "resumed_after": after
                }))
            }
            other => bail!("unexpected scan response: {other:?}"),
        }
    }

    fn scan_after_param(&self, params: &Value, resume: bool) -> Result<Option<String>> {
        if let Some(after) = optional_string_param(params, "after") {
            return Ok(Some(
                normalize_relative_path(after)?
                    .to_string_lossy()
                    .replace('\\', "/"),
            ));
        }
        if resume {
            return self.mirror.background_scan_cursor();
        }
        Ok(None)
    }

    fn record_scan_progress(
        &self,
        resume: bool,
        truncated: bool,
        next_after: Option<&str>,
    ) -> Result<()> {
        if !resume {
            return Ok(());
        }
        if truncated {
            if let Some(next_after) = next_after {
                self.mirror.set_background_scan_cursor(Some(next_after))?;
            }
            self.mirror.set_background_scan_completed_at_ms(None)?;
        } else {
            self.mirror.set_background_scan_cursor(None)?;
            self.mirror
                .set_background_scan_completed_at_ms(Some(now_ms()))?;
        }
        Ok(())
    }

    fn completed_scan_skip_response(&self, rescan_after_ms: Option<u64>) -> Result<Option<Value>> {
        let Some(rescan_after_ms) = rescan_after_ms else {
            return Ok(None);
        };
        let Some(completed_at_ms) = self.mirror.background_scan_completed_at_ms()? else {
            return Ok(None);
        };
        let now = now_ms();
        let age_ms = now.saturating_sub(completed_at_ms);
        if age_ms as u64 >= rescan_after_ms {
            return Ok(None);
        }
        Ok(Some(json!({
            "entries": [],
            "truncated": false,
            "next_after": Value::Null,
            "resumed_after": Value::Null,
            "skipped": true,
            "skip_reason": "background scan completed recently",
            "scan_completed_at_ms": completed_at_ms,
            "rescan_after_ms": rescan_after_ms,
            "rescan_due_in_ms": rescan_after_ms.saturating_sub(age_ms as u64)
        })))
    }

    fn open(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let path = required_string(&params, "path")?;
        let force = params
            .get("force")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let batch_max_file_bytes = params
            .get("batch_max_file_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_FILE_BYTES);
        if let Some(mut entry) = self.mirror.get(path)? {
            if entry.state == "hydrated" {
                let mut restored_from_snapshot = false;
                if entry.dirty && !entry.local_path.exists() {
                    self.mirror.restore_latest_dirty_snapshot(&entry)?;
                    restored_from_snapshot = true;
                    entry = self
                        .mirror
                        .get(&entry.relative_path)?
                        .ok_or_else(|| anyhow!("restored file lost mirror metadata"))?;
                }
                if entry.local_path.exists() {
                    let (synced_entry, _) = self.mirror.sync_cached_file_integrity(&entry)?;
                    entry = synced_entry;
                    if entry.dirty {
                        return Ok(Self::cached_open_response(
                            &entry,
                            "dirty",
                            force,
                            restored_from_snapshot,
                        ));
                    }
                    if !force {
                        let reason = match entry.validation_state.as_str() {
                            "stale" | "deleted" | "conflict" => entry.validation_state.as_str(),
                            _ => "cached",
                        };
                        return Ok(Self::cached_open_response(
                            &entry,
                            reason,
                            false,
                            restored_from_snapshot,
                        ));
                    }
                }
            }
        }
        let hydrated = match self.open_hydrate(path, batch_max_file_bytes, preempt_epoch)? {
            HydrateOutcome::Hydrated { entry, mode } => (entry, mode),
            HydrateOutcome::Preempted => {
                return Ok(json!({
                    "path": path,
                    "preempted": true
                }));
            }
        };
        let (hydrated, mode) = hydrated;
        Ok(json!({
            "path": hydrated.relative_path,
            "local_path": hydrated.local_path.to_string_lossy(),
            "hash": hydrated.remote_hash,
            "size": hydrated.size,
            "validation_state": hydrated.validation_state,
            "validated_at_ms": hydrated.validated_at_ms,
            "hydrated_via": mode.as_str(),
            "cached": false
        }))
    }

    fn cached_open_response(
        entry: &MirrorEntry,
        cache_reason: &str,
        force_skipped: bool,
        restored_from_snapshot: bool,
    ) -> Value {
        json!({
            "path": entry.relative_path,
            "local_path": entry.local_path.to_string_lossy(),
            "hash": entry.remote_hash,
            "local_hash": entry.local_hash,
            "size": entry.size,
            "validation_state": entry.validation_state,
            "validated_at_ms": entry.validated_at_ms,
            "last_error": entry.last_error,
            "dirty": entry.dirty,
            "cached": true,
            "cache_reason": cache_reason,
            "force_skipped": force_skipped,
            "restored_from_snapshot": restored_from_snapshot
        })
    }

    fn open_hydrate(
        &mut self,
        path: &str,
        batch_max_file_bytes: u64,
        preempt_epoch: u64,
    ) -> Result<HydrateOutcome> {
        if batch_max_file_bytes > 0 {
            if let Some(outcome) =
                self.hydrate_open_batch(path, batch_max_file_bytes, preempt_epoch)?
            {
                return Ok(outcome);
            }
        }
        self.hydrate(path, Some(preempt_epoch))
    }

    fn hydrate_open_batch(
        &mut self,
        path: &str,
        max_file_bytes: u64,
        preempt_epoch: u64,
    ) -> Result<Option<HydrateOutcome>> {
        let request = Request::ReadFiles {
            paths: vec![path.to_string()],
            max_file_bytes,
            max_total_bytes: max_file_bytes,
        };
        let response = match self
            .agent
            .request_maybe_preemptible_since(request, preempt_epoch)?
        {
            AgentRequestOutcome::Response(response) => response,
            AgentRequestOutcome::Preempted => return Ok(Some(HydrateOutcome::Preempted)),
        };
        match response {
            Response::ReadFiles { mut files, .. } => {
                let Some(file) = files.pop() else {
                    return Ok(None);
                };
                let path = file.path.clone();
                self.record_batch_file(file)?;
                let entry = self.mirror.get(&path)?.ok_or_else(|| {
                    anyhow!("batch-open file was not recorded in mirror metadata")
                })?;
                Ok(Some(HydrateOutcome::Hydrated {
                    entry,
                    mode: HydrationMode::Batch,
                }))
            }
            other => bail!("unexpected batch open response: {other:?}"),
        }
    }

    fn prefetch(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let paths = params
            .get("paths")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("prefetch requires params.paths array"))?;
        let max_file_bytes = params
            .get("max_file_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_FILE_BYTES);
        let max_total_bytes = params
            .get("max_total_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_TOTAL_BYTES);
        let mut requested_paths = Vec::new();
        let mut errors = Vec::new();
        for value in paths {
            let Some(path) = value.as_str() else {
                errors.push(json!({"path": null, "error": "path must be a string"}));
                continue;
            };
            match self.normalize_prefetch_path(path) {
                Ok(path) => requested_paths.push(path),
                Err(error) => errors.push(json!({"path": path, "error": error.to_string()})),
            }
        }
        let (hydrated, batch_errors, truncated, preempted) = self.batch_hydrate(
            requested_paths,
            max_file_bytes,
            max_total_bytes,
            Some(preempt_epoch),
        )?;
        errors.extend(batch_errors);
        Ok(json!({
            "hydrated": hydrated,
            "errors": errors,
            "truncated": truncated,
            "preempted": preempted,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes
        }))
    }

    fn prefetch_known(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(16) as usize;
        let max_file_bytes = params
            .get("max_file_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_GREP_CACHE_MAX_FILE_BYTES);
        let max_total_bytes = params
            .get("max_total_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_GREP_CACHE_MAX_TOTAL_BYTES);
        let paths = self.mirror.known_prefetch_paths(limit)?;
        let requested = paths.len();
        let (hydrated, errors, truncated, preempted) = self.batch_hydrate(
            paths.clone(),
            max_file_bytes,
            max_total_bytes,
            Some(preempt_epoch),
        )?;
        Ok(json!({
            "requested": requested,
            "paths": paths,
            "hydrated": hydrated,
            "errors": errors,
            "truncated": truncated,
            "preempted": preempted,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes
        }))
    }

    fn prefetch_related(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let anchor = required_string(&params, "anchor")?;
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(16) as usize;
        let max_file_bytes = params
            .get("max_file_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_FILE_BYTES);
        let max_total_bytes = params
            .get("max_total_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_TOTAL_BYTES);
        let paths = self.mirror.related_prefetch_paths(anchor, limit)?;
        let requested = paths.len();
        let (hydrated, errors, truncated, preempted) = self.batch_hydrate(
            paths.clone(),
            max_file_bytes,
            max_total_bytes,
            Some(preempt_epoch),
        )?;
        Ok(json!({
            "anchor": anchor,
            "requested": requested,
            "paths": paths,
            "hydrated": hydrated,
            "errors": errors,
            "truncated": truncated,
            "preempted": preempted,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes
        }))
    }

    fn normalize_prefetch_path(&self, path: &str) -> Result<String> {
        let path = normalize_relative_path(path)?
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(entry) = self.mirror.get(&path)? {
            let (entry, _) = self.mirror.sync_cached_file_integrity(&entry)?;
            if entry.dirty {
                bail!("skipped dirty local mirror file");
            }
        }
        Ok(path)
    }

    fn batch_hydrate(
        &mut self,
        paths: Vec<String>,
        max_file_bytes: u64,
        max_total_bytes: u64,
        preempt_epoch: Option<u64>,
    ) -> Result<(usize, Vec<Value>, bool, bool)> {
        if paths.is_empty() {
            return Ok((0, Vec::new(), false, false));
        }
        let request = Request::ReadFiles {
            paths,
            max_file_bytes,
            max_total_bytes,
        };
        let response = if let Some(preempt_epoch) = preempt_epoch {
            match self
                .agent
                .request_maybe_preemptible_since(request, preempt_epoch)?
            {
                AgentRequestOutcome::Response(response) => response,
                AgentRequestOutcome::Preempted => return Ok((0, Vec::new(), true, true)),
            }
        } else {
            self.agent.request(request)?
        };
        match response {
            Response::ReadFiles {
                files,
                errors,
                truncated,
            } => {
                let mut hydrated = 0;
                let mut reported_errors = Vec::new();
                for file in files {
                    let path = file.path.clone();
                    match self.record_batch_file(file) {
                        Ok(()) => hydrated += 1,
                        Err(error) => reported_errors.push(json!({
                            "path": path,
                            "error": error.to_string()
                        })),
                    }
                }
                reported_errors.extend(
                    errors
                        .into_iter()
                        .map(|error| json!({"path": error.path, "error": error.message})),
                );
                Ok((hydrated, reported_errors, truncated, false))
            }
            other => bail!("unexpected batch read response: {other:?}"),
        }
    }

    fn record_batch_file(&self, file: BatchReadFile) -> Result<()> {
        let local_path = self.mirror.local_path(&file.path)?;
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let part_path = local_path.with_extension("nrm-batch-part");
        let result = (|| -> Result<()> {
            let mut part = File::create(&part_path)?;
            part.write_all(&file.content)?;
            part.sync_all()?;
            drop(part);
            let local_hash = hash_file(&part_path)?;
            if local_hash != file.hash {
                bail!(
                    "batch hydration hash mismatch for {}: local={local_hash} remote={}",
                    file.path,
                    file.hash
                );
            }
            let install = self.prepare_hydration_target(&file.path, &local_path, &file.hash)?;
            let local_hash = match install {
                HydrationInstall::ReplaceWithPart => {
                    rename_durable(&part_path, &local_path)?;
                    local_hash
                }
                HydrationInstall::AdoptExisting { local_hash } => {
                    let _ = fs::remove_file(&part_path);
                    local_hash
                }
            };
            self.mirror
                .record_hydrated(&file.meta, &file.hash, &local_hash)?;
            self.mirror
                .replace_search_index_from_bytes(&file.path, &local_hash, &file.content)?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&part_path);
            return Err(error);
        }
        Ok(())
    }

    fn prepare_hydration_target(
        &self,
        path: &str,
        local_path: &Path,
        remote_hash: &str,
    ) -> Result<HydrationInstall> {
        if let Some(entry) = self.mirror.get(path)? {
            if entry.local_path.exists() && entry.state != "hydrated" {
                if entry.dirty {
                    bail!("skipped dirty local mirror file");
                }
                let existing_hash = hash_file(&entry.local_path).with_context(|| {
                    format!(
                        "failed to hash existing local mirror file {}",
                        entry.local_path.display()
                    )
                })?;
                if existing_hash == remote_hash {
                    return Ok(HydrationInstall::AdoptExisting {
                        local_hash: existing_hash,
                    });
                }
                bail!("skipped existing local mirror file without hydrated metadata");
            }
            let (entry, _) = self.mirror.sync_cached_file_integrity(&entry)?;
            if entry.dirty {
                bail!("skipped dirty local mirror file");
            }
            return Ok(HydrationInstall::ReplaceWithPart);
        } else if local_path.exists() {
            let existing_hash = hash_file(local_path).with_context(|| {
                format!(
                    "failed to hash existing unmanaged local mirror file {}",
                    local_path.display()
                )
            })?;
            if existing_hash == remote_hash {
                return Ok(HydrationInstall::AdoptExisting {
                    local_hash: existing_hash,
                });
            }
            bail!("skipped existing unmanaged local mirror file");
        }
        Ok(HydrationInstall::ReplaceWithPart)
    }

    fn grep(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let query = required_string(&params, "query")?;
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
        let hydrate = params
            .get("hydrate")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let after = optional_string_param(&params, "after")
            .map(normalize_relative_path)
            .transpose()?
            .map(|value| value.to_string_lossy().replace('\\', "/"));
        let session_id = optional_string_param(&params, "session_id").map(ToOwned::to_owned);
        let max_files = optional_positive_usize_param(&params, "max_files");
        let max_file_bytes = params
            .get("max_file_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_GREP_CACHE_MAX_FILE_BYTES);
        let max_total_bytes = params
            .get("max_total_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_GREP_CACHE_MAX_TOTAL_BYTES);
        let response = match self.agent.request_maybe_preemptible_since(
            Request::Grep {
                query: query.to_string(),
                limit,
                after: after.clone(),
                max_files,
                max_file_bytes: Some(max_file_bytes),
                max_total_bytes: Some(max_total_bytes),
                session_id: session_id.clone(),
            },
            preempt_epoch,
        )? {
            AgentRequestOutcome::Response(response) => response,
            AgentRequestOutcome::Preempted => {
                return Ok(json!({
                    "hits": [],
                    "truncated": true,
                    "preempted": true,
                    "hydrated": 0,
                    "hydrate_errors": [],
                    "hydrate_truncated": false,
                    "next_after": after,
                    "session_id": session_id,
                    "scanned_files": 0
                }));
            }
        };
        match response {
            Response::Grep {
                hits,
                truncated,
                next_after,
                session_id,
                scanned_files,
            } => {
                let mut hydrated = 0;
                let mut hydrate_errors = Vec::new();
                let mut hydrate_truncated = false;
                if hydrate {
                    let paths = self.grep_hydration_paths(&hits)?;
                    let result = self.batch_hydrate(
                        paths,
                        max_file_bytes,
                        max_total_bytes,
                        Some(preempt_epoch),
                    )?;
                    hydrated = result.0;
                    hydrate_errors = result.1;
                    hydrate_truncated = result.2;
                    if result.3 {
                        return Ok(json!({
                            "hits": [],
                            "truncated": true,
                            "preempted": true,
                            "hydrated": hydrated,
                            "hydrate_errors": hydrate_errors,
                            "hydrate_truncated": hydrate_truncated,
                            "next_after": next_after,
                            "session_id": session_id,
                            "scanned_files": scanned_files
                        }));
                    }
                }
                let hits = self.grep_hits_with_local_paths(hits)?;
                Ok(json!({
                    "hits": hits,
                    "truncated": truncated,
                    "hydrated": hydrated,
                    "hydrate_errors": hydrate_errors,
                    "hydrate_truncated": hydrate_truncated,
                    "next_after": next_after,
                    "session_id": session_id,
                    "scanned_files": scanned_files
                }))
            }
            other => bail!("unexpected grep response: {other:?}"),
        }
    }

    fn git_status(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let paths = normalized_paths_param(&params, "paths")?;
        self.remote_git_request(
            Request::GitStatus {
                paths,
                max_output_bytes: git_output_max_bytes(&params),
            },
            preempt_epoch,
        )
    }

    fn git_diff(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let path = optional_string_param(&params, "path")
            .map(normalize_relative_path)
            .transpose()?
            .map(|value| value.to_string_lossy().replace('\\', "/"));
        let cached = params
            .get("cached")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        self.remote_git_request(
            Request::GitDiff {
                path,
                cached,
                max_output_bytes: git_output_max_bytes(&params),
            },
            preempt_epoch,
        )
    }

    fn git_blame(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let path = normalize_relative_path(required_string(&params, "path")?)?
            .to_string_lossy()
            .replace('\\', "/");
        self.remote_git_request(
            Request::GitBlame {
                path,
                max_output_bytes: git_output_max_bytes(&params),
            },
            preempt_epoch,
        )
    }

    fn remote_git_request(&mut self, request: Request, preempt_epoch: u64) -> Result<Value> {
        let response = match self
            .agent
            .request_maybe_preemptible_since(request, preempt_epoch)?
        {
            AgentRequestOutcome::Response(response) => response,
            AgentRequestOutcome::Preempted => {
                return Ok(json!({
                    "stdout": "",
                    "stderr": "",
                    "status_code": Value::Null,
                    "truncated": true,
                    "preempted": true
                }));
            }
        };
        match response {
            Response::Git { output } => Ok(json!({
                "stdout": output.stdout,
                "stderr": output.stderr,
                "status_code": output.status_code,
                "truncated": output.truncated
            })),
            other => bail!("unexpected git response: {other:?}"),
        }
    }

    fn grep_hydration_paths(&self, hits: &[nrm_protocol::SearchHit]) -> Result<Vec<String>> {
        let mut seen = HashSet::new();
        let mut paths = Vec::new();
        for hit in hits {
            if !seen.insert(hit.path.clone()) {
                continue;
            }
            let path = normalize_relative_path(&hit.path)?
                .to_string_lossy()
                .replace('\\', "/");
            if let Some(entry) = self.mirror.get(&path)? {
                let (entry, _) = self.mirror.sync_cached_file_integrity(&entry)?;
                if entry.dirty {
                    continue;
                }
            }
            paths.push(path);
        }
        Ok(paths)
    }

    fn grep_hits_with_local_paths(&self, hits: Vec<nrm_protocol::SearchHit>) -> Result<Vec<Value>> {
        let mut values = Vec::with_capacity(hits.len());
        for hit in hits {
            let entry = self
                .mirror
                .get(&hit.path)?
                .map(|entry| self.mirror.sync_cached_file_integrity(&entry))
                .transpose()?
                .map(|(entry, _)| entry);
            let local_path = entry
                .as_ref()
                .filter(|entry| {
                    !entry.dirty && entry.validation_state == "valid" && entry.local_path.is_file()
                })
                .map(|entry| entry.local_path.to_string_lossy().to_string());
            let mut value = json!({
                "path": hit.path,
                "line": hit.line,
                "column": hit.column,
                "text": hit.text
            });
            if let Some(local_path) = local_path {
                value["local_path"] = json!(local_path);
            }
            values.push(value);
        }
        Ok(values)
    }

    fn adopt(&mut self, params: Value) -> Result<Value> {
        let path = required_string(&params, "path")?;
        let queued = self.mirror.enqueue_adopted_local_save(path)?;
        Self::save_attempt_to_json(self.apply_save_entry(queued)?)
    }

    fn flush(&mut self, params: Value) -> Result<Value> {
        let path = required_string(&params, "path")?;
        let queued = self.mirror.enqueue_local_save(path)?;
        Self::save_attempt_to_json(self.apply_save_entry(queued)?)
    }

    fn recover_local_edits(&mut self, params: Value) -> Result<Value> {
        let limit = optional_positive_usize_param(&params, "limit").unwrap_or(256);
        let after = optional_string_param(&params, "after")
            .map(normalize_relative_path)
            .transpose()?
            .map(|value| value.to_string_lossy().replace('\\', "/"));
        self.mirror.recover_local_edits(limit, after.as_deref())
    }

    fn flush_queued(&mut self, params: Value) -> Result<Value> {
        let queue_id = params
            .get("queue_id")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("flush_queued requires params.queue_id"))?;
        let queued = self.mirror.save_queue_entry(queue_id)?;
        Self::save_attempt_to_json(self.apply_save_entry(queued)?)
    }

    fn flush_queue(&mut self, params: Value) -> Result<Value> {
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .map(|value| value.min(usize::MAX as u64) as usize);
        let attempts = self.replay_queued_saves(limit)?;
        let remaining = self.mirror.pending_save_count()?;
        Ok(json!({
            "attempts": attempts,
            "remaining": remaining
        }))
    }

    fn accept_local_conflict(&mut self, params: Value) -> Result<Value> {
        let queue_id = required_i64(&params, "queue_id")?;
        let queued = self.mirror.prepare_accept_local_conflict(queue_id)?;
        Self::save_attempt_to_json(self.apply_save_entry(queued)?)
    }

    fn accept_remote_conflict(&mut self, params: Value) -> Result<Value> {
        let queue_id = required_i64(&params, "queue_id")?;
        self.mirror.accept_remote_conflict(queue_id)
    }

    fn replay_queued_saves(&mut self, limit: Option<usize>) -> Result<Vec<Value>> {
        let entries = self.mirror.pending_save_entries(limit)?;
        let mut attempts = Vec::new();
        for entry in entries {
            let attempt = self.apply_save_entry(entry)?;
            let stop = attempt.should_stop_queue_replay();
            attempts.push(Self::save_attempt_to_json(attempt)?);
            if stop {
                break;
            }
        }
        Ok(attempts)
    }

    fn apply_save_entry(&mut self, entry: SaveQueueEntry) -> Result<SaveAttempt> {
        let snapshot_size = match fs::metadata(&entry.snapshot_path) {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                let reason = format!(
                    "failed to stat queued save snapshot {}: {error}",
                    entry.snapshot_path.display()
                );
                self.mirror
                    .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
                return Ok(SaveAttempt::Queued {
                    path: entry.relative_path,
                    reason,
                    remote_failure: false,
                });
            }
        };
        let actual_local_hash = match hash_file(&entry.snapshot_path) {
            Ok(hash) => hash,
            Err(error) => {
                let reason = format!(
                    "failed to hash queued save snapshot {}: {error}",
                    entry.snapshot_path.display()
                );
                self.mirror
                    .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
                return Ok(SaveAttempt::Queued {
                    path: entry.relative_path,
                    reason,
                    remote_failure: false,
                });
            }
        };
        if actual_local_hash != entry.local_hash {
            let reason = format!(
                "queued save snapshot hash mismatch: expected={} actual={actual_local_hash}",
                entry.local_hash
            );
            self.mirror
                .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
            return Ok(SaveAttempt::Queued {
                path: entry.relative_path,
                reason,
                remote_failure: false,
            });
        }
        if save_should_use_chunked_upload(snapshot_size) {
            return self.apply_chunked_save_entry(entry, snapshot_size);
        }

        let content = match fs::read(&entry.snapshot_path) {
            Ok(content) => content,
            Err(error) => {
                let reason = format!(
                    "failed to read queued save snapshot {}: {error}",
                    entry.snapshot_path.display()
                );
                self.mirror
                    .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
                return Ok(SaveAttempt::Queued {
                    path: entry.relative_path,
                    reason,
                    remote_failure: false,
                });
            }
        };

        self.apply_small_save_entry(entry, content)
    }

    fn apply_small_save_entry(
        &mut self,
        entry: SaveQueueEntry,
        content: Vec<u8>,
    ) -> Result<SaveAttempt> {
        let response = match self.agent.request(Request::WriteFileCas {
            path: entry.relative_path.clone(),
            expected_hash: entry.expected_hash.clone(),
            content,
        }) {
            Ok(response) => response,
            Err(error) => {
                let reason = format!("remote save attempt failed: {error}");
                self.mirror
                    .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
                return Ok(SaveAttempt::Queued {
                    path: entry.relative_path,
                    reason,
                    remote_failure: true,
                });
            }
        };

        match response {
            Response::WriteFileCas { outcome } => self.record_save_outcome(&entry, outcome),
            other => bail!("unexpected flush response: {other:?}"),
        }
    }

    fn apply_chunked_save_entry(
        &mut self,
        entry: SaveQueueEntry,
        snapshot_size: u64,
    ) -> Result<SaveAttempt> {
        let begin = match self.agent.request(Request::BeginWriteFileCas {
            path: entry.relative_path.clone(),
            expected_hash: entry.expected_hash.clone(),
            content_hash: entry.local_hash.clone(),
            size: snapshot_size,
        }) {
            Ok(response) => response,
            Err(error) => {
                let reason = format!("remote chunked save start failed: {error}");
                self.mirror
                    .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
                return Ok(SaveAttempt::Queued {
                    path: entry.relative_path,
                    reason,
                    remote_failure: true,
                });
            }
        };

        let upload_id = match begin {
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Started(started),
            } => started.upload_id,
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Conflict(conflict),
            } => {
                return self.record_save_outcome(&entry, SaveOutcome::Conflict(conflict));
            }
            other => bail!("unexpected chunked save begin response: {other:?}"),
        };

        if let Err(error) = self.upload_snapshot_chunks(&entry, &upload_id) {
            let _ = self.agent.request(Request::AbortWriteFileCas {
                upload_id: upload_id.clone(),
            });
            let reason = format!("remote chunked save upload failed: {error}");
            self.mirror
                .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
            return Ok(SaveAttempt::Queued {
                path: entry.relative_path,
                reason,
                remote_failure: true,
            });
        }

        let finish = match self
            .agent
            .request(Request::FinishWriteFileCas { upload_id })
        {
            Ok(response) => response,
            Err(error) => {
                let reason = format!("remote chunked save finish failed: {error}");
                self.mirror
                    .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
                return Ok(SaveAttempt::Queued {
                    path: entry.relative_path,
                    reason,
                    remote_failure: true,
                });
            }
        };

        match finish {
            Response::FinishWriteFileCas { outcome } => self.record_save_outcome(&entry, outcome),
            other => bail!("unexpected chunked save finish response: {other:?}"),
        }
    }

    fn upload_snapshot_chunks(&mut self, entry: &SaveQueueEntry, upload_id: &str) -> Result<()> {
        let mut file = File::open(&entry.snapshot_path)?;
        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; SAVE_UPLOAD_CHUNK_BYTES];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let response = self.agent.request(Request::WriteFileChunk {
                upload_id: upload_id.to_string(),
                offset,
                content: buffer[..read].to_vec(),
            })?;
            match response {
                Response::WriteFileChunk { accepted, .. } if accepted == offset + read as u64 => {
                    offset = accepted;
                }
                Response::WriteFileChunk { accepted, .. } => {
                    bail!(
                        "agent accepted unexpected byte count for {}: expected={} accepted={accepted}",
                        entry.relative_path,
                        offset + read as u64
                    );
                }
                other => bail!("unexpected chunk write response: {other:?}"),
            }
        }
        Ok(())
    }

    fn record_save_outcome(
        &self,
        entry: &SaveQueueEntry,
        outcome: SaveOutcome,
    ) -> Result<SaveAttempt> {
        match outcome {
            SaveOutcome::Applied(applied) => {
                self.mirror.mark_save_applied(
                    entry.id,
                    &applied.path,
                    &applied.new_hash,
                    applied.size,
                    applied.mtime_ms,
                )?;
                Ok(SaveAttempt::Applied {
                    path: applied.path,
                    hash: applied.new_hash,
                    size: applied.size,
                })
            }
            SaveOutcome::Conflict(conflict) => {
                if conflict.actual_hash.as_deref() == Some(entry.local_hash.as_str()) {
                    let size = conflict.remote_size.unwrap_or_else(|| {
                        fs::metadata(&entry.snapshot_path)
                            .map(|metadata| metadata.len())
                            .unwrap_or(0)
                    });
                    self.mirror.mark_save_applied(
                        entry.id,
                        &conflict.path,
                        &entry.local_hash,
                        size,
                        now_ms(),
                    )?;
                    return Ok(SaveAttempt::Applied {
                        path: conflict.path,
                        hash: entry.local_hash.clone(),
                        size,
                    });
                }
                let remote_content_bytes = conflict.remote_content.len();
                let message = if conflict.remote_content_truncated {
                    format!(
                        "remote content changed before queued save was applied; saved first {} of {} remote bytes",
                        remote_content_bytes,
                        conflict
                            .remote_size
                            .map(|size| size.to_string())
                            .unwrap_or_else(|| "unknown".to_string())
                    )
                } else {
                    "remote content changed before queued save was applied".to_string()
                };
                let conflict_path = self.mirror.record_save_conflict(
                    entry.id,
                    &conflict.path,
                    conflict.actual_hash.as_deref(),
                    &conflict.remote_content,
                    conflict.remote_content_truncated,
                    &message,
                )?;
                Ok(SaveAttempt::Conflict {
                    path: conflict.path,
                    expected_hash: conflict.expected_hash,
                    actual_hash: conflict.actual_hash,
                    remote_path: conflict_path,
                    remote_content_truncated: conflict.remote_content_truncated,
                    remote_size: conflict.remote_size,
                    remote_content_bytes,
                })
            }
        }
    }

    fn save_attempt_to_json(attempt: SaveAttempt) -> Result<Value> {
        Ok(match attempt {
            SaveAttempt::Applied { path, hash, size } => json!({
                "status": "applied",
                "path": path,
                "hash": hash,
                "size": size
            }),
            SaveAttempt::Conflict {
                path,
                expected_hash,
                actual_hash,
                remote_path,
                remote_content_truncated,
                remote_size,
                remote_content_bytes,
            } => json!({
                "status": "conflict",
                "path": path,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "remote_path": remote_path.to_string_lossy(),
                "remote_content_truncated": remote_content_truncated,
                "remote_size": remote_size,
                "remote_content_bytes": remote_content_bytes
            }),
            SaveAttempt::Queued {
                path,
                reason,
                remote_failure,
            } => json!({
                "status": "queued",
                "path": path,
                "reason": reason,
                "remote_failure": remote_failure
            }),
        })
    }

    fn validate(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let path = required_string(&params, "path")?;
        let mut entry = self
            .mirror
            .get(path)?
            .ok_or_else(|| anyhow!("{path} is not known in the mirror"))?;
        if entry.state == "hydrated" && entry.local_path.is_file() {
            let (synced_entry, _) = self.mirror.sync_cached_file_integrity(&entry)?;
            entry = synced_entry;
        }
        if entry.dirty {
            self.mirror
                .record_validation(&entry.relative_path, "dirty", None, None)?;
            return Ok(json!({
                "path": entry.relative_path,
                "status": "dirty",
                "remote_hash": entry.remote_hash,
                "local_hash": entry.local_hash,
                "skipped": true
            }));
        }
        let response = match self.agent.request_maybe_preemptible_since(
            Request::ValidateFiles {
                paths: vec![entry.relative_path.clone()],
                include_hash: true,
            },
            preempt_epoch,
        )? {
            AgentRequestOutcome::Response(response) => response,
            AgentRequestOutcome::Preempted => {
                return Ok(json!({
                    "path": entry.relative_path,
                    "preempted": true
                }));
            }
        };
        match response {
            Response::ValidateFiles { files, errors } => {
                if let Some(error) = errors.into_iter().next() {
                    self.mirror
                        .mark_validation_error(&error.path, &error.message)?;
                    return Ok(json!({
                        "path": error.path,
                        "status": "error",
                        "error": error.message,
                        "local_hash": entry.local_hash,
                        "remote_hash": null
                    }));
                }
                let file = files.into_iter().next().ok_or_else(|| {
                    anyhow!("validate returned no result for {}", entry.relative_path)
                })?;
                self.validation_file_to_json(file)
            }
            other => bail!("unexpected validate response: {other:?}"),
        }
    }

    fn refresh(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(500) as usize;
        let paths = if let Some(values) = params.get("paths").and_then(Value::as_array) {
            let mut paths = Vec::new();
            for value in values {
                let Some(path) = value.as_str() else {
                    bail!("refresh params.paths entries must be strings");
                };
                let normalized = normalize_relative_path(path)?
                    .to_string_lossy()
                    .replace('\\', "/");
                paths.push(normalized);
            }
            paths
        } else {
            self.mirror.cached_clean_paths(limit)?
        };
        self.refresh_paths(paths, preempt_epoch)
    }

    fn refresh_paths(&mut self, paths: Vec<String>, preempt_epoch: u64) -> Result<Value> {
        if paths.is_empty() {
            return Ok(json!({
                "checked": 0,
                "valid": 0,
                "stale": 0,
                "deleted": 0,
                "skipped": 0,
                "errors": []
            }));
        }
        let response = match self.agent.request_maybe_preemptible_since(
            Request::ValidateFiles {
                paths,
                include_hash: true,
            },
            preempt_epoch,
        )? {
            AgentRequestOutcome::Response(response) => response,
            AgentRequestOutcome::Preempted => {
                return Ok(json!({
                    "checked": 0,
                    "valid": 0,
                    "stale": 0,
                    "deleted": 0,
                    "skipped": 0,
                    "errors": [],
                    "preempted": true
                }));
            }
        };
        match response {
            Response::ValidateFiles { files, errors } => {
                let mut valid = 0;
                let mut stale = 0;
                let mut deleted = 0;
                let mut skipped = 0;
                let mut reported_errors = Vec::new();
                for file in files {
                    match self.record_validation_file(file) {
                        Ok("valid") => valid += 1,
                        Ok("stale") => stale += 1,
                        Ok("deleted") => deleted += 1,
                        Ok("dirty") => skipped += 1,
                        Ok(other) => reported_errors.push(json!({
                            "path": null,
                            "error": format!("unexpected validation state {other}")
                        })),
                        Err(error) => reported_errors.push(json!({
                            "path": null,
                            "error": error.to_string()
                        })),
                    }
                }
                for error in errors {
                    self.mirror
                        .mark_validation_error(&error.path, &error.message)
                        .ok();
                    reported_errors.push(json!({
                        "path": error.path,
                        "error": error.message
                    }));
                }
                Ok(json!({
                    "checked": valid + stale + deleted + skipped + reported_errors.len(),
                    "valid": valid,
                    "stale": stale,
                    "deleted": deleted,
                    "skipped": skipped,
                    "errors": reported_errors
                }))
            }
            other => bail!("unexpected refresh response: {other:?}"),
        }
    }

    fn record_validation_file(&self, file: BatchValidateFile) -> Result<&'static str> {
        let mut entry = self
            .mirror
            .get(&file.path)?
            .ok_or_else(|| anyhow!("{} is not known in the mirror", file.path))?;
        if entry.state == "hydrated" && entry.local_path.is_file() {
            let (synced_entry, _) = self.mirror.sync_cached_file_integrity(&entry)?;
            entry = synced_entry;
        }
        if entry.dirty {
            self.mirror
                .record_validation(&entry.relative_path, "dirty", None, None)?;
            return Ok("dirty");
        }
        let Some(meta) = file.meta else {
            self.mirror.record_validation(
                &entry.relative_path,
                "deleted",
                None,
                Some("remote file no longer exists"),
            )?;
            return Ok("deleted");
        };
        let remote_hash = meta.hash.as_deref();
        let state = if remote_hash == entry.remote_hash.as_deref() {
            "valid"
        } else {
            "stale"
        };
        let error = if state == "stale" {
            Some("remote hash differs from local mirror metadata")
        } else {
            None
        };
        let recorded_remote_hash = if state == "valid" { remote_hash } else { None };
        self.mirror
            .record_validation(&entry.relative_path, state, recorded_remote_hash, error)?;
        Ok(state)
    }

    fn validation_file_to_json(&self, file: BatchValidateFile) -> Result<Value> {
        let path = file.path.clone();
        let remote_hash = file.meta.as_ref().and_then(|meta| meta.hash.clone());
        let status = self.record_validation_file(file)?;
        let entry = self
            .mirror
            .get(&path)?
            .ok_or_else(|| anyhow!("{path} is not known in the mirror"))?;
        Ok(json!({
            "path": entry.relative_path,
            "status": status,
            "remote_hash": remote_hash,
            "local_hash": entry.local_hash,
            "skipped": status == "dirty"
        }))
    }

    fn hydrate(&mut self, path: &str, preempt_epoch: Option<u64>) -> Result<HydrateOutcome> {
        let local_path = self.mirror.local_path(path)?;
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let part_path = local_path.with_extension("nrm-part");
        let hydrated = (|| -> Result<Option<(FileMeta, String, String)>> {
            let mut part = File::create(&part_path)?;
            let mut offset = 0_u64;

            let (meta, remote_hash) = loop {
                let request = Request::ReadFile {
                    path: path.to_string(),
                    offset,
                    len: Some(DEFAULT_CHUNK_SIZE),
                };
                let response = if let Some(preempt_epoch) = preempt_epoch {
                    match self
                        .agent
                        .request_maybe_preemptible_since(request, preempt_epoch)?
                    {
                        AgentRequestOutcome::Response(response) => response,
                        AgentRequestOutcome::Preempted => return Ok(None),
                    }
                } else {
                    self.agent.request(request)?
                };
                match response {
                    Response::ReadFile {
                        eof,
                        content,
                        hash,
                        meta,
                        ..
                    } => {
                        part.write_all(&content)?;
                        offset += content.len() as u64;
                        if eof {
                            if hash.is_empty() {
                                bail!("remote read for {path} completed without a content hash");
                            }
                            break (meta, hash);
                        }
                    }
                    other => bail!("unexpected read response: {other:?}"),
                }
            };
            part.sync_all()?;
            drop(part);

            let local_hash = hash_file(&part_path)?;
            if local_hash != remote_hash {
                bail!(
                    "local hydration hash mismatch for {path}: local={local_hash} remote={remote_hash}"
                );
            }
            let install = self.prepare_hydration_target(path, &local_path, &remote_hash)?;
            let local_hash = match install {
                HydrationInstall::ReplaceWithPart => {
                    rename_durable(&part_path, &local_path)?;
                    local_hash
                }
                HydrationInstall::AdoptExisting { local_hash } => {
                    let _ = fs::remove_file(&part_path);
                    local_hash
                }
            };
            Ok(Some((meta, remote_hash, local_hash)))
        })();
        let Some((meta, remote_hash, local_hash)) = (match hydrated {
            Ok(hydrated) => hydrated,
            Err(error) => {
                let _ = fs::remove_file(&part_path);
                return Err(error);
            }
        }) else {
            let _ = fs::remove_file(&part_path);
            return Ok(HydrateOutcome::Preempted);
        };
        self.mirror
            .record_hydrated(&meta, &remote_hash, &local_hash)?;
        let hydrated = self
            .mirror
            .get(path)?
            .ok_or_else(|| anyhow!("hydrated file was not recorded in mirror metadata"))?;
        let file_len = fs::metadata(&hydrated.local_path)
            .map(|metadata| metadata.len())
            .unwrap_or(meta.size);
        self.mirror
            .rebuild_search_index_from_local_file(&hydrated, &local_hash, file_len)?;
        Ok(HydrateOutcome::Hydrated {
            entry: hydrated,
            mode: HydrationMode::Chunked,
        })
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        CommandKind::Serve {
            remote_root,
            ssh,
            agent,
            local_agent,
            state_dir,
            request_timeout_ms,
            ssh_connect_timeout_seconds,
            registry,
        } => {
            let registry = registry.into_config()?;
            let transport = RemoteTransport::from_ssh(ssh, ssh_connect_timeout_seconds)?;
            let remote_root = transport.normalize_remote_root(remote_root)?;
            run_server(
                remote_root,
                transport,
                agent,
                local_agent,
                registry,
                state_dir,
                request_timeout_ms,
            )
        }
        CommandKind::Listen {
            socket,
            remote_root,
            ssh,
            agent,
            local_agent,
            state_dir,
            request_timeout_ms,
            ssh_connect_timeout_seconds,
            registry,
        } => {
            let registry = registry.into_config()?;
            let transport = RemoteTransport::from_ssh(ssh, ssh_connect_timeout_seconds)?;
            let remote_root = transport.normalize_remote_root(remote_root)?;
            run_listener(
                socket,
                remote_root,
                transport,
                agent,
                local_agent,
                registry,
                state_dir,
                request_timeout_ms,
            )
        }
        CommandKind::LspProxy {
            remote_root,
            local_root,
            ssh,
            ssh_connect_timeout_seconds,
            command,
        } => {
            let transport = RemoteTransport::from_ssh(ssh, ssh_connect_timeout_seconds)?;
            let remote_root = transport.normalize_remote_root(remote_root)?;
            run_lsp_proxy(remote_root, local_root, transport, command)
        }
    }
}

fn run_server(
    remote_root: PathBuf,
    transport: RemoteTransport,
    agent: String,
    local_agent: Option<PathBuf>,
    registry: Option<RegistryLaunchConfig>,
    state_dir: Option<PathBuf>,
    request_timeout_ms: u64,
) -> Result<()> {
    let (response_tx, response_rx) = mpsc::sync_channel::<ServerMessage>(1024);
    let writer = spawn_stdout_writer(response_rx);
    let stdin = io::stdin();
    let session = run_server_session(
        remote_root,
        transport,
        agent,
        local_agent,
        registry,
        state_dir,
        request_timeout_ms,
        stdin.lock(),
        response_tx,
        true,
    );
    join_writer(writer, "server writer thread")?;
    session.map(|_| ())
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_listener(
    socket: PathBuf,
    remote_root: PathBuf,
    transport: RemoteTransport,
    agent: String,
    local_agent: Option<PathBuf>,
    registry: Option<RegistryLaunchConfig>,
    state_dir: Option<PathBuf>,
    request_timeout_ms: u64,
) -> Result<()> {
    prepare_listener_socket(&socket)?;
    let listener = bind_secure_listener_socket(&socket)?;
    sync_parent_dir(&socket)?;

    let listen_result = (|| -> Result<()> {
        for stream in listener.incoming() {
            let stream = stream.with_context(|| {
                format!(
                    "failed to accept sidecar socket connection on {}",
                    socket.display()
                )
            })?;
            let exit = run_socket_server_session(
                remote_root.clone(),
                transport.clone(),
                agent.clone(),
                local_agent.clone(),
                registry.clone(),
                state_dir.clone(),
                request_timeout_ms,
                stream,
            )?;
            if exit.shutdown_listener {
                break;
            }
        }
        Ok(())
    })();

    drop(listener);
    let _ = fs::remove_file(&socket);
    let _ = sync_parent_dir(&socket);
    listen_result
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
fn run_listener(
    _socket: PathBuf,
    _remote_root: PathBuf,
    _transport: RemoteTransport,
    _agent: String,
    _local_agent: Option<PathBuf>,
    _registry: Option<RegistryLaunchConfig>,
    _state_dir: Option<PathBuf>,
    _request_timeout_ms: u64,
) -> Result<()> {
    bail!("sidecar socket listener is only supported on Unix platforms")
}

#[cfg(unix)]
const LISTENER_DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
const LISTENER_SOCKET_MODE: u32 = 0o600;

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not access caller-provided memory.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn listener_socket_directory(socket: &Path) -> &Path {
    socket
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn validate_listener_directory_metadata(
    directory: &Path,
    metadata: &fs::Metadata,
    expected_uid: u32,
) -> Result<()> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "sidecar socket directory must be a directory and not a symlink: {}",
            directory.display()
        );
    }
    if metadata.uid() != expected_uid {
        bail!(
            "sidecar socket directory must be owned by the current uid: {} (owner={}, current={expected_uid})",
            directory.display(),
            metadata.uid()
        );
    }
    let mode = metadata.mode() & 0o7777;
    if mode != LISTENER_DIRECTORY_MODE {
        bail!(
            "sidecar socket directory must have mode 0700: {} (mode={mode:04o})",
            directory.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_listener_ancestor_metadata(
    ancestor: &Path,
    metadata: &fs::Metadata,
    child_uid: u32,
    expected_uid: u32,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        // The symlink entry is protected by its lexical parent. The resolved
        // target chain is validated independently.
        return Ok(());
    }
    if !metadata.file_type().is_dir() {
        bail!(
            "sidecar socket ancestor must be a directory or symlink: {}",
            ancestor.display()
        );
    }
    if metadata.uid() != expected_uid && metadata.uid() != 0 {
        bail!(
            "sidecar socket ancestors must be owned by the current uid or root: {} (owner={}, current={expected_uid})",
            ancestor.display(),
            metadata.uid()
        );
    }

    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        if mode & 0o1000 == 0 {
            bail!(
                "sidecar socket ancestors must not be group/world-writable unless sticky: {} (mode={mode:04o})",
                ancestor.display()
            );
        }
        if child_uid != expected_uid && child_uid != 0 {
            bail!(
                "sidecar socket sticky ancestor does not protect its child entry: {}",
                ancestor.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_listener_ancestor_chain(directory: &Path, expected_uid: u32) -> Result<()> {
    let mut current = directory.to_path_buf();
    let mut child_metadata = fs::symlink_metadata(&current).with_context(|| {
        format!(
            "failed to inspect sidecar socket directory ancestor {}",
            current.display()
        )
    })?;
    while let Some(parent) = current.parent() {
        if parent == current {
            break;
        }
        let metadata = fs::symlink_metadata(parent).with_context(|| {
            format!(
                "failed to inspect sidecar socket directory ancestor {}",
                parent.display()
            )
        })?;
        validate_listener_ancestor_metadata(parent, &metadata, child_metadata.uid(), expected_uid)?;
        child_metadata = metadata;
        current = parent.to_path_buf();
    }
    Ok(())
}

#[cfg(unix)]
fn validate_listener_directory_ancestors(directory: &Path, expected_uid: u32) -> Result<()> {
    let lexical = std::path::absolute(directory).with_context(|| {
        format!(
            "failed to make sidecar socket directory absolute: {}",
            directory.display()
        )
    })?;
    validate_listener_ancestor_chain(&lexical, expected_uid)?;

    let resolved = fs::canonicalize(directory).with_context(|| {
        format!(
            "failed to resolve sidecar socket directory {}",
            directory.display()
        )
    })?;
    if resolved != lexical {
        let metadata = fs::symlink_metadata(&resolved).with_context(|| {
            format!(
                "failed to inspect resolved sidecar socket directory {}",
                resolved.display()
            )
        })?;
        validate_listener_directory_metadata(&resolved, &metadata, expected_uid)?;
        validate_listener_ancestor_chain(&resolved, expected_uid)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_listener_creation_anchor(anchor: &Path, expected_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(anchor).with_context(|| {
        format!(
            "failed to inspect sidecar socket creation ancestor {}",
            anchor.display()
        )
    })?;
    validate_listener_ancestor_metadata(anchor, &metadata, expected_uid, expected_uid)?;
    validate_listener_ancestor_chain(anchor, expected_uid)?;

    let resolved = fs::canonicalize(anchor).with_context(|| {
        format!(
            "failed to resolve sidecar socket creation ancestor {}",
            anchor.display()
        )
    })?;
    if resolved != anchor {
        let resolved_metadata = fs::symlink_metadata(&resolved).with_context(|| {
            format!(
                "failed to inspect resolved sidecar socket creation ancestor {}",
                resolved.display()
            )
        })?;
        validate_listener_ancestor_metadata(
            &resolved,
            &resolved_metadata,
            expected_uid,
            expected_uid,
        )?;
        validate_listener_ancestor_chain(&resolved, expected_uid)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_created_listener_component(
    component: &Path,
    expected_uid: u32,
    created: bool,
) -> Result<()> {
    let metadata = fs::symlink_metadata(component).with_context(|| {
        format!(
            "failed to inspect sidecar socket directory component {}",
            component.display()
        )
    })?;
    if created {
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != expected_uid
        {
            validate_listener_directory_metadata(component, &metadata, expected_uid)?;
        }
        fs::set_permissions(
            component,
            fs::Permissions::from_mode(LISTENER_DIRECTORY_MODE),
        )
        .with_context(|| {
            format!(
                "failed to secure sidecar socket directory component {}",
                component.display()
            )
        })?;
    }
    let metadata = fs::symlink_metadata(component).with_context(|| {
        format!(
            "failed to recheck sidecar socket directory component {}",
            component.display()
        )
    })?;
    validate_listener_directory_metadata(component, &metadata, expected_uid)?;
    validate_listener_directory_ancestors(component, expected_uid)
}

#[cfg(unix)]
fn ensure_secure_listener_directory(socket: &Path) -> Result<()> {
    let directory = listener_socket_directory(socket);
    if directory
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        bail!(
            "sidecar socket directory must not contain parent traversal: {}",
            directory.display()
        );
    }
    let uid = effective_uid();
    match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            validate_listener_directory_metadata(directory, &metadata, uid)?;
            return validate_listener_directory_ancestors(directory, uid);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect sidecar socket directory {}",
                    directory.display()
                )
            })
        }
    }

    let absolute = std::path::absolute(directory).with_context(|| {
        format!(
            "failed to make sidecar socket directory absolute: {}",
            directory.display()
        )
    })?;
    let mut missing = Vec::new();
    let mut anchor = absolute.clone();
    loop {
        match fs::symlink_metadata(&anchor) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(anchor.clone());
                anchor = anchor.parent().map(Path::to_path_buf).ok_or_else(|| {
                    anyhow!(
                        "sidecar socket directory has no existing creation ancestor: {}",
                        directory.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect sidecar socket creation ancestor {}",
                        anchor.display()
                    )
                })
            }
        }
    }
    validate_listener_creation_anchor(&anchor, uid)?;

    for component in missing.iter().rev() {
        let mut builder = fs::DirBuilder::new();
        builder.mode(LISTENER_DIRECTORY_MODE);
        let created = match builder.create(component) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create sidecar socket directory component {}",
                        component.display()
                    )
                })
            }
        };
        validate_created_listener_component(component, uid, created)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_listener_socket_metadata(
    socket: &Path,
    metadata: &fs::Metadata,
    expected_uid: u32,
) -> Result<()> {
    if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
        bail!(
            "sidecar socket path must be a Unix socket and not a symlink: {}",
            socket.display()
        );
    }
    if metadata.uid() != expected_uid {
        bail!(
            "sidecar socket must be owned by the current uid: {} (owner={}, current={expected_uid})",
            socket.display(),
            metadata.uid()
        );
    }
    let mode = metadata.mode() & 0o7777;
    if mode & !LISTENER_SOCKET_MODE != 0 {
        bail!(
            "sidecar socket permissions must not exceed 0600: {} (mode={mode:04o})",
            socket.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_listener_socket(socket: &Path) -> Result<()> {
    ensure_secure_listener_directory(socket)?;
    match fs::symlink_metadata(socket) {
        Ok(metadata) => {
            validate_listener_socket_metadata(socket, &metadata, effective_uid())?;
            match UnixStream::connect(socket) {
                Ok(_) => bail!("sidecar socket is already in use: {}", socket.display()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(error) => {
                    bail!(
                        "failed to verify existing sidecar socket {}; refusing to remove it: {error}",
                        socket.display()
                    )
                }
            }
            fs::remove_file(socket)
                .with_context(|| format!("failed to remove stale socket {}", socket.display()))?;
            sync_parent_dir(socket)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect sidecar socket path {}", socket.display())
            })
        }
    }
    Ok(())
}

#[cfg(unix)]
fn bind_secure_listener_socket(socket: &Path) -> Result<UnixListener> {
    let listener = UnixListener::bind(socket)
        .with_context(|| format!("failed to bind sidecar socket {}", socket.display()))?;
    let secured = (|| -> Result<()> {
        fs::set_permissions(socket, fs::Permissions::from_mode(LISTENER_SOCKET_MODE))
            .with_context(|| format!("failed to secure sidecar socket {}", socket.display()))?;
        let metadata = fs::symlink_metadata(socket)
            .with_context(|| format!("failed to inspect bound socket {}", socket.display()))?;
        validate_listener_socket_metadata(socket, &metadata, effective_uid())?;
        let mode = metadata.mode() & 0o7777;
        if mode != LISTENER_SOCKET_MODE {
            bail!(
                "bound sidecar socket does not have mode 0600: {} (mode={mode:04o})",
                socket.display()
            );
        }
        Ok(())
    })();
    if let Err(error) = secured {
        drop(listener);
        let _ = fs::remove_file(socket);
        return Err(error);
    }
    Ok(listener)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_socket_server_session(
    remote_root: PathBuf,
    transport: RemoteTransport,
    agent: String,
    local_agent: Option<PathBuf>,
    registry: Option<RegistryLaunchConfig>,
    state_dir: Option<PathBuf>,
    request_timeout_ms: u64,
    stream: UnixStream,
) -> Result<ServerSessionExit> {
    let reader = BufReader::new(
        stream
            .try_clone()
            .context("failed to clone sidecar socket stream for reading")?,
    );
    let (response_tx, response_rx) = mpsc::sync_channel::<ServerMessage>(1024);
    let writer = spawn_message_writer(stream, response_rx);
    let session = run_server_session(
        remote_root,
        transport,
        agent,
        local_agent,
        registry,
        state_dir,
        request_timeout_ms,
        reader,
        response_tx,
        false,
    );
    join_writer(writer, "socket writer thread")?;
    session
}

#[derive(Debug, Default, Clone, Copy)]
struct ServerSessionExit {
    shutdown_listener: bool,
}

#[allow(clippy::too_many_arguments, clippy::redundant_closure_call)]
fn run_server_session<R>(
    remote_root: PathBuf,
    transport: RemoteTransport,
    agent: String,
    local_agent: Option<PathBuf>,
    registry: Option<RegistryLaunchConfig>,
    state_dir: Option<PathBuf>,
    request_timeout_ms: u64,
    reader: R,
    response_tx: mpsc::SyncSender<ServerMessage>,
    propagate_read_errors: bool,
) -> Result<ServerSessionExit>
where
    R: BufRead,
{
    let agent_interrupt = AgentInterrupt::default();
    let sidecar = Sidecar::new_with_registry(
        remote_root,
        transport,
        agent,
        local_agent,
        registry,
        state_dir,
        request_timeout_ms,
        agent_interrupt.clone(),
    )?;
    let control_interrupt = AgentInterrupt::default();
    let mut control_sidecar = sidecar.clone_for_lane(control_interrupt.clone())?;
    let write_interrupt = AgentInterrupt::default();
    let write_sidecar = sidecar.clone_for_lane(write_interrupt.clone())?;
    let pending_remote = Arc::new(Mutex::new(PendingRemote::default()));
    let pending_writes = Arc::new(Mutex::new(PendingRemote::default()));
    let fast_state = FastState::from_sidecar(&sidecar, Arc::clone(&pending_remote));
    let read_preempt = sidecar.agent.preempt_handle();
    let write_preempt = write_sidecar.agent.preempt_handle();
    let remote_preempts = RemotePreempts {
        read: read_preempt.clone(),
        write: write_preempt.clone(),
    };

    let read_queue = Arc::new(RemoteQueue::new(
        REMOTE_INTERACTIVE_QUEUE_CAPACITY,
        REMOTE_BACKGROUND_QUEUE_CAPACITY,
    ));
    let write_queue = Arc::new(RemoteQueue::new(
        REMOTE_INTERACTIVE_QUEUE_CAPACITY,
        REMOTE_BACKGROUND_QUEUE_CAPACITY,
    ));
    let active_remote = ActiveRemote::default();
    let read_worker = spawn_remote_worker(
        sidecar,
        Arc::clone(&read_queue),
        read_preempt.clone(),
        active_remote.clone(),
        Arc::clone(&pending_remote),
        Arc::clone(&pending_writes),
        agent_interrupt.clone(),
        response_tx.clone(),
    );
    let write_worker = spawn_remote_worker(
        write_sidecar,
        Arc::clone(&write_queue),
        write_preempt.clone(),
        active_remote.clone(),
        Arc::clone(&pending_remote),
        Arc::clone(&pending_writes),
        write_interrupt.clone(),
        response_tx.clone(),
    );

    let mut exit = ServerSessionExit::default();
    let mut explicit_end = false;
    let mut read_error = None;
    let read_result = (|| -> Result<()> {
        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    read_error = Some(error);
                    break;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let mut request: ClientRequest = match serde_json::from_str(&line) {
                Ok(request) => request,
                Err(error) => {
                    send_client_response(
                        &response_tx,
                        ClientResponse {
                            id: 0,
                            ok: false,
                            result: None,
                            error: Some(format!("invalid request JSON: {error}")),
                        },
                    );
                    continue;
                }
            };

            let should_end_session = matches!(request.method.as_str(), "shutdown" | "disconnect");
            if should_end_session {
                explicit_end = true;
                exit.shutdown_listener = request.method == "shutdown";
                agent_interrupt.request_shutdown();
                control_interrupt.request_shutdown();
                write_interrupt.request_shutdown();
                clear_pending_works(
                    &pending_remote,
                    &pending_writes,
                    read_queue.shutdown_and_drain(),
                );
                clear_pending_works(
                    &pending_remote,
                    &pending_writes,
                    write_queue.shutdown_and_drain(),
                );
                send_client_response(
                    &response_tx,
                    ClientResponse {
                        id: request.id,
                        ok: true,
                        result: Some(json!({"shutdown": true})),
                        error: None,
                    },
                );
                break;
            }

            if request.method == "cancel" {
                let response = match cancel_request_id(&request.params) {
                    Ok(target_id) => {
                        if let Some(work) = cancel_queued_request(
                            &read_queue,
                            &pending_remote,
                            &pending_writes,
                            target_id,
                        )
                        .or_else(|| {
                            cancel_queued_request(
                                &write_queue,
                                &pending_remote,
                                &pending_writes,
                                target_id,
                            )
                        }) {
                            send_client_response(&response_tx, canceled_client_response(work));
                            result_to_client_response(
                                request.id,
                                Ok(json!({
                                    "request_id": target_id,
                                    "canceled": true,
                                    "scope": "queued"
                                })),
                            )
                        } else if let Some(result) =
                            cancel_active_request(&active_remote, &remote_preempts, target_id)
                        {
                            result_to_client_response(request.id, Ok(result))
                        } else {
                            result_to_client_response(
                                request.id,
                                Ok(json!({
                                    "request_id": target_id,
                                    "canceled": false,
                                    "scope": "unknown",
                                    "reason": "request is neither queued nor active"
                                })),
                            )
                        }
                    }
                    Err(error) => result_to_client_response(request.id, Err(error)),
                };
                send_client_response(&response_tx, response);
                continue;
            }

            if request.method == "remote_health" {
                let preempt_epoch = control_sidecar.agent.preempt_handle().epoch();
                let response = handle_client_request(&mut control_sidecar, request, preempt_epoch);
                send_client_response(&response_tx, response);
                send_client_notification(
                    &response_tx,
                    control_sidecar.remote_health_notification(),
                );
                continue;
            }

            if request_replaces_remote_agent(&request) {
                let update = request.method == "remote_agent_update";
                let request_id = request.id;
                let deadline =
                    BootstrapDeadline::new(control_sidecar.remote_agent_bootstrap_timeout());
                let preempt_epoch = control_sidecar.agent.preempt_handle().epoch();
                let preflight = match control_sidecar.remote_agent_install_preflight(
                    &request.params,
                    update,
                    preempt_epoch,
                    deadline,
                ) {
                    Ok(preflight) => preflight,
                    Err(error) => {
                        if is_bootstrap_timeout(&error) {
                            control_sidecar.record_registry_bootstrap_timeout();
                        }
                        let error = normalize_bootstrap_error(error);
                        send_client_response(
                            &response_tx,
                            result_to_client_response(request_id, Err(error)),
                        );
                        send_client_notification(
                            &response_tx,
                            control_sidecar.remote_health_notification(),
                        );
                        continue;
                    }
                };
                if let Some(reason) = preflight.skip_reason.as_deref() {
                    control_sidecar.record_remote_health();
                    send_client_response(
                        &response_tx,
                        result_to_client_response(
                            request_id,
                            Ok(json!({
                                "status": "skipped",
                                "reason": reason,
                                "automatic": preflight.automatic,
                                "install_path": preflight.target_path,
                                "remote_health": preflight.before
                            })),
                        ),
                    );
                    send_client_notification(
                        &response_tx,
                        control_sidecar.remote_health_notification(),
                    );
                    continue;
                }

                control_sidecar.record_remote_health();
                let prepared =
                    match control_sidecar.prepare_remote_agent_install(&preflight, deadline) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            if is_bootstrap_timeout(&error) {
                                control_sidecar.record_registry_bootstrap_timeout();
                            }
                            let error = normalize_bootstrap_error(error);
                            send_client_response(
                                &response_tx,
                                result_to_client_response(request_id, Err(error)),
                            );
                            send_client_notification(
                                &response_tx,
                                control_sidecar.remote_health_notification(),
                            );
                            continue;
                        }
                    };

                let (maintenance, drained) = RemoteMaintenanceGuard::begin(
                    Arc::clone(&read_queue),
                    Arc::clone(&write_queue),
                );
                read_preempt.request_preemption();
                write_preempt.request_preemption();
                for work in drained {
                    clear_pending_work(&pending_remote, &pending_writes, &work);
                    send_client_response(&response_tx, canceled_client_response(work));
                }
                let result = (|| -> Result<Value> {
                    let maintenance_timeout =
                        deadline.forward_timeout("remote agent lane quiescence")?;
                    wait_for_remote_queues_quiescent(
                        &read_queue,
                        &write_queue,
                        &agent_interrupt,
                        &write_interrupt,
                        maintenance_timeout,
                    )
                    .map_err(|error| {
                        deadline.map_budgeted_error(
                            BootstrapBudget::Forward,
                            "remote agent lane quiescence",
                            error,
                        )
                    })?;
                    let control_reset_timeout =
                        deadline.forward_timeout("control-lane agent worker exit")?;
                    control_sidecar
                        .agent
                        .invalidate_shared_workers_with_timeout(
                            control_reset_timeout,
                            "control-lane agent worker exit",
                        )
                        .map_err(|error| {
                            deadline.map_budgeted_error(
                                BootstrapBudget::Forward,
                                "control-lane agent worker exit",
                                error,
                            )
                        })?;
                    control_sidecar.agent.clear_all_remote_unavailable();
                    let read_reset_timeout =
                        deadline.forward_timeout("remote read-lane worker exit")?;
                    read_queue
                        .reset_agent_worker(read_reset_timeout)
                        .map_err(|error| {
                            deadline.map_budgeted_error(
                                BootstrapBudget::Forward,
                                "remote read-lane worker exit",
                                error,
                            )
                        })?;
                    let write_reset_timeout =
                        deadline.forward_timeout("remote write-lane worker exit")?;
                    write_queue
                        .reset_agent_worker(write_reset_timeout)
                        .map_err(|error| {
                            deadline.map_budgeted_error(
                                BootstrapBudget::Forward,
                                "remote write-lane worker exit",
                                error,
                            )
                        })?;
                    control_sidecar.remote_agent_install_prepared(
                        preflight,
                        prepared,
                        update,
                        preempt_epoch,
                        deadline,
                    )
                })()
                .map_err(|error| {
                    if is_bootstrap_timeout(&error) {
                        control_sidecar.record_registry_bootstrap_timeout();
                    }
                    normalize_bootstrap_error(error)
                });
                drop(maintenance);
                if result.is_ok() {
                    control_sidecar.record_remote_health();
                }
                let response = result_to_client_response(request_id, result);
                send_client_response(&response_tx, response);
                send_client_notification(
                    &response_tx,
                    control_sidecar.remote_health_notification(),
                );
                continue;
            }

            if matches!(request.method.as_str(), "flush" | "adopt") {
                let adopt = request.method == "adopt";
                request = match fast_state.prepare_flush(&request, adopt) {
                    Ok(request) => request,
                    Err(error) => {
                        send_client_response(
                            &response_tx,
                            result_to_client_response(request.id, Err(error)),
                        );
                        continue;
                    }
                };
            }

            match fast_state.try_handle(&request) {
                FastHandle::Handled(result) => {
                    send_client_response(
                        &response_tx,
                        result_to_client_response(request.id, result),
                    );
                }
                FastHandle::Defer => {
                    let hazard = PendingHazard::for_request(&request);
                    let lane = pending_writes
                        .lock()
                        .map(|pending| RemoteLane::for_request(&request, &pending))
                        .unwrap_or(RemoteLane::Write);
                    let write_hazard_registered = request_is_write_lane(&request);
                    if let Ok(mut pending) = pending_remote.lock() {
                        pending.register(&hazard);
                    }
                    if write_hazard_registered {
                        if let Ok(mut pending) = pending_writes.lock() {
                            pending.register(&hazard);
                        }
                    }
                    let priority = RemotePriority::for_request(&request);
                    let request_id = request.id;
                    let request_method = request.method.clone();
                    let work = RemoteWork {
                        request,
                        hazard,
                        priority,
                        lane,
                        write_hazard_registered,
                        enqueued_at: Instant::now(),
                    };
                    let queue = match lane {
                        RemoteLane::Read => &read_queue,
                        RemoteLane::Write => &write_queue,
                    };
                    let preempt = (priority == RemotePriority::Interactive)
                        .then_some(remote_preempts.for_lane(lane));
                    match queue.try_push(work, preempt) {
                        Ok(canceled) => {
                            trace_event(
                                "request_queued",
                                json!({
                                    "request_id": request_id,
                                    "method": request_method,
                                    "lane": lane.label(),
                                    "priority": priority.label(),
                                    "preempted": !canceled.is_empty()
                                }),
                            );
                            clear_pending_work_refs(&pending_remote, &pending_writes, &canceled);
                            send_preempted_responses(&response_tx, canceled);
                        }
                        Err(work) => {
                            trace_event(
                                "request_queue_full",
                                json!({
                                    "request_id": work.request.id,
                                    "method": work.request.method.as_str(),
                                    "lane": work.lane.label(),
                                    "priority": work.priority.label()
                                }),
                            );
                            clear_pending_work(&pending_remote, &pending_writes, &work);
                            let response = if work.request.method == "flush_queued" {
                                result_to_client_response(
                                    work.request.id,
                                    Ok(json!({
                                        "status": "queued",
                                        "path": work.request.params.get("path").and_then(Value::as_str).unwrap_or(""),
                                        "reason": format!(
                                            "remote {} {} queue is full or not available; saved locally",
                                            work.lane.label(),
                                            work.priority.label()
                                        )
                                    })),
                                )
                            } else {
                                ClientResponse {
                                    id: work.request.id,
                                    ok: false,
                                    result: None,
                                    error: Some(format!(
                                        "remote {} {} queue is full or not available",
                                        work.lane.label(),
                                        work.priority.label()
                                    )),
                                }
                            };
                            send_client_response(&response_tx, response);
                        }
                    }
                }
            }
        }
        Ok(())
    })();

    if !explicit_end {
        agent_interrupt.request_shutdown();
        control_interrupt.request_shutdown();
        write_interrupt.request_shutdown();
        clear_pending_works(
            &pending_remote,
            &pending_writes,
            read_queue.shutdown_and_drain(),
        );
        clear_pending_works(
            &pending_remote,
            &pending_writes,
            write_queue.shutdown_and_drain(),
        );
    }
    clear_pending_works(
        &pending_remote,
        &pending_writes,
        read_queue.close_and_drain_background(),
    );
    clear_pending_works(
        &pending_remote,
        &pending_writes,
        write_queue.close_and_drain_background(),
    );
    let _ = read_worker.join();
    let _ = write_worker.join();
    drop(response_tx);
    read_result?;
    if propagate_read_errors {
        if let Some(error) = read_error {
            return Err(error).context("failed to read sidecar request");
        }
    }
    Ok(exit)
}

fn spawn_stdout_writer(
    response_rx: mpsc::Receiver<ServerMessage>,
) -> thread::JoinHandle<Result<()>> {
    thread::spawn(move || {
        let stdout = io::stdout();
        let stdout = stdout.lock();
        write_server_messages(stdout, response_rx)
    })
}

#[cfg(unix)]
fn spawn_message_writer<W>(
    writer: W,
    response_rx: mpsc::Receiver<ServerMessage>,
) -> thread::JoinHandle<Result<()>>
where
    W: Write + Send + 'static,
{
    thread::spawn(move || write_server_messages(writer, response_rx))
}

fn write_server_messages<W>(mut writer: W, response_rx: mpsc::Receiver<ServerMessage>) -> Result<()>
where
    W: Write,
{
    for message in response_rx {
        let encoded = serde_json::to_string(&message)?;
        if let Err(error) = writeln!(writer, "{encoded}") {
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) {
                return Ok(());
            }
            return Err(error).context("failed to write sidecar response");
        }
        if let Err(error) = writer.flush() {
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) {
                return Ok(());
            }
            return Err(error).context("failed to flush sidecar response");
        }
    }
    Ok(())
}

fn join_writer(handle: thread::JoinHandle<Result<()>>, name: &str) -> Result<()> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => bail!("{name} panicked"),
    }
}

struct RemoteInFlightGuard {
    queue: Arc<RemoteQueue>,
}

impl RemoteInFlightGuard {
    fn new(queue: Arc<RemoteQueue>) -> Self {
        Self { queue }
    }
}

impl Drop for RemoteInFlightGuard {
    fn drop(&mut self) {
        self.queue.finish_started();
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_remote_worker(
    mut sidecar: Sidecar,
    queue: Arc<RemoteQueue>,
    preempt: AgentPreempt,
    active: ActiveRemote,
    pending_remote: Arc<Mutex<PendingRemote>>,
    pending_writes: Arc<Mutex<PendingRemote>>,
    interrupt: AgentInterrupt,
    response_tx: mpsc::SyncSender<ServerMessage>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        let Some(item) = queue.pop_worker_item(Some(&preempt)) else {
            break;
        };
        let started = match item {
            RemoteWorkerItem::Work(started) => started,
            RemoteWorkerItem::Control(RemoteWorkerControl::ResetAgent {
                started,
                timeout,
                reply,
            }) => {
                let remaining = remaining_timeout_since(started, timeout);
                let result = sidecar
                    .agent
                    .kill_worker_with_timeout(remaining, "remote lane worker reset");
                let _ = reply.send(result);
                continue;
            }
        };
        let _in_flight = RemoteInFlightGuard::new(Arc::clone(&queue));
        let preempt_epoch = started.preempt_epoch;
        let work = started.work;
        let request_id = work.request.id;
        let queue_wait_ms = duration_ms(work.enqueued_at.elapsed());
        let method = work.request.method.clone();
        let lane = work.lane;
        let priority = work.priority;
        active.set(&work);
        if interrupt.is_shutdown_requested() {
            clear_pending_work(&pending_remote, &pending_writes, &work);
            active.clear(request_id);
            clear_pending_works(&pending_remote, &pending_writes, queue.shutdown_and_drain());
            break;
        }

        let should_shutdown = matches!(work.request.method.as_str(), "shutdown" | "disconnect");
        let RemoteWork {
            request,
            hazard,
            write_hazard_registered,
            ..
        } = work;
        let response = handle_client_request(&mut sidecar, request, preempt_epoch);
        clear_pending_hazard(
            &pending_remote,
            &pending_writes,
            &hazard,
            write_hazard_registered,
        );
        active.clear(request_id);
        trace_event(
            "request_finished",
            json!({
                "request_id": request_id,
                "method": method,
                "lane": lane.label(),
                "priority": priority.label(),
                "queue_wait_ms": queue_wait_ms,
                "ok": response.ok,
                "preempted": response.result.as_ref()
                    .and_then(|result| result.get("preempted"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                "truncated": response.result.as_ref()
                    .and_then(|result| result.get("truncated"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                "error": response.error.as_deref()
            }),
        );
        send_client_response(&response_tx, response);
        send_client_notification(&response_tx, sidecar.remote_health_notification());
        if should_shutdown || interrupt.is_shutdown_requested() {
            clear_pending_works(&pending_remote, &pending_writes, queue.shutdown_and_drain());
            break;
        }
    })
}

fn handle_client_request(
    sidecar: &mut Sidecar,
    request: ClientRequest,
    preempt_epoch: u64,
) -> ClientResponse {
    let id = request.id;
    let result = sidecar.handle(&request.method, request.params, preempt_epoch);
    result_to_client_response(id, result)
}

fn result_to_client_response(id: u64, result: Result<Value>) -> ClientResponse {
    match result {
        Ok(result) => ClientResponse {
            id,
            ok: true,
            result: Some(result),
            error: None,
        },
        Err(error) => ClientResponse {
            id,
            ok: false,
            result: None,
            error: Some(error.to_string()),
        },
    }
}

#[cfg(test)]
fn clear_pending_hazards(pending_remote: &Arc<Mutex<PendingRemote>>, works: Vec<RemoteWork>) {
    if works.is_empty() {
        return;
    }
    if let Ok(mut pending) = pending_remote.lock() {
        for work in works {
            pending.clear(&work.hazard);
        }
    }
}

fn clear_pending_works(
    pending_remote: &Arc<Mutex<PendingRemote>>,
    pending_writes: &Arc<Mutex<PendingRemote>>,
    works: Vec<RemoteWork>,
) {
    if works.is_empty() {
        return;
    }
    clear_pending_work_refs(pending_remote, pending_writes, &works);
}

fn clear_pending_work(
    pending_remote: &Arc<Mutex<PendingRemote>>,
    pending_writes: &Arc<Mutex<PendingRemote>>,
    work: &RemoteWork,
) {
    clear_pending_hazard(
        pending_remote,
        pending_writes,
        &work.hazard,
        work.write_hazard_registered,
    );
}

fn clear_pending_work_refs(
    pending_remote: &Arc<Mutex<PendingRemote>>,
    pending_writes: &Arc<Mutex<PendingRemote>>,
    works: &[RemoteWork],
) {
    if works.is_empty() {
        return;
    }
    if let Ok(mut pending) = pending_remote.lock() {
        for work in works {
            pending.clear(&work.hazard);
        }
    }
    if let Ok(mut pending) = pending_writes.lock() {
        for work in works {
            if work.write_hazard_registered {
                pending.clear(&work.hazard);
            }
        }
    }
}

fn clear_pending_hazard(
    pending_remote: &Arc<Mutex<PendingRemote>>,
    pending_writes: &Arc<Mutex<PendingRemote>>,
    hazard: &PendingHazard,
    write_hazard_registered: bool,
) {
    if let Ok(mut pending) = pending_remote.lock() {
        pending.clear(hazard);
    }
    if write_hazard_registered {
        if let Ok(mut pending) = pending_writes.lock() {
            pending.clear(hazard);
        }
    }
}

fn send_preempted_responses(tx: &mpsc::SyncSender<ServerMessage>, works: Vec<RemoteWork>) {
    for work in works {
        send_client_response(tx, preempted_client_response(work));
    }
}

fn cancel_request_id(params: &Value) -> Result<u64> {
    params
        .get("request_id")
        .or_else(|| params.get("id"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing required integer params.request_id"))
}

fn cancel_queued_request(
    remote_queue: &RemoteQueue,
    pending_remote: &Arc<Mutex<PendingRemote>>,
    pending_writes: &Arc<Mutex<PendingRemote>>,
    request_id: u64,
) -> Option<RemoteWork> {
    let canceled = remote_queue.cancel(request_id)?;
    clear_pending_work(pending_remote, pending_writes, &canceled);
    Some(canceled)
}

fn cancel_active_request(
    active_remote: &ActiveRemote,
    preempts: &RemotePreempts,
    request_id: u64,
) -> Option<Value> {
    let active_cancel = active_remote.cancel_if_active(request_id, preempts)?;
    let active = active_cancel.active;
    if active_cancel.canceled {
        return Some(json!({
            "request_id": request_id,
            "canceled": true,
            "scope": "active",
            "method": active.method
        }));
    }
    Some(json!({
        "request_id": request_id,
        "canceled": false,
        "scope": "active",
        "method": active.method,
        "reason": "active request is not cancellation-preemptible"
    }))
}

fn active_request_is_preemptible(active: &ActiveRemoteWork) -> bool {
    matches!(
        active.method.as_str(),
        "open"
            | "grep"
            | "validate"
            | "scan"
            | "prefetch"
            | "prefetch_known"
            | "prefetch_related"
            | "refresh"
            | "remote_probe"
            | "git_status"
            | "git_diff"
            | "git_blame"
    )
}

fn canceled_client_response(work: RemoteWork) -> ClientResponse {
    ClientResponse {
        id: work.request.id,
        ok: false,
        result: None,
        error: Some(format!(
            "request `{}` canceled before remote execution",
            work.request.method
        )),
    }
}

fn preempted_client_response(work: RemoteWork) -> ClientResponse {
    result_to_client_response(work.request.id, Ok(preempted_result(&work.request)))
}

fn preempted_result(request: &ClientRequest) -> Value {
    match request.method.as_str() {
        "scan" => json!({"entries": [], "truncated": true, "preempted": true}),
        "prefetch" => json!({
            "hydrated": 0,
            "errors": [],
            "truncated": true,
            "preempted": true,
            "max_file_bytes": request
                .params
                .get("max_file_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_BATCH_MAX_FILE_BYTES),
            "max_total_bytes": request
                .params
                .get("max_total_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_BATCH_MAX_TOTAL_BYTES)
        }),
        "prefetch_known" => json!({
            "requested": 0,
            "paths": [],
            "hydrated": 0,
            "errors": [],
            "truncated": true,
            "preempted": true,
            "max_file_bytes": request
                .params
                .get("max_file_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_BATCH_MAX_FILE_BYTES),
            "max_total_bytes": request
                .params
                .get("max_total_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_BATCH_MAX_TOTAL_BYTES)
        }),
        "prefetch_related" => json!({
            "anchor": request.params.get("anchor").and_then(Value::as_str).unwrap_or(""),
            "requested": 0,
            "paths": [],
            "hydrated": 0,
            "errors": [],
            "truncated": true,
            "preempted": true,
            "max_file_bytes": request
                .params
                .get("max_file_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_BATCH_MAX_FILE_BYTES),
            "max_total_bytes": request
                .params
                .get("max_total_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_BATCH_MAX_TOTAL_BYTES)
        }),
        "refresh" => json!({
            "checked": 0,
            "valid": 0,
            "stale": 0,
            "deleted": 0,
            "skipped": 0,
            "errors": [],
            "preempted": true
        }),
        "grep" => json!({
            "hits": [],
            "truncated": true,
            "preempted": true,
            "hydrated": 0,
            "hydrate_errors": [],
            "hydrate_truncated": false,
            "next_after": request.params.get("after").and_then(Value::as_str),
            "session_id": request.params.get("session_id").and_then(Value::as_str),
            "scanned_files": 0
        }),
        "remote_probe" => json!({
            "remote_status": "unchecked",
            "remote_checked": false,
            "remote_available": false,
            "preempted": true
        }),
        _ => json!({"preempted": true}),
    }
}

fn send_client_response(tx: &mpsc::SyncSender<ServerMessage>, response: ClientResponse) -> bool {
    tx.send(ServerMessage::Response(response)).is_ok()
}

fn send_client_notification(
    tx: &mpsc::SyncSender<ServerMessage>,
    notification: ClientNotification,
) -> bool {
    tx.send(ServerMessage::Notification(notification)).is_ok()
}

fn run_lsp_proxy(
    remote_root: PathBuf,
    local_root: PathBuf,
    transport: RemoteTransport,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        bail!("lsp-proxy requires a language server command after --");
    }

    let host = detect_remote_host_info(
        &transport,
        Duration::from_millis(REMOTE_HOST_PROBE_TIMEOUT_MS),
    )?;
    let exit_grace = if matches!(transport, RemoteTransport::Ssh(_)) {
        Duration::from_millis(LSP_PROXY_SSH_EXIT_GRACE_MS)
    } else {
        Duration::from_millis(LSP_PROXY_EXIT_GRACE_MS)
    };
    let launch = LspLaunch::new(remote_root.clone(), transport, command, &host)?;
    let stdin_prefix = launch.stdin_prefix().to_vec();
    let mut child_command = launch.command();
    configure_agent_process(&mut child_command);

    let mut child = child_command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to launch language server")?;
    let mut server_stdin = child
        .stdin
        .take()
        .context("language server stdin was not piped")?;
    let server_stdout = child
        .stdout
        .take()
        .context("language server stdout was not piped")?;

    let local_prefix = local_root.to_string_lossy().to_string();
    let remote_prefix = remote_root.to_string_lossy().to_string();
    let upstream_local = local_prefix.clone();
    let upstream_remote = remote_prefix.clone();

    let child = Arc::new(Mutex::new(child));
    let upstream_child = Arc::clone(&child);
    let mut upstream = Some(thread::spawn(move || -> Result<()> {
        let stdin = io::stdin();
        let mut client_reader = BufReader::new(stdin.lock());
        let result = (|| -> Result<()> {
            server_stdin
                .write_all(&stdin_prefix)
                .and_then(|()| server_stdin.flush())
                .context("failed to write Windows LSP bootstrap")?;
            while let Some(body) = read_lsp_message(&mut client_reader)? {
                let rewritten = rewrite_lsp_body(&body, &upstream_local, &upstream_remote)?;
                write_lsp_message(&mut server_stdin, &rewritten)?;
            }
            Ok(())
        })();
        drop(server_stdin);
        finish_lsp_upstream_result(result, &upstream_child, exit_grace)
    }));

    let stdout = io::stdout();
    let mut client_writer = stdout.lock();
    let mut server_reader = BufReader::new(LeadingBomReader::new(server_stdout));
    let downstream_result = (|| -> Result<()> {
        while let Some(body) = read_lsp_message(&mut server_reader)? {
            let rewritten = rewrite_lsp_body(&body, &remote_prefix, &local_prefix)?;
            write_lsp_message(&mut client_writer, &rewritten)?;
        }
        Ok(())
    })();
    if let Err(err) = downstream_result {
        return fail_lsp_downstream(err, &child, &mut upstream, exit_grace);
    }

    join_lsp_upstream_if_finished(&mut upstream, &child, exit_grace)?;

    let status = wait_lsp_child_handle_with_grace(&child, exit_grace)?;
    join_lsp_upstream_if_finished(&mut upstream, &child, exit_grace)?;
    if !status.success() {
        bail!("language server exited with {status}");
    }
    Ok(())
}

fn fail_lsp_downstream(
    err: anyhow::Error,
    child: &Arc<Mutex<Child>>,
    upstream: &mut Option<thread::JoinHandle<Result<()>>>,
    grace: Duration,
) -> Result<()> {
    let status_context = match kill_and_wait_lsp_child_handle(child, grace) {
        Ok(status) => format!("language server stopped with {status}"),
        Err(wait_err) => format!("failed to reap language server: {wait_err:#}"),
    };
    if let Err(upstream_err) = join_lsp_upstream_if_finished(upstream, child, grace) {
        return Err(err).context(format!(
            "LSP proxy downstream pump failed; {status_context}; upstream also failed: {upstream_err:#}"
        ));
    }
    Err(err).context(format!(
        "LSP proxy downstream pump failed; {status_context}"
    ))
}

fn finish_lsp_upstream_result(
    result: Result<()>,
    child: &Arc<Mutex<Child>>,
    grace: Duration,
) -> Result<()> {
    match result {
        Ok(()) => {
            let status = wait_lsp_child_handle_with_grace(child, grace)
                .context("language server did not stop after LSP client input closed")?;
            if !status.success() {
                bail!("language server exited with {status}");
            }
            Ok(())
        }
        Err(err) => {
            let status_context = match kill_and_wait_lsp_child_handle(child, grace) {
                Ok(status) => format!("language server stopped with {status}"),
                Err(wait_err) => format!("failed to reap language server: {wait_err:#}"),
            };
            Err(err).context(status_context)
        }
    }
}

fn join_lsp_upstream_if_finished(
    upstream: &mut Option<thread::JoinHandle<Result<()>>>,
    child: &Arc<Mutex<Child>>,
    grace: Duration,
) -> Result<()> {
    let finished = upstream
        .as_ref()
        .map(|handle| handle.is_finished())
        .unwrap_or(false);
    if !finished {
        return Ok(());
    }
    let handle = upstream.take().expect("checked upstream handle");
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            let status_context = match kill_and_wait_lsp_child_handle(child, grace) {
                Ok(status) => format!("language server stopped with {status}"),
                Err(wait_err) => format!("failed to reap language server: {wait_err:#}"),
            };
            Err(err).context(format!("LSP proxy upstream pump failed; {status_context}"))
        }
        Err(_) => {
            let status_context = match kill_and_wait_lsp_child_handle(child, grace) {
                Ok(status) => format!("language server stopped with {status}"),
                Err(wait_err) => format!("failed to reap language server: {wait_err:#}"),
            };
            bail!("LSP proxy upstream pump panicked; {status_context}")
        }
    }
}

fn wait_lsp_child_handle_with_grace(
    child: &Arc<Mutex<Child>>,
    grace: Duration,
) -> Result<ExitStatus> {
    let started = Instant::now();
    let reap_reserve = (grace / 2).min(Duration::from_millis(100));
    let natural_grace = grace.saturating_sub(reap_reserve);
    let mut killed = false;
    loop {
        match child.try_lock() {
            Ok(mut child) => {
                if !killed && started.elapsed() >= natural_grace {
                    kill_child_tree(&mut child);
                    killed = true;
                } else if killed {
                    kill_child_tree(&mut child);
                }
                if let Some(status) = child.try_wait()? {
                    if killed {
                        bail!(
                            "language server did not exit within {:?}; killed with {status}",
                            natural_grace
                        );
                    }
                    return Ok(status);
                }
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                let mut child = poisoned.into_inner();
                kill_child_tree(&mut child);
                if let Some(status) = child.try_wait()? {
                    bail!("language server child lock was poisoned; killed with {status}");
                }
                killed = true;
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        let remaining = remaining_timeout_since(started, grace);
        if remaining.is_zero() {
            bail!(
                "language server did not exit within {grace:?}; process-tree termination requested but reap did not complete"
            );
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

fn kill_and_wait_lsp_child_handle(
    child: &Arc<Mutex<Child>>,
    timeout: Duration,
) -> Result<ExitStatus> {
    let started = Instant::now();
    loop {
        match child.try_lock() {
            Ok(mut child) => {
                kill_child_tree(&mut child);
                if let Some(status) = child.try_wait()? {
                    return Ok(status);
                }
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                let mut child = poisoned.into_inner();
                kill_child_tree(&mut child);
                if let Some(status) = child.try_wait()? {
                    return Ok(status);
                }
            }
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        let remaining = remaining_timeout_since(started, timeout);
        if remaining.is_zero() {
            bail!("language server process-tree termination did not complete within {timeout:?}");
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

#[cfg(all(test, unix))]
fn wait_lsp_child_with_grace(child: &mut Child, grace: Duration) -> Result<ExitStatus> {
    let started = Instant::now();
    let reap_reserve = (grace / 2).min(Duration::from_millis(100));
    let natural_grace = grace.saturating_sub(reap_reserve);
    let mut killed = false;
    loop {
        if let Some(status) = child.try_wait()? {
            if killed {
                bail!(
                    "language server did not exit within {:?}; killed with {status}",
                    natural_grace
                );
            }
            return Ok(status);
        }
        if !killed && started.elapsed() >= natural_grace {
            kill_child_tree(child);
            killed = true;
        } else if killed {
            kill_child_tree(child);
        }
        let remaining = remaining_timeout_since(started, grace);
        if remaining.is_zero() {
            bail!(
                "language server did not exit within {grace:?}; process-tree termination requested but reap did not complete"
            );
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

#[derive(Debug)]
struct CapturedProcessOutput {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
struct ProcessOutputLimitError {
    context: String,
    stream: &'static str,
    limit: usize,
}

impl fmt::Display for ProcessOutputLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} exceeded the {} byte capture limit",
            self.context, self.stream, self.limit
        )
    }
}

impl std::error::Error for ProcessOutputLimitError {}

struct ProcessOutputReader {
    handle: thread::JoinHandle<io::Result<Vec<u8>>>,
    limit_exceeded: Arc<AtomicBool>,
}

impl ProcessOutputReader {
    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    fn limit_exceeded(&self) -> bool {
        self.limit_exceeded.load(Ordering::Acquire)
    }
}

fn spawn_process_output_reader<R>(stream: R) -> ProcessOutputReader
where
    R: Read + Send + 'static,
{
    let limit_exceeded = Arc::new(AtomicBool::new(false));
    let reader_limit_exceeded = Arc::clone(&limit_exceeded);
    let handle = thread::spawn(move || {
        let mut stream =
            LeadingBomReader::new(stream).take((PROCESS_CAPTURE_MAX_STREAM_BYTES + 1) as u64);
        let mut output = Vec::new();
        stream.read_to_end(&mut output)?;
        if output.len() > PROCESS_CAPTURE_MAX_STREAM_BYTES {
            output.truncate(PROCESS_CAPTURE_MAX_STREAM_BYTES);
            reader_limit_exceeded.store(true, Ordering::Release);
        }
        Ok(output)
    });
    ProcessOutputReader {
        handle,
        limit_exceeded,
    }
}

fn join_process_output_reader(
    reader: ProcessOutputReader,
    context: &str,
    stream_name: &'static str,
) -> Result<Vec<u8>> {
    debug_assert!(reader.is_finished());
    let limit_exceeded = reader.limit_exceeded();
    let output = match reader.handle.join() {
        Ok(result) => result.with_context(|| format!("failed to read {context} {stream_name}")),
        Err(_) => bail!("{context} {stream_name} reader panicked"),
    }?;
    if limit_exceeded {
        return Err(anyhow!(ProcessOutputLimitError {
            context: context.to_string(),
            stream: stream_name,
            limit: PROCESS_CAPTURE_MAX_STREAM_BYTES,
        }));
    }
    Ok(output)
}

fn reap_child_in_background(mut child: Child) {
    let _ = thread::Builder::new()
        .name("nrm-process-reaper".to_string())
        .spawn(move || loop {
            kill_child_tree(&mut child);
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) | Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        });
}

fn run_command_capture(
    mut command: Command,
    input: Option<Box<dyn Read + Send>>,
    timeout: Duration,
    context: &str,
) -> Result<CapturedProcessOutput> {
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_agent_process(&mut command);
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {context}"))?;

    let stdin_writer = if let Some(mut input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("{context} stdin was not piped"))?;
        Some(thread::spawn(move || -> Result<()> {
            io::copy(&mut input, &mut stdin)?;
            Ok(())
        }))
    } else {
        None
    };

    let stdout_reader = child
        .stdout
        .take()
        .map(spawn_process_output_reader)
        .ok_or_else(|| anyhow!("{context} stdout was not piped"))?;
    let stderr_reader = child
        .stderr
        .take()
        .map(spawn_process_output_reader)
        .ok_or_else(|| anyhow!("{context} stderr was not piped"))?;

    let started = Instant::now();
    let mut status = None;
    let mut stdout_reader = Some(stdout_reader);
    let mut stderr_reader = Some(stderr_reader);
    let mut stdin_writer = stdin_writer;
    loop {
        let output_limit_exceeded = if stdout_reader
            .as_ref()
            .is_some_and(ProcessOutputReader::limit_exceeded)
        {
            Some("stdout")
        } else if stderr_reader
            .as_ref()
            .is_some_and(ProcessOutputReader::limit_exceeded)
        {
            Some("stderr")
        } else {
            None
        };
        if let Some(stream) = output_limit_exceeded {
            kill_child_tree(&mut child);
            if child.try_wait().ok().flatten().is_none() {
                reap_child_in_background(child);
            }
            return Err(anyhow!(ProcessOutputLimitError {
                context: context.to_string(),
                stream,
                limit: PROCESS_CAPTURE_MAX_STREAM_BYTES,
            }));
        }
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    kill_child_tree(&mut child);
                    reap_child_in_background(child);
                    return Err(error).with_context(|| format!("failed to poll {context}"));
                }
            };
        }
        if let Some(exit_status) = status {
            let stdout_finished = stdout_reader
                .as_ref()
                .is_none_or(ProcessOutputReader::is_finished);
            let stderr_finished = stderr_reader
                .as_ref()
                .is_none_or(ProcessOutputReader::is_finished);
            let stdin_finished = stdin_writer
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished);
            // A failing remote command's status/stderr is authoritative even
            // if its upload producer is still blocked. Successful commands
            // require the complete stdin copy to have finished.
            if stdout_finished && stderr_finished && (!exit_status.success() || stdin_finished) {
                let stdout = join_process_output_reader(
                    stdout_reader.take().expect("stdout reader exists"),
                    context,
                    "stdout",
                )?;
                let stderr = join_process_output_reader(
                    stderr_reader.take().expect("stderr reader exists"),
                    context,
                    "stderr",
                )?;
                if stdin_finished {
                    if let Some(writer) = stdin_writer.take() {
                        debug_assert!(writer.is_finished());
                        let stdin_result = match writer.join() {
                            Ok(result) => result.with_context(|| format!("{context} stdin failed")),
                            Err(_) => Err(anyhow!("{context} stdin writer panicked")),
                        };
                        if exit_status.success() {
                            stdin_result?;
                        }
                    }
                }
                return Ok(CapturedProcessOutput {
                    status: exit_status,
                    stdout: String::from_utf8_lossy(&stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&stderr).into_owned(),
                });
            }
        }
        if started.elapsed() >= timeout {
            kill_child_tree(&mut child);
            if status.is_none() {
                status = child.try_wait().ok().flatten();
            }
            if status.is_none() {
                reap_child_in_background(child);
            }
            return Err(anyhow!(ProcessTimeoutError {
                context: context.to_string(),
                timeout,
                status,
            }));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct LspLaunch {
    plan: ProcessLaunchPlan,
}

impl LspLaunch {
    fn new(
        remote_root: PathBuf,
        transport: RemoteTransport,
        command: Vec<String>,
        host: &RemoteHostInfo,
    ) -> Result<Self> {
        Ok(Self {
            plan: transport.lsp_plan(remote_root, command, host)?,
        })
    }

    fn command(&self) -> Command {
        self.plan.command()
    }

    fn stdin_prefix(&self) -> &[u8] {
        &self.plan.stdin_prefix
    }
}

fn posix_agent_remote_command(agent: &str, remote_root: &Path) -> String {
    const SCRIPT: &str = r#"set -u
agent=$1
root=$2
managed=$3
shift 3
fail() {
  printf 'NRM_AGENT_LAUNCH_V1\tFAILURE\t%s\n' "$1"
  exit "$2"
}
if [ ! -d "$root" ]; then fail root_missing 66; fi
if [ "$managed" = 1 ]; then
  PATH="${HOME-}/.local/bin:${PATH-}"
  export PATH
fi
case "$agent" in
  */*) executable=$agent ;;
  *) executable=$(command -v "$agent" 2>/dev/null) || fail missing 127 ;;
esac
if [ ! -e "$executable" ] && [ ! -L "$executable" ]; then fail missing 127; fi
if [ ! -f "$executable" ] || [ ! -x "$executable" ]; then fail not_executable 126; fi
printf 'NRM_AGENT_LAUNCH_V1\tREADY\n' || exit 70
exec "$executable" "$@""#;
    [
        shell_quote("sh"),
        shell_quote("-c"),
        shell_quote(SCRIPT),
        shell_quote("nrm-agent-launch"),
        shell_quote(agent),
        shell_quote(remote_root.to_string_lossy()),
        shell_quote(if remote_agent_uses_managed_path(agent) {
            "1"
        } else {
            "0"
        }),
        shell_quote("serve"),
        shell_quote("--root"),
        shell_quote(remote_root.to_string_lossy()),
    ]
    .join(" ")
}

fn powershell_agent_remote_command(
    agent: &str,
    remote_root: &Path,
    host: &RemoteHostInfo,
) -> Result<PowerShellProcessCommand> {
    let remote_root = remote_root
        .to_str()
        .ok_or_else(|| anyhow!("Windows remote root must be valid UTF-8"))?;
    let args = vec![
        "serve".to_string(),
        "--root".to_string(),
        remote_root.to_string(),
    ];
    let (program, path_prepend) = if remote_agent_uses_managed_path(agent) {
        let local_app_data = host
            .local_app_data
            .as_deref()
            .ok_or_else(|| anyhow!("Windows remote host did not report LOCALAPPDATA"))?;
        let managed_dir = format!("{}\\nrm\\bin", local_app_data.trim_end_matches(['/', '\\']));
        let program = if agent.eq_ignore_ascii_case("nrm-agent")
            || agent.eq_ignore_ascii_case("nrm-agent.exe")
        {
            format!("{managed_dir}\\nrm-agent.exe")
        } else {
            agent.to_string()
        };
        (program, Some(managed_dir))
    } else {
        (agent.to_string(), None)
    };
    powershell_agent_process_command(&program, &args, None, path_prepend.as_deref())
}

fn remote_agent_uses_managed_path(agent: &str) -> bool {
    !agent.contains(['/', '\\', ':'])
}

fn validate_managed_remote_agent_name(agent: &str) -> Result<()> {
    if agent.is_empty()
        || matches!(agent, "." | "..")
        || agent.starts_with('-')
        || !agent
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("remote_agent must be an absolute path or a safe bare command name");
    }
    Ok(())
}

fn default_posix_remote_agent_install_path(agent: &str) -> Result<String> {
    if agent.starts_with('/') {
        return Ok(agent.to_string());
    }
    if !remote_agent_uses_managed_path(agent) {
        bail!("POSIX remote_agent must be an absolute path or a bare command name");
    }
    validate_managed_remote_agent_name(agent)?;
    Ok(format!("$HOME/.local/bin/{agent}"))
}

fn default_remote_agent_install_path(agent: &str, host: &RemoteHostInfo) -> Result<String> {
    match host.path_style {
        RemotePathStyle::Posix => default_posix_remote_agent_install_path(agent),
        RemotePathStyle::Windows if !remote_agent_uses_managed_path(agent) => Ok(agent.to_string()),
        RemotePathStyle::Windows => {
            validate_managed_remote_agent_name(agent)?;
            let local_app_data = host
                .local_app_data
                .as_deref()
                .ok_or_else(|| anyhow!("Windows remote host did not report LOCALAPPDATA"))?;
            let local_app_data = local_app_data.trim_end_matches(['/', '\\']);
            if local_app_data.is_empty() {
                bail!("Windows remote host reported an empty LOCALAPPDATA");
            }
            let filename = if agent.to_ascii_lowercase().ends_with(".exe") {
                agent.to_string()
            } else {
                format!("{agent}.exe")
            };
            Ok(format!("{local_app_data}\\nrm\\bin\\{filename}"))
        }
    }
}

fn classify_remote_agent_status(value: &Value) -> String {
    if value
        .get("remote_available")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return "ok".to_string();
    }

    if let Some(status) = value
        .get("agent_launch_failure")
        .and_then(Value::as_str)
        .and_then(|failure| match failure {
            "missing" => Some(RemoteAgentLaunchFailure::Missing),
            "not_executable" => Some(RemoteAgentLaunchFailure::NotExecutable),
            "root_missing" => Some(RemoteAgentLaunchFailure::RootMissing),
            _ => None,
        })
    {
        return status.agent_status().to_owned();
    }

    if let Some(status) = value
        .get("agent_compatibility_failure")
        .and_then(Value::as_str)
        .and_then(|failure| match failure {
            "version_mismatch" => Some("version_mismatch"),
            "protocol_mismatch" => Some("protocol_mismatch"),
            _ => None,
        })
    {
        return status.to_owned();
    }
    "unavailable".to_string()
}

fn posix_lsp_remote_command(remote_root: PathBuf, command: Vec<String>) -> String {
    let mut parts = vec![
        shell_quote("sh"),
        shell_quote("-lc"),
        shell_quote("cd \"$1\" && shift && exec \"$@\""),
        shell_quote("nrm-lsp-proxy"),
        shell_quote(remote_root.to_string_lossy()),
    ];
    parts.extend(command.into_iter().map(shell_quote));
    parts.join(" ")
}

fn powershell_lsp_remote_command(
    remote_root: PathBuf,
    command: Vec<String>,
) -> Result<PowerShellProcessCommand> {
    let remote_root = remote_root
        .to_str()
        .ok_or_else(|| anyhow!("Windows remote root must be valid UTF-8"))?;
    powershell_process_command(&command[0], &command[1..], Some(remote_root), None)
}

fn shell_quote(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    if value.is_empty() {
        return "''".to_string();
    }
    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn read_lsp_message<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut content_len = None;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_len = Some(value.trim().parse::<usize>()?);
        }
    }

    let len = content_len.ok_or_else(|| anyhow!("LSP message missing Content-Length header"))?;
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_lsp_message<W: Write>(writer: &mut W, body: &[u8]) -> Result<()> {
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

fn required_string<'a>(params: &'a Value, key: &str) -> Result<&'a str> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing required string params.{key}"))
}

fn required_i64(params: &Value, key: &str) -> Result<i64> {
    params
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("missing required integer params.{key}"))
}

fn optional_string_param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn optional_positive_usize_param(params: &Value, key: &str) -> Option<usize> {
    params.get(key).and_then(|value| {
        value
            .as_u64()
            .map(|value| value.max(1).min(usize::MAX as u64) as usize)
            .or_else(|| value.as_i64().map(|_| 1))
    })
}

fn git_output_max_bytes(params: &Value) -> u64 {
    params
        .get("max_output_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_GIT_OUTPUT_MAX_BYTES)
}

fn normalized_paths_param(params: &Value, key: &str) -> Result<Vec<String>> {
    let Some(values) = params.get(key).and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    for value in values {
        let path = value
            .as_str()
            .ok_or_else(|| anyhow!("params.{key} must contain strings"))?;
        paths.push(
            normalize_relative_path(path)?
                .to_string_lossy()
                .replace('\\', "/"),
        );
    }
    Ok(paths)
}

fn normalize_relative_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if path.is_absolute() {
        bail!("paths must be workspace-relative");
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir => bail!("path must not contain '..'"),
            Component::RootDir | Component::Prefix(_) => bail!("path must be relative"),
        }
    }
    if clean.as_os_str().is_empty() {
        bail!("path must not be empty");
    }
    Ok(clean)
}

fn parent_dir(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_default()
}

fn file_extension(path: &str) -> String {
    let file_name = path.rsplit_once('/').map(|(_, name)| name).unwrap_or(path);
    file_name
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map(|(_, extension)| extension.to_string())
        .unwrap_or_default()
}

fn escape_sql_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' | '%' | '_' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[derive(Debug, Clone, Copy)]
enum RelatedBucket {
    SameDirectoryAndExtension,
    SameDirectory,
    DescendantAndExtension,
    SameExtension,
    AnyMetadata,
}

impl RelatedBucket {
    fn sql_predicate(self) -> &'static str {
        const SAME_DIR: &str = "((?3 = 0 AND instr(relative_path, '/') = 0) OR (?3 > 0 AND relative_path LIKE ?2 ESCAPE '\\' AND instr(substr(relative_path, ?3 + 1), '/') = 0))";
        const SAME_EXT: &str = "(?4 != '' AND relative_path LIKE ?4 ESCAPE '\\')";
        match self {
            Self::SameDirectoryAndExtension => {
                "(((?3 = 0 AND instr(relative_path, '/') = 0) OR (?3 > 0 AND relative_path LIKE ?2 ESCAPE '\\' AND instr(substr(relative_path, ?3 + 1), '/') = 0)) AND (?4 != '' AND relative_path LIKE ?4 ESCAPE '\\'))"
            }
            Self::SameDirectory => SAME_DIR,
            Self::DescendantAndExtension => {
                "(?3 > 0 AND relative_path LIKE ?2 ESCAPE '\\' AND instr(substr(relative_path, ?3 + 1), '/') > 0 AND ?4 != '' AND relative_path LIKE ?4 ESCAPE '\\')"
            }
            Self::SameExtension => SAME_EXT,
            Self::AnyMetadata => "1 = 1",
        }
    }
}

fn default_state_dir() -> PathBuf {
    if let Some(value) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(value).join("nvim-remote-mirror")
    } else if let Some(value) = std::env::var_os("HOME") {
        PathBuf::from(value).join(".local/state/nvim-remote-mirror")
    } else {
        PathBuf::from(".nrm-state")
    }
}

fn workspace_key(transport: &RemoteTransport, remote_root: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(transport.workspace_identity().as_bytes());
    hasher.update(b"\0");
    hasher.update(remote_root.to_string_lossy().as_bytes());
    hasher.finalize().to_hex()[..24].to_string()
}

fn write_durable_file(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("durable file path must have a parent: {}", path.display()))?;
    fs::create_dir_all(parent)?;

    let tmp = path.with_extension(format!(
        "tmp-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let install = (|| -> Result<()> {
        {
            let mut file = File::options().write(true).create_new(true).open(&tmp)?;
            file.write_all(content)?;
            file.sync_all()?;
        }
        rename_durable(&tmp, path)?;
        Ok(())
    })();

    if install.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    install
}

fn rename_durable(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to)?;
    sync_parent_dir(to)?;
    Ok(())
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        sync_dir(parent)
            .with_context(|| format!("failed to sync directory {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn hash_agent_source(
    file: &mut File,
    deadline: BootstrapDeadline,
) -> Result<(String, String, u64)> {
    file.seek(SeekFrom::Start(0))?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        deadline.forward_timeout("agent source hashing")?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size.saturating_add(read as u64);
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
    }
    deadline.forward_timeout("agent source hashing")?;
    file.seek(SeekFrom::Start(0))?;
    let source_hash = blake3.finalize().to_hex().to_string();
    let source_sha256 = {
        let digest = sha256.finalize();
        let mut output = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    };
    Ok((source_hash, source_sha256, size))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn conflict_copy_path_is_partial(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.contains(".remote.partial."))
        .unwrap_or(false)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("NRM_TRACE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

fn trace_event(event: &str, fields: Value) {
    if !trace_enabled() {
        return;
    }
    let mut object = match fields {
        Value::Object(object) => object,
        _ => Map::new(),
    };
    object.insert("event".to_string(), json!(event));
    object.insert("at_ms".to_string(), json!(now_ms()));
    eprintln!("{}", Value::Object(object));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use base64::engine::general_purpose::STANDARD;
    #[cfg(unix)]
    use base64::Engine as _;
    #[cfg(unix)]
    use ed25519_dalek::{Signer as _, SigningKey};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn secure_socket_test_directory(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(LISTENER_DIRECTORY_MODE)).unwrap();
    }

    struct TestAbortHandle {
        aborts: AtomicUsize,
        waits: AtomicUsize,
        stopped: AtomicBool,
    }

    impl Default for TestAbortHandle {
        fn default() -> Self {
            Self {
                aborts: AtomicUsize::new(0),
                waits: AtomicUsize::new(0),
                stopped: AtomicBool::new(true),
            }
        }
    }

    impl AgentAbortHandle for TestAbortHandle {
        fn abort(&self) {
            self.aborts.fetch_add(1, Ordering::SeqCst);
        }

        fn is_stopped(&self) -> bool {
            self.waits.fetch_add(1, Ordering::SeqCst);
            self.stopped.load(Ordering::SeqCst)
        }
    }

    #[cfg(unix)]
    struct StalledRead {
        release: mpsc::Receiver<()>,
    }

    #[cfg(unix)]
    impl Read for StalledRead {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            let _ = self.release.recv();
            Ok(0)
        }
    }

    #[cfg(unix)]
    fn command_that_fails_with_stderr() -> Command {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("printf 'NRM_INSTALL_ERROR_V1\\talready_exists\\n' >&2; exit 23");
        command
    }

    #[cfg(unix)]
    fn local_remote_install_lease(script: &str) -> (RemoteInstallLease, u32) {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        configure_agent_process(&mut command);
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        let stdin = child.stdin.take().unwrap();
        let stderr = spawn_process_output_reader(child.stderr.take().unwrap());
        (
            RemoteInstallLease {
                child: Some(child),
                stdin: Some(stdin),
                stderr: Some(stderr),
                release_signal: None,
                released: false,
            },
            pid,
        )
    }

    #[cfg(unix)]
    fn wait_for_local_process_reap(pid: u32) {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            // SAFETY: signal zero only checks whether the captured child PID is
            // still present; it does not deliver a signal.
            if unsafe { libc::kill(pid as libc::pid_t, 0) } != 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("detached install-lease reaper did not reap process {pid}");
    }

    #[cfg(windows)]
    fn command_that_fails_with_stderr() -> Command {
        let mut command = Command::new("cmd.exe");
        command.args([
            "/d",
            "/s",
            "/c",
            "echo NRM_INSTALL_ERROR_V1 already_exists 1>&2 & exit /b 23",
        ]);
        command
    }

    #[cfg(unix)]
    fn command_that_floods_output(stderr: bool) -> Command {
        let mut command = Command::new("sh");
        command.arg("-c").arg(if stderr {
            "yes 0123456789 >&2"
        } else {
            "yes 0123456789"
        });
        command
    }

    #[cfg(windows)]
    fn command_that_floods_output(stderr: bool) -> Command {
        let mut command = Command::new("powershell.exe");
        let stream = if stderr {
            "OpenStandardError"
        } else {
            "OpenStandardOutput"
        };
        command
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!(
                "$ProgressPreference='SilentlyContinue'; $stream=[Console]::{stream}(1); $bytes=New-Object byte[] {}; $stream.Write($bytes,0,$bytes.Length)",
                PROCESS_CAPTURE_MAX_STREAM_BYTES * 2
            ));
        command
    }

    fn test_meta_kind(
        path: &str,
        hash: &str,
        size: u64,
        is_dir: bool,
        is_symlink: bool,
    ) -> FileMeta {
        FileMeta {
            path: path.to_string(),
            size,
            mtime_ms: 10,
            mode: 0,
            is_dir,
            is_symlink,
            hash: Some(hash.to_string()),
        }
    }

    fn test_meta(path: &str, hash: &str, size: u64) -> FileMeta {
        test_meta_kind(path, hash, size, false, false)
    }

    fn test_posix_host() -> RemoteHostInfo {
        parse_posix_probe("NRM_HOST_INFO_V1\nLinux\nx86_64\n/home/test\n").unwrap()
    }

    fn test_windows_host() -> RemoteHostInfo {
        parse_powershell_probe(
            r#"{"schema_version":1,"os":"windows","arch":"AMD64","shell":"powershell","home":"C:\\Users\\test","local_app_data":"C:\\Users\\test\\AppData\\Local","path_style":"windows"}"#,
        )
        .unwrap()
    }

    fn registry_cli_args() -> RegistryCliArgs {
        RegistryCliArgs {
            remote_agent_registry_url: None,
            remote_agent_registry_public_keys: Vec::new(),
            remote_agent_registry_signature_threshold: 1,
            remote_agent_registry_cache_dir: None,
            remote_agent_registry_cache_max_bytes: DEFAULT_REGISTRY_CACHE_MAX_BYTES,
            remote_agent_registry_timeout_ms: DEFAULT_REGISTRY_TIMEOUT_MS,
        }
    }

    fn test_registry_launch_config(timeout: Duration) -> RegistryLaunchConfig {
        RegistryLaunchConfig {
            url_template: RegistryUrlTemplate::parse(
                "https://registry.example.test/v{version}/manifest.json",
            )
            .unwrap(),
            trusted_keys: TrustedKeySet::from_base64([(
                "release-test",
                "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
            )])
            .unwrap(),
            signature_threshold: 1,
            cache_dir: None,
            cache_max_bytes: DEFAULT_REGISTRY_CACHE_MAX_BYTES,
            timeout,
            policy_fingerprint: "test-registry-policy".to_owned(),
        }
    }

    fn configure_test_registry(sidecar: &mut Sidecar, timeout: Duration) {
        let registry = test_registry_launch_config(timeout);
        sidecar.registry_health =
            Arc::new(Mutex::new(RegistryHealth::from_registry(Some(&registry))));
        sidecar.agent.launch.registry = Some(registry);
    }

    type TestBackoffSlotSnapshot = (
        Option<Instant>,
        Option<String>,
        Option<TrustedAgentFailure>,
        Option<Instant>,
        u32,
    );

    fn test_backoff_snapshot(
        backoff: &RemoteBackoffState,
    ) -> (TestBackoffSlotSnapshot, TestBackoffSlotSnapshot) {
        let slot = |slot: &RemoteBackoffSlot| {
            (
                slot.unavailable_until,
                slot.last_remote_error.clone(),
                slot.trusted_failure.clone(),
                slot.last_remote_error_at,
                slot.consecutive_failures,
            )
        };
        (slot(&backoff.read), slot(&backoff.write))
    }

    #[test]
    fn registry_cli_is_opt_in_and_rejects_orphaned_policy() {
        assert!(registry_cli_args().into_config().unwrap().is_none());

        let mut args = registry_cli_args();
        args.remote_agent_registry_public_keys
            .push("release-a=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string());
        let error = args.into_config().unwrap_err().to_string();
        assert!(error.contains("require --remote-agent-registry-url"));
    }

    #[test]
    fn registry_cli_parses_trust_policy_in_deterministic_key_order() {
        let mut args = registry_cli_args();
        args.remote_agent_registry_url =
            Some("https://example.test/releases/v{version}/nrm-agent-manifest-v1.json".to_string());
        args.remote_agent_registry_public_keys = vec![
            "release-z=PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=".to_string(),
            "release-a=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string(),
        ];
        args.remote_agent_registry_signature_threshold = 1;
        args.remote_agent_registry_cache_dir = Some(PathBuf::from("/tmp/nrm registry cache"));
        args.remote_agent_registry_cache_max_bytes = 4096;
        args.remote_agent_registry_timeout_ms = 7000;

        let config = args.into_config().unwrap().unwrap();
        assert_eq!(
            config.trusted_keys.key_ids().collect::<Vec<_>>(),
            vec!["release-a", "release-z"]
        );
        assert_eq!(config.signature_threshold, 1);
        assert_eq!(config.cache_max_bytes, 4096);
        assert_eq!(config.timeout, Duration::from_millis(7000));
        assert_eq!(
            config.policy_fingerprint,
            "59697bb3ee09d89a1122612967070aa5bb29f3c4f420a6c0d64405bba134abf2"
        );
    }

    #[test]
    fn registry_cli_rejects_duplicate_key_material_and_bad_thresholds() {
        let mut duplicate = registry_cli_args();
        duplicate.remote_agent_registry_url =
            Some("https://example.test/v{version}/manifest.json".to_string());
        duplicate.remote_agent_registry_public_keys = vec![
            "release-a=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string(),
            "release-b=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string(),
        ];
        assert!(duplicate
            .into_config()
            .unwrap_err()
            .to_string()
            .contains("invalid remote agent registry public keys"));

        let mut threshold = registry_cli_args();
        threshold.remote_agent_registry_url =
            Some("https://example.test/v{version}/manifest.json".to_string());
        threshold.remote_agent_registry_public_keys =
            vec!["release-a=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".to_string()];
        threshold.remote_agent_registry_signature_threshold = 2;
        assert!(threshold
            .into_config()
            .unwrap_err()
            .to_string()
            .contains("threshold must be between 1 and 1"));
    }

    #[test]
    fn registry_fetch_timeout_is_clipped_to_remaining_bootstrap_budget() {
        let deadline =
            BootstrapDeadline::with_elapsed(Duration::from_secs(20), Duration::from_secs(8));
        let timeout = registry_fetch_timeout(Duration::from_secs(120), deadline).unwrap();

        assert!(timeout <= Duration::from_secs(7));
        assert!(timeout > Duration::from_secs(6));
    }

    #[test]
    fn agent_spawn_and_reply_share_one_request_timeout() {
        let total = Duration::from_millis(100);
        let after_spawn = Instant::now()
            .checked_sub(Duration::from_millis(70))
            .unwrap();
        let reply_budget = remaining_timeout_since(after_spawn, total);
        assert!(reply_budget <= Duration::from_millis(30));
        assert!(reply_budget > Duration::ZERO);

        let after_spawn_and_reply = Instant::now()
            .checked_sub(Duration::from_millis(110))
            .unwrap();
        assert_eq!(
            remaining_timeout_since(after_spawn_and_reply, total),
            Duration::ZERO
        );
    }

    #[test]
    fn bootstrap_timeout_classification_is_structural() {
        let deadline = BootstrapDeadline::new(Duration::from_secs(5));
        let diagnostic = deadline.map_budgeted_error(
            BootstrapBudget::Forward,
            "test diagnostic",
            anyhow!("remote tool said it timed out, but returned immediately"),
        );
        assert!(!is_bootstrap_timeout(&diagnostic));

        let timeout = deadline.map_budgeted_error(
            BootstrapBudget::Forward,
            "test request",
            anyhow!(AgentRequestTimeoutError {
                id: 7,
                timeout: Duration::from_secs(1),
                phase: "while waiting for its reply",
            }),
        );
        assert!(is_bootstrap_timeout(&timeout));

        let registry_timeout = deadline.map_budgeted_error(
            BootstrapBudget::Forward,
            "registry fetch",
            anyhow!(FetchError::OperationDeadline {
                phase: "cached artifact digest",
            }),
        );
        assert!(is_bootstrap_timeout(&registry_timeout));
    }

    #[cfg(unix)]
    #[test]
    fn registry_health_redacts_https_paths_and_url_components() {
        let registry = RegistryLaunchConfig {
            url_template: RegistryUrlTemplate::parse(
                "https://registry.example.test:8443/private/releases/v{version}/manifest.json",
            )
            .unwrap(),
            trusted_keys: TrustedKeySet::from_base64([(
                "release-test",
                "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
            )])
            .unwrap(),
            signature_threshold: 1,
            cache_dir: Some(PathBuf::from("/secret/cache")),
            cache_max_bytes: DEFAULT_REGISTRY_CACHE_MAX_BYTES,
            timeout: Duration::from_secs(5),
            policy_fingerprint: "test-registry-policy".to_string(),
        };

        let health = RegistryHealth::from_registry(Some(&registry));
        assert_eq!(
            health.manifest_url.as_deref(),
            Some("https://registry.example.test:8443/<redacted>")
        );
        let exposed = health.to_value().to_string();
        assert!(!exposed.contains("private"));
        assert!(!exposed.contains("releases"));
        assert!(!exposed.contains("manifest.json"));
        assert!(!exposed.contains("secret/cache"));
        assert!(!exposed.contains('@'));
        assert!(!exposed.contains('?'));
        assert!(!exposed.contains('#'));
    }

    #[test]
    fn registry_health_redaction_preserves_bracketed_ipv6_host() {
        let ipv6 =
            url::Url::parse("https://[2001:4860:4860::8888]:8443/private/manifest.json").unwrap();
        assert_eq!(
            redact_registry_manifest_url(&ipv6),
            "https://[2001:4860:4860::8888]:8443/<redacted>"
        );
    }

    #[test]
    fn fast_workspace_info_never_waits_for_registry_health_lock() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let sidecar = test_sidecar(mirror);
        sidecar.update_registry_health(|health| {
            health.state = RegistryHealthState::Fetching;
            health.source = "registry";
        });
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));
        let _held = sidecar.registry_health.lock().unwrap();

        let info = fast.workspace_info();
        assert_eq!(info["registry_health"]["state"], "fetching");
        assert_eq!(info["registry_health"]["source"], "registry");
    }

    struct ScriptedInstallOps {
        calls: Vec<&'static str>,
        fail_at: Option<&'static str>,
        target: Option<&'static str>,
        stage_exists: bool,
        backup: Option<&'static str>,
        deadline: Option<BootstrapDeadline>,
        phase_delay: Duration,
    }

    impl ScriptedInstallOps {
        fn new(fail_at: Option<&'static str>) -> Self {
            Self {
                calls: Vec::new(),
                fail_at,
                target: Some("previous"),
                stage_exists: false,
                backup: None,
                deadline: None,
                phase_delay: Duration::ZERO,
            }
        }

        fn without_previous(fail_at: Option<&'static str>) -> Self {
            Self {
                target: None,
                ..Self::new(fail_at)
            }
        }

        fn fails(&self, phase: &str) -> bool {
            self.fail_at == Some(phase)
                || (self.fail_at == Some("rollback_after_activation")
                    && matches!(phase, "validate_activated" | "rollback"))
        }

        fn staged(had_previous: bool) -> agent_install::StagedInstall {
            agent_install::StagedInstall {
                target_path: "/tmp/nrm-agent".to_string(),
                stage_path: "/tmp/nrm-agent.nrm-stage.abcdef".to_string(),
                backup_path: "/tmp/nrm-agent.nrm-backup.abcdef".to_string(),
                had_previous,
            }
        }
    }

    impl AgentInstallOps for ScriptedInstallOps {
        fn stage(&mut self) -> Result<agent_install::StagedInstall> {
            self.calls.push("stage");
            thread::sleep(self.phase_delay);
            if self.fails("stage") {
                bail!("upload failed");
            }
            let had_previous = self.target.is_some();
            self.stage_exists = true;
            Ok(Self::staged(had_previous))
        }

        fn validate_staged(&mut self, _staged: &agent_install::StagedInstall) -> Result<()> {
            self.calls.push("validate_staged");
            thread::sleep(self.phase_delay);
            if self.fails("validate_staged") {
                bail!("wrong protocol");
            }
            Ok(())
        }

        fn ensure_activation_budget(&mut self) -> Result<()> {
            if let Some(deadline) = self.deadline {
                deadline.forward_timeout("test activation").map(drop)?;
            }
            Ok(())
        }

        fn activate(
            &mut self,
            staged: &agent_install::StagedInstall,
        ) -> Result<agent_install::ActivatedInstall> {
            self.calls.push("activate");
            if self.fails("activate") {
                bail!("process_in_use: target is locked");
            }
            if self.fail_at == Some("activate_stage_lost_without_backup") {
                self.stage_exists = false;
                bail!("transport failed after stage disappeared");
            }
            self.backup = self.target.take();
            self.target = Some("candidate");
            self.stage_exists = false;
            if self.fail_at == Some("activate_timeout_after_mutation") {
                return Err(anyhow!(BootstrapTimeoutError {
                    phase: "test activation response was ambiguous".to_string(),
                }));
            }
            if self.fail_at == Some("activate_after_mutation") {
                bail!("transport failed after remote activation");
            }
            if self.fail_at == Some("activate_malformed_record") {
                bail!("remote agent activation returned an invalid record");
            }
            Ok(agent_install::ActivatedInstall {
                staged: staged.clone(),
                had_previous: self.backup.is_some(),
            })
        }

        fn reconcile_activation(
            &mut self,
            staged: &agent_install::StagedInstall,
        ) -> Result<agent_install::ActivationRecovery> {
            self.calls.push("reconcile_activation");
            if self.fails("reconcile_activation") {
                bail!("reconciliation failed");
            }
            let kind = if self.stage_exists {
                if self.target.is_some() != staged.had_previous {
                    bail!("staged prior state changed before reconciliation");
                }
                self.stage_exists = false;
                self.backup = None;
                if self.target.is_some() {
                    agent_install::ActivationRecoveryKind::ActivationUnchangedPresent
                } else {
                    agent_install::ActivationRecoveryKind::ActivationUnchangedMissing
                }
            } else if staged.had_previous {
                let previous = self
                    .backup
                    .take()
                    .ok_or_else(|| anyhow!("missing prior-agent backup"))?;
                self.target = Some(previous);
                agent_install::ActivationRecoveryKind::RestoredPrevious
            } else {
                if self.backup.is_some() {
                    bail!("unexpected backup for new install");
                }
                self.target = None;
                agent_install::ActivationRecoveryKind::RemovedCandidate
            };
            Ok(agent_install::ActivationRecovery {
                target_path: "/tmp/nrm-agent".to_string(),
                kind,
            })
        }

        fn validate_reconciliation(
            &mut self,
            recovery: &agent_install::ActivationRecovery,
        ) -> Result<()> {
            self.calls.push("validate_reconciliation");
            if self.fails("validate_reconciliation") {
                bail!("reconciled target validation failed");
            }
            let should_be_present = matches!(
                recovery.kind,
                agent_install::ActivationRecoveryKind::ActivationUnchangedPresent
                    | agent_install::ActivationRecoveryKind::RestoredPrevious
            );
            if self.target.is_some() != should_be_present {
                bail!("reconciliation outcome does not match target state");
            }
            Ok(())
        }

        fn validate_activated(
            &mut self,
            _activated: &agent_install::ActivatedInstall,
        ) -> Result<()> {
            self.calls.push("validate_activated");
            if self.fails("validate_activated") {
                bail!("normal Hello failed");
            }
            Ok(())
        }

        fn rollback(
            &mut self,
            _activated: &agent_install::ActivatedInstall,
        ) -> Result<agent_install::RollbackOutcome> {
            self.calls.push("rollback");
            if self.fails("rollback") {
                bail!("restore failed");
            }
            self.target = self.backup.take();
            self.stage_exists = false;
            Ok(agent_install::RollbackOutcome {
                target_path: "/tmp/nrm-agent".to_string(),
                restored_previous: self.target.is_some(),
            })
        }

        fn validate_rollback(&mut self, _rollback: &agent_install::RollbackOutcome) -> Result<()> {
            self.calls.push("validate_rollback");
            if self.fails("validate_rollback") {
                bail!("restored Hello failed");
            }
            Ok(())
        }

        fn cleanup(&mut self, _staged: &agent_install::StagedInstall) -> Result<()> {
            self.calls.push("cleanup");
            if self.fails("cleanup") {
                bail!("cleanup denied");
            }
            self.stage_exists = false;
            self.backup = None;
            Ok(())
        }
    }

    #[test]
    fn transaction_commits_only_after_both_hello_checks() {
        let mut operations = ScriptedInstallOps::new(None);
        run_agent_install_transaction(&mut operations).unwrap();
        assert_eq!(
            operations.calls,
            [
                "stage",
                "validate_staged",
                "activate",
                "validate_activated",
                "cleanup"
            ]
        );
        assert_eq!(operations.target, Some("candidate"));
        assert!(!operations.stage_exists);
        assert_eq!(operations.backup, None);
    }

    #[test]
    fn transaction_staged_failure_leaves_target_untouched_and_cleans_stage() {
        let mut operations = ScriptedInstallOps::new(Some("validate_staged"));
        let error = run_agent_install_transaction(&mut operations).unwrap_err();
        assert_eq!(error.final_state, AgentInstallFinalState::TargetUnchanged);
        assert!(error.to_string().contains("staged_validation_failed"));
        assert_eq!(operations.calls, ["stage", "validate_staged", "cleanup"]);
        assert_eq!(operations.target, Some("previous"));
        assert!(!operations.stage_exists);
    }

    #[test]
    fn bootstrap_deadline_is_cumulative_and_cleans_stage_before_activation() {
        let mut operations = ScriptedInstallOps::new(None);
        operations.deadline = Some(BootstrapDeadline::new(Duration::from_millis(240)));
        operations.phase_delay = Duration::from_millis(70);

        let error = run_agent_install_transaction(&mut operations).unwrap_err();

        assert_eq!(error.final_state, AgentInstallFinalState::TargetUnchanged);
        assert!(error.to_string().contains("bootstrap_timeout"));
        assert_eq!(operations.target, Some("previous"));
        assert!(!operations.stage_exists);
        assert_eq!(operations.calls, ["stage", "validate_staged", "cleanup"]);
    }

    #[test]
    fn exhausted_forward_budget_leaves_target_unchanged() {
        let mut operations = ScriptedInstallOps::new(None);
        operations.deadline = Some(BootstrapDeadline::with_elapsed(
            Duration::from_secs(1),
            Duration::from_millis(800),
        ));

        let error = run_agent_install_transaction(&mut operations).unwrap_err();

        assert_eq!(error.final_state, AgentInstallFinalState::TargetUnchanged);
        assert!(error.to_string().contains("bootstrap_timeout"));
        assert_eq!(operations.target, Some("previous"));
        assert_eq!(operations.backup, None);
        assert!(!operations.stage_exists);
        assert!(!operations.calls.contains(&"activate"));
    }

    #[test]
    fn transaction_postactivation_failure_restores_and_reprobes_previous() {
        let mut operations = ScriptedInstallOps::new(Some("validate_activated"));
        let error = run_agent_install_transaction(&mut operations).unwrap_err();
        assert_eq!(error.final_state, AgentInstallFinalState::PreviousRestored);
        assert!(error
            .to_string()
            .contains("post_activation_validation_failed"));
        assert!(error.to_string().contains("rollback=restored"));
        assert_eq!(
            operations.calls,
            [
                "stage",
                "validate_staged",
                "activate",
                "validate_activated",
                "rollback",
                "validate_rollback"
            ]
        );
        assert_eq!(operations.target, Some("previous"));
    }

    #[test]
    fn transaction_reports_rollback_failed_with_original_error() {
        let mut operations = ScriptedInstallOps::new(Some("rollback_after_activation"));
        let error = run_agent_install_transaction(&mut operations).unwrap_err();
        assert_eq!(error.final_state, AgentInstallFinalState::LiveStateUnknown);
        assert!(error.to_string().contains("rollback_failed"));
        assert!(error.to_string().contains("normal Hello failed"));
        assert!(operations.calls.contains(&"rollback"));
    }

    #[test]
    fn transaction_reports_process_in_use_without_touching_previous() {
        let mut operations = ScriptedInstallOps::new(Some("activate"));
        let error = run_agent_install_transaction(&mut operations).unwrap_err();
        assert_eq!(error.final_state, AgentInstallFinalState::TargetUnchanged);
        assert!(error.to_string().contains("process_in_use"));
        assert_eq!(operations.target, Some("previous"));
        assert_eq!(
            operations.calls,
            [
                "stage",
                "validate_staged",
                "activate",
                "reconcile_activation",
                "validate_reconciliation"
            ]
        );
        assert!(!operations.stage_exists);
        assert_eq!(operations.backup, None);
    }

    #[test]
    fn transaction_transport_error_after_remote_mv_restores_previous() {
        let mut operations = ScriptedInstallOps::new(Some("activate_after_mutation"));
        let error = run_agent_install_transaction(&mut operations).unwrap_err();
        assert_eq!(error.final_state, AgentInstallFinalState::PreviousRestored);
        assert!(error.to_string().contains("activation_failed"));
        assert!(error.to_string().contains("RestoredPrevious"));
        assert_eq!(operations.target, Some("previous"));
        assert_eq!(operations.backup, None);
        assert!(!operations.stage_exists);
        assert_eq!(
            operations.calls,
            [
                "stage",
                "validate_staged",
                "activate",
                "reconcile_activation",
                "validate_reconciliation"
            ]
        );
    }

    #[test]
    fn activation_timeout_is_reconciled_and_restores_previous_target() {
        let mut operations = ScriptedInstallOps::new(Some("activate_timeout_after_mutation"));

        let error = run_agent_install_transaction(&mut operations).unwrap_err();

        assert_eq!(error.final_state, AgentInstallFinalState::PreviousRestored);
        assert!(error.bootstrap_timeout);
        assert!(error.to_string().contains("bootstrap_timeout"));
        assert!(error.to_string().contains("RestoredPrevious"));
        assert_eq!(operations.target, Some("previous"));
        assert_eq!(operations.backup, None);
        assert!(!operations.stage_exists);
        assert_eq!(
            operations.calls,
            [
                "stage",
                "validate_staged",
                "activate",
                "reconcile_activation",
                "validate_reconciliation"
            ]
        );
    }

    #[test]
    fn transaction_malformed_activation_record_after_mv_restores_previous() {
        let mut operations = ScriptedInstallOps::new(Some("activate_malformed_record"));
        let error = run_agent_install_transaction(&mut operations)
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid record"));
        assert!(error.contains("RestoredPrevious"));
        assert_eq!(operations.target, Some("previous"));
        assert_eq!(operations.backup, None);
        assert!(!operations.stage_exists);
        assert!(operations.calls.contains(&"validate_reconciliation"));
    }

    #[test]
    fn transaction_ambiguous_activation_without_prior_removes_candidate() {
        let mut operations = ScriptedInstallOps::without_previous(Some("activate_after_mutation"));
        let error = run_agent_install_transaction(&mut operations).unwrap_err();
        assert_eq!(error.final_state, AgentInstallFinalState::PreviousRestored);
        assert!(error.to_string().contains("RemovedCandidate"));
        assert_eq!(operations.target, None);
        assert_eq!(operations.backup, None);
        assert!(!operations.stage_exists);
        assert!(operations.calls.contains(&"validate_reconciliation"));
    }

    #[test]
    fn transaction_missing_stage_and_prior_backup_fails_closed() {
        let mut operations = ScriptedInstallOps::new(Some("activate_stage_lost_without_backup"));
        let error = run_agent_install_transaction(&mut operations).unwrap_err();
        assert_eq!(error.final_state, AgentInstallFinalState::LiveStateUnknown);
        assert!(error.to_string().contains("rollback_failed"));
        assert!(error.to_string().contains("missing prior-agent backup"));
        assert!(error
            .to_string()
            .contains("transport failed after stage disappeared"));
        assert_eq!(operations.target, Some("previous"));
        assert_eq!(operations.backup, None);
        assert!(!operations.stage_exists);
        assert_eq!(
            operations.calls,
            [
                "stage",
                "validate_staged",
                "activate",
                "reconcile_activation"
            ]
        );
    }

    #[test]
    fn transaction_cleanup_failure_reports_healthy_candidate_state() {
        let mut operations = ScriptedInstallOps::new(Some("cleanup"));
        let error = run_agent_install_transaction(&mut operations).unwrap_err();
        assert_eq!(error.final_state, AgentInstallFinalState::CandidateHealthy);
        assert!(error.to_string().contains("cleanup_failed"));
        assert_eq!(operations.target, Some("candidate"));
        assert_eq!(operations.backup, Some("previous"));
    }

    #[test]
    fn install_error_health_tracks_typed_live_target_state() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar(mirror);
        *sidecar.remote_health.lock().unwrap() = RemoteHealth::connected();

        let unchanged =
            install_transaction_error(AgentInstallFinalState::TargetUnchanged, "staging failed");
        sidecar.record_agent_install_error_health(&unchanged);
        assert_eq!(
            sidecar.remote_health.lock().unwrap().state,
            RemoteHealthState::Connected
        );
        assert_eq!(sidecar.status().unwrap()["remote_status"], "connected");

        sidecar.agent.handshake_complete = true;
        let healthy =
            install_transaction_error(AgentInstallFinalState::CandidateHealthy, "cleanup failed");
        sidecar.record_agent_install_error_health(&healthy);
        assert_eq!(
            sidecar.remote_health.lock().unwrap().state,
            RemoteHealthState::Connected
        );

        let unknown =
            install_transaction_error(AgentInstallFinalState::LiveStateUnknown, "rollback failed");
        sidecar.record_agent_install_error_health(&unknown);
        let health = sidecar.remote_health.lock().unwrap();
        assert_eq!(health.state, RemoteHealthState::Unavailable);
        assert!(health
            .error
            .as_deref()
            .unwrap()
            .contains("live state is unknown"));
    }

    #[test]
    fn direct_bootstrap_uses_one_request_deadline_and_preserves_working_health() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar(mirror);
        sidecar.agent.launch.transport = RemoteTransport::Ssh(SshTransport {
            program: PathBuf::from("ssh"),
            target: "example.test".to_string(),
            connect_timeout_seconds: 1,
        });
        sidecar.agent.launch.request_timeout = Duration::ZERO;
        sidecar.agent.handshake_complete = true;
        *sidecar.remote_health.lock().unwrap() = RemoteHealth::connected();
        *sidecar.agent.launch.remote_host_info.lock().unwrap() = Some(test_posix_host());

        let error = sidecar
            .remote_agent_install(
                json!({"install_path": "/home/test/.local/bin/nrm-agent"}),
                false,
                0,
            )
            .unwrap_err();

        assert!(error.to_string().starts_with("bootstrap_timeout:"));
        assert_eq!(sidecar.status().unwrap()["remote_status"], "connected");
        assert_eq!(
            sidecar.registry_health_snapshot().state,
            RegistryHealthState::Disabled
        );
    }

    #[test]
    fn failed_agent_source_preparation_does_not_invalidate_workers() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().join("state")), "test").unwrap();
        let mut sidecar = test_sidecar(mirror);
        sidecar.agent.launch.transport = RemoteTransport::Ssh(SshTransport {
            program: PathBuf::from("ssh"),
            target: "example.test".to_string(),
            connect_timeout_seconds: 1,
        });
        sidecar.agent.launch.local_agent = Some(dir.path().join("missing-agent"));
        *sidecar.agent.launch.remote_host_info.lock().unwrap() = Some(test_posix_host());
        let generation = sidecar
            .agent
            .launch
            .worker_generation
            .load(Ordering::SeqCst);
        let preflight = AgentInstallPreflight {
            before: json!({"agent_status": "ok"}),
            target_path: "/home/test/.local/bin/nrm-agent".to_string(),
            effective_force: true,
            skip_reason: None,
            automatic: false,
        };

        let error = sidecar
            .prepare_remote_agent_install(
                &preflight,
                BootstrapDeadline::new(Duration::from_secs(5)),
            )
            .err()
            .expect("missing source must fail preparation")
            .to_string();

        assert!(error.contains("local agent source is not readable"));
        assert_eq!(
            sidecar
                .agent
                .launch
                .worker_generation
                .load(Ordering::SeqCst),
            generation
        );

        *sidecar.agent.launch.remote_host_info.lock().unwrap() = Some(test_windows_host());
        let windows_preflight = AgentInstallPreflight {
            before: json!({"agent_status": "ok"}),
            target_path: r"C:\Users\test\AppData\Local\nrm\bin\nrm-agent.exe".to_string(),
            effective_force: true,
            skip_reason: None,
            automatic: false,
        };
        let error = sidecar
            .prepare_remote_agent_install(
                &windows_preflight,
                BootstrapDeadline::new(Duration::from_secs(5)),
            )
            .err()
            .expect("missing Windows source must fail preparation")
            .to_string();
        assert!(error.contains("local agent source is not readable"));
        assert!(!error.contains("unsupported_platform"));
        assert_eq!(
            sidecar
                .agent
                .launch
                .worker_generation
                .load(Ordering::SeqCst),
            generation
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_registry_source_is_verified_cached_and_never_falls_back_to_local() {
        let release = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let state = tempdir().unwrap();
        let target = AgentTarget::X86_64UnknownLinuxMusl;
        let version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        let filename = format!("nrm-agent-{version}-{target}");
        let artifact_path = release.path().join(&filename);
        let artifact_bytes = b"signed registry agent";
        fs::write(&artifact_path, artifact_bytes).unwrap();

        let manifest_path = release.path().join(format!("manifest-{version}.json"));
        let signature_path = PathBuf::from(format!("{}.sig", manifest_path.display()));
        let manifest = serde_json::to_vec(&json!({
            "schema_version": 1,
            "package": "nrm-agent",
            "version": version.to_string(),
            "protocol_version": u32::from(PROTOCOL_VERSION),
            "source_commit": "0123456789abcdef0123456789abcdef01234567",
            "artifacts": [{
                "target": target.to_string(),
                "filename": filename,
                "sha256": sha256_bytes(artifact_bytes),
                "size": artifact_bytes.len(),
            }]
        }))
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let signature = serde_json::to_vec(&json!({
            "schema_version": 1,
            "signatures": [{
                "key_id": "release-test",
                "signature": STANDARD.encode(signing_key.sign(&manifest).to_bytes()),
            }]
        }))
        .unwrap();
        fs::write(&manifest_path, &manifest).unwrap();
        fs::write(&signature_path, &signature).unwrap();

        let decoy = release.path().join("unsigned-local-agent");
        fs::write(&decoy, b"unsigned decoy").unwrap();
        let template = format!(
            "file://{}/manifest-{{version}}.json",
            release.path().display()
        );
        let registry = RegistryLaunchConfig {
            url_template: RegistryUrlTemplate::parse(&template).unwrap(),
            trusted_keys: TrustedKeySet::from_base64([(
                "release-test",
                STANDARD.encode(signing_key.verifying_key().as_bytes()),
            )])
            .unwrap(),
            signature_threshold: 1,
            cache_dir: Some(cache.path().to_path_buf()),
            cache_max_bytes: DEFAULT_REGISTRY_CACHE_MAX_BYTES,
            timeout: Duration::from_secs(5),
            policy_fingerprint: "test-registry-policy".to_string(),
        };
        let sidecar = Sidecar::new_with_registry(
            PathBuf::from("/repo"),
            RemoteTransport::Local,
            "nrm-agent".to_string(),
            Some(decoy.clone()),
            Some(registry),
            Some(state.path().to_path_buf()),
            5_000,
            AgentInterrupt::default(),
        )
        .unwrap();
        *sidecar.agent.launch.remote_host_info.lock().unwrap() = Some(test_posix_host());
        let initial_health = sidecar.registry_health_snapshot();
        assert_eq!(initial_health.state, RegistryHealthState::NotChecked);
        assert_eq!(initial_health.source, "registry");
        assert_eq!(
            initial_health.manifest_url.as_deref(),
            Some("file:///<redacted>")
        );
        assert!(!initial_health
            .to_value()
            .to_string()
            .contains(release.path().to_string_lossy().as_ref()));

        let mut source = sidecar
            .resolve_agent_source(BootstrapDeadline::new(Duration::from_secs(5)))
            .unwrap();
        let mut resolved = Vec::new();
        source.file.read_to_end(&mut resolved).unwrap();
        assert_eq!(resolved, artifact_bytes);
        assert_ne!(source.path, decoy);
        assert_eq!(source.details["agent_source"], "registry");
        assert_eq!(source.details["registry_artifact_source"], "file");
        assert_eq!(
            source.details["registry_manifest_url"],
            "file:///<redacted>"
        );
        let verified = sidecar.registry_health_snapshot();
        assert_eq!(verified.state, RegistryHealthState::Verified);
        assert_eq!(verified.platform.as_ref().unwrap().os, "linux");
        assert_eq!(verified.platform.as_ref().unwrap().arch, "x86_64");
        assert_eq!(
            verified.platform.as_ref().unwrap().target,
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(verified.signing_key_ids, ["release-test"]);
        assert_eq!(
            verified.artifact_sha256.as_deref(),
            Some(sha256_bytes(artifact_bytes).as_str())
        );
        assert_eq!(verified.artifact_source, Some("file"));
        assert_eq!(verified.manifest_source, Some("file"));
        drop(source);

        fs::remove_file(&artifact_path).unwrap();
        let mut cached = sidecar
            .resolve_agent_source(BootstrapDeadline::new(Duration::from_secs(5)))
            .unwrap();
        let mut cached_bytes = Vec::new();
        cached.file.read_to_end(&mut cached_bytes).unwrap();
        assert_eq!(cached_bytes, artifact_bytes);
        assert_eq!(cached.details["registry_artifact_source"], "cache");
        assert_eq!(
            sidecar.registry_health_snapshot().artifact_source,
            Some("cache")
        );
        drop(cached);

        *sidecar.remote_health.lock().unwrap() = RemoteHealth::connected();
        fs::write(&signature_path, b"not a signature document").unwrap();
        assert!(sidecar
            .resolve_agent_source(BootstrapDeadline::new(Duration::from_secs(5)))
            .is_err());
        let registry_error = sidecar.registry_health_snapshot();
        assert_eq!(registry_error.state, RegistryHealthState::Error);
        assert_eq!(
            registry_error.error_code.as_deref(),
            Some("malformed_signature")
        );
        assert_eq!(
            sidecar.remote_health.lock().unwrap().state,
            RemoteHealthState::Connected,
            "a registry failure must not invalidate a working remote agent"
        );
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));
        let workspace = fast.workspace_info();
        assert_eq!(workspace["remote_status"], "connected");
        assert_eq!(workspace["registry_health"]["state"], "error");
        assert_eq!(
            workspace["registry_health"]["error_code"],
            "malformed_signature"
        );
        let public_error = registry_error.to_value().to_string();
        assert!(!public_error.contains(release.path().to_string_lossy().as_ref()));
        assert!(!public_error.contains(manifest_path.to_string_lossy().as_ref()));
        fs::write(&signature_path, &signature).unwrap();
        fs::remove_file(&manifest_path).unwrap();
        assert!(sidecar
            .resolve_agent_source(BootstrapDeadline::new(Duration::from_secs(5)))
            .is_err());
    }

    fn test_sidecar(mirror: Mirror) -> Sidecar {
        Sidecar {
            agent: AgentClient::new(
                "unused-agent".to_string(),
                None,
                RemoteTransport::Local,
                PathBuf::from("/unused"),
                // Mock replies are delivered by scheduler-driven helper
                // threads. Keep this comfortably above a loaded CI quantum;
                // tests that exercise expiry set an explicit zero budget.
                Duration::from_secs(1),
                AgentInterrupt::default(),
            ),
            mirror,
            remote_root: PathBuf::from("/unused"),
            workspace_key: "test".to_string(),
            remote_health: Arc::new(Mutex::new(RemoteHealth::default())),
            registry_health: Arc::new(Mutex::new(RegistryHealth::from_registry(None))),
        }
    }

    fn test_sidecar_with_agent_reply(mirror: Mirror, reply: AgentWorkerReply) -> Sidecar {
        let mut sidecar = test_sidecar(mirror);
        let (tx, rx) = mpsc::channel::<AgentWorkerCommand>();
        thread::spawn(move || {
            if let Ok(command) = rx.recv() {
                let _ = command.reply.send(reply);
            }
        });
        sidecar.agent.worker = Some(AgentWorker {
            tx,
            abort: Arc::new(TestAbortHandle::default()),
            join: None,
        });
        sidecar
    }

    fn test_sidecar_with_agent_replies(mirror: Mirror, replies: Vec<AgentWorkerReply>) -> Sidecar {
        let mut sidecar = test_sidecar(mirror);
        let (tx, rx) = mpsc::channel::<AgentWorkerCommand>();
        thread::spawn(move || {
            let mut replies = VecDeque::from(replies);
            while let Ok(command) = rx.recv() {
                let reply = replies.pop_front().unwrap_or_else(|| {
                    AgentWorkerReply::TransportError(format!(
                        "no test reply for {:?}",
                        command.request
                    ))
                });
                let _ = command.reply.send(reply);
            }
        });
        sidecar.agent.worker = Some(AgentWorker {
            tx,
            abort: Arc::new(TestAbortHandle::default()),
            join: None,
        });
        sidecar
    }

    fn test_sidecar_with_git_request<F>(
        mirror: Mirror,
        assert_request: F,
        response: Response,
    ) -> Sidecar
    where
        F: FnOnce(Request) + Send + 'static,
    {
        let mut sidecar = test_sidecar(mirror);
        let (tx, rx) = mpsc::channel::<AgentWorkerCommand>();
        thread::spawn(move || {
            let hello = rx.recv().expect("expected hello request");
            assert!(matches!(hello.request, Request::Hello { .. }));
            let _ = hello
                .reply
                .send(AgentWorkerReply::Response(Response::Hello {
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    capabilities: nrm_protocol::CapabilitySet::v1_agent(),
                }));

            let command = rx.recv().expect("expected git request");
            assert_request(command.request);
            let _ = command.reply.send(AgentWorkerReply::Response(response));
        });
        sidecar.agent.worker = Some(AgentWorker {
            tx,
            abort: Arc::new(TestAbortHandle::default()),
            join: None,
        });
        sidecar
    }

    fn record_hydrated_content(mirror: &Mirror, path: &str, content: &[u8]) -> PathBuf {
        let hash = hash_bytes(content);
        mirror
            .record_hydrated(&test_meta(path, &hash, content.len() as u64), &hash, &hash)
            .unwrap();
        let local_path = mirror.local_path(path).unwrap();
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&local_path, content).unwrap();
        local_path
    }

    fn insert_unreplayable_save(
        mirror: &Mirror,
        path: &str,
        expected_hash: Option<&str>,
        local_hash: &str,
        state: &str,
    ) -> i64 {
        assert!(matches!(state, "pending" | "failed"));
        let now = now_ms();
        mirror
            .db
            .execute(
                "
                INSERT INTO save_queue (
                  relative_path, expected_hash, local_hash, snapshot_path, state,
                  attempts, created_at_ms, updated_at_ms
                )
                VALUES (?1, ?2, ?3, NULL, ?4, 0, ?5, ?5)
                ",
                params![path, expected_hash, local_hash, state, now],
            )
            .unwrap();
        mirror.db.last_insert_rowid()
    }

    fn save_state(mirror: &Mirror, queue_id: i64) -> String {
        mirror
            .db
            .query_row(
                "SELECT state FROM save_queue WHERE id=?1",
                params![queue_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn slot_backoff_window_ms(slot: &RemoteBackoffSlot) -> u64 {
        slot.unavailable_until
            .unwrap()
            .duration_since(slot.last_remote_error_at.unwrap())
            .as_millis() as u64
    }

    #[test]
    fn local_paths_reject_traversal() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        assert!(mirror.local_path("../x").is_err());
        assert!(mirror.local_path("/x").is_err());
    }

    #[test]
    fn remote_unavailable_backoff_grows_and_caps() {
        assert_eq!(remote_unavailable_backoff_ms(0), 0);
        assert_eq!(
            remote_unavailable_backoff_ms(1),
            REMOTE_UNAVAILABLE_BACKOFF_BASE_MS
        );
        assert_eq!(
            remote_unavailable_backoff_ms(2),
            REMOTE_UNAVAILABLE_BACKOFF_BASE_MS * 2
        );
        assert_eq!(
            remote_unavailable_backoff_ms(5),
            REMOTE_UNAVAILABLE_BACKOFF_BASE_MS * 16
        );
        assert_eq!(
            remote_unavailable_backoff_ms(6),
            REMOTE_UNAVAILABLE_BACKOFF_MAX_MS
        );
        assert_eq!(
            remote_unavailable_backoff_ms(u32::MAX),
            REMOTE_UNAVAILABLE_BACKOFF_MAX_MS
        );
    }

    #[test]
    fn remote_backoff_state_resets_lane_failure_count_on_clear() {
        let mut backoff = RemoteBackoffState::default();

        backoff.mark_unavailable(AgentBackoffLane::Read, "first".to_string(), None);
        assert_eq!(
            slot_backoff_window_ms(backoff.slot(AgentBackoffLane::Read)),
            REMOTE_UNAVAILABLE_BACKOFF_BASE_MS
        );

        backoff.mark_unavailable(AgentBackoffLane::Read, "second".to_string(), None);
        assert_eq!(
            slot_backoff_window_ms(backoff.slot(AgentBackoffLane::Read)),
            REMOTE_UNAVAILABLE_BACKOFF_BASE_MS * 2
        );
        assert_eq!(
            backoff.slot(AgentBackoffLane::Write).consecutive_failures,
            0
        );

        backoff.clear_lane(AgentBackoffLane::Read);
        assert_eq!(backoff.slot(AgentBackoffLane::Read).consecutive_failures, 0);
        backoff.mark_unavailable(AgentBackoffLane::Read, "third".to_string(), None);
        assert_eq!(
            slot_backoff_window_ms(backoff.slot(AgentBackoffLane::Read)),
            REMOTE_UNAVAILABLE_BACKOFF_BASE_MS
        );
    }

    #[test]
    fn agent_client_recovers_poisoned_shared_backoff() {
        let dir = tempdir().unwrap();
        let mut read = AgentClient::new(
            "nrm-agent".to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_millis(100),
            AgentInterrupt::default(),
        );
        let mut write = read.clone_for_lane(AgentInterrupt::default());
        let _ = read.mark_remote_unavailable_with_launch_failure(
            "missing",
            RemoteAgentLaunchFailure::Missing,
        );
        let _ = write.mark_remote_unavailable_with_compatibility_failure(
            "old version",
            AgentCompatibilityFailure::VersionMismatch {
                agent_version: "0.0.1".to_string(),
            },
        );

        let shared = Arc::clone(&read.remote_backoff);
        let poison = Arc::clone(&shared);
        assert!(thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison shared backoff for regression coverage");
        })
        .join()
        .is_err());
        assert!(shared.is_poisoned());

        read.clear_all_remote_unavailable();
        assert!(!shared.is_poisoned());
        {
            let backoff = shared.lock().unwrap();
            for lane in [AgentBackoffLane::Read, AgentBackoffLane::Write] {
                let slot = backoff.slot(lane);
                assert_eq!(slot.consecutive_failures, 0);
                assert!(slot.unavailable_until.is_none());
                assert!(slot.last_remote_error.is_none());
                assert!(slot.trusted_failure.is_none());
                assert!(slot.last_remote_error_at.is_none());
            }
        }

        let _ = write.mark_remote_unavailable("retry after poison recovery");
        assert!(write.remote_backoff().is_some());
        write.clear_remote_unavailable();
        assert!(write.remote_backoff().is_none());
    }

    #[test]
    fn remote_agent_managed_path_rules_are_explicit() {
        assert!(remote_agent_uses_managed_path("nrm-agent"));
        assert!(remote_agent_uses_managed_path("nrm-agent.exe"));
        assert!(!remote_agent_uses_managed_path("./nrm-agent"));
        assert!(!remote_agent_uses_managed_path("/opt/nrm-agent"));
        assert!(!remote_agent_uses_managed_path(r"C:\nrm\nrm-agent.exe"));
        assert!(!remote_agent_uses_managed_path("C:/nrm/nrm-agent.exe"));
        assert_eq!(
            default_remote_agent_install_path("nrm-agent", &test_posix_host()).unwrap(),
            REMOTE_AGENT_MANAGED_PATH
        );
        assert_eq!(
            default_remote_agent_install_path("custom-agent", &test_posix_host()).unwrap(),
            "$HOME/.local/bin/custom-agent"
        );
        assert_eq!(
            default_remote_agent_install_path("/opt/bin/nrm-agent", &test_posix_host()).unwrap(),
            "/opt/bin/nrm-agent"
        );
        for invalid in [
            "./nrm-agent",
            "bin/nrm-agent",
            "-nrm-agent",
            "nrm agent",
            "nrm-agent\n",
            "*.exe",
            "agent?.exe",
            "[ab].exe",
            "agent+debug",
            "nrm-agént",
            ".",
            "..",
            "",
        ] {
            assert!(
                default_remote_agent_install_path(invalid, &test_posix_host()).is_err(),
                "accepted invalid POSIX remote agent {invalid:?}"
            );
        }
        let ssh = RemoteTransport::from_ssh(Some("example.test".to_owned()), 1).unwrap();
        for invalid in ["*.exe", "agent?.exe", "[ab].exe"] {
            assert!(
                ssh.agent_plan(invalid, Path::new("/repo"), &test_posix_host())
                    .is_err(),
                "accepted unsafe POSIX launch name {invalid:?}"
            );
            assert!(
                ssh.agent_plan(invalid, Path::new("B:/repo"), &test_windows_host())
                    .is_err(),
                "accepted wildcard-aware PowerShell launch name {invalid:?}"
            );
        }
        assert_eq!(
            default_remote_agent_install_path("nrm-agent", &test_windows_host()).unwrap(),
            r"C:\Users\test\AppData\Local\nrm\bin\nrm-agent.exe"
        );
        assert_eq!(
            default_remote_agent_install_path("custom-agent", &test_windows_host()).unwrap(),
            r"C:\Users\test\AppData\Local\nrm\bin\custom-agent.exe"
        );
        assert_eq!(
            default_remote_agent_install_path(r"D:\tools\nrm-agent.exe", &test_windows_host())
                .unwrap(),
            r"D:\tools\nrm-agent.exe"
        );
    }

    #[test]
    fn ssh_destination_validation_accepts_common_safe_forms() {
        for destination in [
            "host",
            "host.example",
            "user@host.example",
            "build_host-1",
            "[2001:db8::1]",
            "user@[fe80::1%eth0]",
        ] {
            validate_ssh_destination(destination).unwrap();
        }
    }

    #[test]
    fn ssh_destination_validation_rejects_option_injection_and_malformed_values() {
        for destination in [
            "",
            "-oProxyCommand=evil",
            "user@-oProxyCommand=evil",
            "host name",
            "host\nname",
            "host\u{0}name",
            "host/path",
            "host\\path",
            "@host",
            "user@",
            "user@@host",
            "host:22",
            "[2001:db8::1",
            "2001:db8::1",
        ] {
            assert!(
                validate_ssh_destination(destination).is_err(),
                "accepted invalid ssh destination {destination:?}"
            );
        }
    }

    #[test]
    fn scp_upload_uses_forced_sftp_and_literal_argv_paths() {
        let transport = SshTransport {
            program: PathBuf::from("/opt/openssh/bin/ssh"),
            target: "builder@windows-host".to_owned(),
            connect_timeout_seconds: 17,
        };
        let source = Path::new("-local artifact with spaces.exe");
        let remote = r"B:\safe dir\agent';$(Write-Output owned).exe";
        let command = transport.scp_upload_command(source, remote).unwrap();
        assert_eq!(
            Path::new(command.get_program())
                .file_name()
                .unwrap()
                .to_string_lossy(),
            "scp"
        );
        let args: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|argument| argument == "-s"));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-o", "ControlPath=none"]));
        assert_eq!(args[args.len() - 3], "--");
        assert_eq!(args[args.len() - 2], source.to_string_lossy());
        assert_eq!(
            args[args.len() - 1],
            "builder@windows-host:B:/safe dir/agent';$(Write-Output owned).exe"
        );
    }

    #[test]
    fn scp_upload_rejects_noncanonical_or_injectable_remote_paths() {
        let transport = SshTransport {
            program: PathBuf::from("ssh"),
            target: "windows-host".to_owned(),
            connect_timeout_seconds: 15,
        };
        for path in [
            r"relative\agent.exe",
            r"\\server\share\agent.exe",
            "B:/safe/../agent.exe",
            "B:/safe//agent.exe",
            "B:/safe/agent.exe\n-oProxyCommand=evil",
            "B:/safe/agent:stream.exe",
        ] {
            assert!(
                transport
                    .scp_upload_command(Path::new("agent.exe"), path)
                    .is_err(),
                "accepted unsafe scp path {path:?}"
            );
        }
    }

    #[test]
    fn agent_hello_requires_exact_package_and_protocol_versions() {
        validate_agent_hello(env!("CARGO_PKG_VERSION"), PROTOCOL_VERSION).unwrap();

        let version_error = validate_agent_hello("0.0.0-incompatible", PROTOCOL_VERSION)
            .unwrap_err()
            .to_string();
        assert!(version_error.contains("package version mismatch"));

        let protocol_error = validate_agent_hello(
            env!("CARGO_PKG_VERSION"),
            PROTOCOL_VERSION.saturating_add(1),
        )
        .unwrap_err()
        .to_string();
        assert!(protocol_error.contains("protocol version mismatch"));

        let malformed = validate_agent_hello("not-semver\x1b[31m", PROTOCOL_VERSION).unwrap_err();
        assert!(malformed.failure.is_none());
        assert_eq!(
            malformed.to_string(),
            "agent Hello reported a malformed package version"
        );
    }

    #[test]
    fn compatibility_rpc_error_requires_exact_hello_bound_grammar() {
        let hello = Request::Hello {
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: PROTOCOL_VERSION,
        };
        let error = |message: String| RpcError {
            code: nrm_protocol::RpcErrorCode::Agent,
            message,
            retryable: false,
        };

        assert_eq!(
            parse_agent_compatibility_rpc_error(
                &error(format!(
                    "package version mismatch: client={} agent=0.0.1",
                    env!("CARGO_PKG_VERSION")
                )),
                &hello,
            ),
            Some(AgentCompatibilityFailure::VersionMismatch {
                agent_version: "0.0.1".to_owned()
            })
        );
        let agent_protocol = PROTOCOL_VERSION.saturating_add(1);
        assert_eq!(
            parse_agent_compatibility_rpc_error(
                &error(format!(
                    "protocol version mismatch: client={PROTOCOL_VERSION} agent={agent_protocol}"
                )),
                &hello,
            ),
            Some(AgentCompatibilityFailure::ProtocolMismatch {
                protocol_version: agent_protocol
            })
        );

        let malformed = [
            "package version mismatch".to_owned(),
            format!(
                "prefix package version mismatch: client={} agent=0.0.1",
                env!("CARGO_PKG_VERSION")
            ),
            "package version mismatch: client=spoofed agent=0.0.1".to_owned(),
            format!(
                "package version mismatch: client={} agent=not-semver",
                env!("CARGO_PKG_VERSION")
            ),
            format!(
                "package version mismatch: client={} agent=0.0.1 suffix",
                env!("CARGO_PKG_VERSION")
            ),
            format!(
                "package version mismatch: client={} agent=0.0.1\n",
                env!("CARGO_PKG_VERSION")
            ),
            format!(
                "package version mismatch: client={} agent={}",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_VERSION")
            ),
            format!(
                "protocol version mismatch: client={} agent={}",
                PROTOCOL_VERSION.saturating_add(1),
                PROTOCOL_VERSION
            ),
            format!(
                "protocol version mismatch: client={PROTOCOL_VERSION} agent=01"
            ),
            format!(
                "protocol version mismatch: client={PROTOCOL_VERSION} agent={PROTOCOL_VERSION}"
            ),
            format!(
                "protocol version mismatch: client={PROTOCOL_VERSION} agent={agent_protocol}\x1b[31m"
            ),
        ];
        for message in malformed {
            assert_eq!(
                parse_agent_compatibility_rpc_error(&error(message.clone()), &hello),
                None,
                "accepted malformed compatibility error {message:?}"
            );
        }

        let wrong_code = RpcError {
            code: nrm_protocol::RpcErrorCode::Protocol,
            message: format!(
                "package version mismatch: client={} agent=0.0.1",
                env!("CARGO_PKG_VERSION")
            ),
            retryable: false,
        };
        assert_eq!(
            parse_agent_compatibility_rpc_error(&wrong_code, &hello),
            None
        );
        let retryable = RpcError {
            retryable: true,
            ..error(format!(
                "package version mismatch: client={} agent=0.0.1",
                env!("CARGO_PKG_VERSION")
            ))
        };
        assert_eq!(
            parse_agent_compatibility_rpc_error(&retryable, &hello),
            None
        );
        assert_eq!(
            parse_agent_compatibility_rpc_error(
                &error(format!(
                    "package version mismatch: client={} agent=0.0.1",
                    env!("CARGO_PKG_VERSION")
                )),
                &Request::Shutdown,
            ),
            None
        );
    }

    #[test]
    fn command_capture_keeps_remote_error_when_streaming_stdin_breaks() {
        let command = command_that_fails_with_stderr();
        let input = io::Cursor::new(vec![0_u8; 1024 * 1024]);

        let output = run_command_capture(
            command,
            Some(Box::new(input)),
            Duration::from_secs(1),
            "test upload",
        )
        .unwrap();

        assert_eq!(output.status.code(), Some(23));
        assert!(output.stderr.contains("already_exists"));
    }

    #[test]
    fn command_capture_stream_reader_enforces_exact_byte_limit() {
        for (size, succeeds) in [
            (PROCESS_CAPTURE_MAX_STREAM_BYTES, true),
            (PROCESS_CAPTURE_MAX_STREAM_BYTES + 1, false),
        ] {
            let handle = spawn_process_output_reader(io::Cursor::new(vec![b'x'; size]));
            while !handle.is_finished() {
                thread::yield_now();
            }
            let result = join_process_output_reader(handle, "test process", "stdout");
            if succeeds {
                assert_eq!(result.unwrap().len(), size);
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("exceeded"), "{error}");
            }
        }
    }

    #[test]
    fn command_capture_kills_output_floods_at_the_stream_limit() {
        for (stderr, expected_stream) in [(false, "stdout"), (true, "stderr")] {
            let started = Instant::now();
            let error = run_command_capture(
                command_that_floods_output(stderr),
                None,
                Duration::from_secs(15),
                "output flood test",
            )
            .unwrap_err();
            let limit = error
                .downcast_ref::<ProcessOutputLimitError>()
                .expect("output overflow must retain its typed error");
            assert_eq!(limit.stream, expected_stream);
            assert_eq!(limit.limit, PROCESS_CAPTURE_MAX_STREAM_BYTES);
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "output overflow should terminate promptly: {error:#}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn command_capture_timeout_kills_descendant_process_group() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("descendant-survived");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("(sleep 0.2; printf alive > \"$NRM_DESCENDANT_MARKER\") & wait")
            .env("NRM_DESCENDANT_MARKER", &marker);

        let error = run_command_capture(
            command,
            None,
            Duration::from_millis(30),
            "descendant process-group test",
        )
        .unwrap_err();
        assert!(error.downcast_ref::<ProcessTimeoutError>().is_some());

        thread::sleep(Duration::from_millis(300));
        assert!(
            !marker.exists(),
            "a descendant survived command-capture timeout teardown"
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_capture_timeout_does_not_join_stalled_stdin_producer() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("sleep 5");
        let (release_tx, release_rx) = mpsc::channel();
        let input = StalledRead {
            release: release_rx,
        };

        let started = Instant::now();
        let error = run_command_capture(
            command,
            Some(Box::new(input)),
            Duration::from_millis(30),
            "stalled stdin test",
        )
        .unwrap_err();

        assert!(error.downcast_ref::<ProcessTimeoutError>().is_some());
        assert!(started.elapsed() < Duration::from_millis(500));
        release_tx.send(()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn command_capture_preserves_record_whitespace_after_bom_filtering() {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("printf '\\nRECORD\\t\\n\\n'; printf ' error \\n' >&2");

        let output =
            run_command_capture(command, None, Duration::from_secs(1), "test exact output")
                .unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, "\nRECORD\t\n\n");
        assert_eq!(output.stderr, " error \n");
    }

    #[cfg(unix)]
    #[test]
    fn remote_install_lease_reports_contention_and_reaps_holder() {
        let dir = tempdir().unwrap();
        let fake_ssh = dir.path().join("fake-ssh");
        fs::write(
            &fake_ssh,
            b"#!/bin/sh\nprintf 'test login banner\\n' >&2\nfor last do :; done\nexec sh -c \"$last\"\n",
        )
        .unwrap();
        fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o755)).unwrap();
        let ssh = SshTransport {
            program: fake_ssh,
            target: "ignored.example".to_owned(),
            connect_timeout_seconds: 1,
        };
        let target = dir.path().join("nrm-agent");
        let mut plan = agent_install::PosixInstallPlan::new(
            target.to_str().unwrap(),
            env!("CARGO_PKG_VERSION"),
            PROTOCOL_VERSION,
            true,
        )
        .unwrap();
        plan.set_expected_sha256(&"0".repeat(64)).unwrap();
        let token_one = "0123456789abcdef0123456789abcdef";
        let token_two = "fedcba9876543210fedcba9876543210";
        let (mut lease, readiness) = RemoteInstallLease::acquire(
            &ssh,
            plan.lease_command(token_one).unwrap(),
            None,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            plan.parse_lease_ready_stdout(token_one, &readiness)
                .unwrap(),
            target.to_str().unwrap()
        );

        let contender = RemoteInstallLease::acquire(
            &ssh,
            plan.lease_command(token_two).unwrap(),
            None,
            Duration::from_secs(2),
        )
        .err()
        .expect("a second holder must not acquire the same target");
        assert!(
            contender.to_string().contains("install_in_progress"),
            "{contender:#}"
        );
        lease.ensure_held("test mutation").unwrap();
        lease.release(Duration::from_secs(2)).unwrap();
        assert!(!PathBuf::from(format!("{}.nrm-install-lease", target.display())).exists());

        let oversized = RemoteInstallLease::acquire(
            &ssh,
            "printf '%05000d' 0".to_owned(),
            None,
            Duration::from_secs(2),
        )
        .err()
        .expect("oversized readiness must fail");
        assert!(
            oversized.to_string().contains("readiness exceeded"),
            "{oversized:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_install_lease_sends_bounded_out_of_band_release_signal() {
        let dir = tempdir().unwrap();
        let fake_ssh = dir.path().join("fake-ssh");
        fs::write(
            &fake_ssh,
            b"#!/bin/sh\nfor last do :; done\nexec sh -c \"$last\"\n",
        )
        .unwrap();
        fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o755)).unwrap();
        let ssh = SshTransport {
            program: fake_ssh,
            target: "ignored.example".to_owned(),
            connect_timeout_seconds: 1,
        };
        let marker = dir.path().join("release-marker");
        let marker_quoted = shell_quote(marker.to_string_lossy());
        let holder_command = format!(
            "printf 'NRM_TEST_LEASE_READY\\n'; while [ ! -f {marker_quoted} ]; do sleep 0.01; done; rm -f {marker_quoted}"
        );
        let release_command =
            format!("printf release > {marker_quoted}; printf 'NRM_TEST_LEASE_RELEASED\\n'");
        let signal = RemoteInstallLeaseReleaseSignal {
            ssh: ssh.clone(),
            remote_command: release_command,
            expected_record: "NRM_TEST_LEASE_RELEASED".to_owned(),
        };
        let (mut lease, readiness) =
            RemoteInstallLease::acquire(&ssh, holder_command, Some(signal), Duration::from_secs(2))
                .unwrap();
        assert_eq!(readiness, "NRM_TEST_LEASE_READY\n");
        lease.release(Duration::from_secs(2)).unwrap();
        assert!(!marker.exists());

        let delayed_marker = dir.path().join("delayed-release-marker");
        let delayed_marker_quoted = shell_quote(delayed_marker.to_string_lossy());
        let holder_command = format!(
            "printf 'NRM_TEST_LEASE_READY\\n'; while [ ! -f {delayed_marker_quoted} ]; do sleep 0.01; done; rm -f {delayed_marker_quoted}"
        );
        let release_command = format!(
            "printf release > {delayed_marker_quoted}; printf 'NRM_TEST_LEASE_RELEASED\\n'; sleep 1"
        );
        let signal = RemoteInstallLeaseReleaseSignal {
            ssh: ssh.clone(),
            remote_command: release_command,
            expected_record: "NRM_TEST_LEASE_RELEASED".to_owned(),
        };
        let (mut lease, _) =
            RemoteInstallLease::acquire(&ssh, holder_command, Some(signal), Duration::from_secs(2))
                .unwrap();
        let error = lease.release(Duration::from_millis(100)).unwrap_err();
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<ProcessTimeoutError>().is_some()),
            "{error:#}"
        );
        assert!(!delayed_marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn remote_install_lease_release_budget_detaches_retained_stderr() {
        let (mut lease, _) = local_remote_install_lease("(sleep 0.3) & exit 0");
        let budget = Duration::from_millis(30);
        let started = Instant::now();
        let error = lease.release(budget).unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            error.to_string().contains("stderr did not close"),
            "{error:#}"
        );
        assert!(
            elapsed < Duration::from_millis(200),
            "release waited {elapsed:?} for a descendant-held stderr pipe"
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_install_lease_release_and_drop_bound_eof_ignoring_holder() {
        let script = "trap '' HUP TERM; while :; do sleep 1; done";
        let (mut lease, release_pid) = local_remote_install_lease(script);
        let budget = Duration::from_millis(30);
        let started = Instant::now();
        let error = lease.release(budget).unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            error
                .chain()
                .any(|cause| cause.downcast_ref::<ProcessTimeoutError>().is_some()),
            "{error:#}"
        );
        assert!(
            elapsed < Duration::from_millis(200),
            "release exceeded its teardown budget: {elapsed:?}"
        );
        wait_for_local_process_reap(release_pid);

        let (lease, drop_pid) = local_remote_install_lease(script);
        let started = Instant::now();
        drop(lease);
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(100),
            "zero-budget Drop blocked for {elapsed:?}"
        );
        wait_for_local_process_reap(drop_pid);
    }

    #[cfg(unix)]
    #[test]
    fn expired_recovery_budget_does_not_grant_lease_release_a_fresh_grace() {
        let (mut lease, pid) =
            local_remote_install_lease("trap '' HUP TERM; while :; do sleep 1; done");
        let deadline =
            BootstrapDeadline::with_elapsed(Duration::from_millis(20), Duration::from_secs(1));

        let started = Instant::now();
        let error = release_remote_install_lease_with_deadline(
            &mut lease,
            deadline,
            "test expired lease release",
        )
        .unwrap_err();
        let elapsed = started.elapsed();

        assert!(is_bootstrap_timeout(&error), "{error:#}");
        assert!(
            elapsed < Duration::from_millis(100),
            "expired recovery budget gained a new teardown grace: {elapsed:?}"
        );
        wait_for_local_process_reap(pid);
    }

    #[test]
    fn incompatible_agent_hello_blocks_ordinary_remote_work() {
        for (response, expected_error, expected_status) in [
            (
                Response::Hello {
                    agent_version: "0.0.0-incompatible".to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    capabilities: nrm_protocol::CapabilitySet::v1_agent(),
                },
                "package version mismatch",
                "version_mismatch",
            ),
            (
                Response::Hello {
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION.saturating_add(1),
                    capabilities: nrm_protocol::CapabilitySet::v1_agent(),
                },
                "protocol version mismatch",
                "protocol_mismatch",
            ),
        ] {
            let dir = tempdir().unwrap();
            let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
            let mut sidecar =
                test_sidecar_with_agent_reply(mirror, AgentWorkerReply::Response(response));

            let error = sidecar
                .handle("scan", json!({"limit": 1}), 0)
                .unwrap_err()
                .to_string();

            assert!(error.contains(expected_error), "{error}");
            assert!(!sidecar.agent.handshake_complete());
            let health = sidecar.remote_health(0);
            assert_eq!(health["remote_available"], false);
            assert_eq!(health["agent_status"], expected_status);
            assert!(health["remote_error"]
                .as_str()
                .unwrap()
                .contains(expected_error));
        }
    }

    #[test]
    fn remote_agent_status_classifies_common_failures() {
        assert_eq!(
            classify_remote_agent_status(&json!({
                "remote_available": true,
                "agent_version": env!("CARGO_PKG_VERSION")
            })),
            "ok"
        );
        assert_eq!(
            classify_remote_agent_status(&json!({
                "remote_available": true,
                "agent_version": "0.0.0"
            })),
            "ok"
        );
        assert_eq!(
            classify_remote_agent_status(&json!({
                "agent_compatibility_failure": "protocol_mismatch",
                "protocol_version": 1
            })),
            "protocol_mismatch"
        );
        assert_eq!(
            classify_remote_agent_status(&json!({
                "agent_compatibility_failure": "version_mismatch",
                "agent_version": "0.0.9"
            })),
            "version_mismatch"
        );
        assert_eq!(
            classify_remote_agent_status(&json!({
                "agent_launch_failure": "root_missing",
                "remote_error": "remote agent launcher reported a missing remote root"
            })),
            "remote_root_missing"
        );
        assert_eq!(
            classify_remote_agent_status(&json!({
                "agent_launch_failure": "not_executable",
                "remote_error": "remote agent launcher reported a non-executable"
            })),
            "agent_not_executable"
        );
        assert_eq!(
            classify_remote_agent_status(&json!({
                "agent_launch_failure": "missing",
                "remote_error": "remote agent launcher reported a missing executable"
            })),
            "missing_agent"
        );
        for untrusted_text in [
            "failed to canonicalize root: No such file or directory",
            "failed to launch agent: Permission denied",
            "failed to launch agent: nrm-agent: not found",
            "protocol version mismatch: agent=1 client=2",
            "package version mismatch: sidecar=0.1.0 agent=0.0.9",
        ] {
            assert_eq!(
                classify_remote_agent_status(&json!({ "remote_error": untrusted_text })),
                "unavailable"
            );
        }
    }

    #[test]
    fn automatic_agent_bootstrap_repairs_only_known_agent_failures() {
        let compatible = agent_install_decision("ok", true, false, true).unwrap();
        assert!(!compatible.effective_force);
        assert_eq!(
            compatible.skip_reason.as_deref(),
            Some("remote agent is already compatible")
        );

        let missing = agent_install_decision("missing_agent", true, false, true).unwrap();
        assert!(!missing.effective_force);
        assert!(missing.skip_reason.is_none());

        for status in [
            "agent_not_executable",
            "version_mismatch",
            "protocol_mismatch",
        ] {
            let repair = agent_install_decision(status, true, false, true).unwrap();
            assert!(repair.effective_force, "status {status}");
            assert!(repair.skip_reason.is_none(), "status {status}");
        }

        for status in ["unavailable", "remote_root_missing", "unknown"] {
            let unchanged = agent_install_decision(status, true, false, true).unwrap();
            assert!(!unchanged.effective_force, "status {status}");
            assert!(
                unchanged
                    .skip_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("left remote agent unchanged")),
                "status {status}"
            );
        }

        assert!(agent_install_decision("missing_agent", false, false, true)
            .unwrap_err()
            .to_string()
            .contains("update/repair semantics"));
        assert!(agent_install_decision("missing_agent", true, true, true)
            .unwrap_err()
            .to_string()
            .contains("does not accept force=true"));

        let explicit_update = agent_install_decision("unavailable", true, false, false).unwrap();
        assert!(explicit_update.effective_force);
        assert!(explicit_update.skip_reason.is_none());
    }

    #[test]
    fn automatic_agent_bootstrap_requires_signed_registry_before_remote_work() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar(mirror);

        let error = sidecar
            .remote_agent_install_preflight(
                &json!({"automatic": true}),
                true,
                0,
                BootstrapDeadline::new(Duration::from_secs(1)),
            )
            .err()
            .expect("automatic bootstrap without registry must fail")
            .to_string();

        assert!(error.contains("requires a configured signed registry"));
        assert_eq!(
            sidecar.remote_health_snapshot().state,
            RemoteHealthState::Unchecked
        );
    }

    #[test]
    fn automatic_preflight_rejects_invalid_policy_and_path_before_remote_work() {
        struct Case {
            name: &'static str,
            params: Value,
            update: bool,
            registry: bool,
            ssh: bool,
            expected: &'static str,
        }

        let cases = [
            Case {
                name: "force type",
                params: json!({"automatic": true, "force": "yes"}),
                update: true,
                registry: false,
                ssh: false,
                expected: "params.force must be a boolean",
            },
            Case {
                name: "automatic type",
                params: json!({"automatic": 1}),
                update: true,
                registry: false,
                ssh: false,
                expected: "params.automatic must be a boolean",
            },
            Case {
                name: "install semantics",
                params: json!({"automatic": true}),
                update: false,
                registry: false,
                ssh: false,
                expected: "requires update/repair semantics",
            },
            Case {
                name: "forced automatic repair",
                params: json!({"automatic": true, "force": true}),
                update: true,
                registry: false,
                ssh: false,
                expected: "does not accept force=true",
            },
            Case {
                name: "local transport",
                params: json!({"automatic": true}),
                update: true,
                registry: true,
                ssh: false,
                expected: "only supported for ssh targets",
            },
            Case {
                name: "install path type",
                params: json!({"automatic": true, "install_path": ["/tmp/agent"]}),
                update: true,
                registry: true,
                ssh: true,
                expected: "params.install_path must be a string",
            },
            Case {
                name: "empty install path",
                params: json!({"automatic": true, "install_path": "  "}),
                update: true,
                registry: true,
                ssh: true,
                expected: "params.install_path must not be empty",
            },
        ];

        for case in cases {
            let dir = tempdir().unwrap();
            let mirror = Mirror::open(Some(dir.path().join("state")), case.name).unwrap();
            let mut sidecar = test_sidecar(mirror);
            if case.registry {
                configure_test_registry(&mut sidecar, Duration::from_secs(2));
            }
            if case.ssh {
                sidecar.agent.launch.transport = RemoteTransport::Ssh(SshTransport {
                    program: PathBuf::from("definitely-not-a-real-ssh-program"),
                    target: "test.example".to_owned(),
                    connect_timeout_seconds: 1,
                });
            }
            let backoff_before = {
                let mut backoff = sidecar.agent.remote_backoff.lock().unwrap();
                backoff.mark_unavailable(
                    AgentBackoffLane::Read,
                    "prior read failure".to_owned(),
                    Some(TrustedAgentFailure::Launch(
                        RemoteAgentLaunchFailure::Missing,
                    )),
                );
                backoff.mark_unavailable(
                    AgentBackoffLane::Write,
                    "prior write failure".to_owned(),
                    Some(TrustedAgentFailure::Compatibility(
                        AgentCompatibilityFailure::VersionMismatch {
                            agent_version: "9.9.9".to_owned(),
                        },
                    )),
                );
                test_backoff_snapshot(&backoff)
            };
            let worker_generation = sidecar
                .agent
                .launch
                .worker_generation
                .load(Ordering::SeqCst);
            let next_request_id = sidecar.agent.next_id;

            let error = sidecar
                .remote_agent_install_preflight(
                    &case.params,
                    case.update,
                    0,
                    BootstrapDeadline::new(Duration::from_secs(2)),
                )
                .err()
                .unwrap_or_else(|| panic!("{} unexpectedly passed preflight", case.name))
                .to_string();

            assert!(error.contains(case.expected), "{}: {error}", case.name);
            let backoff_after = sidecar
                .agent
                .remote_backoff
                .lock()
                .map(|backoff| test_backoff_snapshot(&backoff))
                .unwrap();
            assert_eq!(
                backoff_after, backoff_before,
                "{} changed cached failure state",
                case.name
            );
            assert!(
                sidecar.agent.launch.cached_remote_host_info().is_none(),
                "{} performed remote host detection",
                case.name
            );
            assert_eq!(
                sidecar
                    .agent
                    .launch
                    .worker_generation
                    .load(Ordering::SeqCst),
                worker_generation,
                "{} invalidated an agent worker",
                case.name
            );
            assert_eq!(
                sidecar.agent.next_id, next_request_id,
                "{} attempted remote work",
                case.name
            );
        }
    }

    #[test]
    fn automatic_preflight_mutates_only_for_typed_repairable_failures() {
        struct Case {
            name: &'static str,
            reply: AgentWorkerReply,
            expected_status: &'static str,
            expected_force: bool,
            expected_skip: bool,
        }

        let cases = vec![
            Case {
                name: "missing",
                reply: AgentWorkerReply::LaunchError(RemoteAgentLaunchFailure::Missing),
                expected_status: "missing_agent",
                expected_force: false,
                expected_skip: false,
            },
            Case {
                name: "not executable",
                reply: AgentWorkerReply::LaunchError(RemoteAgentLaunchFailure::NotExecutable),
                expected_status: "agent_not_executable",
                expected_force: true,
                expected_skip: false,
            },
            Case {
                name: "version mismatch",
                reply: AgentWorkerReply::Response(Response::Hello {
                    agent_version: "9.9.9".to_owned(),
                    protocol_version: PROTOCOL_VERSION,
                    capabilities: nrm_protocol::CapabilitySet::v1_agent(),
                }),
                expected_status: "version_mismatch",
                expected_force: true,
                expected_skip: false,
            },
            Case {
                name: "protocol mismatch",
                reply: AgentWorkerReply::Response(Response::Hello {
                    agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                    protocol_version: PROTOCOL_VERSION + 1,
                    capabilities: nrm_protocol::CapabilitySet::v1_agent(),
                }),
                expected_status: "protocol_mismatch",
                expected_force: true,
                expected_skip: false,
            },
            Case {
                name: "missing root",
                reply: AgentWorkerReply::LaunchError(RemoteAgentLaunchFailure::RootMissing),
                expected_status: "remote_root_missing",
                expected_force: false,
                expected_skip: true,
            },
            Case {
                name: "generic transport",
                reply: AgentWorkerReply::TransportError("ssh authentication failed".to_owned()),
                expected_status: "unavailable",
                expected_force: false,
                expected_skip: true,
            },
            Case {
                name: "spoofed missing",
                reply: AgentWorkerReply::TransportError(
                    "nrm-agent: not found; permission denied".to_owned(),
                ),
                expected_status: "unavailable",
                expected_force: false,
                expected_skip: true,
            },
            Case {
                name: "spoofed compatibility",
                reply: AgentWorkerReply::TransportError(format!(
                    "package version mismatch: client={} agent=9.9.9; protocol version mismatch",
                    env!("CARGO_PKG_VERSION")
                )),
                expected_status: "unavailable",
                expected_force: false,
                expected_skip: true,
            },
        ];

        for case in cases {
            let dir = tempdir().unwrap();
            let mirror = Mirror::open(Some(dir.path().join("state")), case.name).unwrap();
            let mut sidecar = test_sidecar_with_agent_reply(mirror, case.reply);
            configure_test_registry(&mut sidecar, Duration::from_secs(2));
            sidecar.agent.launch.transport = RemoteTransport::Ssh(SshTransport {
                program: PathBuf::from("definitely-not-a-real-ssh-program"),
                target: "test.example".to_owned(),
                connect_timeout_seconds: 1,
            });

            let preflight = sidecar
                .remote_agent_install_preflight(
                    &json!({
                        "automatic": true,
                        "install_path": "/tmp/nrm-test-agent"
                    }),
                    true,
                    0,
                    BootstrapDeadline::new(Duration::from_secs(2)),
                )
                .unwrap_or_else(|error| panic!("{} preflight failed: {error:#}", case.name));

            assert_eq!(
                preflight.before["agent_status"], case.expected_status,
                "{}",
                case.name
            );
            assert_eq!(
                preflight.effective_force, case.expected_force,
                "{}",
                case.name
            );
            assert_eq!(
                preflight.skip_reason.is_some(),
                case.expected_skip,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn zero_budget_registry_automatic_request_fails_before_remote_work() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().join("state")), "zero-budget-registry").unwrap();
        let mut sidecar = test_sidecar(mirror);
        configure_test_registry(&mut sidecar, Duration::ZERO);
        sidecar.agent.launch.transport = RemoteTransport::Ssh(SshTransport {
            program: PathBuf::from("definitely-not-a-real-ssh-program"),
            target: "test.example".to_owned(),
            connect_timeout_seconds: 1,
        });

        let error = sidecar
            .remote_agent_install(
                json!({
                    "automatic": true,
                    "install_path": "/tmp/nrm-test-agent"
                }),
                true,
                0,
            )
            .unwrap_err()
            .to_string();

        assert!(error.starts_with("bootstrap_timeout:"), "{error}");
        assert!(sidecar.agent.remote_backoff().is_none());
        assert!(sidecar.agent.launch.cached_remote_host_info().is_none());
        let registry = sidecar.registry_health_snapshot();
        assert_eq!(registry.state, RegistryHealthState::Error);
        assert_eq!(registry.error_code.as_deref(), Some("bootstrap_timeout"));
    }

    #[cfg(unix)]
    fn test_install_lease_ssh(directory: &Path) -> (SshTransport, PathBuf) {
        let invocation_log = directory.join("ssh-invocations");
        let fake_ssh = directory.join("fake-ssh");
        fs::write(
            &fake_ssh,
            format!(
                "#!/bin/sh\nfor last do :; done\ncase \"$last\" in *nrm-agent-install-lease*) printf L ;; *nrm-agent-stage*) printf S ;; *) printf O ;; esac >> {}\nexec sh -c \"$last\"\n",
                shell_quote(invocation_log.to_string_lossy())
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o755)).unwrap();
        (
            SshTransport {
                program: fake_ssh,
                target: "ignored.example".to_owned(),
                connect_timeout_seconds: 1,
            },
            invocation_log,
        )
    }

    #[cfg(unix)]
    fn test_prepared_posix_install(
        directory: &Path,
        target: &Path,
        ssh: SshTransport,
    ) -> PreparedAgentInstall {
        let source_path = directory.join("candidate-agent");
        let source_bytes = b"signed candidate bytes";
        fs::write(&source_path, source_bytes).unwrap();
        let source_file = File::open(&source_path).unwrap();
        let upload = source_file.try_clone().unwrap();
        let source_sha256 = sha256_bytes(source_bytes);
        let mut plan = agent_install::PosixInstallPlan::new(
            target.to_string_lossy(),
            env!("CARGO_PKG_VERSION"),
            PROTOCOL_VERSION,
            false,
        )
        .unwrap();
        plan.set_expected_sha256(&source_sha256).unwrap();
        PreparedAgentInstall {
            source: ResolvedAgentSource {
                path: source_path,
                file: source_file,
                expected_sha256: Some(source_sha256.clone()),
                details: json!({"agent_source": "registry"}),
                _registry_artifact: None,
            },
            upload,
            source_hash: blake3::hash(source_bytes).to_hex().to_string(),
            source_sha256,
            source_size: source_bytes.len() as u64,
            ssh,
            plan: PreparedAgentInstallPlan::Posix(plan),
        }
    }

    #[cfg(unix)]
    #[test]
    fn automatic_post_lease_compatible_peer_skips_and_releases_without_staging() {
        let dir = tempdir().unwrap();
        let remote_dir = dir.path().join("remote-bin");
        fs::create_dir_all(&remote_dir).unwrap();
        let target = remote_dir.join("nrm-agent");
        fs::write(&target, b"peer-installed-agent").unwrap();
        let (ssh, invocation_log) = test_install_lease_ssh(dir.path());
        let prepared = test_prepared_posix_install(dir.path(), &target, ssh.clone());
        let mirror = Mirror::open(Some(dir.path().join("state")), "post-lease-peer").unwrap();
        let mut sidecar = test_sidecar_with_agent_reply(
            mirror,
            AgentWorkerReply::Response(Response::Hello {
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: nrm_protocol::CapabilitySet::v1_agent(),
            }),
        );
        configure_test_registry(&mut sidecar, Duration::from_secs(3));
        sidecar.agent.launch.transport = RemoteTransport::Ssh(ssh);
        let preflight = AgentInstallPreflight {
            before: json!({"agent_status": "missing_agent"}),
            target_path: target.to_string_lossy().into_owned(),
            effective_force: false,
            skip_reason: None,
            automatic: true,
        };

        let result = sidecar
            .remote_agent_install_prepared(
                preflight,
                prepared,
                true,
                0,
                BootstrapDeadline::new(Duration::from_secs(3)),
            )
            .unwrap();

        assert_eq!(result["status"], "skipped");
        assert_eq!(result["automatic"], true);
        assert!(result["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("already compatible")));
        assert_eq!(fs::read(&target).unwrap(), b"peer-installed-agent");
        assert_eq!(fs::read_to_string(&invocation_log).unwrap(), "L");
        assert_eq!(
            fs::read_dir(&remote_dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            [target.file_name().unwrap().to_os_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn automatic_post_lease_probe_timeout_releases_lease_without_staging() {
        const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(3);
        const RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);

        let dir = tempdir().unwrap();
        let remote_dir = dir.path().join("remote-bin");
        fs::create_dir_all(&remote_dir).unwrap();
        let target = remote_dir.join("nrm-agent");
        let (ssh, invocation_log) = test_install_lease_ssh(dir.path());
        let prepared = test_prepared_posix_install(dir.path(), &target, ssh.clone());
        let mirror = Mirror::open(Some(dir.path().join("state")), "post-lease-timeout").unwrap();
        let mut sidecar = test_sidecar(mirror);
        // Native process startup is part of the cumulative bootstrap budget.
        // Leave enough time for a busy hosted macOS runner to reach the
        // deliberately stalled post-lease probe that this test exercises.
        configure_test_registry(&mut sidecar, BOOTSTRAP_TIMEOUT);
        let recovery_ssh = ssh.clone();
        sidecar.agent.launch.transport = RemoteTransport::Ssh(ssh);
        let (worker_tx, worker_rx) = mpsc::channel::<AgentWorkerCommand>();
        let (release_tx, release_rx) = mpsc::channel();
        let request_seen = Arc::new(AtomicBool::new(false));
        let worker_request_seen = Arc::clone(&request_seen);
        let worker_thread = thread::spawn(move || {
            if let Ok(command) = worker_rx.recv() {
                worker_request_seen.store(true, Ordering::SeqCst);
                let _ = release_rx.recv();
                drop(command);
            }
        });
        sidecar.agent.worker = Some(AgentWorker {
            tx: worker_tx,
            abort: Arc::new(TestAbortHandle::default()),
            join: None,
        });
        let preflight = AgentInstallPreflight {
            before: json!({"agent_status": "missing_agent"}),
            target_path: target.to_string_lossy().into_owned(),
            effective_force: false,
            skip_reason: None,
            automatic: true,
        };

        let request_started = Instant::now();
        let result = sidecar.remote_agent_install_prepared(
            preflight,
            prepared,
            true,
            0,
            BootstrapDeadline::new(BOOTSTRAP_TIMEOUT),
        );
        let request_elapsed = request_started.elapsed();
        sidecar.agent.kill_worker();
        let _ = release_tx.send(());
        worker_thread.join().unwrap();
        let error = result.unwrap_err();

        assert!(request_seen.load(Ordering::SeqCst));
        assert!(is_bootstrap_timeout(&error), "{error:#}");
        assert!(
            request_elapsed < BOOTSTRAP_TIMEOUT + Duration::from_millis(250),
            "bootstrap teardown exceeded its request deadline: {request_elapsed:?}"
        );
        assert_eq!(fs::read_to_string(&invocation_log).unwrap(), "L");

        // Zero-budget teardown hands the holder to a detached reaper. If
        // SIGKILL wins the race with the remote EXIT trap, the stable owner
        // record deliberately remains for the next acquisition to reap.
        let source_sha256 = sha256_bytes(b"signed candidate bytes");
        let mut recovery_plan = agent_install::PosixInstallPlan::new(
            target.to_string_lossy(),
            env!("CARGO_PKG_VERSION"),
            PROTOCOL_VERSION,
            false,
        )
        .unwrap();
        recovery_plan.set_expected_sha256(&source_sha256).unwrap();
        let recovery_token = "fedcba9876543210fedcba9876543210";
        let recovery_started = Instant::now();
        // A native process launch can be delayed on a busy hosted runner.
        // Budget every attempt cumulatively so a genuinely live stale owner
        // still fails the test without imposing an unrelated per-attempt cap.
        let (mut recovery_lease, readiness) = loop {
            let recovery_remaining = remaining_timeout_since(recovery_started, RECOVERY_TIMEOUT);
            assert!(
                !recovery_remaining.is_zero(),
                "next lease acquisition exceeded its recovery deadline"
            );
            match RemoteInstallLease::acquire(
                &recovery_ssh,
                recovery_plan.lease_command(recovery_token).unwrap(),
                None,
                recovery_remaining,
            ) {
                Ok(acquired) => break acquired,
                Err(error)
                    if error.to_string().contains("install_in_progress")
                        && recovery_started.elapsed() < RECOVERY_TIMEOUT =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("next lease acquisition did not reap stale owner: {error:#}"),
            }
        };
        recovery_plan
            .parse_lease_ready_stdout(recovery_token, &readiness)
            .unwrap();
        let release_remaining = remaining_timeout_since(recovery_started, RECOVERY_TIMEOUT);
        assert!(
            !release_remaining.is_zero(),
            "recovered lease exceeded its release deadline"
        );
        recovery_lease.release(release_remaining).unwrap();

        let lease_path = PathBuf::from(format!("{}.nrm-install-lease", target.display()));
        assert!(fs::read_dir(&remote_dir).unwrap().next().is_none());
        assert!(!lease_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn automatic_preflight_skips_unsafe_health_without_detecting_install_target() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar_with_agent_reply(
            mirror,
            AgentWorkerReply::LaunchError(RemoteAgentLaunchFailure::RootMissing),
        );
        sidecar.agent.launch.transport = RemoteTransport::Ssh(SshTransport {
            program: PathBuf::from("definitely-not-a-real-ssh-program"),
            target: "test.example".to_owned(),
            connect_timeout_seconds: 1,
        });
        sidecar.agent.launch.registry = Some(RegistryLaunchConfig {
            url_template: RegistryUrlTemplate::parse(
                "https://registry.example.test/v{version}/manifest.json",
            )
            .unwrap(),
            trusted_keys: TrustedKeySet::from_base64([(
                "release-test",
                "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
            )])
            .unwrap(),
            signature_threshold: 1,
            cache_dir: None,
            cache_max_bytes: DEFAULT_REGISTRY_CACHE_MAX_BYTES,
            timeout: Duration::from_secs(2),
            policy_fingerprint: "test-registry-policy".to_owned(),
        });

        let preflight = sidecar
            .remote_agent_install_preflight(
                &json!({"automatic": true}),
                true,
                0,
                BootstrapDeadline::new(Duration::from_secs(2)),
            )
            .unwrap();

        assert_eq!(preflight.before["agent_status"], "remote_root_missing");
        assert!(preflight
            .skip_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("left remote agent unchanged")));
        assert_eq!(preflight.target_path, "$HOME/.local/bin/unused-agent");
        assert!(sidecar
            .agent
            .launch
            .remote_host_info
            .lock()
            .unwrap()
            .is_none());
    }

    #[test]
    fn non_retryable_agent_rpc_error_does_not_poison_remote_backoff() {
        let dir = tempdir().unwrap();
        let mut client = AgentClient::new(
            "missing-agent".to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_millis(100),
            AgentInterrupt::default(),
        );

        let error = client
            .handle_worker_reply(
                AgentWorkerReply::Error(RpcError {
                    code: nrm_protocol::RpcErrorCode::Agent,
                    message: "missing file".to_string(),
                    retryable: false,
                }),
                &Request::Shutdown,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("missing file"));
        assert!(client.remote_backoff().is_none());
    }

    #[test]
    fn retryable_agent_rpc_error_sets_remote_backoff() {
        let dir = tempdir().unwrap();
        let mut client = AgentClient::new(
            "missing-agent".to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_millis(100),
            AgentInterrupt::default(),
        );

        let error = client
            .handle_worker_reply(
                AgentWorkerReply::Error(RpcError {
                    code: nrm_protocol::RpcErrorCode::Agent,
                    message: "transport reset".to_string(),
                    retryable: true,
                }),
                &Request::Shutdown,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("transport reset"));
        assert!(client.remote_backoff().is_some());
    }

    #[test]
    fn client_response_send_applies_backpressure_instead_of_dropping() {
        let (tx, rx) = mpsc::sync_channel(1);
        let first = ClientResponse {
            id: 1,
            ok: true,
            result: Some(json!({"ok": true})),
            error: None,
        };
        let second = ClientResponse {
            id: 2,
            ok: true,
            result: Some(json!({"ok": true})),
            error: None,
        };

        assert!(send_client_response(&tx, first));
        let (done_tx, done_rx) = mpsc::channel();
        let tx_for_thread = tx.clone();
        let sender = thread::spawn(move || {
            let sent = send_client_response(&tx_for_thread, second);
            done_tx.send(sent).unwrap();
        });

        assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());
        match rx.recv().unwrap() {
            ServerMessage::Response(response) => assert_eq!(response.id, 1),
            ServerMessage::Notification(_) => panic!("expected response"),
        }
        assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        sender.join().unwrap();
        match rx.recv().unwrap() {
            ServerMessage::Response(response) => assert_eq!(response.id, 2),
            ServerMessage::Notification(_) => panic!("expected response"),
        }
    }

    #[test]
    fn client_notification_serializes_as_method_params_message() {
        let message = ServerMessage::Notification(ClientNotification {
            method: "workspace/remote_health".to_string(),
            params: json!({
                "workspace_key": "workspace",
                "remote_status": "unavailable",
                "remote_checked": true,
                "remote_available": false
            }),
        });

        let value: Value = serde_json::from_str(&serde_json::to_string(&message).unwrap()).unwrap();

        assert_eq!(value["method"], "workspace/remote_health");
        assert_eq!(value["params"]["workspace_key"], "workspace");
        assert_eq!(value.get("id"), None);
    }

    #[test]
    fn optional_positive_usize_param_clamps_non_positive_values() {
        assert_eq!(
            optional_positive_usize_param(&json!({"max_files": 0}), "max_files"),
            Some(1)
        );
        assert_eq!(
            optional_positive_usize_param(&json!({"max_files": -8}), "max_files"),
            Some(1)
        );
        assert_eq!(
            optional_positive_usize_param(&json!({"max_files": 32}), "max_files"),
            Some(32)
        );
        assert_eq!(
            optional_positive_usize_param(&json!({"max_files": "bad"}), "max_files"),
            None
        );
    }

    #[test]
    fn save_upload_route_chunks_above_inline_threshold() {
        assert!(!save_should_use_chunked_upload(SAVE_INLINE_MAX_BYTES - 1));
        assert!(!save_should_use_chunked_upload(SAVE_INLINE_MAX_BYTES));
        assert!(save_should_use_chunked_upload(SAVE_INLINE_MAX_BYTES + 1));
    }

    #[test]
    fn save_upload_inline_threshold_stays_below_protocol_limit() {
        const {
            assert!(SAVE_UPLOAD_CHUNK_BYTES as u64 <= SAVE_INLINE_MAX_BYTES);
            assert!(SAVE_INLINE_MAX_BYTES < MAX_SAVE_PAYLOAD_BYTES);
        }
        assert!(save_should_use_chunked_upload(MAX_SAVE_PAYLOAD_BYTES + 1));
    }

    #[test]
    fn durable_file_helper_installs_content_and_cleans_temp() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("artifact.bin");

        write_durable_file(&path, b"one").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");

        write_durable_file(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");

        let entries = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec!["artifact.bin".to_string()]);
    }

    #[test]
    fn mirror_records_hydrated_files() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = test_meta("src/main.rs", "abc", 5);
        mirror.record_hydrated(&meta, "abc", "abc").unwrap();
        let entry = mirror.get("src/main.rs").unwrap().unwrap();
        assert_eq!(entry.relative_path, "src/main.rs");
        assert_eq!(entry.remote_hash.as_deref(), Some("abc"));
        assert_eq!(entry.state, "hydrated");
        assert_eq!(entry.validation_state, "valid");
    }

    #[test]
    fn sidecar_starts_and_serves_cache_without_agent_handshake() {
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let remote_root = remote_dir.path().join("repo");
        let key = workspace_key(&RemoteTransport::Local, &remote_root);
        let mirror = Mirror::open(Some(state_dir.path().to_path_buf()), &key).unwrap();
        let local_path = record_hydrated_content(&mirror, "src/main.rs", b"main");
        drop(mirror);

        let mut sidecar = Sidecar::new(
            remote_root,
            RemoteTransport::Local,
            state_dir
                .path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            Some(state_dir.path().to_path_buf()),
            1,
            AgentInterrupt::default(),
        )
        .unwrap();

        let hello = sidecar.handle("hello", json!({}), 0).unwrap();
        assert_eq!(hello["remote_status"], "unchecked");
        assert_eq!(hello["remote_checked"], false);
        assert_eq!(hello["remote_available"], false);

        let opened = sidecar
            .open(json!({"path": "src/main.rs", "force": false}), 0)
            .unwrap();
        assert_eq!(opened["cached"], true);
        assert_eq!(
            opened["local_path"].as_str().unwrap(),
            local_path.to_string_lossy()
        );

        let probe = sidecar.remote_probe(0);
        assert_eq!(probe["remote_status"], "unavailable");
        assert_eq!(probe["remote_checked"], true);
        assert_eq!(probe["remote_available"], false);
        assert!(probe["retry_after_ms"].as_u64().unwrap() > 0);
        let probe = sidecar.remote_probe(0);
        assert_eq!(probe["remote_status"], "unavailable");
        assert!(probe["retry_after_ms"].as_u64().unwrap() > 0);

        let error = sidecar
            .scan(json!({"limit": 1}), 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to launch agent"));
    }

    #[test]
    fn remote_probe_records_protocol_mismatch_as_unavailable_health() {
        let state_dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(state_dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar_with_agent_reply(
            mirror,
            AgentWorkerReply::Error(RpcError {
                code: nrm_protocol::RpcErrorCode::Agent,
                message: format!(
                    "protocol version mismatch: client={} agent={}",
                    PROTOCOL_VERSION,
                    PROTOCOL_VERSION + 1
                ),
                retryable: false,
            }),
        );

        let probe = sidecar.handle("remote_probe", json!({}), 0).unwrap();
        assert_eq!(probe["remote_status"], "unavailable");
        assert_eq!(probe["remote_checked"], true);
        assert_eq!(probe["remote_available"], false);
        assert_eq!(probe["agent_compatibility_failure"], "protocol_mismatch");
        assert_eq!(probe["protocol_version"], PROTOCOL_VERSION + 1);
        assert!(probe["retry_after_ms"].as_u64().unwrap() > 0);
        assert!(probe["remote_error"]
            .as_str()
            .unwrap()
            .contains("protocol version mismatch"));

        let info = sidecar.handle("workspace_info", json!({}), 0).unwrap();
        assert_eq!(info["remote_status"], "unavailable");
        assert_eq!(info["remote_health"]["remote_status"], "unavailable");
        assert!(info["remote_error"]
            .as_str()
            .unwrap()
            .contains("protocol version mismatch"));
    }

    #[test]
    fn remote_health_fast_path_retains_negotiated_agent_details() {
        let state_dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(state_dir.path().to_path_buf()), "test").unwrap();
        let capabilities = nrm_protocol::CapabilitySet::v1_agent();
        let mut sidecar = test_sidecar_with_agent_reply(
            mirror,
            AgentWorkerReply::Response(Response::Hello {
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: capabilities.clone(),
            }),
        );

        let first = sidecar.handle("remote_health", json!({}), 0).unwrap();
        let fast = sidecar.handle("remote_health", json!({}), 0).unwrap();

        for health in [&first, &fast] {
            assert_eq!(health["remote_status"], "connected");
            assert_eq!(health["agent_status"], "ok");
            assert_eq!(health["agent_version"], env!("CARGO_PKG_VERSION"));
            assert_eq!(health["protocol_version"], PROTOCOL_VERSION);
            assert_eq!(health["expected_agent_version"], env!("CARGO_PKG_VERSION"));
            assert_eq!(health["expected_protocol_version"], PROTOCOL_VERSION);
            assert_eq!(health["capabilities"], json!(capabilities));
        }
    }

    #[test]
    fn workspace_info_reports_daemon_capabilities_without_agent_handshake() {
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let remote_root = remote_dir.path().join("repo");
        let transport = RemoteTransport::from_ssh(Some("host".to_string()), 7).unwrap();
        let mut sidecar = Sidecar::new(
            remote_root.clone(),
            transport.clone(),
            state_dir
                .path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            Some(state_dir.path().to_path_buf()),
            30_000,
            AgentInterrupt::default(),
        )
        .unwrap();

        let info = sidecar.handle("workspace_info", json!({}), 0).unwrap();

        let expected_workspace_key = workspace_key(&transport, &remote_root);
        assert_eq!(
            info["workspace_key"].as_str(),
            Some(expected_workspace_key.as_str())
        );
        assert_eq!(info["transport"]["kind"], "ssh");
        assert_eq!(info["transport"]["endpoint"], "host");
        assert_eq!(info["transport"]["connect_timeout_ms"], 7000);
        assert_eq!(info["transport"]["agent_io"], "stdio");
        assert_eq!(info["transport"]["target"], "host");
        assert_eq!(info["transport"]["ssh_connect_timeout_seconds"], 7);
        assert_eq!(info["client_mode"], "single_writer");
        assert_eq!(info["client_policy"]["mode"], "single_writer");
        assert_eq!(info["client_policy"]["concurrency"], "sequential");
        assert_eq!(info["client_policy"]["write_owner"], "current_session");
        assert_eq!(info["remote_status"], "unchecked");
        assert_eq!(info["remote_health"]["remote_status"], "unchecked");
        assert_eq!(info["registry_health"]["state"], "disabled");
        assert_eq!(info["registry_health"]["source"], "local");
        assert_eq!(info["capabilities"]["server_notifications"], true);
        assert_eq!(info["capabilities"]["transport_neutral_agent_frames"], true);
        assert_eq!(info["capabilities"]["agent_abort_handle"], true);
        assert_eq!(info["capabilities"]["agent_abort_scope"], "lane_worker");
        assert_eq!(info["capabilities"]["sidecar_socket_listener"], cfg!(unix));
        assert_eq!(info["capabilities"]["single_writer_sessions"], true);
        assert!(info["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method.as_str() == Some("open")));
        assert!(info["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method.as_str() == Some("flush_queued")));
        assert!(info["public_commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method.as_str() == Some("flush")));
        assert!(!info["public_commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method.as_str() == Some("flush_queued")));
        assert!(info["internal_commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method.as_str() == Some("flush_queued")));
        let command_specs = info["command_specs"].as_array().unwrap();
        let flush_queued = command_specs
            .iter()
            .find(|command| command["name"] == "flush_queued")
            .unwrap();
        assert_eq!(flush_queued["visibility"], "internal");
        assert_eq!(flush_queued["execution"], "remote");
        assert_eq!(flush_queued["remote_lane"], "write");
        assert_eq!(flush_queued["mutates_remote"], true);
        let accept_local = command_specs
            .iter()
            .find(|command| command["name"] == "accept_local_conflict")
            .unwrap();
        assert_eq!(accept_local["visibility"], "public");
        assert_eq!(accept_local["execution"], "remote");
        assert_eq!(accept_local["remote_lane"], "write");
        assert_eq!(accept_local["mutates_remote"], true);
        let accept_remote = command_specs
            .iter()
            .find(|command| command["name"] == "accept_remote_conflict")
            .unwrap();
        assert_eq!(accept_remote["visibility"], "public");
        assert_eq!(accept_remote["execution"], "local");
        assert_eq!(accept_remote["remote_lane"], Value::Null);
        assert_eq!(accept_remote["mutates_remote"], false);
        let save_queue = command_specs
            .iter()
            .find(|command| command["name"] == "save_queue")
            .unwrap();
        assert_eq!(save_queue["visibility"], "public");
        assert_eq!(save_queue["execution"], "local");
        assert_eq!(save_queue["fast_path"], true);
        let cancel = command_specs
            .iter()
            .find(|command| command["name"] == "cancel")
            .unwrap();
        assert_eq!(cancel["visibility"], "public");
        assert_eq!(cancel["execution"], "control");
        assert_eq!(info["capabilities"]["command_metadata"], true);
        assert!(info["notifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method.as_str() == Some("workspace/remote_health")));
    }

    struct FailingRequestReader;

    impl Read for FailingRequestReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("request stream failed"))
        }
    }

    impl BufRead for FailingRequestReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("request stream failed"))
        }

        fn consume(&mut self, _amt: usize) {}
    }

    #[test]
    fn stdio_session_propagates_request_read_errors() {
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let (response_tx, _response_rx) = mpsc::sync_channel::<ServerMessage>(1);

        let error = run_server_session(
            remote_dir.path().join("repo"),
            RemoteTransport::Local,
            "missing-agent".to_string(),
            None,
            None,
            Some(state_dir.path().to_path_buf()),
            1,
            FailingRequestReader,
            response_tx,
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("failed to read sidecar request"));
    }

    #[cfg(unix)]
    #[test]
    fn listener_socket_security_creates_private_leaf_and_bound_socket() {
        let root = tempdir().unwrap();
        let parent = root.path().join("sockets");
        let directory = parent.join("nested");
        let socket = directory.join("sidecar.sock");

        prepare_listener_socket(&socket).unwrap();
        let parent_metadata = fs::symlink_metadata(&parent).unwrap();
        assert!(parent_metadata.file_type().is_dir());
        assert_eq!(parent_metadata.uid(), effective_uid());
        assert_eq!(parent_metadata.mode() & 0o7777, LISTENER_DIRECTORY_MODE);
        let directory_metadata = fs::symlink_metadata(&directory).unwrap();
        assert!(directory_metadata.file_type().is_dir());
        assert_eq!(directory_metadata.uid(), effective_uid());
        assert_eq!(directory_metadata.mode() & 0o7777, LISTENER_DIRECTORY_MODE);

        let listener = bind_secure_listener_socket(&socket).unwrap();
        let socket_metadata = fs::symlink_metadata(&socket).unwrap();
        assert!(socket_metadata.file_type().is_socket());
        assert_eq!(socket_metadata.uid(), effective_uid());
        assert_eq!(socket_metadata.mode() & 0o7777, LISTENER_SOCKET_MODE);

        drop(listener);
        fs::remove_file(socket).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn listener_socket_security_creation_is_atomic_and_never_chmods_a_raced_entry() {
        let root = tempdir().unwrap();
        secure_socket_test_directory(root.path());

        let traversal = root.path().join("missing").join("..").join("escaped");
        let error = prepare_listener_socket(&traversal.join("sidecar.sock"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not contain parent traversal"));
        assert!(!root.path().join("missing").exists());
        assert!(!root.path().join("escaped").exists());

        let shared = root.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let missing = shared.join("missing").join("leaf");
        let error = prepare_listener_socket(&missing.join("sidecar.sock"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not be group/world-writable unless sticky"));
        assert!(!shared.join("missing").exists());

        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        prepare_listener_socket(&missing.join("sidecar.sock")).unwrap();
        for component in [shared.join("missing"), missing] {
            let metadata = fs::symlink_metadata(component).unwrap();
            assert!(metadata.file_type().is_dir());
            assert_eq!(metadata.uid(), effective_uid());
            assert_eq!(metadata.mode() & 0o7777, LISTENER_DIRECTORY_MODE);
        }

        let target = root.path().join("race-target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let raced = shared.join("raced");
        std::os::unix::fs::symlink(&target, &raced).unwrap();
        let error = validate_created_listener_component(&raced, effective_uid(), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be a directory and not a symlink"));
        assert_eq!(
            fs::symlink_metadata(&target).unwrap().mode() & 0o7777,
            0o755,
            "an EEXIST race must not chmod the symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn listener_socket_security_rejects_insecure_foreign_or_symlink_leaf() {
        let root = tempdir().unwrap();
        let insecure = root.path().join("insecure");
        fs::create_dir(&insecure).unwrap();
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755)).unwrap();
        let insecure_error = prepare_listener_socket(&insecure.join("sidecar.sock"))
            .unwrap_err()
            .to_string();
        assert!(insecure_error.contains("must have mode 0700"));

        let secure = root.path().join("secure");
        fs::create_dir(&secure).unwrap();
        secure_socket_test_directory(&secure);
        let secure_metadata = fs::symlink_metadata(&secure).unwrap();
        let foreign_error = validate_listener_directory_metadata(
            &secure,
            &secure_metadata,
            secure_metadata.uid().wrapping_add(1),
        )
        .unwrap_err()
        .to_string();
        assert!(foreign_error.contains("must be owned by the current uid"));

        let link = root.path().join("linked-sockets");
        std::os::unix::fs::symlink(&secure, &link).unwrap();
        let link_error = prepare_listener_socket(&link.join("sidecar.sock"))
            .unwrap_err()
            .to_string();
        assert!(link_error.contains("must be a directory and not a symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn listener_socket_security_rejects_unsafe_lexical_and_resolved_ancestors() {
        let root = tempdir().unwrap();
        secure_socket_test_directory(root.path());

        let shared = root.path().join("shared");
        let leaf = shared.join("leaf");
        fs::create_dir_all(&leaf).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        secure_socket_test_directory(&leaf);
        let shared_error = prepare_listener_socket(&leaf.join("sidecar.sock"))
            .unwrap_err()
            .to_string();
        assert!(shared_error.contains("must not be group/world-writable unless sticky"));

        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        prepare_listener_socket(&leaf.join("sidecar.sock")).unwrap();

        let safe_target = root.path().join("safe-target");
        let safe_target_leaf = safe_target.join("leaf");
        fs::create_dir_all(&safe_target_leaf).unwrap();
        secure_socket_test_directory(&safe_target);
        secure_socket_test_directory(&safe_target_leaf);
        let unsafe_lexical = root.path().join("unsafe-lexical");
        fs::create_dir(&unsafe_lexical).unwrap();
        fs::set_permissions(&unsafe_lexical, fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&safe_target, unsafe_lexical.join("link")).unwrap();
        let lexical_error = prepare_listener_socket(&unsafe_lexical.join("link/leaf/sidecar.sock"))
            .unwrap_err()
            .to_string();
        assert!(lexical_error.contains("must not be group/world-writable unless sticky"));

        let unsafe_target = root.path().join("unsafe-target");
        let unsafe_target_leaf = unsafe_target.join("leaf");
        fs::create_dir_all(&unsafe_target_leaf).unwrap();
        fs::set_permissions(&unsafe_target, fs::Permissions::from_mode(0o777)).unwrap();
        secure_socket_test_directory(&unsafe_target_leaf);
        let safe_lexical = root.path().join("safe-lexical");
        fs::create_dir(&safe_lexical).unwrap();
        secure_socket_test_directory(&safe_lexical);
        std::os::unix::fs::symlink(&unsafe_target, safe_lexical.join("link")).unwrap();
        let resolved_error = prepare_listener_socket(&safe_lexical.join("link/leaf/sidecar.sock"))
            .unwrap_err()
            .to_string();
        assert!(resolved_error.contains("must not be group/world-writable unless sticky"));
    }

    #[cfg(unix)]
    #[test]
    fn listener_socket_security_rejects_unsafe_existing_socket_and_removes_safe_stale_socket() {
        let root = tempdir().unwrap();
        secure_socket_test_directory(root.path());
        let socket = root.path().join("sidecar.sock");

        fs::write(&socket, b"not a socket").unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(LISTENER_SOCKET_MODE)).unwrap();
        let type_error = prepare_listener_socket(&socket).unwrap_err().to_string();
        assert!(type_error.contains("must be a Unix socket and not a symlink"));
        fs::remove_file(&socket).unwrap();

        let link_target = root.path().join("link-target");
        fs::write(&link_target, b"not a socket").unwrap();
        std::os::unix::fs::symlink(&link_target, &socket).unwrap();
        let link_error = prepare_listener_socket(&socket).unwrap_err().to_string();
        assert!(link_error.contains("must be a Unix socket and not a symlink"));
        fs::remove_file(&socket).unwrap();

        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        let mode_error = prepare_listener_socket(&socket).unwrap_err().to_string();
        assert!(mode_error.contains("permissions must not exceed 0600"));
        drop(listener);
        fs::remove_file(&socket).unwrap();

        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(LISTENER_SOCKET_MODE)).unwrap();
        let live_error = prepare_listener_socket(&socket).unwrap_err().to_string();
        assert!(live_error.contains("already in use"));
        assert!(socket.exists(), "a live socket must never be removed");
        let socket_metadata = fs::symlink_metadata(&socket).unwrap();
        let foreign_error = validate_listener_socket_metadata(
            &socket,
            &socket_metadata,
            socket_metadata.uid().wrapping_add(1),
        )
        .unwrap_err()
        .to_string();
        assert!(foreign_error.contains("must be owned by the current uid"));

        drop(listener);
        fs::remove_file(&socket).unwrap();

        let stale_socket = root.path().join("stale-sidecar.sock");
        let stale_listener = UnixListener::bind(&stale_socket).unwrap();
        fs::set_permissions(
            &stale_socket,
            fs::Permissions::from_mode(LISTENER_SOCKET_MODE),
        )
        .unwrap();
        drop(stale_listener);
        prepare_listener_socket(&stale_socket).unwrap();
        assert!(!stale_socket.exists());
    }

    #[cfg(unix)]
    #[test]
    fn socket_listener_accepts_sequential_sessions() {
        let socket_dir = tempdir().unwrap();
        secure_socket_test_directory(socket_dir.path());
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let socket = socket_dir.path().join("sidecar.sock");
        let remote_root = remote_dir.path().join("repo");
        let listener_socket = socket.clone();
        let listener_state = state_dir.path().to_path_buf();
        let listener_root = remote_root.clone();
        let listener = thread::spawn(move || {
            run_listener(
                listener_socket,
                listener_root,
                RemoteTransport::Local,
                "missing-agent".to_string(),
                None,
                None,
                Some(listener_state),
                1,
            )
        });

        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(socket.exists());
        assert_eq!(
            fs::symlink_metadata(&socket).unwrap().mode() & 0o7777,
            LISTENER_SOCKET_MODE
        );

        fn connect_socket(socket: &Path) -> UnixStream {
            for _ in 0..100 {
                if let Ok(stream) = UnixStream::connect(socket) {
                    return stream;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("timed out connecting to {}", socket.display());
        }

        fn request(stream: &mut UnixStream, id: u64, method: &str) -> Value {
            writeln!(
                stream,
                "{}",
                json!({
                    "id": id,
                    "method": method,
                    "params": {}
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        }

        let mut first = connect_socket(&socket);
        let first_info = request(&mut first, 1, "workspace_info");
        assert_eq!(first_info["id"], 1);
        assert_eq!(first_info["ok"], true);
        assert_eq!(
            first_info["result"]["remote_root"].as_str(),
            Some(remote_root.to_string_lossy().as_ref())
        );
        let first_disconnect = request(&mut first, 2, "disconnect");
        assert_eq!(first_disconnect["id"], 2);
        assert_eq!(first_disconnect["ok"], true);
        drop(first);

        let mut second = connect_socket(&socket);
        let second_info = request(&mut second, 1, "workspace_info");
        assert_eq!(second_info["id"], 1);
        assert_eq!(second_info["ok"], true);
        let shutdown = request(&mut second, 2, "shutdown");
        assert_eq!(shutdown["id"], 2);
        assert_eq!(shutdown["ok"], true);
        drop(second);

        listener.join().unwrap().unwrap();
        assert!(!socket.exists());
    }

    #[cfg(unix)]
    #[test]
    fn socket_listener_interrupts_active_request_on_client_eof() {
        let socket_dir = tempdir().unwrap();
        secure_socket_test_directory(socket_dir.path());
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let agent_dir = tempdir().unwrap();
        let socket = socket_dir.path().join("sidecar.sock");
        let remote_root = remote_dir.path().join("repo");
        let agent = agent_dir.path().join("stall-agent");
        let marker = agent_dir.path().join("started");
        fs::write(
            &agent,
            format!(
                "#!/bin/sh\n: > {}\nsleep 30\n",
                shell_quote(marker.to_string_lossy())
            ),
        )
        .unwrap();
        let mut perms = fs::metadata(&agent).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&agent, perms).unwrap();

        let listener_socket = socket.clone();
        let listener_state = state_dir.path().to_path_buf();
        let listener_root = remote_root;
        let listener_agent = agent.to_string_lossy().to_string();
        let listener = thread::spawn(move || {
            run_listener(
                listener_socket,
                listener_root,
                RemoteTransport::Local,
                listener_agent,
                None,
                None,
                Some(listener_state),
                30_000,
            )
        });

        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(socket.exists());

        let mut first = UnixStream::connect(&socket).unwrap();
        writeln!(
            first,
            "{}",
            json!({
                "id": 1,
                "method": "scan",
                "params": {"limit": 1}
            })
        )
        .unwrap();
        first.flush().unwrap();
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists());
        drop(first);

        let mut second = None;
        for _ in 0..100 {
            match UnixStream::connect(&socket) {
                Ok(stream) => {
                    second = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        let mut second = second.expect("listener did not accept a second session after EOF");
        writeln!(
            second,
            "{}",
            json!({
                "id": 2,
                "method": "shutdown",
                "params": {}
            })
        )
        .unwrap();
        second.flush().unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(second);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let shutdown: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(shutdown["id"], 2);
        assert_eq!(shutdown["ok"], true);

        listener.join().unwrap().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn socket_listener_interrupts_active_write_request_on_client_eof() {
        let socket_dir = tempdir().unwrap();
        secure_socket_test_directory(socket_dir.path());
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let agent_dir = tempdir().unwrap();
        let socket = socket_dir.path().join("sidecar.sock");
        let remote_root = remote_dir.path().join("repo");
        let transport = RemoteTransport::Local;
        let key = workspace_key(&transport, &remote_root);
        let mirror = Mirror::open(Some(state_dir.path().to_path_buf()), &key).unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base");
        mirror
            .enqueue_save(
                "a.txt",
                &hash_bytes(b"local"),
                Some(&hash_bytes(b"base")),
                b"local",
            )
            .unwrap();
        drop(mirror);

        let agent = agent_dir.path().join("stall-agent");
        let marker = agent_dir.path().join("started");
        fs::write(
            &agent,
            format!(
                "#!/bin/sh\n: > {}\nsleep 30\n",
                shell_quote(marker.to_string_lossy())
            ),
        )
        .unwrap();
        let mut perms = fs::metadata(&agent).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&agent, perms).unwrap();

        let listener_socket = socket.clone();
        let listener_state = state_dir.path().to_path_buf();
        let listener_root = remote_root;
        let listener_agent = agent.to_string_lossy().to_string();
        let listener = thread::spawn(move || {
            run_listener(
                listener_socket,
                listener_root,
                transport,
                listener_agent,
                None,
                None,
                Some(listener_state),
                30_000,
            )
        });

        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(socket.exists());

        let mut first = UnixStream::connect(&socket).unwrap();
        writeln!(
            first,
            "{}",
            json!({
                "id": 1,
                "method": "flush_queue",
                "params": {"limit": 1}
            })
        )
        .unwrap();
        first.flush().unwrap();
        for _ in 0..100 {
            if marker.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists());
        drop(first);

        let mut second = None;
        for _ in 0..100 {
            match UnixStream::connect(&socket) {
                Ok(stream) => {
                    second = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        let mut second =
            second.expect("listener did not accept a second session after write-lane EOF");
        writeln!(
            second,
            "{}",
            json!({
                "id": 2,
                "method": "shutdown",
                "params": {}
            })
        )
        .unwrap();
        second.flush().unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(second);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let shutdown: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(shutdown["id"], 2);
        assert_eq!(shutdown["ok"], true);

        listener.join().unwrap().unwrap();
    }

    #[test]
    fn sidecar_command_metadata_covers_implemented_commands() {
        let commands = sidecar_commands();
        let command_set: HashSet<_> = commands.iter().copied().collect();
        let specs: HashSet<_> = SIDECAR_COMMAND_SPECS
            .iter()
            .map(|command| command.name)
            .collect();
        assert_eq!(commands.len(), command_set.len());
        assert_eq!(specs, command_set);

        let public = sidecar_commands_by_visibility("public");
        let internal = sidecar_commands_by_visibility("internal");
        let public_set: HashSet<_> = public.iter().copied().collect();
        let internal_set: HashSet<_> = internal.iter().copied().collect();
        let partition: HashSet<_> = public_set.union(&internal_set).copied().collect();
        assert!(public_set.is_disjoint(&internal_set));
        assert_eq!(partition, command_set);
        assert!(public.contains(&"flush"));
        assert!(!public.contains(&"flush_queued"));
        assert!(public.contains(&"cancel"));
        assert_eq!(internal, vec!["flush_queued"]);

        for command in SIDECAR_COMMAND_SPECS {
            assert!(matches!(command.visibility, "public" | "internal"));
            assert!(matches!(
                command.execution,
                "local" | "remote" | "hybrid" | "control"
            ));
            assert!(matches!(
                command.remote_lane,
                None | Some("read") | Some("write") | Some("read_or_write")
            ));
            assert_eq!(
                command.remote_lane.is_some(),
                matches!(command.execution, "remote" | "hybrid")
            );
            if command.mutates_remote {
                assert_eq!(command.remote_lane, Some("write"));
            }
        }
    }

    #[test]
    fn sidecar_git_diff_maps_json_params_to_agent_request() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar_with_git_request(
            mirror,
            |request| match request {
                Request::GitDiff {
                    path,
                    cached,
                    max_output_bytes,
                } => {
                    assert_eq!(path.as_deref(), Some("src/main.rs"));
                    assert!(cached);
                    assert_eq!(max_output_bytes, 7);
                }
                other => panic!("unexpected request: {other:?}"),
            },
            Response::Git {
                output: nrm_protocol::GitCommandOutput {
                    stdout: "diff".to_string(),
                    stderr: String::new(),
                    status_code: Some(0),
                    truncated: false,
                },
            },
        );

        let result = sidecar
            .handle(
                "git_diff",
                json!({"path": "src/./main.rs", "cached": true, "max_output_bytes": 7}),
                0,
            )
            .unwrap();

        assert_eq!(result["stdout"], "diff");
        assert_eq!(result["status_code"], 0);
        assert_eq!(result["truncated"], false);
    }

    #[test]
    fn sidecar_git_status_maps_path_filters() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar_with_git_request(
            mirror,
            |request| match request {
                Request::GitStatus {
                    paths,
                    max_output_bytes,
                } => {
                    assert_eq!(
                        paths,
                        vec!["src/main.rs".to_string(), "README.md".to_string()]
                    );
                    assert_eq!(max_output_bytes, DEFAULT_GIT_OUTPUT_MAX_BYTES);
                }
                other => panic!("unexpected request: {other:?}"),
            },
            Response::Git {
                output: nrm_protocol::GitCommandOutput {
                    stdout: " M src/main.rs\n".to_string(),
                    stderr: String::new(),
                    status_code: Some(0),
                    truncated: false,
                },
            },
        );

        let result = sidecar
            .handle(
                "git_status",
                json!({"paths": ["src/./main.rs", "README.md"]}),
                0,
            )
            .unwrap();

        assert!(result["stdout"].as_str().unwrap().contains("src/main.rs"));
    }

    #[test]
    fn sidecar_git_rejects_bad_paths_before_agent_request() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar(mirror);

        let status = sidecar
            .handle("git_status", json!({"paths": ["../outside"]}), 0)
            .unwrap_err()
            .to_string();
        assert!(
            status.contains("path must") && (status.contains("relative") || status.contains("..")),
            "{status}"
        );

        let blame = sidecar
            .handle("git_blame", json!({"path": "/outside"}), 0)
            .unwrap_err()
            .to_string();
        assert!(
            blame.contains("path") && blame.contains("relative"),
            "{blame}"
        );
    }

    #[test]
    fn agent_interrupt_uses_registered_abort_handle() {
        let interrupt = AgentInterrupt::default();
        let handle = Arc::new(TestAbortHandle::default());
        let handle_trait: Arc<dyn AgentAbortHandle> = handle.clone();

        interrupt.set_abort_handle(Arc::clone(&handle_trait));
        assert!(interrupt.has_current_abort());

        interrupt.kill_current();

        assert!(handle.aborts.load(Ordering::SeqCst) >= 1);
        assert_eq!(handle.waits.load(Ordering::SeqCst), 0);

        interrupt.clear_abort_handle(&handle_trait);
        assert!(!interrupt.has_current_abort());
    }

    #[test]
    fn agent_interrupt_aborts_handle_registered_after_shutdown() {
        let interrupt = AgentInterrupt::default();
        let handle = Arc::new(TestAbortHandle::default());
        let handle_trait: Arc<dyn AgentAbortHandle> = handle.clone();

        interrupt.request_shutdown();
        interrupt.set_abort_handle(Arc::clone(&handle_trait));

        assert_eq!(handle.aborts.load(Ordering::SeqCst), 1);
        assert!(interrupt.has_current_abort());
        interrupt.clear_abort_handle(&handle_trait);
        assert!(!interrupt.has_current_abort());
    }

    #[test]
    fn agent_interrupt_aborts_late_handle_after_shutdown_misses_locked_registry() {
        let interrupt = AgentInterrupt::default();
        let registry_guard = interrupt.current_abort.lock().unwrap();

        // request_shutdown() uses a nonblocking snapshot so it cannot see a
        // handle registered while another path temporarily owns this lock.
        interrupt.request_shutdown();
        drop(registry_guard);

        let handle = Arc::new(TestAbortHandle::default());
        let handle_trait: Arc<dyn AgentAbortHandle> = handle.clone();
        interrupt.set_abort_handle(Arc::clone(&handle_trait));

        assert_eq!(handle.aborts.load(Ordering::SeqCst), 1);
        interrupt.clear_abort_handle(&handle_trait);
        assert!(!interrupt.has_current_abort());
    }

    #[test]
    fn agent_interrupt_abort_and_wait_reaps_registered_worker() {
        let interrupt = AgentInterrupt::default();
        let handle = Arc::new(TestAbortHandle::default());
        let handle_trait: Arc<dyn AgentAbortHandle> = handle.clone();
        interrupt.set_abort_handle(handle_trait);

        interrupt
            .kill_current_and_wait(Duration::from_secs(1), "test worker exit")
            .unwrap();

        assert_eq!(handle.aborts.load(Ordering::SeqCst), 1);
        assert!(handle.waits.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn agent_interrupt_stalled_abort_respects_wait_budget() {
        let interrupt = AgentInterrupt::default();
        let handle = Arc::new(TestAbortHandle::default());
        handle.stopped.store(false, Ordering::SeqCst);
        let handle_trait: Arc<dyn AgentAbortHandle> = handle.clone();
        interrupt.set_abort_handle(Arc::clone(&handle_trait));

        let started = Instant::now();
        let error = interrupt
            .kill_current_and_wait(Duration::from_millis(20), "stalled test worker")
            .unwrap_err();

        assert!(error
            .downcast_ref::<AgentWorkerExitTimeoutError>()
            .is_some());
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(handle.aborts.load(Ordering::SeqCst) >= 1);
        interrupt.clear_abort_handle(&handle_trait);
    }

    #[test]
    fn agent_interrupt_keeps_replacement_when_stale_handle_clears() {
        let interrupt = AgentInterrupt::default();
        let stale = Arc::new(TestAbortHandle::default());
        let current = Arc::new(TestAbortHandle::default());
        let stale_trait: Arc<dyn AgentAbortHandle> = stale.clone();
        let current_trait: Arc<dyn AgentAbortHandle> = current.clone();

        interrupt.set_abort_handle(Arc::clone(&stale_trait));
        interrupt.set_abort_handle(Arc::clone(&current_trait));
        interrupt.clear_abort_handle(&stale_trait);

        assert!(interrupt.has_current_abort());
        interrupt.kill_current();

        assert_eq!(stale.aborts.load(Ordering::SeqCst), 0);
        assert_eq!(current.aborts.load(Ordering::SeqCst), 1);

        interrupt.clear_abort_handle(&current_trait);
        assert!(!interrupt.has_current_abort());
    }

    #[test]
    fn agent_client_kill_worker_aborts_and_waits_via_handle() {
        let handle = Arc::new(TestAbortHandle::default());
        let handle_trait: Arc<dyn AgentAbortHandle> = handle.clone();
        let (tx, _rx) = mpsc::channel();
        let mut client = AgentClient::new(
            "unused-agent".to_string(),
            None,
            RemoteTransport::Local,
            PathBuf::from("/unused"),
            Duration::from_secs(1),
            AgentInterrupt::default(),
        );
        client.worker = Some(AgentWorker {
            tx,
            abort: handle_trait,
            join: None,
        });
        client.handshake_complete = true;

        client.kill_worker();

        assert!(client.worker.is_none());
        assert!(!client.handshake_complete);
        assert!(handle.aborts.load(Ordering::SeqCst) >= 1);
        assert!(handle.waits.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn agent_client_worker_join_is_bounded_and_remains_tracked() {
        let handle = Arc::new(TestAbortHandle::default());
        let handle_trait: Arc<dyn AgentAbortHandle> = handle.clone();
        let (tx, _rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            let _ = release_rx.recv();
        });
        let mut client = AgentClient::new(
            "unused-agent".to_string(),
            None,
            RemoteTransport::Local,
            PathBuf::from("/unused"),
            Duration::from_secs(1),
            AgentInterrupt::default(),
        );
        client.worker = Some(AgentWorker {
            tx,
            abort: handle_trait,
            join: Some(join),
        });

        let started = Instant::now();
        let error = client
            .kill_worker_with_timeout(Duration::from_millis(20), "stalled join test")
            .unwrap_err();

        assert!(error
            .downcast_ref::<AgentWorkerExitTimeoutError>()
            .is_some());
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(client.retired_workers.len(), 1);
        release_tx.send(()).unwrap();
        client
            .kill_worker_with_timeout(Duration::from_secs(1), "released join test")
            .unwrap();
        assert!(client.retired_workers.is_empty());
    }

    #[test]
    fn shared_worker_generation_discards_idle_lane_workers_after_replacement() {
        let read_handle = Arc::new(TestAbortHandle::default());
        let write_handle = Arc::new(TestAbortHandle::default());
        let (read_tx, _read_rx) = mpsc::channel();
        let (write_tx, _write_rx) = mpsc::channel();
        let mut read = AgentClient::new(
            "definitely-missing-agent".to_string(),
            None,
            RemoteTransport::Local,
            PathBuf::from("/unused"),
            Duration::from_millis(10),
            AgentInterrupt::default(),
        );
        let mut write = read.clone_for_lane(AgentInterrupt::default());
        read.worker = Some(AgentWorker {
            tx: read_tx,
            abort: read_handle.clone(),
            join: None,
        });
        write.worker = Some(AgentWorker {
            tx: write_tx,
            abort: write_handle.clone(),
            join: None,
        });

        read.invalidate_shared_workers();
        assert!(write.ensure_worker(Duration::from_millis(10)).is_err());

        assert!(read_handle.aborts.load(Ordering::SeqCst) >= 1);
        assert!(read_handle.waits.load(Ordering::SeqCst) >= 1);
        assert!(write_handle.aborts.load(Ordering::SeqCst) >= 1);
        assert!(write_handle.waits.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn sidecar_remote_health_notification_reports_workspace_state() {
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let remote_root = remote_dir.path().join("repo");
        let mut sidecar = Sidecar::new(
            remote_root.clone(),
            RemoteTransport::Local,
            state_dir
                .path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            Some(state_dir.path().to_path_buf()),
            1,
            AgentInterrupt::default(),
        )
        .unwrap();

        let probe = sidecar.handle("remote_probe", json!({}), 0).unwrap();
        let notification = sidecar.remote_health_notification();
        let expected_workspace_key = workspace_key(&RemoteTransport::Local, &remote_root);
        let expected_remote_root = remote_root.to_string_lossy().to_string();

        assert_eq!(probe["remote_status"], "unavailable");
        assert_eq!(notification.method, "workspace/remote_health");
        assert_eq!(
            notification.params["workspace_key"].as_str(),
            Some(expected_workspace_key.as_str())
        );
        assert_eq!(
            notification.params["remote_root"].as_str(),
            Some(expected_remote_root.as_str())
        );
        assert_eq!(notification.params["remote_status"], "unavailable");
        assert_eq!(notification.params["remote_checked"], true);
        assert_eq!(notification.params["remote_available"], false);
        assert_eq!(notification.params["registry_health"]["state"], "disabled");
        assert_eq!(notification.params["registry_health"]["source"], "local");
        assert!(notification.params["retry_after_ms"].as_u64().unwrap() > 0);
    }

    #[test]
    fn metadata_scan_does_not_move_hydrated_base_hash() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .record_hydrated(&test_meta("src/main.rs", "opened", 6), "opened", "opened")
            .unwrap();

        mirror
            .upsert_metadata(&test_meta("src/main.rs", "remote-newer", 12), "metadata")
            .unwrap();

        let entry = mirror.get("src/main.rs").unwrap().unwrap();
        assert_eq!(entry.remote_hash.as_deref(), Some("opened"));
        assert_eq!(entry.state, "hydrated");
    }

    #[test]
    fn background_scan_cursor_persists_across_mirror_reopen() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mirror_root = mirror.root().to_path_buf();

        assert_eq!(mirror.background_scan_cursor().unwrap(), None);
        assert_eq!(mirror.background_scan_completed_at_ms().unwrap(), None);
        mirror
            .set_background_scan_cursor(Some("src/lib.rs"))
            .unwrap();
        mirror
            .set_background_scan_completed_at_ms(Some(12345))
            .unwrap();
        drop(mirror);

        let reopened = Mirror::open_root(mirror_root.clone()).unwrap();
        assert_eq!(
            reopened.background_scan_cursor().unwrap().as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(
            reopened.background_scan_completed_at_ms().unwrap(),
            Some(12345)
        );
        reopened.set_background_scan_cursor(None).unwrap();
        reopened.set_background_scan_completed_at_ms(None).unwrap();
        drop(reopened);

        let reopened = Mirror::open_root(mirror_root).unwrap();
        assert_eq!(reopened.background_scan_cursor().unwrap(), None);
        assert_eq!(reopened.background_scan_completed_at_ms().unwrap(), None);
    }

    #[test]
    fn resumable_scan_uses_persisted_cursor_and_tracks_progress() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .set_background_scan_cursor(Some("src/lib.rs"))
            .unwrap();
        let sidecar = test_sidecar(mirror);

        assert_eq!(
            sidecar
                .scan_after_param(&json!({"resume": true}), true)
                .unwrap()
                .as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(sidecar.scan_after_param(&json!({}), false).unwrap(), None);
        assert_eq!(
            sidecar
                .scan_after_param(&json!({"resume": true, "after": "./README.md"}), true)
                .unwrap()
                .as_deref(),
            Some("README.md")
        );

        sidecar
            .record_scan_progress(true, true, Some("src/main.rs"))
            .unwrap();
        assert_eq!(
            sidecar.mirror.background_scan_cursor().unwrap().as_deref(),
            Some("src/main.rs")
        );
        let status = sidecar.mirror.status().unwrap();
        assert_eq!(status["background_scan_state"], "in_progress");
        assert_eq!(status["background_scan_cursor"], "src/main.rs");
        assert_eq!(status["background_scan_completed_at_ms"], Value::Null);
        assert_eq!(
            sidecar.mirror.background_scan_completed_at_ms().unwrap(),
            None
        );
        sidecar.record_scan_progress(true, true, None).unwrap();
        assert_eq!(
            sidecar.mirror.background_scan_cursor().unwrap().as_deref(),
            Some("src/main.rs")
        );
        sidecar
            .record_scan_progress(false, true, Some("ignored.rs"))
            .unwrap();
        assert_eq!(
            sidecar.mirror.background_scan_cursor().unwrap().as_deref(),
            Some("src/main.rs")
        );
        sidecar.record_scan_progress(true, false, None).unwrap();
        assert_eq!(sidecar.mirror.background_scan_cursor().unwrap(), None);
        assert!(
            sidecar
                .mirror
                .background_scan_completed_at_ms()
                .unwrap()
                .unwrap()
                > 0
        );
        let status = sidecar.mirror.status().unwrap();
        assert_eq!(status["background_scan_state"], "completed");
        assert_eq!(status["background_scan_cursor"], Value::Null);
        assert!(status["background_scan_completed_at_ms"].as_i64().unwrap() > 0);
    }

    #[test]
    fn completed_resumable_scan_skips_until_rescan_interval_expires() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let mut sidecar = test_sidecar(mirror);
        sidecar.agent.launch.agent = dir
            .path()
            .join("missing-agent")
            .to_string_lossy()
            .to_string();
        sidecar.record_scan_progress(true, false, None).unwrap();

        let skipped = sidecar
            .scan(json!({"resume": true, "rescan_after_ms": 60_000}), 0)
            .unwrap();
        assert_eq!(skipped["skipped"], true);
        assert_eq!(skipped["skip_reason"], "background scan completed recently");
        assert_eq!(skipped["entries"].as_array().unwrap().len(), 0);
        assert_eq!(skipped["truncated"], false);
        assert!(skipped["rescan_due_in_ms"].as_u64().unwrap() <= 60_000);

        let error = sidecar
            .scan(json!({"resume": true, "rescan_after_ms": 0}), 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to launch agent"));
    }

    #[test]
    fn grep_cache_searches_hydrated_and_dirty_local_files() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "src/main.rs", b"fn cached_hit() {}\n");

        mirror
            .record_hydrated(&test_meta("src/dirty.rs", "base", 4), "base", "base")
            .unwrap();
        let dirty_path = mirror.local_path("src/dirty.rs").unwrap();
        fs::write(&dirty_path, b"fn dirty_hit() {}\n").unwrap();
        let dirty_hash = hash_bytes(b"fn dirty_hit() {}\n");
        mirror
            .enqueue_save(
                "src/dirty.rs",
                &dirty_hash,
                Some("base"),
                b"fn dirty_hit() {}\n",
            )
            .unwrap();

        record_hydrated_content(&mirror, "src/binary.rs", b"\xff\x00hit");

        let result = mirror
            .grep_cache(&json!({"query": "hit", "limit": 10}))
            .unwrap();
        let hits = result["hits"].as_array().unwrap();

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0]["path"], "src/dirty.rs");
        assert_eq!(hits[0]["dirty"], true);
        assert_eq!(
            hits[0]["local_path"].as_str().unwrap(),
            dirty_path.to_string_lossy().as_ref()
        );
        assert_eq!(hits[1]["path"], "src/main.rs");
        assert_eq!(hits[1]["dirty"], false);
        assert_eq!(result["searched_files"], 2);
        assert_eq!(result["truncated"], false);
    }

    #[test]
    fn grep_cache_respects_hit_limit() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.rs", b"hit one\nhit two\n");

        let result = mirror
            .grep_cache(&json!({"query": "hit", "limit": 1}))
            .unwrap();
        let hits = result["hits"].as_array().unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(result["truncated"], true);
    }

    #[test]
    fn grep_cache_reports_file_limit_truncation() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.rs", b"no match\n");
        record_hydrated_content(&mirror, "b.rs", b"hit beyond cutoff\n");

        let result = mirror
            .grep_cache(&json!({"query": "hit", "limit": 10, "max_files": 1}))
            .unwrap();
        let hits = result["hits"].as_array().unwrap();

        assert!(hits.is_empty());
        assert_eq!(result["searched_files"], 1);
        assert_eq!(result["max_files"], 1);
        assert_eq!(result["truncated"], true);
    }

    #[test]
    fn grep_cache_rebuilds_missing_search_index_after_reopen() {
        let dir = tempdir().unwrap();
        {
            let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
            record_hydrated_content(&mirror, "src/main.rs", b"fn reopened_hit() {}\n");
        }
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();

        let result = mirror
            .grep_cache(&json!({"query": "reopened_hit", "limit": 10}))
            .unwrap();

        let hits = result["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["path"], "src/main.rs");
        assert_eq!(result["indexed_files"], 1);
        let indexed: i64 = mirror
            .db
            .query_row(
                "SELECT COUNT(*) FROM search_files WHERE index_state='ready'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexed, 1);
    }

    #[test]
    fn grep_cache_refreshes_index_for_dirty_save_bytes() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "src/main.rs", b"fn old() {}\n");
        let dirty_content = b"fn dirty_index_hit() {}\n";
        fs::write(&local_path, dirty_content).unwrap();
        let dirty_hash = hash_bytes(dirty_content);

        mirror
            .enqueue_save("src/main.rs", &dirty_hash, Some("base"), dirty_content)
            .unwrap();
        let result = mirror
            .grep_cache(&json!({"query": "dirty_index_hit", "limit": 10}))
            .unwrap();

        let hits = result["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["path"], "src/main.rs");
        assert_eq!(hits[0]["dirty"], true);
        assert_eq!(result["indexed_files"], 1);
    }

    #[test]
    fn grep_cache_reindexes_out_of_band_edit_before_searching() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "src/main.rs", b"fn base() {}\n");
        let _ = mirror
            .grep_cache(&json!({"query": "base", "limit": 10}))
            .unwrap();
        fs::write(&local_path, b"fn out_of_band_hit() {}\n").unwrap();

        let result = mirror
            .grep_cache(&json!({"query": "out_of_band_hit", "limit": 10}))
            .unwrap();

        let hits = result["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["path"], "src/main.rs");
        assert_eq!(hits[0]["dirty"], true);
        assert_eq!(mirror.pending_save_count().unwrap(), 1);
        assert_eq!(result["indexed_files"], 1);
    }

    #[test]
    fn grep_cache_preserves_literal_byte_columns_from_index() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "unicode.rs", "å%_Hit\n".as_bytes());

        let result = mirror
            .grep_cache(&json!({"query": "%_Hit", "limit": 10}))
            .unwrap();

        let hits = result["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["column"], 3);
        assert_eq!(hits[0]["text"], "å%_Hit");
        let miss = mirror
            .grep_cache(&json!({"query": "%_hit", "limit": 10}))
            .unwrap();
        assert!(miss["hits"].as_array().unwrap().is_empty());
    }

    #[test]
    fn grep_cache_skips_indexed_hit_when_file_cap_excludes_it() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "large.rs", b"hit beyond tiny cap\n");
        let _ = mirror
            .grep_cache(&json!({"query": "hit", "limit": 10}))
            .unwrap();

        let result = mirror
            .grep_cache(&json!({"query": "hit", "limit": 10, "max_file_bytes": 1}))
            .unwrap();

        assert!(result["hits"].as_array().unwrap().is_empty());
        assert_eq!(result["skipped_files"], 1);
        assert_eq!(result["truncated"], true);
    }

    #[test]
    fn grep_cache_falls_back_for_mixed_invalid_utf8_files() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "mixed.bin", b"hit before invalid\n\xff");

        let result = mirror
            .grep_cache(&json!({"query": "hit", "limit": 10}))
            .unwrap();

        let hits = result["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["path"], "mixed.bin");
        assert_eq!(hits[0]["text"], "hit before invalid");
        assert_eq!(result["legacy_files"], 1);
        assert_eq!(result["skipped_files"], 1);
    }

    #[test]
    fn remote_grep_paths_skip_dirty_and_stale_mirror_entries() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let clean_path = record_hydrated_content(&mirror, "clean.rs", b"hit clean\n");

        mirror
            .record_hydrated(&test_meta("dirty.rs", "base", 1), "base", "base")
            .unwrap();
        let dirty_path = mirror.local_path("dirty.rs").unwrap();
        fs::write(&dirty_path, b"hit dirty\n").unwrap();
        let dirty_hash = hash_bytes(b"hit dirty\n");
        mirror
            .enqueue_save("dirty.rs", &dirty_hash, Some("base"), b"hit dirty\n")
            .unwrap();

        record_hydrated_content(&mirror, "stale.rs", b"hit stale\n");
        mirror
            .record_validation("stale.rs", "stale", Some("new"), None)
            .unwrap();

        let sidecar = test_sidecar(mirror);
        let hits = sidecar
            .grep_hits_with_local_paths(vec![
                nrm_protocol::SearchHit {
                    path: "clean.rs".to_string(),
                    line: 1,
                    column: 1,
                    text: "hit clean".to_string(),
                },
                nrm_protocol::SearchHit {
                    path: "dirty.rs".to_string(),
                    line: 1,
                    column: 1,
                    text: "hit dirty".to_string(),
                },
                nrm_protocol::SearchHit {
                    path: "stale.rs".to_string(),
                    line: 1,
                    column: 1,
                    text: "hit stale".to_string(),
                },
            ])
            .unwrap();

        assert_eq!(
            hits[0]["local_path"].as_str().unwrap(),
            clean_path.to_string_lossy().as_ref()
        );
        assert!(hits[1]["local_path"].is_null());
        assert!(hits[2]["local_path"].is_null());
    }

    #[test]
    fn queued_saves_keep_exact_snapshots_and_chain_expected_hashes() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = test_meta("src/main.rs", "base", 3);
        mirror.record_hydrated(&meta, "base", "base").unwrap();

        let first_content = b"one";
        let first_hash = hash_bytes(first_content);
        let first = mirror
            .enqueue_save("src/main.rs", &first_hash, Some("base"), first_content)
            .unwrap();
        let second_content = b"two";
        let second_hash = hash_bytes(second_content);
        let second = mirror
            .enqueue_save("src/main.rs", &second_hash, Some("base"), second_content)
            .unwrap();

        assert_eq!(first.expected_hash.as_deref(), Some("base"));
        assert_eq!(second.expected_hash.as_deref(), Some(first_hash.as_str()));
        assert_eq!(fs::read(&first.snapshot_path).unwrap(), first_content);
        assert_eq!(fs::read(&second.snapshot_path).unwrap(), second_content);

        mirror
            .mark_save_applied(first.id, "src/main.rs", &first_hash, 3, 20)
            .unwrap();
        let entry = mirror.get("src/main.rs").unwrap().unwrap();
        assert!(entry.dirty);
        assert_eq!(entry.remote_hash.as_deref(), Some(first_hash.as_str()));
        assert_eq!(entry.local_hash.as_deref(), Some(second_hash.as_str()));

        mirror
            .mark_save_applied(second.id, "src/main.rs", &second_hash, 3, 30)
            .unwrap();
        let entry = mirror.get("src/main.rs").unwrap().unwrap();
        assert!(!entry.dirty);
        assert_eq!(entry.remote_hash.as_deref(), Some(second_hash.as_str()));
        assert_eq!(entry.local_hash.as_deref(), Some(second_hash.as_str()));
    }

    #[test]
    fn unreplayable_save_rows_do_not_chain_new_snapshots() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let base_hash = hash_bytes(b"base");
        let lost_hash = hash_bytes(b"lost local edit");
        insert_unreplayable_save(
            &mirror,
            "a.txt",
            Some(base_hash.as_str()),
            &lost_hash,
            "pending",
        );
        fs::write(&local_path, b"resolved").unwrap();

        let queued = mirror.enqueue_local_save("a.txt").unwrap();

        assert_eq!(queued.expected_hash.as_deref(), Some(base_hash.as_str()));
        assert_ne!(queued.expected_hash.as_deref(), Some(lost_hash.as_str()));
    }

    #[test]
    fn applied_save_ignores_unreplayable_rows_when_cleaning_dirty_state() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base");
        let base_hash = hash_bytes(b"base");
        let lost_hash = hash_bytes(b"lost local edit");
        insert_unreplayable_save(
            &mirror,
            "a.txt",
            Some(base_hash.as_str()),
            &lost_hash,
            "pending",
        );
        let resolved_hash = hash_bytes(b"resolved");
        let queued = mirror
            .enqueue_save(
                "a.txt",
                &resolved_hash,
                Some(base_hash.as_str()),
                b"resolved",
            )
            .unwrap();

        mirror
            .mark_save_applied(queued.id, "a.txt", &resolved_hash, 8, 42)
            .unwrap();

        assert_eq!(mirror.pending_save_count().unwrap(), 0);
        let entry = mirror.get("a.txt").unwrap().unwrap();
        assert!(!entry.dirty);
        assert_eq!(entry.remote_hash.as_deref(), Some(resolved_hash.as_str()));
        assert_eq!(entry.local_hash.as_deref(), Some(resolved_hash.as_str()));
        assert_eq!(entry.validation_state, "valid");

        let status = mirror.status().unwrap();
        assert_eq!(status["pending_saves"], 0);
        assert_eq!(status["failed_saves"], 0);
        assert_eq!(status["unreplayable_saves"], 1);

        let queue = mirror
            .save_queue(&json!({"state": "unreplayable"}))
            .unwrap();
        assert_eq!(queue["total"], 1);
        assert_eq!(queue["counts"]["pending"], 0);
        assert_eq!(queue["counts"]["unreplayable"], 1);
        assert_eq!(queue["entries"][0]["state"], "unreplayable");
    }

    #[test]
    fn recover_local_edits_queues_changed_hydrated_files_in_pages() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base a");
        let b_path = record_hydrated_content(&mirror, "b.txt", b"base b");
        fs::write(&b_path, b"dirty b").unwrap();

        let first = mirror.recover_local_edits(1, None).unwrap();

        assert_eq!(first["scanned"], 1);
        assert_eq!(first["queued"].as_array().unwrap().len(), 0);
        assert_eq!(first["truncated"], true);
        assert_eq!(first["next_after"], "a.txt");

        let second = mirror.recover_local_edits(10, Some("a.txt")).unwrap();

        let queued = second["queued"].as_array().unwrap();
        assert_eq!(second["scanned"], 1);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0]["path"], "b.txt");
        assert!(queued[0]["queue_id"].as_i64().unwrap() > 0);
        assert_eq!(second["truncated"], false);
        assert_eq!(mirror.pending_save_count().unwrap(), 1);

        let save = mirror
            .latest_unresolved_save_entry("b.txt")
            .unwrap()
            .unwrap();
        assert_eq!(fs::read(&save.snapshot_path).unwrap(), b"dirty b");
        let entry = mirror.get("b.txt").unwrap().unwrap();
        assert!(entry.dirty);
        assert_eq!(
            entry.local_hash.as_deref(),
            Some(hash_bytes(b"dirty b").as_str())
        );
    }

    #[test]
    fn recover_local_edits_chains_new_dirty_snapshot_after_existing_save() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");

        fs::write(&local_path, b"dirty one").unwrap();
        let first_hash = hash_bytes(b"dirty one");
        mirror
            .enqueue_save("a.txt", &first_hash, Some("base"), b"dirty one")
            .unwrap();
        fs::write(&local_path, b"dirty two").unwrap();

        let result = mirror.recover_local_edits(10, None).unwrap();

        let queued = result["queued"].as_array().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0]["path"], "a.txt");

        let saves = mirror.pending_save_entries(Some(10)).unwrap();
        assert_eq!(saves.len(), 2);
        assert_eq!(saves[1].expected_hash.as_deref(), Some(first_hash.as_str()));
        assert_eq!(fs::read(&saves[0].snapshot_path).unwrap(), b"dirty one");
        assert_eq!(fs::read(&saves[1].snapshot_path).unwrap(), b"dirty two");
    }

    #[test]
    fn save_conflict_reports_truncated_remote_copy() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_hash = hash_bytes(b"dirty");
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        let sidecar = test_sidecar(mirror);

        let attempt = sidecar
            .record_save_outcome(
                &queued,
                SaveOutcome::Conflict(nrm_protocol::SaveConflict {
                    path: "a.txt".to_string(),
                    expected_hash: Some("base".to_string()),
                    actual_hash: Some("remote".to_string()),
                    remote_content: b"remote prefix".to_vec(),
                    remote_content_truncated: true,
                    remote_size: Some(10_000),
                }),
            )
            .unwrap();
        let value = Sidecar::save_attempt_to_json(attempt).unwrap();

        assert_eq!(value["status"], "conflict");
        assert_eq!(value["remote_content_truncated"], true);
        assert_eq!(value["remote_size"], 10_000);
        assert_eq!(value["remote_content_bytes"], 13);
        let conflict_path = PathBuf::from(value["remote_path"].as_str().unwrap());
        assert!(conflict_path.to_string_lossy().contains(".partial."));
        assert_eq!(fs::read(conflict_path).unwrap(), b"remote prefix");
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert_eq!(entry.validation_state, "conflict");
        assert_eq!(entry.remote_hash.as_deref(), Some("remote"));
        assert!(entry
            .last_error
            .as_deref()
            .unwrap()
            .contains("saved first 13 of 10000 remote bytes"));
    }

    #[test]
    fn conflict_actual_hash_becomes_next_resolved_save_base() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_hash = hash_bytes(b"dirty");
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        let sidecar = test_sidecar(mirror);
        sidecar
            .record_save_outcome(
                &queued,
                SaveOutcome::Conflict(nrm_protocol::SaveConflict {
                    path: "a.txt".to_string(),
                    expected_hash: Some("base".to_string()),
                    actual_hash: Some("remote-after-conflict".to_string()),
                    remote_content: b"remote".to_vec(),
                    remote_content_truncated: false,
                    remote_size: Some(6),
                }),
            )
            .unwrap();
        fs::write(&local_path, b"resolved").unwrap();

        let resolved = sidecar.mirror.enqueue_local_save("a.txt").unwrap();

        assert_eq!(
            resolved.expected_hash.as_deref(),
            Some("remote-after-conflict")
        );
        assert_eq!(resolved.local_hash, hash_bytes(b"resolved"));
    }

    #[test]
    fn save_conflict_matching_queued_hash_marks_save_applied() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_content = b"dirty";
        fs::write(&local_path, dirty_content).unwrap();
        let dirty_hash = hash_bytes(dirty_content);
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), dirty_content)
            .unwrap();
        let sidecar = test_sidecar(mirror);

        let attempt = sidecar
            .record_save_outcome(
                &queued,
                SaveOutcome::Conflict(nrm_protocol::SaveConflict {
                    path: "a.txt".to_string(),
                    expected_hash: Some("base".to_string()),
                    actual_hash: Some(dirty_hash.clone()),
                    remote_content: dirty_content.to_vec(),
                    remote_content_truncated: false,
                    remote_size: Some(dirty_content.len() as u64),
                }),
            )
            .unwrap();
        let value = Sidecar::save_attempt_to_json(attempt).unwrap();

        assert_eq!(value["status"], "applied");
        assert_eq!(value["hash"], dirty_hash);
        assert_eq!(sidecar.mirror.pending_save_count().unwrap(), 0);
        let save_state: String = sidecar
            .mirror
            .db
            .query_row(
                "SELECT state FROM save_queue WHERE id=?1",
                params![queued.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(save_state, "applied");
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert!(!entry.dirty);
        assert_eq!(entry.remote_hash.as_deref(), Some(dirty_hash.as_str()));
        assert_eq!(entry.local_hash.as_deref(), Some(dirty_hash.as_str()));
        assert_eq!(entry.validation_state, "valid");
    }

    #[test]
    fn accept_local_conflict_rebases_snapshot_and_supersedes_older_saves() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base");
        let first_hash = hash_bytes(b"dirty one");
        let second_hash = hash_bytes(b"dirty two");
        let first = mirror
            .enqueue_save("a.txt", &first_hash, Some("base"), b"dirty one")
            .unwrap();
        let second = mirror
            .enqueue_save(
                "a.txt",
                &second_hash,
                Some(first_hash.as_str()),
                b"dirty two",
            )
            .unwrap();
        mirror
            .record_save_conflict(
                second.id,
                "a.txt",
                Some("remote-after-conflict"),
                b"remote",
                false,
                "remote changed",
            )
            .unwrap();
        let mut sidecar = test_sidecar_with_agent_replies(
            mirror,
            vec![
                AgentWorkerReply::Response(Response::Hello {
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    capabilities: nrm_protocol::CapabilitySet::v1_agent(),
                }),
                AgentWorkerReply::Response(Response::WriteFileCas {
                    outcome: SaveOutcome::Applied(nrm_protocol::SaveApplied {
                        path: "a.txt".to_string(),
                        new_hash: second_hash.clone(),
                        size: b"dirty two".len() as u64,
                        mtime_ms: 123,
                    }),
                }),
            ],
        );

        let result = sidecar
            .accept_local_conflict(json!({"queue_id": second.id}))
            .unwrap();

        assert_eq!(result["status"], "applied", "result={result:?}");
        assert_eq!(save_state(&sidecar.mirror, first.id), "superseded");
        assert_eq!(save_state(&sidecar.mirror, second.id), "applied");
        let expected_hash: Option<String> = sidecar
            .mirror
            .db
            .query_row(
                "SELECT expected_hash FROM save_queue WHERE id=?1",
                params![second.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expected_hash.as_deref(), Some("remote-after-conflict"));
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert!(!entry.dirty);
        assert_eq!(entry.remote_hash.as_deref(), Some(second_hash.as_str()));
        assert_eq!(entry.local_hash.as_deref(), Some(second_hash.as_str()));
        assert_eq!(entry.validation_state, "valid");
    }

    #[test]
    fn accept_local_conflict_missing_snapshot_keeps_conflict_state() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_hash = hash_bytes(b"dirty");
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        mirror
            .record_save_conflict(
                queued.id,
                "a.txt",
                Some("remote-after-conflict"),
                b"remote",
                false,
                "remote changed",
            )
            .unwrap();
        fs::remove_file(&queued.snapshot_path).unwrap();

        let error = mirror
            .prepare_accept_local_conflict(queued.id)
            .unwrap_err()
            .to_string();

        assert!(error.contains("failed to hash conflict snapshot"));
        assert_eq!(save_state(&mirror, queued.id), "conflict");
    }

    #[test]
    fn accept_local_conflict_remote_failure_keeps_rebased_failed_row() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_hash = hash_bytes(b"dirty");
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        mirror
            .record_save_conflict(
                queued.id,
                "a.txt",
                Some("remote-after-conflict"),
                b"remote",
                false,
                "remote changed",
            )
            .unwrap();
        let mut sidecar = test_sidecar_with_agent_replies(
            mirror,
            vec![
                AgentWorkerReply::Response(Response::Hello {
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    capabilities: nrm_protocol::CapabilitySet::v1_agent(),
                }),
                AgentWorkerReply::TransportError("ssh unavailable".to_string()),
            ],
        );

        let result = sidecar
            .accept_local_conflict(json!({"queue_id": queued.id}))
            .unwrap();

        assert_eq!(result["status"], "queued");
        assert_eq!(save_state(&sidecar.mirror, queued.id), "failed");
        let expected_hash: Option<String> = sidecar
            .mirror
            .db
            .query_row(
                "SELECT expected_hash FROM save_queue WHERE id=?1",
                params![queued.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expected_hash.as_deref(), Some("remote-after-conflict"));
    }

    #[test]
    fn accept_remote_conflict_installs_full_copy_and_resolves_path_queue() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let first_hash = hash_bytes(b"dirty one");
        let second_hash = hash_bytes(b"dirty two");
        let first = mirror
            .enqueue_save("a.txt", &first_hash, Some("base"), b"dirty one")
            .unwrap();
        let second = mirror
            .enqueue_save(
                "a.txt",
                &second_hash,
                Some(first_hash.as_str()),
                b"dirty two",
            )
            .unwrap();
        let remote_hash = hash_bytes(b"remote");
        mirror
            .record_save_conflict(
                second.id,
                "a.txt",
                Some(remote_hash.as_str()),
                b"remote",
                false,
                "remote changed",
            )
            .unwrap();
        fs::write(&local_path, b"dirty two").unwrap();
        let sidecar = test_sidecar(mirror);

        let result = sidecar.mirror.accept_remote_conflict(second.id).unwrap();

        assert_eq!(result["status"], "accepted_remote");
        assert_eq!(result["path"], "a.txt");
        assert_eq!(result["hash"], remote_hash);
        assert_eq!(fs::read(&local_path).unwrap(), b"remote");
        assert_eq!(save_state(&sidecar.mirror, first.id), "resolved_remote");
        assert_eq!(save_state(&sidecar.mirror, second.id), "resolved_remote");
        assert_eq!(sidecar.mirror.save_queue(&json!({})).unwrap()["total"], 0);
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert!(!entry.dirty);
        assert_eq!(entry.remote_hash.as_deref(), Some(remote_hash.as_str()));
        assert_eq!(entry.local_hash.as_deref(), Some(remote_hash.as_str()));
        assert_eq!(entry.validation_state, "valid");
    }

    #[test]
    fn accept_remote_conflict_rejects_changed_local_file() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_hash = hash_bytes(b"dirty");
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        let remote_hash = hash_bytes(b"remote");
        mirror
            .record_save_conflict(
                queued.id,
                "a.txt",
                Some(remote_hash.as_str()),
                b"remote",
                false,
                "remote changed",
            )
            .unwrap();
        fs::write(&local_path, b"new unsaved local edit").unwrap();

        let error = mirror
            .accept_remote_conflict(queued.id)
            .unwrap_err()
            .to_string();

        assert!(error.contains("local mirror file changed"));
        assert_eq!(save_state(&mirror, queued.id), "conflict");
        assert_eq!(fs::read(local_path).unwrap(), b"new unsaved local edit");
    }

    #[test]
    fn accept_remote_conflict_rejects_partial_copy() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_hash = hash_bytes(b"dirty");
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        mirror
            .record_save_conflict(
                queued.id,
                "a.txt",
                Some("remote"),
                b"remote prefix",
                true,
                "remote changed",
            )
            .unwrap();
        let sidecar = test_sidecar(mirror);

        let error = sidecar
            .mirror
            .accept_remote_conflict(queued.id)
            .unwrap_err()
            .to_string();

        assert!(error.contains("partial"));
        assert_eq!(save_state(&sidecar.mirror, queued.id), "conflict");
        assert_eq!(fs::read(local_path).unwrap(), b"base");
    }

    #[test]
    fn accept_remote_conflict_rejects_missing_remote_hash() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_hash = hash_bytes(b"dirty");
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        mirror
            .record_save_conflict(queued.id, "a.txt", None, b"remote", false, "remote changed")
            .unwrap();
        fs::write(&local_path, b"dirty").unwrap();

        let error = mirror
            .accept_remote_conflict(queued.id)
            .unwrap_err()
            .to_string();

        assert!(error.contains("no recorded remote hash"));
        assert_eq!(save_state(&mirror, queued.id), "conflict");
    }

    #[test]
    fn accept_remote_conflict_rejects_conflict_copy_hash_mismatch() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let dirty_hash = hash_bytes(b"dirty");
        let queued = mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        mirror
            .record_save_conflict(
                queued.id,
                "a.txt",
                Some("wrong-hash"),
                b"remote",
                false,
                "remote changed",
            )
            .unwrap();
        fs::write(&local_path, b"dirty").unwrap();

        let error = mirror
            .accept_remote_conflict(queued.id)
            .unwrap_err()
            .to_string();

        assert!(error.contains("hash mismatch"));
        assert_eq!(save_state(&mirror, queued.id), "conflict");
    }

    #[test]
    fn accept_conflict_refuses_stale_queue_row_when_newer_save_exists() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base");
        let first_hash = hash_bytes(b"dirty one");
        let second_hash = hash_bytes(b"dirty two");
        let first = mirror
            .enqueue_save("a.txt", &first_hash, Some("base"), b"dirty one")
            .unwrap();
        mirror
            .record_save_conflict(
                first.id,
                "a.txt",
                Some("remote-after-conflict"),
                b"remote",
                false,
                "remote changed",
            )
            .unwrap();
        mirror
            .enqueue_save(
                "a.txt",
                &second_hash,
                Some(first_hash.as_str()),
                b"dirty two",
            )
            .unwrap();

        let error = mirror
            .prepare_accept_local_conflict(first.id)
            .unwrap_err()
            .to_string();

        assert!(error.contains("newer queued saves"));
        assert_eq!(save_state(&mirror, first.id), "conflict");
    }

    #[test]
    fn pending_save_entries_respect_limit_and_report_remaining() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .record_hydrated(&test_meta("a.txt", "base-a", 1), "base-a", "base-a")
            .unwrap();
        mirror
            .record_hydrated(&test_meta("b.txt", "base-b", 1), "base-b", "base-b")
            .unwrap();
        let a_hash = hash_bytes(b"dirty a");
        let b_hash = hash_bytes(b"dirty b");
        mirror
            .enqueue_save("a.txt", &a_hash, Some("base-a"), b"dirty a")
            .unwrap();
        mirror
            .enqueue_save("b.txt", &b_hash, Some("base-b"), b"dirty b")
            .unwrap();

        let entries = mirror.pending_save_entries(Some(1)).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].relative_path, "a.txt");
        assert_eq!(mirror.pending_save_count().unwrap(), 2);
    }

    #[test]
    fn enqueue_local_save_rejects_unknown_mirror_entry() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = mirror.local_path("src/new.rs").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"new file").unwrap();

        let error = mirror
            .enqueue_local_save("src/new.rs")
            .unwrap_err()
            .to_string();

        assert!(error.contains("RemoteAdopt"));
        assert_eq!(mirror.pending_save_count().unwrap(), 0);
    }

    #[test]
    fn enqueue_adopted_local_save_creates_unknown_mirror_entry() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = mirror.local_path("src/new.rs").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"new file").unwrap();
        let expected_hash = hash_bytes(b"new file");

        let queued = mirror.enqueue_adopted_local_save("src/new.rs").unwrap();

        assert_eq!(queued.relative_path, "src/new.rs");
        assert_eq!(queued.expected_hash, None);
        assert_eq!(queued.local_hash, expected_hash);
        assert_eq!(fs::read(&queued.snapshot_path).unwrap(), b"new file");
        let entry = mirror.get("src/new.rs").unwrap().unwrap();
        assert_eq!(entry.state, "hydrated");
        assert!(entry.dirty);
        assert_eq!(entry.remote_hash, None);
        assert_eq!(entry.local_hash.as_deref(), Some(expected_hash.as_str()));
        assert_eq!(mirror.pending_save_count().unwrap(), 1);
    }

    #[test]
    fn applied_unknown_save_becomes_known_for_find_paths() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = mirror.local_path("src/new.rs").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"new file").unwrap();
        let hash = hash_bytes(b"new file");
        let queued = mirror.enqueue_adopted_local_save("src/new.rs").unwrap();
        let before = mirror
            .find_paths(&json!({"query": "src/new", "limit": 10}))
            .unwrap();
        assert_eq!(before["hits"].as_array().unwrap().len(), 0);

        mirror
            .mark_save_applied(queued.id, "src/new.rs", &hash, 8, 123)
            .unwrap();

        let after = mirror
            .find_paths(&json!({"query": "src/new", "limit": 10}))
            .unwrap();
        let hits = after["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["path"], "src/new.rs");
        assert_eq!(hits[0]["cached"], true);
        assert_eq!(hits[0]["dirty"], false);
        assert_eq!(hits[0]["validation_state"], "valid");
    }

    #[test]
    fn flush_unknown_local_file_requires_adopt() {
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let remote_root = remote_dir.path().join("repo");
        let mut sidecar = Sidecar::new(
            remote_root,
            RemoteTransport::Local,
            state_dir
                .path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            Some(state_dir.path().to_path_buf()),
            1,
            AgentInterrupt::default(),
        )
        .unwrap();
        let local_path = sidecar.mirror.local_path("src/new.rs").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"new file").unwrap();

        let error = sidecar
            .flush(json!({"path": "src/new.rs"}))
            .unwrap_err()
            .to_string();

        assert!(error.contains("RemoteAdopt"));
        assert_eq!(
            sidecar.mirror.pending_save_entries(Some(1)).unwrap().len(),
            0
        );
    }

    #[test]
    fn adopt_unknown_local_file_preserves_snapshot_when_remote_unavailable() {
        let state_dir = tempdir().unwrap();
        let remote_dir = tempdir().unwrap();
        let remote_root = remote_dir.path().join("repo");
        let mut sidecar = Sidecar::new(
            remote_root,
            RemoteTransport::Local,
            state_dir
                .path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            Some(state_dir.path().to_path_buf()),
            1,
            AgentInterrupt::default(),
        )
        .unwrap();
        let local_path = sidecar.mirror.local_path("src/new.rs").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"new file").unwrap();

        let result = sidecar.adopt(json!({"path": "src/new.rs"})).unwrap();

        assert_eq!(result["status"], "queued");
        assert_eq!(result["path"], "src/new.rs");
        let queued = sidecar.mirror.pending_save_entries(Some(1)).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].expected_hash, None);
        assert_eq!(fs::read(&queued[0].snapshot_path).unwrap(), b"new file");
    }

    #[test]
    fn save_queue_lists_unresolved_states_with_paths_and_counts() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"base a");
        record_hydrated_content(&mirror, "b.txt", b"base b");
        record_hydrated_content(&mirror, "c.txt", b"base c");

        let a_hash = hash_bytes(b"dirty a");
        let b_hash = hash_bytes(b"dirty b");
        let c_hash = hash_bytes(b"dirty c");
        let queued_a = mirror
            .enqueue_save("a.txt", &a_hash, Some("base-a"), b"dirty a")
            .unwrap();
        let queued_b = mirror
            .enqueue_save("b.txt", &b_hash, Some("base-b"), b"dirty b")
            .unwrap();
        let queued_c = mirror
            .enqueue_save("c.txt", &c_hash, Some("base-c"), b"dirty c")
            .unwrap();
        mirror
            .mark_save_failed(queued_b.id, "b.txt", "ssh connect failed")
            .unwrap();
        let conflict_path = mirror
            .record_save_conflict(
                queued_c.id,
                "c.txt",
                Some("remote-c"),
                b"remote c",
                false,
                "remote changed",
            )
            .unwrap();

        let result = mirror.save_queue(&json!({"limit": 2})).unwrap();
        let entries = result["entries"].as_array().unwrap();

        assert_eq!(result["total"], 3);
        assert_eq!(result["limit"], 2);
        assert_eq!(result["truncated"], true);
        assert_eq!(result["counts"]["pending"], 1);
        assert_eq!(result["counts"]["failed"], 1);
        assert_eq!(result["counts"]["conflict"], 1);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["queue_id"], queued_a.id);
        assert_eq!(entries[0]["path"], "a.txt");
        assert_eq!(entries[0]["state"], "pending");
        assert_eq!(entries[0]["local_hash"], a_hash);
        assert!(entries[0]["snapshot_path"]
            .as_str()
            .unwrap()
            .ends_with(".snapshot"));
        assert!(entries[0]["local_path"]
            .as_str()
            .is_some_and(|path| Path::new(path).ends_with(Path::new("files").join("a.txt"))));
        assert_eq!(entries[1]["queue_id"], queued_b.id);
        assert_eq!(entries[1]["state"], "failed");
        assert_eq!(entries[1]["attempts"], 1);
        assert_eq!(entries[1]["last_error"], "ssh connect failed");

        let full = mirror.save_queue(&json!({"limit": 10})).unwrap();
        let entries = full["entries"].as_array().unwrap();
        assert_eq!(full["truncated"], false);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2]["queue_id"], queued_c.id);
        assert_eq!(entries[2]["state"], "conflict");
        assert_eq!(
            entries[2]["remote_conflict_path"].as_str().unwrap(),
            conflict_path.to_string_lossy().as_ref()
        );
        assert_eq!(entries[2]["remote_conflict_truncated"], false);
    }

    #[test]
    fn fast_state_serves_save_queue_from_reopened_mirror() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "src/main.rs", b"base");
        let queued = mirror
            .enqueue_save("src/main.rs", &hash_bytes(b"dirty"), Some("base"), b"dirty")
            .unwrap();
        let sidecar = test_sidecar(mirror);
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));

        let request = ClientRequest {
            id: 1,
            method: "save_queue".to_string(),
            params: json!({"limit": 5}),
        };
        let FastHandle::Handled(result) = fast.try_handle(&request) else {
            panic!("save_queue should be handled by fast state");
        };
        let result = result.unwrap();
        let entries = result["entries"].as_array().unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["queue_id"], queued.id);
        assert_eq!(entries[0]["path"], "src/main.rs");
    }

    #[test]
    fn validation_can_mark_cached_file_stale() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = test_meta("a.txt", "local", 3);
        mirror.record_hydrated(&meta, "local", "local").unwrap();
        mirror
            .record_validation("a.txt", "stale", None, Some("remote hash differs"))
            .unwrap();

        let entry = mirror.get("a.txt").unwrap().unwrap();
        assert_eq!(entry.validation_state, "stale");
        assert_eq!(entry.remote_hash.as_deref(), Some("local"));
        assert_eq!(entry.last_error.as_deref(), Some("remote hash differs"));
    }

    #[test]
    fn open_returns_dirty_cache_even_when_force_requested() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = test_meta("a.txt", "base", 4);
        mirror.record_hydrated(&meta, "base", "base").unwrap();
        let local_path = mirror.local_path("a.txt").unwrap();
        fs::write(&local_path, b"dirty").unwrap();
        let dirty_hash = hash_bytes(b"dirty");
        mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();

        let mut sidecar = test_sidecar(mirror);
        let result = sidecar
            .open(json!({"path": "a.txt", "force": true}), 0)
            .unwrap();

        assert_eq!(result["cached"], true);
        assert_eq!(result["dirty"], true);
        assert_eq!(result["force_skipped"], true);
        assert_eq!(result["cache_reason"], "dirty");
        assert_eq!(fs::read(local_path).unwrap(), b"dirty");
        assert_eq!(sidecar.mirror.unresolved_save_count("a.txt").unwrap(), 1);
        assert!(sidecar.mirror.get("a.txt").unwrap().unwrap().dirty);
    }

    #[test]
    fn open_snapshots_out_of_band_cache_edit_before_serving() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let base_hash = hash_bytes(b"base");
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        fs::write(&local_path, b"local edit").unwrap();

        let mut sidecar = test_sidecar(mirror);
        let result = sidecar.open(json!({"path": "a.txt"}), 0).unwrap();
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        let queued = sidecar.mirror.pending_save_entries(Some(1)).unwrap();

        assert_eq!(result["cached"], true);
        assert_eq!(result["dirty"], true);
        assert_eq!(result["cache_reason"], "dirty");
        assert_eq!(entry.validation_state, "dirty");
        assert_eq!(
            entry.local_hash.as_deref(),
            Some(hash_bytes(b"local edit").as_str())
        );
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].expected_hash.as_deref(), Some(base_hash.as_str()));
        assert_eq!(fs::read(&queued[0].snapshot_path).unwrap(), b"local edit");
    }

    #[test]
    fn open_restores_missing_dirty_file_from_latest_snapshot() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = test_meta("a.txt", "base", 4);
        mirror.record_hydrated(&meta, "base", "base").unwrap();
        let local_path = mirror.local_path("a.txt").unwrap();
        fs::write(&local_path, b"dirty").unwrap();
        let dirty_hash = hash_bytes(b"dirty");
        mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        fs::remove_file(&local_path).unwrap();

        let mut sidecar = test_sidecar(mirror);
        let result = sidecar
            .open(json!({"path": "a.txt", "force": true}), 0)
            .unwrap();

        assert_eq!(result["cached"], true);
        assert_eq!(result["dirty"], true);
        assert_eq!(result["force_skipped"], true);
        assert_eq!(result["restored_from_snapshot"], true);
        assert_eq!(fs::read(local_path).unwrap(), b"dirty");
        assert_eq!(sidecar.mirror.unresolved_save_count("a.txt").unwrap(), 1);
        assert!(sidecar.mirror.get("a.txt").unwrap().unwrap().dirty);
    }

    #[test]
    fn open_returns_stale_cache_without_force() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"local");
        mirror
            .record_validation("a.txt", "stale", None, Some("remote hash differs"))
            .unwrap();

        let mut sidecar = test_sidecar(mirror);
        let result = sidecar.open(json!({"path": "a.txt"}), 0).unwrap();

        assert_eq!(result["cached"], true);
        assert_eq!(result["dirty"], false);
        assert_eq!(result["force_skipped"], false);
        assert_eq!(result["cache_reason"], "stale");
        assert_eq!(result["validation_state"], "stale");
    }

    #[test]
    fn open_returns_deleted_cache_without_force() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "a.txt", b"local");
        mirror
            .record_validation(
                "a.txt",
                "deleted",
                None,
                Some("remote file no longer exists"),
            )
            .unwrap();

        let mut sidecar = test_sidecar(mirror);
        let result = sidecar.open(json!({"path": "a.txt"}), 0).unwrap();

        assert_eq!(result["cached"], true);
        assert_eq!(result["dirty"], false);
        assert_eq!(result["cache_reason"], "deleted");
        assert_eq!(result["validation_state"], "deleted");
    }

    #[test]
    fn validate_skips_dirty_cache_without_remote_request() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = test_meta("a.txt", "base", 4);
        mirror.record_hydrated(&meta, "base", "base").unwrap();
        let local_path = mirror.local_path("a.txt").unwrap();
        fs::write(&local_path, b"dirty").unwrap();
        let dirty_hash = hash_bytes(b"dirty");
        mirror
            .enqueue_save("a.txt", &dirty_hash, Some("base"), b"dirty")
            .unwrap();

        let mut sidecar = test_sidecar(mirror);
        let result = sidecar.validate(json!({"path": "a.txt"}), 0).unwrap();

        assert_eq!(result["status"], "dirty");
        assert_eq!(result["skipped"], true);
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert!(entry.dirty);
        assert_eq!(entry.validation_state, "dirty");
    }

    #[test]
    fn validate_marks_out_of_band_cache_edit_dirty_without_remote_request() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        fs::write(&local_path, b"local edit").unwrap();

        let mut sidecar = test_sidecar(mirror);
        let result = sidecar.validate(json!({"path": "a.txt"}), 0).unwrap();
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();

        assert_eq!(result["status"], "dirty");
        assert_eq!(result["skipped"], true);
        assert_eq!(sidecar.mirror.pending_save_count().unwrap(), 1);
        assert!(entry.dirty);
        assert_eq!(entry.validation_state, "dirty");
    }

    #[test]
    fn single_validate_reports_deleted_for_metadata_entry_without_hash() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .upsert_metadata(
                &FileMeta {
                    path: "missing.txt".to_string(),
                    size: 0,
                    mtime_ms: 0,
                    mode: 0,
                    is_dir: false,
                    is_symlink: false,
                    hash: None,
                },
                "metadata",
            )
            .unwrap();
        let sidecar = test_sidecar(mirror);

        let result = sidecar
            .validation_file_to_json(BatchValidateFile {
                path: "missing.txt".to_string(),
                meta: None,
            })
            .unwrap();

        assert_eq!(result["path"], "missing.txt");
        assert_eq!(result["status"], "deleted");
        assert!(result["remote_hash"].is_null());
        assert!(result["local_hash"].is_null());
        let entry = sidecar.mirror.get("missing.txt").unwrap().unwrap();
        assert_eq!(entry.validation_state, "deleted");
        assert!(entry
            .last_error
            .as_deref()
            .unwrap()
            .contains("remote file no longer exists"));
    }

    #[test]
    fn single_validate_reports_deleted_for_hydrated_file_missing_remote() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_hash = hash_bytes(b"base");
        record_hydrated_content(&mirror, "a.txt", b"base");
        let sidecar = test_sidecar(mirror);

        let result = sidecar
            .validation_file_to_json(BatchValidateFile {
                path: "a.txt".to_string(),
                meta: None,
            })
            .unwrap();

        assert_eq!(result["status"], "deleted");
        assert!(result["remote_hash"].is_null());
        assert_eq!(result["local_hash"].as_str().unwrap(), local_hash);
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert_eq!(entry.validation_state, "deleted");
        assert_eq!(entry.remote_hash.as_deref(), Some(local_hash.as_str()));
    }

    #[test]
    fn deleted_remote_file_requires_explicit_adopt_to_recreate() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        let base_hash = hash_bytes(b"base");
        mirror
            .record_validation("a.txt", "deleted", None, Some("remote deleted"))
            .unwrap();
        fs::write(&local_path, b"recreated").unwrap();

        let error = mirror.enqueue_local_save("a.txt").unwrap_err().to_string();
        let recreated = mirror.enqueue_adopted_local_save("a.txt").unwrap();

        assert!(error.contains("RemoteAdopt"));
        assert_eq!(recreated.expected_hash, None);
        assert_eq!(recreated.local_hash, hash_bytes(b"recreated"));
        let entry = mirror.get("a.txt").unwrap().unwrap();
        assert_eq!(entry.remote_hash.as_deref(), Some(base_hash.as_str()));
        assert!(entry.dirty);
    }

    #[test]
    fn single_validate_reports_stale_remote_hash() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_hash = hash_bytes(b"base");
        let remote_hash = hash_bytes(b"remote");
        record_hydrated_content(&mirror, "a.txt", b"base");
        let sidecar = test_sidecar(mirror);

        let result = sidecar
            .validation_file_to_json(BatchValidateFile {
                path: "a.txt".to_string(),
                meta: Some(test_meta("a.txt", &remote_hash, 6)),
            })
            .unwrap();

        assert_eq!(result["status"], "stale");
        assert_eq!(result["remote_hash"].as_str().unwrap(), remote_hash);
        assert_eq!(result["local_hash"].as_str().unwrap(), local_hash);
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert_eq!(entry.validation_state, "stale");
        assert_eq!(entry.remote_hash.as_deref(), Some(local_hash.as_str()));
    }

    #[test]
    fn batch_hydrate_skips_out_of_band_cache_edit() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "a.txt", b"base");
        fs::write(&local_path, b"local edit").unwrap();
        let sidecar = test_sidecar(mirror);
        let remote_hash = hash_bytes(b"remote new");

        let error = sidecar
            .record_batch_file(BatchReadFile {
                path: "a.txt".to_string(),
                content: b"remote new".to_vec(),
                hash: remote_hash.clone(),
                meta: test_meta("a.txt", &remote_hash, b"remote new".len() as u64),
            })
            .unwrap_err()
            .to_string();

        assert!(error.contains("skipped dirty local mirror file"));
        assert_eq!(fs::read(local_path).unwrap(), b"local edit");
        assert!(!sidecar
            .mirror
            .local_path("a.txt")
            .unwrap()
            .with_extension("nrm-batch-part")
            .exists());
        assert_eq!(sidecar.mirror.pending_save_count().unwrap(), 1);
        assert!(sidecar.mirror.get("a.txt").unwrap().unwrap().dirty);
    }

    #[test]
    fn batch_hydrate_adopts_unmanaged_existing_matching_remote_file() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = mirror.local_path("a.txt").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"remote new").unwrap();
        let sidecar = test_sidecar(mirror);
        let remote_hash = hash_bytes(b"remote new");

        sidecar
            .record_batch_file(BatchReadFile {
                path: "a.txt".to_string(),
                content: b"remote new".to_vec(),
                hash: remote_hash.clone(),
                meta: test_meta("a.txt", &remote_hash, b"remote new".len() as u64),
            })
            .unwrap();

        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert_eq!(fs::read(&local_path).unwrap(), b"remote new");
        assert_eq!(entry.state, "hydrated");
        assert_eq!(entry.remote_hash.as_deref(), Some(remote_hash.as_str()));
        assert_eq!(entry.local_hash.as_deref(), Some(remote_hash.as_str()));
        assert_eq!(entry.validation_state, "valid");
        assert!(!local_path.with_extension("nrm-batch-part").exists());
    }

    #[test]
    fn batch_hydrate_adopts_metadata_existing_matching_remote_file() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let remote_hash = hash_bytes(b"remote new");
        mirror
            .upsert_metadata(
                &test_meta("a.txt", &remote_hash, b"remote new".len() as u64),
                "metadata",
            )
            .unwrap();
        let local_path = mirror.local_path("a.txt").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"remote new").unwrap();
        let sidecar = test_sidecar(mirror);

        sidecar
            .record_batch_file(BatchReadFile {
                path: "a.txt".to_string(),
                content: b"remote new".to_vec(),
                hash: remote_hash.clone(),
                meta: test_meta("a.txt", &remote_hash, b"remote new".len() as u64),
            })
            .unwrap();

        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();
        assert_eq!(entry.state, "hydrated");
        assert_eq!(entry.remote_hash.as_deref(), Some(remote_hash.as_str()));
        assert_eq!(entry.local_hash.as_deref(), Some(remote_hash.as_str()));
        assert_eq!(entry.validation_state, "valid");
    }

    #[test]
    fn batch_hydrate_skips_unmanaged_existing_local_file() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = mirror.local_path("a.txt").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"local edit").unwrap();
        let sidecar = test_sidecar(mirror);
        let remote_hash = hash_bytes(b"remote new");

        let error = sidecar
            .record_batch_file(BatchReadFile {
                path: "a.txt".to_string(),
                content: b"remote new".to_vec(),
                hash: remote_hash.clone(),
                meta: test_meta("a.txt", &remote_hash, b"remote new".len() as u64),
            })
            .unwrap_err()
            .to_string();

        assert!(error.contains("skipped existing unmanaged local mirror file"));
        assert_eq!(fs::read(local_path).unwrap(), b"local edit");
        assert!(!sidecar
            .mirror
            .local_path("a.txt")
            .unwrap()
            .with_extension("nrm-batch-part")
            .exists());
    }

    #[test]
    fn batch_hydrate_hash_mismatch_removes_partial_file() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let sidecar = test_sidecar(mirror);

        let error = sidecar
            .record_batch_file(BatchReadFile {
                path: "a.txt".to_string(),
                content: b"remote new".to_vec(),
                hash: "not-the-content-hash".to_string(),
                meta: test_meta("a.txt", "not-the-content-hash", b"remote new".len() as u64),
            })
            .unwrap_err()
            .to_string();

        assert!(error.contains("batch hydration hash mismatch"));
        assert!(!sidecar
            .mirror
            .local_path("a.txt")
            .unwrap()
            .with_extension("nrm-batch-part")
            .exists());
        assert!(sidecar.mirror.get("a.txt").unwrap().is_none());
    }

    #[test]
    fn related_prefetch_prioritizes_nearby_uncached_files() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .record_hydrated(&test_meta("src/main.rs", "main", 4), "main", "main")
            .unwrap();
        for path in [
            "src/lib.rs",
            "src/readme.md",
            "src/nested/mod.rs",
            "tests/main.rs",
        ] {
            mirror
                .upsert_metadata(&test_meta(path, "meta", 4), "metadata")
                .unwrap();
        }
        mirror
            .upsert_metadata(&test_meta_kind("src", "dir", 0, true, false), "metadata")
            .unwrap();
        mirror
            .upsert_metadata(
                &test_meta_kind("src/link.rs", "link", 0, false, true),
                "metadata",
            )
            .unwrap();
        mirror
            .record_hydrated(&test_meta("src/cached.rs", "cached", 6), "cached", "cached")
            .unwrap();
        mirror
            .record_hydrated(&test_meta("src/stale.rs", "stale", 5), "stale", "stale")
            .unwrap();
        mirror
            .record_validation("src/stale.rs", "stale", None, Some("remote changed"))
            .unwrap();
        mirror
            .record_hydrated(&test_meta("src/dirty.rs", "base", 4), "base", "base")
            .unwrap();
        let dirty_hash = hash_bytes(b"dirty");
        mirror
            .enqueue_save("src/dirty.rs", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        mirror
            .upsert_metadata(&test_meta("src/deleted.rs", "deleted", 7), "metadata")
            .unwrap();
        mirror
            .record_validation("src/deleted.rs", "deleted", None, Some("remote deleted"))
            .unwrap();
        mirror
            .upsert_metadata(&test_meta("src/legacy.rs", "legacy", 6), "metadata")
            .unwrap();
        mirror
            .db
            .execute(
                "UPDATE files SET metadata_kind_known=0 WHERE relative_path='src/legacy.rs'",
                [],
            )
            .unwrap();

        let paths = mirror.related_prefetch_paths("src/main.rs", 10).unwrap();

        assert_eq!(
            paths,
            vec![
                "src/lib.rs".to_string(),
                "src/readme.md".to_string(),
                "src/nested/mod.rs".to_string(),
                "tests/main.rs".to_string(),
            ]
        );
    }

    #[test]
    fn known_prefetch_paths_select_clean_uncached_metadata_files() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .upsert_metadata(&test_meta("src/a.rs", "a", 1), "metadata")
            .unwrap();
        mirror
            .upsert_metadata(&test_meta("src/b.rs", "b", 1), "metadata")
            .unwrap();
        record_hydrated_content(&mirror, "src/cached.rs", b"cached");
        mirror
            .upsert_metadata(
                &test_meta_kind("src/dir", "dir", 0, true, false),
                "metadata",
            )
            .unwrap();
        mirror
            .upsert_metadata(&test_meta("src/deleted.rs", "deleted", 1), "metadata")
            .unwrap();
        mirror
            .record_validation("src/deleted.rs", "deleted", None, None)
            .unwrap();

        let paths = mirror.known_prefetch_paths(10).unwrap();

        assert_eq!(paths, vec!["src/a.rs".to_string(), "src/b.rs".to_string()]);
    }

    #[test]
    fn find_paths_searches_cached_and_metadata_entries_locally() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .upsert_metadata(&test_meta("src/main.rs", "main", 4), "metadata")
            .unwrap();
        record_hydrated_content(&mirror, "src/lib.rs", b"lib");
        mirror
            .upsert_metadata(
                &test_meta_kind("src/dir", "dir", 0, true, false),
                "metadata",
            )
            .unwrap();
        mirror
            .upsert_metadata(
                &test_meta_kind("src/link.rs", "link", 0, false, true),
                "metadata",
            )
            .unwrap();

        let result = mirror
            .find_paths(&json!({"query": "src/", "limit": 10}))
            .unwrap();
        let hits = result["hits"].as_array().unwrap();

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0]["path"], "src/lib.rs");
        assert_eq!(hits[0]["cached"], true);
        assert!(hits[0]["local_path"]
            .as_str()
            .is_some_and(|path| Path::new(path).ends_with(Path::new("src").join("lib.rs"))));
        assert_eq!(hits[1]["path"], "src/main.rs");
        assert_eq!(hits[1]["cached"], false);
        assert!(hits[1]["local_path"]
            .as_str()
            .is_some_and(|path| Path::new(path).ends_with(Path::new("src").join("main.rs"))));
        assert_eq!(result["truncated"], false);
    }

    #[test]
    fn find_paths_uses_literal_query_and_reports_truncation() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .upsert_metadata(&test_meta("src/percent%name.rs", "a", 1), "metadata")
            .unwrap();
        mirror
            .upsert_metadata(&test_meta("src/percent-name.rs", "b", 1), "metadata")
            .unwrap();
        mirror
            .upsert_metadata(&test_meta("src/other.rs", "c", 1), "metadata")
            .unwrap();

        let literal = mirror
            .find_paths(&json!({"query": "%name", "limit": 10}))
            .unwrap();
        let hits = literal["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["path"], "src/percent%name.rs");

        let limited = mirror
            .find_paths(&json!({"query": "src/", "limit": 1}))
            .unwrap();
        assert_eq!(limited["hits"].as_array().unwrap().len(), 1);
        assert_eq!(limited["truncated"], true);
    }

    #[test]
    fn fast_state_serves_cached_open_and_status_from_reopened_mirror() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path = record_hydrated_content(&mirror, "src/main.rs", b"main");
        let sidecar = test_sidecar(mirror);
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));

        let request = ClientRequest {
            id: 1,
            method: "open".to_string(),
            params: json!({"path": "src/main.rs"}),
        };
        let FastHandle::Handled(result) = fast.try_handle(&request) else {
            panic!("cached open should be handled by fast state");
        };
        let result = result.unwrap();
        assert_eq!(result["cached"], true);
        assert_eq!(result["cache_reason"], "cached");
        assert_eq!(
            result["local_path"].as_str().unwrap(),
            local_path.to_string_lossy()
        );

        let request = ClientRequest {
            id: 2,
            method: "status".to_string(),
            params: json!({}),
        };
        let FastHandle::Handled(result) = fast.try_handle(&request) else {
            panic!("status should be handled by fast state");
        };
        let result = result.unwrap();
        assert_eq!(result["cached_files"], 1);
        assert_eq!(result["background_scan_state"], "not_started");
        assert_eq!(result["background_scan_cursor"], Value::Null);
        assert_eq!(result["background_scan_completed_at_ms"], Value::Null);
        assert_eq!(result["remote_status"], "unchecked");
        assert_eq!(result["remote_checked"], false);
        assert_eq!(result["remote_available"], false);
    }

    #[test]
    fn fast_state_status_reports_remote_backoff_after_failed_probe() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "src/main.rs", b"main");
        let mut sidecar = test_sidecar(mirror);
        sidecar.agent.launch.agent = dir
            .path()
            .join("missing-agent")
            .to_string_lossy()
            .to_string();
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));

        let probe = sidecar.handle("remote_probe", json!({}), 0).unwrap();
        assert_eq!(probe["remote_status"], "unavailable");
        assert_eq!(probe["remote_available"], false);
        assert!(probe["remote_error"]
            .as_str()
            .unwrap()
            .contains("failed to launch agent"));

        let request = ClientRequest {
            id: 2,
            method: "status".to_string(),
            params: json!({}),
        };
        let FastHandle::Handled(result) = fast.try_handle(&request) else {
            panic!("status should stay on fast path after a failed probe");
        };
        let result = result.unwrap();

        assert_eq!(result["cached_files"], 1);
        assert_eq!(result["remote_status"], "unavailable");
        assert_eq!(result["remote_checked"], true);
        assert_eq!(result["remote_available"], false);
        assert!(result["retry_after_ms"].as_u64().unwrap() <= REMOTE_UNAVAILABLE_BACKOFF_BASE_MS);
        assert!(result["remote_error"]
            .as_str()
            .unwrap()
            .contains("failed to launch agent"));

        let request = ClientRequest {
            id: 3,
            method: "workspace_info".to_string(),
            params: json!({}),
        };
        let FastHandle::Handled(info) = fast.try_handle(&request) else {
            panic!("workspace_info should stay on fast path after a failed probe");
        };
        let info = info.unwrap();

        assert_eq!(info["remote_status"], "unavailable");
        assert_eq!(info["remote_health"]["remote_status"], "unavailable");
        assert!(info["remote_error"]
            .as_str()
            .unwrap()
            .contains("failed to launch agent"));
        assert!(info["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method.as_str() == Some("workspace_info")));
    }

    #[test]
    fn fast_state_serves_find_paths_from_reopened_mirror() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .upsert_metadata(&test_meta("src/main.rs", "main", 4), "metadata")
            .unwrap();
        let sidecar = test_sidecar(mirror);
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));

        let request = ClientRequest {
            id: 1,
            method: "find_paths".to_string(),
            params: json!({"query": "main", "limit": 10}),
        };
        let FastHandle::Handled(result) = fast.try_handle(&request) else {
            panic!("find_paths should be handled by fast state");
        };
        let result = result.unwrap();
        let hits = result["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["path"], "src/main.rs");
        assert_eq!(hits[0]["cached"], false);
    }

    #[test]
    fn fast_state_serves_grep_cache_from_reopened_mirror() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let local_path =
            record_hydrated_content(&mirror, "src/main.rs", b"fn cached_symbol() {}\n");
        let sidecar = test_sidecar(mirror);
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));

        let request = ClientRequest {
            id: 1,
            method: "grep_cache".to_string(),
            params: json!({"query": "cached_symbol", "limit": 10}),
        };
        let FastHandle::Handled(result) = fast.try_handle(&request) else {
            panic!("grep_cache should be handled by fast state");
        };
        let result = result.unwrap();

        assert_eq!(result["cached"], true);
        assert_eq!(result["hits"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["hits"][0]["local_path"].as_str().unwrap(),
            local_path.to_string_lossy().as_ref()
        );
    }

    #[test]
    fn fast_state_prepares_flush_by_enqueueing_local_snapshot() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .record_hydrated(&test_meta("src/main.rs", "base", 4), "base", "base")
            .unwrap();
        let local_path = mirror.local_path("src/main.rs").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"dirty").unwrap();
        let mirror_root = mirror.root().to_path_buf();
        let sidecar = test_sidecar(mirror);
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));

        let request = ClientRequest {
            id: 7,
            method: "flush".to_string(),
            params: json!({"path": "src/main.rs"}),
        };
        let prepared = fast.prepare_flush(&request, false).unwrap();
        let reopened = Mirror::open_root(mirror_root).unwrap();
        let entries = reopened.pending_save_entries(Some(10)).unwrap();

        assert_eq!(prepared.id, 7);
        assert_eq!(prepared.method, "flush_queued");
        assert_eq!(prepared.params["path"], "src/main.rs");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].relative_path, "src/main.rs");
        assert_eq!(fs::read(&entries[0].snapshot_path).unwrap(), b"dirty");
    }

    #[test]
    fn fast_state_defers_force_or_uncached_open() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "src/main.rs", b"main");
        let sidecar = test_sidecar(mirror);
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));

        let force = ClientRequest {
            id: 1,
            method: "open".to_string(),
            params: json!({"path": "src/main.rs", "force": true}),
        };
        assert!(matches!(fast.try_handle(&force), FastHandle::Defer));

        let uncached = ClientRequest {
            id: 2,
            method: "open".to_string(),
            params: json!({"path": "missing.rs"}),
        };
        assert!(matches!(fast.try_handle(&uncached), FastHandle::Defer));
    }

    #[test]
    fn fast_state_serves_dirty_force_open_without_remote() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        mirror
            .record_hydrated(&test_meta("src/main.rs", "base", 4), "base", "base")
            .unwrap();
        let local_path = mirror.local_path("src/main.rs").unwrap();
        fs::create_dir_all(local_path.parent().unwrap()).unwrap();
        fs::write(&local_path, b"dirty").unwrap();
        let dirty_hash = hash_bytes(b"dirty");
        mirror
            .enqueue_save("src/main.rs", &dirty_hash, Some("base"), b"dirty")
            .unwrap();
        let sidecar = test_sidecar(mirror);
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));

        let force = ClientRequest {
            id: 1,
            method: "open".to_string(),
            params: json!({"path": "src/main.rs", "force": true}),
        };
        let FastHandle::Handled(result) = fast.try_handle(&force) else {
            panic!("dirty force open should be handled by fast state");
        };
        let result = result.unwrap();

        assert_eq!(result["cached"], true);
        assert_eq!(result["dirty"], true);
        assert_eq!(result["force_skipped"], true);
        assert_eq!(
            result["local_path"].as_str().unwrap(),
            local_path.to_string_lossy().as_ref()
        );
    }

    #[test]
    fn fast_state_defers_open_blocked_by_pending_remote_hazard() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        record_hydrated_content(&mirror, "src/main.rs", b"main");
        let sidecar = test_sidecar(mirror);
        let pending = Arc::new(Mutex::new(PendingRemote::default()));
        let fast = FastState::from_sidecar(&sidecar, Arc::clone(&pending));
        let force = ClientRequest {
            id: 1,
            method: "open".to_string(),
            params: json!({"path": "src/main.rs", "force": true}),
        };
        let hazard = PendingHazard::for_request(&force);
        pending.lock().unwrap().register(&hazard);

        let cached = ClientRequest {
            id: 2,
            method: "open".to_string(),
            params: json!({"path": "src/main.rs"}),
        };
        assert!(matches!(fast.try_handle(&cached), FastHandle::Defer));

        pending.lock().unwrap().clear(&hazard);
        assert!(matches!(fast.try_handle(&cached), FastHandle::Handled(_)));
    }

    fn test_client_request(id: u64, method: &str, params: Value) -> ClientRequest {
        ClientRequest {
            id,
            method: method.to_string(),
            params,
        }
    }

    fn test_remote_work(id: u64, method: &str) -> RemoteWork {
        let request = test_client_request(id, method, json!({}));
        test_remote_work_from_request(request)
    }

    fn test_remote_work_from_request(request: ClientRequest) -> RemoteWork {
        let hazard = PendingHazard::for_request(&request);
        let priority = RemotePriority::for_request(&request);
        let pending_writes = PendingRemote::default();
        let lane = RemoteLane::for_request(&request, &pending_writes);
        let write_hazard_registered = request_is_write_lane(&request);
        RemoteWork {
            request,
            hazard,
            priority,
            lane,
            write_hazard_registered,
            enqueued_at: Instant::now(),
        }
    }

    fn test_preempts() -> RemotePreempts {
        RemotePreempts {
            read: AgentPreempt::default(),
            write: AgentPreempt::default(),
        }
    }

    #[test]
    fn git_reads_route_around_pending_write_hazards() {
        let mut pending_writes = PendingRemote::default();
        pending_writes.register(&PendingHazard::for_request(&test_client_request(
            1,
            "flush",
            json!({"path": "src/main.rs"}),
        )));

        let same_path_diff = test_client_request(2, "git_diff", json!({"path": "src/main.rs"}));
        assert_eq!(
            RemoteLane::for_request(&same_path_diff, &pending_writes),
            RemoteLane::Write
        );

        let unrelated_status =
            test_client_request(3, "git_status", json!({"paths": ["src/lib.rs"]}));
        assert_eq!(
            RemoteLane::for_request(&unrelated_status, &pending_writes),
            RemoteLane::Write
        );

        let broad_status = test_client_request(4, "git_status", json!({}));
        assert_eq!(
            RemoteLane::for_request(&broad_status, &pending_writes),
            RemoteLane::Write
        );
    }

    #[test]
    fn remote_queue_prioritizes_interactive_and_preserves_fifo() {
        let queue = RemoteQueue::new(8, 8);
        queue
            .try_push(test_remote_work(1, "prefetch"), None)
            .unwrap();
        queue.try_push(test_remote_work(2, "open"), None).unwrap();
        queue.try_push(test_remote_work(3, "flush"), None).unwrap();
        queue
            .try_push(test_remote_work(4, "prefetch_related"), None)
            .unwrap();

        assert_eq!(queue.pop().unwrap().request.id, 2);
        assert_eq!(queue.pop().unwrap().request.id, 3);
        assert_eq!(queue.pop().unwrap().request.id, 1);
        assert_eq!(queue.pop().unwrap().request.id, 4);

        queue.shutdown_and_drain();
        assert!(queue.pop().is_none());
    }

    #[test]
    fn remote_queue_preserves_background_fifo_without_interactive_work() {
        let queue = RemoteQueue::new(8, 8);
        queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    1,
                    "prefetch",
                    json!({"paths": ["src/main.rs"]}),
                )),
                None,
            )
            .unwrap();
        queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    2,
                    "prefetch",
                    json!({"paths": ["src/lib.rs"]}),
                )),
                None,
            )
            .unwrap();

        assert_eq!(queue.pop().unwrap().request.id, 1);
        assert_eq!(queue.pop().unwrap().request.id, 2);
        queue.shutdown_and_drain();
    }

    #[test]
    fn background_flush_queue_yields_to_interactive_work() {
        let queue = RemoteQueue::new(8, 8);
        queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    1,
                    "flush_queue",
                    json!({"background": true, "limit": 1}),
                )),
                None,
            )
            .unwrap();
        queue.try_push(test_remote_work(2, "open"), None).unwrap();

        assert_eq!(queue.pop().unwrap().request.id, 2);
        assert_eq!(queue.pop().unwrap().request.id, 1);
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_flush_bypasses_conflicting_background_hydration() {
        let queue = RemoteQueue::new(8, 8);
        queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    1,
                    "prefetch",
                    json!({"paths": ["src/main.rs"]}),
                )),
                None,
            )
            .unwrap();
        queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    2,
                    "flush",
                    json!({"path": "src/main.rs"}),
                )),
                None,
            )
            .unwrap();

        assert_eq!(queue.pop().unwrap().request.id, 2);
        assert_eq!(queue.pop().unwrap().request.id, 1);
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_background_capacity_does_not_block_interactive() {
        let queue = RemoteQueue::new(1, 1);
        queue
            .try_push(test_remote_work(1, "prefetch"), None)
            .unwrap();
        let rejected_background = queue
            .try_push(test_remote_work(2, "prefetch_related"), None)
            .unwrap_err();
        assert_eq!(rejected_background.priority, RemotePriority::Background);

        queue.try_push(test_remote_work(3, "open"), None).unwrap();
        let rejected_interactive = queue
            .try_push(test_remote_work(4, "flush"), None)
            .unwrap_err();
        assert_eq!(rejected_interactive.priority, RemotePriority::Interactive);

        assert_eq!(queue.pop().unwrap().request.id, 3);
        assert_eq!(queue.pop().unwrap().request.id, 1);
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_cancel_removes_queued_work_and_restores_capacity() {
        let queue = RemoteQueue::new(1, 1);
        queue
            .try_push(test_remote_work(1, "prefetch"), None)
            .unwrap();
        assert!(queue
            .try_push(test_remote_work(2, "prefetch_related"), None)
            .is_err());

        let canceled = queue.cancel(1).unwrap();

        assert_eq!(canceled.request.id, 1);
        queue
            .try_push(test_remote_work(2, "prefetch_related"), None)
            .unwrap();
        assert_eq!(queue.pop().unwrap().request.id, 2);
        assert!(queue.cancel(999).is_none());
        queue.shutdown_and_drain();
    }

    #[test]
    fn cancel_queued_request_clears_pending_hazard_and_reports_original_request() {
        let queue = RemoteQueue::new(8, 8);
        let pending = Arc::new(Mutex::new(PendingRemote::default()));
        let pending_writes = Arc::new(Mutex::new(PendingRemote::default()));
        let request = test_client_request(7, "open", json!({"path": "src/main.rs", "force": true}));
        let work = test_remote_work_from_request(request);
        pending.lock().unwrap().register(&work.hazard);
        queue.try_push(work, None).unwrap();
        assert!(pending.lock().unwrap().blocks_path("src/main.rs"));

        let canceled = cancel_queued_request(&queue, &pending, &pending_writes, 7).unwrap();
        let response = canceled_client_response(canceled);

        assert!(!pending.lock().unwrap().blocks_path("src/main.rs"));
        assert_eq!(response.id, 7);
        assert!(!response.ok);
        assert!(response
            .error
            .unwrap()
            .contains("canceled before remote execution"));
        assert!(queue.shutdown_and_drain().is_empty());
    }

    #[test]
    fn cancel_active_background_request_requests_preemption() {
        let active = ActiveRemote::default();
        let preempts = test_preempts();
        let work = test_remote_work(9, "prefetch");
        active.set(&work);

        let result = cancel_active_request(&active, &preempts, 9).unwrap();

        assert_eq!(result["request_id"], 9);
        assert_eq!(result["canceled"], true);
        assert_eq!(result["scope"], "active");
        assert_eq!(result["method"], "prefetch");
        assert_eq!(preempts.read.epoch(), 1);
        assert_eq!(preempts.write.epoch(), 0);
        assert_eq!(active.get(9).unwrap().id, 9);
        active.clear(9);
        assert!(active.get(9).is_none());
    }

    #[test]
    fn cancel_active_open_request_requests_preemption() {
        let active = ActiveRemote::default();
        let preempts = test_preempts();
        let work = test_remote_work(10, "open");
        active.set(&work);

        let result = cancel_active_request(&active, &preempts, 10).unwrap();

        assert_eq!(result["request_id"], 10);
        assert_eq!(result["canceled"], true);
        assert_eq!(result["scope"], "active");
        assert_eq!(result["method"], "open");
        assert_eq!(preempts.read.epoch(), 1);
        assert_eq!(preempts.write.epoch(), 0);
    }

    #[test]
    fn cancel_active_save_request_reports_not_interrupted() {
        let active = ActiveRemote::default();
        let preempts = test_preempts();
        let work = test_remote_work(11, "flush");
        active.set(&work);

        let result = cancel_active_request(&active, &preempts, 11).unwrap();

        assert_eq!(result["request_id"], 11);
        assert_eq!(result["canceled"], false);
        assert_eq!(result["scope"], "active");
        assert_eq!(result["method"], "flush");
        assert_eq!(
            result["reason"],
            "active request is not cancellation-preemptible"
        );
        assert_eq!(preempts.read.epoch(), 0);
        assert_eq!(preempts.write.epoch(), 0);
    }

    #[test]
    fn cancel_stale_active_request_does_not_preempt_current_work() {
        let active = ActiveRemote::default();
        let preempts = test_preempts();
        active.set(&test_remote_work(12, "open"));
        active.clear(12);
        active.set(&test_remote_work(13, "grep"));

        let result = cancel_active_request(&active, &preempts, 12);

        assert!(result.is_none());
        assert_eq!(preempts.read.epoch(), 0);
        assert_eq!(preempts.write.epoch(), 0);
        assert_eq!(active.get(13).unwrap().id, 13);
    }

    #[test]
    fn lane_routing_allows_unrelated_reads_while_write_pending() {
        let mut pending_writes = PendingRemote::default();
        let write = test_client_request(1, "flush_queued", json!({"path": "src/a.rs"}));
        pending_writes.register(&PendingHazard::for_request(&write));

        let unrelated_open =
            test_client_request(2, "open", json!({"path": "src/b.rs", "force": true}));

        assert_eq!(
            RemoteLane::for_request(&unrelated_open, &pending_writes),
            RemoteLane::Read
        );
    }

    #[test]
    fn lane_routing_serializes_conflicting_reads_with_pending_writes() {
        let mut pending_writes = PendingRemote::default();
        let write = test_client_request(1, "flush_queued", json!({"path": "src/a.rs"}));
        pending_writes.register(&PendingHazard::for_request(&write));

        let same_path_open =
            test_client_request(2, "open", json!({"path": "src/a.rs", "force": true}));
        let hydrating_grep = test_client_request(3, "grep", json!({"query": "needle"}));

        assert_eq!(
            RemoteLane::for_request(&same_path_open, &pending_writes),
            RemoteLane::Write
        );
        assert_eq!(
            RemoteLane::for_request(&hydrating_grep, &pending_writes),
            RemoteLane::Write
        );
    }

    #[test]
    fn remote_queue_bumps_preemption_before_accepting_interactive_work() {
        let queue = RemoteQueue::new(8, 8);
        let preempt = AgentPreempt::default();

        queue
            .try_push(test_remote_work(1, "prefetch"), Some(&preempt))
            .unwrap();
        assert_eq!(preempt.epoch(), 0);

        queue
            .try_push(test_remote_work(2, "open"), Some(&preempt))
            .unwrap();
        assert_eq!(preempt.epoch(), 1);
        queue.shutdown_and_drain();
    }

    #[test]
    fn interactive_open_preempts_conflicting_background_prefetch() {
        let queue = RemoteQueue::new(8, 8);
        let preempt = AgentPreempt::default();
        queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    1,
                    "prefetch",
                    json!({"paths": ["src/main.rs"]}),
                )),
                None,
            )
            .unwrap();

        let canceled = queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    2,
                    "open",
                    json!({"path": "src/main.rs"}),
                )),
                Some(&preempt),
            )
            .unwrap();

        assert_eq!(preempt.epoch(), 1);
        assert_eq!(canceled.len(), 1);
        assert_eq!(canceled[0].request.id, 1);
        assert_eq!(queue.pop().unwrap().request.id, 2);
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_pop_started_captures_preemption_epoch_under_lock() {
        let queue = RemoteQueue::new(8, 8);
        let preempt = AgentPreempt::default();
        preempt.request_preemption();
        queue
            .try_push(test_remote_work(1, "prefetch"), None)
            .unwrap();

        let started = queue.pop_started(&preempt).unwrap();

        assert_eq!(started.work.request.id, 1);
        assert_eq!(started.preempt_epoch, 1);
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_cancels_queued_background_that_blocks_interactive_work() {
        let queue = RemoteQueue::new(8, 8);
        queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    1,
                    "prefetch",
                    json!({"paths": ["src/main.rs"]}),
                )),
                None,
            )
            .unwrap();

        let canceled = queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    2,
                    "open",
                    json!({"path": "src/main.rs"}),
                )),
                None,
            )
            .unwrap();

        assert_eq!(canceled.len(), 1);
        assert_eq!(canceled[0].request.id, 1);
        assert_eq!(queue.pop().unwrap().request.id, 2);
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_shutdown_drains_queued_hazards() {
        let pending = Arc::new(Mutex::new(PendingRemote::default()));
        let queue = RemoteQueue::new(8, 8);
        let request = test_client_request(1, "open", json!({"path": "src/main.rs", "force": true}));
        let hazard = PendingHazard::for_request(&request);
        pending.lock().unwrap().register(&hazard);
        queue
            .try_push(
                RemoteWork {
                    request,
                    hazard,
                    priority: RemotePriority::Interactive,
                    lane: RemoteLane::Read,
                    write_hazard_registered: false,
                    enqueued_at: Instant::now(),
                },
                None,
            )
            .unwrap();

        assert!(pending.lock().unwrap().blocks_path("src/main.rs"));
        clear_pending_hazards(&pending, queue.shutdown_and_drain());

        assert!(!pending.lock().unwrap().blocks_path("src/main.rs"));
        assert!(queue.pop().is_none());
    }

    #[test]
    fn remote_queue_drain_queued_keeps_queue_open() {
        let queue = RemoteQueue::new(8, 8);
        queue
            .try_push(test_remote_work(1, "prefetch"), None)
            .unwrap();
        queue.try_push(test_remote_work(2, "open"), None).unwrap();

        let drained = queue.drain_queued();

        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].request.id, 1);
        assert_eq!(drained[1].request.id, 2);
        queue.try_push(test_remote_work(3, "status"), None).unwrap();
        assert_eq!(queue.pop().unwrap().request.id, 3);
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_maintenance_closes_claim_race_and_resumes_after_guard_drop() {
        let read = Arc::new(RemoteQueue::new(8, 8));
        let write = Arc::new(RemoteQueue::new(8, 8));
        read.try_push(test_remote_work(1, "open"), None).unwrap();
        write.try_push(test_remote_work(2, "flush"), None).unwrap();

        let (maintenance, drained) =
            RemoteMaintenanceGuard::begin(Arc::clone(&read), Arc::clone(&write));
        assert_eq!(drained.len(), 2);
        assert!(read.try_push(test_remote_work(3, "open"), None).is_err());
        assert!(write.try_push(test_remote_work(4, "flush"), None).is_err());

        drop(maintenance);
        read.try_push(test_remote_work(5, "open"), None).unwrap();
        assert_eq!(read.pop().unwrap().request.id, 5);
        read.shutdown_and_drain();
        write.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_quiescence_waits_for_claimed_work_cleanup() {
        let queue = RemoteQueue::new(8, 8);
        queue.try_push(test_remote_work(1, "open"), None).unwrap();
        let item = queue.pop_worker_item(None).unwrap();
        assert!(matches!(item, RemoteWorkerItem::Work(_)));
        queue.begin_maintenance_and_drain();

        assert!(!queue.wait_quiescent_for(Duration::from_millis(1)));
        queue.finish_started();
        assert!(queue.wait_quiescent_for(Duration::from_millis(1)));
        queue.end_maintenance();
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_queue_maintenance_does_not_pass_a_stalled_lane_process() {
        let read_queue = RemoteQueue::new(8, 8);
        let write_queue = RemoteQueue::new(8, 8);
        let read_interrupt = AgentInterrupt::default();
        let write_interrupt = AgentInterrupt::default();
        let handle = Arc::new(TestAbortHandle::default());
        handle.stopped.store(false, Ordering::SeqCst);
        let handle_trait: Arc<dyn AgentAbortHandle> = handle.clone();
        read_interrupt.set_abort_handle(Arc::clone(&handle_trait));

        let started = Instant::now();
        let error = wait_for_remote_queues_quiescent(
            &read_queue,
            &write_queue,
            &read_interrupt,
            &write_interrupt,
            Duration::from_millis(20),
        )
        .unwrap_err();

        assert!(error
            .downcast_ref::<AgentWorkerExitTimeoutError>()
            .is_some());
        assert!(started.elapsed() < Duration::from_millis(500));
        read_interrupt.clear_abort_handle(&handle_trait);
    }

    #[test]
    fn remote_queue_reset_control_is_acknowledged_while_maintenance_is_paused() {
        let queue = Arc::new(RemoteQueue::new(8, 8));
        queue.begin_maintenance_and_drain();
        let worker_queue = Arc::clone(&queue);
        let worker = thread::spawn(move || {
            let item = worker_queue.pop_worker_item(None).unwrap();
            let RemoteWorkerItem::Control(RemoteWorkerControl::ResetAgent { reply, .. }) = item
            else {
                panic!("expected reset control");
            };
            reply.send(Ok(())).unwrap();
        });

        queue.reset_agent_worker(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        queue.end_maintenance();
        queue.shutdown_and_drain();
    }

    #[test]
    fn remote_agent_replacement_requests_are_write_control_work() {
        for method in ["remote_agent_install", "remote_agent_update"] {
            let request = test_client_request(9, method, json!({}));

            assert!(request_is_write_lane(&request));
            assert!(request_replaces_remote_agent(&request));
        }

        assert!(!request_replaces_remote_agent(&test_client_request(
            10,
            "remote_health",
            json!({})
        )));
    }

    #[test]
    fn remote_queue_close_keeps_interactive_work_and_drains_background() {
        let queue = RemoteQueue::new(8, 8);
        queue
            .try_push(test_remote_work(1, "prefetch"), None)
            .unwrap();
        queue
            .try_push(
                test_remote_work_from_request(test_client_request(
                    2,
                    "flush",
                    json!({"path": "src/main.rs"}),
                )),
                None,
            )
            .unwrap();

        let drained = queue.close_and_drain_background();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].request.id, 1);
        assert_eq!(queue.pop().unwrap().request.id, 2);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn flush_queue_blocks_cached_opens_while_pending() {
        let hazard = PendingHazard::for_request(&test_client_request(1, "flush_queue", json!({})));
        let mut pending = PendingRemote::default();
        pending.register(&hazard);

        assert!(pending.blocks_path("src/main.rs"));

        pending.clear(&hazard);
        assert!(!pending.blocks_path("src/main.rs"));
    }

    #[test]
    fn background_flush_queue_does_not_block_cached_opens_while_pending() {
        let request = test_client_request(1, "flush_queue", json!({"background": true}));
        let hazard = PendingHazard::for_request(&request);
        let mut pending = PendingRemote::default();
        pending.register(&hazard);

        assert!(!pending.blocks_path("src/main.rs"));
        assert_eq!(
            RemotePriority::for_request(&request),
            RemotePriority::Background
        );
    }

    #[test]
    fn workspace_key_changes_by_host() {
        let path = PathBuf::from("/repo");
        assert_ne!(
            workspace_key(
                &RemoteTransport::from_ssh(Some("host-a".to_string()), 10).unwrap(),
                &path
            ),
            workspace_key(
                &RemoteTransport::from_ssh(Some("host-b".to_string()), 10).unwrap(),
                &path
            )
        );
    }

    #[test]
    fn ssh_remote_root_normalization_canonicalizes_windows_drive_letter() {
        let transport = RemoteTransport::from_ssh(Some("host".to_string()), 10).unwrap();
        assert_eq!(
            transport
                .normalize_remote_root(PathBuf::from("b:/repos/project"))
                .unwrap(),
            PathBuf::from("B:/repos/project")
        );
        assert_eq!(
            transport
                .normalize_remote_root(PathBuf::from("/home/me/repo"))
                .unwrap(),
            PathBuf::from("/home/me/repo")
        );
        assert!(transport
            .normalize_remote_root(PathBuf::from("/repo\nname"))
            .is_err());
    }

    #[test]
    fn workspace_key_uses_stable_transport_identity() {
        let path = PathBuf::from("/repo");
        assert_eq!(
            workspace_key(&RemoteTransport::Local, &path),
            "12641c7f13ac356c035ce63c"
        );
        assert_eq!(
            workspace_key(
                &RemoteTransport::from_ssh(Some("host".to_string()), 10).unwrap(),
                &path
            ),
            "d72defea26893914ac542b53"
        );
        assert_eq!(
            workspace_key(
                &RemoteTransport::from_ssh(Some("host".to_string()), 5).unwrap(),
                &path
            ),
            workspace_key(
                &RemoteTransport::from_ssh(Some("host".to_string()), 60).unwrap(),
                &path
            )
        );
        // This preserves the legacy key format. Future non-SSH transports must
        // use namespaced identities instead of reusing bare endpoint strings.
        assert_eq!(
            workspace_key(&RemoteTransport::Local, &path),
            workspace_key(
                &RemoteTransport::from_ssh(Some("local".to_string()), 10).unwrap(),
                &path
            )
        );
    }

    #[test]
    fn rewrites_lsp_uri_prefixes() {
        let body = br#"{"params":{"textDocument":{"uri":"file:///local/mirror/src/main.rs"},"rootPath":"/local/mirror","message":"/local/mirror should stay in prose","profile":"/local/mirror should stay profile text"}}"#;
        let rewritten = rewrite_lsp_body(body, "/local/mirror", "/remote/repo").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(
            value["params"]["textDocument"]["uri"],
            "file:///remote/repo/src/main.rs"
        );
        assert_eq!(value["params"]["rootPath"], "/remote/repo");
        assert_eq!(
            value["params"]["message"],
            "/local/mirror should stay in prose"
        );
        assert_eq!(
            value["params"]["profile"],
            "/local/mirror should stay profile text"
        );
    }

    #[test]
    fn rewrites_lsp_workspace_edit_uri_keys() {
        let body = br#"{"result":{"changes":{"file:///remote/repo/src/lib.rs":[{"newText":"x"}]},"documentChanges":[{"textDocument":{"uri":"file:///remote/repo/src/main.rs"}},{"kind":"rename","oldUri":"file:///remote/repo/src/old.rs","newUri":"file:///remote/repo/src/new.rs"}]}}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert!(value["result"]["changes"]
            .as_object()
            .unwrap()
            .contains_key("file:///local/mirror/src/lib.rs"));
        assert_eq!(
            value["result"]["documentChanges"][0]["textDocument"]["uri"],
            "file:///local/mirror/src/main.rs"
        );
        assert_eq!(
            value["result"]["documentChanges"][1]["oldUri"],
            "file:///local/mirror/src/old.rs"
        );
        assert_eq!(
            value["result"]["documentChanges"][1]["newUri"],
            "file:///local/mirror/src/new.rs"
        );
    }

    #[test]
    fn lsp_rewrite_does_not_rewrite_plain_path_object_keys() {
        let body = br#"{"result":{"metadata":{"/remote/repo/src/lib.rs":{"kind":"opaque"}}}}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();
        let metadata = value["result"]["metadata"].as_object().unwrap();

        assert!(metadata.contains_key("/remote/repo/src/lib.rs"));
        assert!(!metadata.contains_key("/local/mirror/src/lib.rs"));
    }

    #[test]
    fn rewrites_lsp_location_target_uri() {
        let body = br#"{"result":[{"targetUri":"file:///remote/repo/src/lib.rs","targetRange":{"start":{"line":0,"character":0},"end":{"line":0,"character":1}},"originSelectionRange":{"start":{"line":0,"character":0},"end":{"line":0,"character":1}}}]}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            value["result"][0]["targetUri"],
            "file:///local/mirror/src/lib.rs"
        );
    }

    #[test]
    fn rewrites_lsp_encoded_file_uri_prefixes() {
        let body =
            br#"{"params":{"textDocument":{"uri":"file:///local/mirror%20space/src/main.rs"}}}"#;
        let rewritten =
            rewrite_lsp_body(body, "/local/mirror space", "/remote/repo space").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            value["params"]["textDocument"]["uri"],
            "file:///remote/repo%20space/src/main.rs"
        );
    }

    #[test]
    fn lsp_rewrite_respects_path_boundaries() {
        let body = br#"{"params":{"textDocument":{"uri":"file:///local/mirror-other/src/main.rs"},"rootPath":"/local/mirror-other","path":"/local/mirror/src/main.rs"}}"#;
        let rewritten = rewrite_lsp_body(body, "/local/mirror", "/remote/repo").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            value["params"]["textDocument"]["uri"],
            "file:///local/mirror-other/src/main.rs"
        );
        assert_eq!(value["params"]["rootPath"], "/local/mirror-other");
        assert_eq!(value["params"]["path"], "/remote/repo/src/main.rs");
    }

    #[test]
    fn lsp_rewrite_does_not_touch_non_path_keys_with_plain_paths() {
        let body = br#"{"params":{"message":"/local/mirror/src/main.rs failed","profile":"/local/mirror/src/profile","path":"/local/mirror/src/main.rs"}}"#;
        let rewritten = rewrite_lsp_body(body, "/local/mirror", "/remote/repo").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            value["params"]["message"],
            "/local/mirror/src/main.rs failed"
        );
        assert_eq!(value["params"]["profile"], "/local/mirror/src/profile");
        assert_eq!(value["params"]["path"], "/remote/repo/src/main.rs");
    }

    #[test]
    fn lsp_rewrite_does_not_rewrite_file_uri_prose() {
        let body = br#"{"params":{"message":"file:///remote/repo/src/lib.rs failed","detail":"file:///remote/repo/src/lib.rs:3:1","textDocument":{"uri":"file:///remote/repo/src/lib.rs"}}}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            value["params"]["message"],
            "file:///remote/repo/src/lib.rs failed"
        );
        assert_eq!(
            value["params"]["detail"],
            "file:///remote/repo/src/lib.rs:3:1"
        );
        assert_eq!(
            value["params"]["textDocument"]["uri"],
            "file:///local/mirror/src/lib.rs"
        );
    }

    #[test]
    fn lsp_rewrite_preserves_file_localhost_uri() {
        let body = br#"{"params":{"textDocument":{"uri":"file://localhost/remote/repo/src/lib.rs"},"path":"/remote/repo/src/lib.rs"}}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            value["params"]["textDocument"]["uri"],
            "file://localhost/remote/repo/src/lib.rs"
        );
        assert_eq!(value["params"]["path"], "/local/mirror/src/lib.rs");
    }

    #[test]
    fn lsp_rewrite_preserves_uri_query_and_fragment() {
        let body =
            br#"{"params":{"textDocument":{"uri":"file:///remote/repo/src/lib.rs?version=1#L4"}}}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            value["params"]["textDocument"]["uri"],
            "file:///local/mirror/src/lib.rs?version=1#L4"
        );
    }

    #[test]
    fn lsp_rewrite_does_not_drop_colliding_workspace_edit_keys() {
        let body = br#"{"result":{"changes":{"file:///remote/repo/src/lib.rs":[{"newText":"remote"}],"file:///local/mirror/src/lib.rs":[{"newText":"local"}]}}}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();
        let changes = value["result"]["changes"].as_object().unwrap();
        let edits = changes["file:///local/mirror/src/lib.rs"]
            .as_array()
            .unwrap();

        assert!(!changes.contains_key("file:///remote/repo/src/lib.rs"));
        assert_eq!(edits.len(), 2);
        assert!(edits.iter().any(|edit| edit["newText"] == "remote"));
        assert!(edits.iter().any(|edit| edit["newText"] == "local"));
    }

    #[test]
    fn rewrites_lsp_publish_diagnostics_related_information() {
        let body = br#"{"method":"textDocument/publishDiagnostics","params":{"uri":"file:///remote/repo/src/lib.rs","diagnostics":[{"relatedInformation":[{"location":{"uri":"file:///remote/repo/src/dep.rs"}}]}]}}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(value["params"]["uri"], "file:///local/mirror/src/lib.rs");
        assert_eq!(
            value["params"]["diagnostics"][0]["relatedInformation"][0]["location"]["uri"],
            "file:///local/mirror/src/dep.rs"
        );
    }

    #[test]
    fn rewrites_lsp_code_action_edits() {
        let body = br#"{"result":[{"edit":{"changes":{"file:///remote/repo/src/lib.rs":[{"newText":"x"}]},"documentChanges":[{"kind":"create","uri":"file:///remote/repo/src/new.rs"}]}}]}"#;
        let rewritten = rewrite_lsp_body(body, "/remote/repo", "/local/mirror").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();

        assert!(value["result"][0]["edit"]["changes"]
            .as_object()
            .unwrap()
            .contains_key("file:///local/mirror/src/lib.rs"));
        assert_eq!(
            value["result"][0]["edit"]["documentChanges"][0]["uri"],
            "file:///local/mirror/src/new.rs"
        );
    }

    #[test]
    fn agent_local_transport_launches_agent_directly() {
        let plan = RemoteTransport::from_ssh(None, 10)
            .unwrap()
            .agent_plan(
                "nrm-agent",
                Path::new("/tmp/repo with spaces"),
                &test_posix_host(),
            )
            .unwrap();

        assert_eq!(plan.program, "nrm-agent");
        assert_eq!(plan.args, vec!["serve", "--root", "/tmp/repo with spaces"]);
        assert_eq!(plan.current_dir, None);
    }

    #[test]
    fn agent_ssh_transport_uses_quoted_remote_command_and_connection_options() {
        let plan = RemoteTransport::from_ssh(Some("host".to_string()), 7)
            .unwrap()
            .agent_plan(
                "nrm-agent",
                Path::new("/tmp/repo with 'quote' ; x"),
                &test_posix_host(),
            )
            .unwrap();

        assert_eq!(plan.program, "ssh");
        assert_eq!(plan.current_dir, None);
        assert_eq!(
            &plan.args[..plan.args.len() - 1],
            vec![
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=7",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=none",
                "--",
                "host"
            ]
        );
        let remote_command = plan.args.last().unwrap();
        assert!(remote_command.starts_with("'sh' '-c'"));
        assert!(remote_command.contains("NRM_AGENT_LAUNCH_V1"));
        assert!(remote_command.contains("FAILURE"));
        assert!(remote_command.contains("READY"));
        assert!(remote_command.contains("'nrm-agent-launch' 'nrm-agent'"));
        assert!(remote_command.contains("'/tmp/repo with '\\''quote'\\'' ; x'"));
    }

    #[test]
    fn agent_windows_ssh_transport_uses_encoded_powershell_and_canonical_drive_root() {
        let plan = RemoteTransport::from_ssh(Some("windows-host".to_string()), 7)
            .unwrap()
            .agent_plan(
                "nrm-agent",
                Path::new("B:/repo with 'quote' ; x"),
                &test_windows_host(),
            )
            .unwrap();

        assert_eq!(plan.program, "ssh");
        assert_eq!(plan.args[plan.args.len() - 2], "windows-host");
        let remote_command = plan.args.last().unwrap();
        assert!(remote_command.starts_with("powershell.exe -NoLogo -NoProfile"));
        assert!(!remote_command.contains("repo with"));
        assert!(!remote_command.contains("'quote'"));
    }

    #[test]
    fn windows_ssh_planners_reject_posix_unc_and_drive_relative_roots() {
        let transport = RemoteTransport::from_ssh(Some("windows-host".to_string()), 7).unwrap();
        let host = test_windows_host();
        for root in ["/repo", "//server/share", "B:relative", "B:\\repo"] {
            let error = transport
                .agent_plan("nrm-agent", Path::new(root), &host)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("Windows remote root") || error.contains("UNC"),
                "{root}: {error}"
            );
        }
    }

    #[test]
    fn lsp_local_launch_runs_in_remote_root() {
        let launch = LspLaunch::new(
            PathBuf::from("/repo"),
            RemoteTransport::Local,
            vec!["rust-analyzer".to_string(), "--stdio".to_string()],
            &test_posix_host(),
        )
        .unwrap();

        assert_eq!(launch.plan.program, "rust-analyzer");
        assert_eq!(launch.plan.args, vec!["--stdio"]);
        assert_eq!(launch.plan.current_dir.as_deref(), Some(Path::new("/repo")));
    }

    #[test]
    fn lsp_ssh_launch_uses_remote_root_and_connection_options() {
        let launch = LspLaunch::new(
            PathBuf::from("/tmp/repo with 'quote' ; x"),
            RemoteTransport::from_ssh(Some("host".to_string()), 7).unwrap(),
            vec![
                "rust-analyzer".to_string(),
                "--config".to_string(),
                "check.command=\"clippy\"; $(echo no)".to_string(),
            ],
            &test_posix_host(),
        )
        .unwrap();

        assert_eq!(launch.plan.program, "ssh");
        assert_eq!(launch.plan.current_dir, None);
        assert_eq!(
            launch.plan.args,
            vec![
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=7",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=none",
                "--",
                "host",
                "'sh' '-lc' 'cd \"$1\" && shift && exec \"$@\"' 'nrm-lsp-proxy' '/tmp/repo with '\\''quote'\\'' ; x' 'rust-analyzer' '--config' 'check.command=\"clippy\"; $(echo no)'"
            ]
        );
    }

    #[test]
    fn lsp_windows_ssh_launch_uses_encoded_powershell_relay() {
        let launch = LspLaunch::new(
            PathBuf::from("B:/repo with space"),
            RemoteTransport::from_ssh(Some("windows-host".to_string()), 7).unwrap(),
            vec![
                "rust-analyzer.exe".to_string(),
                "--config".to_string(),
                "check.command=clippy; Write-Output owned".to_string(),
            ],
            &test_windows_host(),
        )
        .unwrap();

        assert_eq!(launch.plan.program, "ssh");
        let remote_command = launch.plan.args.last().unwrap();
        assert!(remote_command.starts_with("powershell.exe -NoLogo -NoProfile"));
        assert!(!remote_command.contains("Write-Output owned"));
        assert!(!remote_command.contains("repo with space"));
    }

    #[test]
    fn remote_host_cache_is_shared_across_agent_lanes_and_can_be_invalidated() {
        let read = AgentClient::new(
            "nrm-agent".to_string(),
            None,
            RemoteTransport::from_ssh(Some("host".to_string()), 10).unwrap(),
            PathBuf::from("/repo"),
            Duration::from_secs(30),
            AgentInterrupt::default(),
        );
        let write = read.clone_for_lane(AgentInterrupt::default());
        *read.launch.remote_host_info.lock().unwrap() = Some(test_posix_host());

        assert_eq!(
            write.launch.cached_remote_host_info().unwrap().target,
            "x86_64-unknown-linux-musl"
        );
        write.launch.invalidate_remote_host_info();
        assert!(read.launch.cached_remote_host_info().is_none());
    }

    #[test]
    fn fast_workspace_info_does_not_wait_for_remote_host_detection_lock() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let sidecar = test_sidecar(mirror);
        let fast =
            FastState::from_sidecar(&sidecar, Arc::new(Mutex::new(PendingRemote::default())));
        let _detection_guard = sidecar.agent.launch.remote_host_info.lock().unwrap();

        let info = fast.workspace_info();

        assert!(info.get("remote_host").is_none());
        assert_eq!(info["remote_status"], "unchecked");
    }

    #[test]
    fn local_host_detection_does_not_apply_ssh_root_syntax() {
        let client = AgentClient::new(
            "nrm-agent".to_string(),
            None,
            RemoteTransport::Local,
            PathBuf::from(r"C:\repo"),
            Duration::from_secs(30),
            AgentInterrupt::default(),
        );

        client.launch.remote_host_info().unwrap();
    }

    #[test]
    fn agent_transport_failure_invalidates_shared_remote_host_cache() {
        let read = AgentClient::new(
            "nrm-agent".to_string(),
            None,
            RemoteTransport::from_ssh(Some("host".to_string()), 10).unwrap(),
            PathBuf::from("/repo"),
            Duration::from_secs(30),
            AgentInterrupt::default(),
        );
        let mut write = read.clone_for_lane(AgentInterrupt::default());
        *read.launch.remote_host_info.lock().unwrap() = Some(test_posix_host());

        let error = write
            .handle_worker_reply(
                AgentWorkerReply::TransportError("ssh transport closed".to_string()),
                &Request::Shutdown,
            )
            .unwrap_err()
            .to_string();

        assert!(error.contains("ssh transport closed"));
        assert!(read.launch.cached_remote_host_info().is_none());
    }

    #[test]
    fn shell_quote_handles_metacharacters() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("two words"), "'two words'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("semi; $(echo nope)"), "'semi; $(echo nope)'");
        assert_eq!(shell_quote("line\nbreak"), "'line\nbreak'");
    }

    #[cfg(unix)]
    #[test]
    fn lsp_ssh_remote_command_preserves_cwd_and_args_through_shell_parse() {
        let dir = tempdir().unwrap();
        let remote_root = dir.path().join("repo with 'quote' ; x");
        fs::create_dir_all(&remote_root).unwrap();
        let remote_command = posix_lsp_remote_command(
            remote_root.clone(),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf 'PWD=<%s>\\nARG=<%s>\\n' \"$PWD\" \"$1\"".to_string(),
                "inner".to_string(),
                "arg with spaces; $(echo nope)".to_string(),
            ],
        );

        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(remote_command)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(&format!("PWD=<{}>", remote_root.display())));
        assert!(stdout.contains("ARG=<arg with spaces; $(echo nope)>"));
    }

    #[cfg(unix)]
    #[test]
    fn lsp_wait_reports_child_exit_status() {
        let mut child = Command::new("sh").arg("-c").arg("exit 7").spawn().unwrap();
        let status = wait_lsp_child_with_grace(&mut child, Duration::from_secs(1)).unwrap();
        assert_eq!(status.code(), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn lsp_wait_kills_stalled_child_after_grace() {
        let mut child = Command::new("sh").arg("-c").arg("sleep 5").spawn().unwrap();
        let started = Instant::now();
        // Leave enough of the grace period for macOS to schedule and reap a
        // SIGKILLed child while remaining far below its natural five seconds.
        let err = wait_lsp_child_with_grace(&mut child, Duration::from_millis(500)).unwrap_err();
        let elapsed = started.elapsed();
        assert!(err.to_string().contains("killed with"), "{err:#}");
        assert!(
            elapsed < Duration::from_secs(2),
            "wait should kill promptly, elapsed {elapsed:?}"
        );
        let status = child.try_wait().unwrap().expect("child should be reaped");
        assert!(!status.success());
    }

    #[cfg(unix)]
    #[test]
    fn lsp_upstream_eof_kills_stalled_child_after_grace() {
        let child = Arc::new(Mutex::new(
            Command::new("sh").arg("-c").arg("sleep 5").spawn().unwrap(),
        ));
        let started = Instant::now();
        // As above, exercise the killed-and-reaped path rather than making
        // the assertion depend on a 10 ms hosted-runner scheduling window.
        let err =
            finish_lsp_upstream_result(Ok(()), &child, Duration::from_millis(500)).unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            format!("{err:#}")
                .contains("language server did not stop after LSP client input closed"),
            "{err:#}"
        );
        assert!(format!("{err:#}").contains("killed with"), "{err:#}");
        assert!(
            elapsed < Duration::from_secs(2),
            "upstream EOF should not wait for natural child exit, elapsed {elapsed:?}"
        );
        let status = child
            .lock()
            .unwrap()
            .try_wait()
            .unwrap()
            .expect("child should be reaped");
        assert!(!status.success());
    }

    #[cfg(unix)]
    #[test]
    fn lsp_upstream_pending_join_returns_without_blocking() {
        let child = Arc::new(Mutex::new(
            Command::new("sh").arg("-c").arg("sleep 5").spawn().unwrap(),
        ));
        let child_for_join = Arc::clone(&child);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<(Result<()>, bool, bool)>();
        let joiner = thread::spawn(move || {
            let mut upstream = Some(thread::spawn(move || -> Result<()> {
                release_rx.recv().unwrap();
                Ok(())
            }));
            let result = join_lsp_upstream_if_finished(
                &mut upstream,
                &child_for_join,
                Duration::from_millis(100),
            );
            let upstream_pending = upstream.is_some();
            let child_running = child_for_join.lock().unwrap().try_wait().unwrap().is_none();
            done_tx
                .send((result, upstream_pending, child_running))
                .unwrap();
        });

        let (result, upstream_pending, child_running) =
            match done_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(received) => received,
                Err(_) => {
                    release_tx.send(()).unwrap();
                    joiner.join().unwrap();
                    panic!("unfinished upstream join should return promptly");
                }
            };
        result.unwrap();
        assert!(upstream_pending);
        assert!(child_running);

        release_tx.send(()).unwrap();
        joiner.join().unwrap();
        kill_and_wait_lsp_child_handle(&child, Duration::from_secs(1)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lsp_downstream_error_kills_and_reaps_child() {
        let child = Arc::new(Mutex::new(
            Command::new("sh").arg("-c").arg("sleep 5").spawn().unwrap(),
        ));
        let mut upstream = None;

        let err = fail_lsp_downstream(
            anyhow!("client stdout closed"),
            &child,
            &mut upstream,
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("LSP proxy downstream pump failed"));
        assert!(format!("{err:#}").contains("client stdout closed"));
        let status = child
            .lock()
            .unwrap()
            .try_wait()
            .unwrap()
            .expect("child should be reaped");
        assert!(!status.success());
    }

    #[cfg(unix)]
    #[test]
    fn lsp_upstream_finished_join_succeeds_without_killing_child() {
        let child = Arc::new(Mutex::new(
            Command::new("sh").arg("-c").arg("sleep 5").spawn().unwrap(),
        ));
        let mut upstream = Some(thread::spawn(|| -> Result<()> { Ok(()) }));
        while !upstream.as_ref().unwrap().is_finished() {
            thread::sleep(Duration::from_millis(1));
        }
        join_lsp_upstream_if_finished(&mut upstream, &child, Duration::from_secs(1)).unwrap();

        assert!(child.lock().unwrap().try_wait().unwrap().is_none());
        kill_and_wait_lsp_child_handle(&child, Duration::from_secs(1)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lsp_upstream_error_kills_child_handle() {
        let child = Arc::new(Mutex::new(
            Command::new("sh").arg("-c").arg("sleep 5").spawn().unwrap(),
        ));
        let mut upstream = Some(thread::spawn(|| -> Result<()> {
            bail!("upstream broken pipe")
        }));
        while !upstream.as_ref().unwrap().is_finished() {
            thread::sleep(Duration::from_millis(1));
        }

        let err = join_lsp_upstream_if_finished(&mut upstream, &child, Duration::from_secs(1))
            .unwrap_err();
        assert!(format!("{err:#}").contains("upstream broken pipe"));
        let status = child
            .lock()
            .unwrap()
            .try_wait()
            .unwrap()
            .expect("child should be reaped");
        assert!(!status.success());
    }

    #[test]
    fn remote_agent_launch_prelude_accepts_only_one_exact_bounded_record() {
        for (failure, kind) in [
            (RemoteAgentLaunchFailure::Missing, "missing"),
            (RemoteAgentLaunchFailure::NotExecutable, "not_executable"),
            (RemoteAgentLaunchFailure::RootMissing, "root_missing"),
        ] {
            let record = format!("NRM_AGENT_LAUNCH_V1\tFAILURE\t{kind}\n");
            assert_eq!(
                read_agent_launch_prelude(&mut io::Cursor::new(record)).unwrap(),
                Some(failure)
            );
        }

        assert_eq!(
            read_agent_launch_prelude(&mut io::Cursor::new(AGENT_LAUNCH_READY_RECORD)).unwrap(),
            None
        );
        for record in [
            "",
            "missing executable\n",
            "NRM_AGENT_LAUNCH_V1 READY\n",
            "NRM_AGENT_LAUNCH_V1\tFAILURE\tunknown\n",
            "NRM_AGENT_LAUNCH_V1\tFAILURE\tmissing\r\n",
            "NRM_AGENT_LAUNCH_V1\tREADY suffix\n",
            "NRM_AGENT_LAUNCH_V1\tREADY",
        ] {
            assert!(
                read_agent_launch_prelude(&mut io::Cursor::new(record)).is_err(),
                "accepted malformed launch prelude {record:?}"
            );
        }
        let oversized = format!("{}\n", "x".repeat(AGENT_LAUNCH_PRELUDE_MAX_BYTES));
        let error = read_agent_launch_prelude(&mut io::Cursor::new(oversized))
            .unwrap_err()
            .to_string();
        assert!(error.contains("exceeded"), "{error}");
    }

    #[test]
    fn agent_stderr_capture_continuously_drains_and_retains_a_bounded_tail() {
        let mut input = vec![b'x'; AGENT_STDERR_TAIL_MAX_BYTES * 3];
        input.extend_from_slice(b"final-tail");
        let capture = AgentStderrCapture::spawn(io::Cursor::new(input)).unwrap();
        capture.wait_for_finish(Duration::from_secs(1));
        let snapshot = capture.snapshot();
        assert!(capture.finish_bounded(Duration::from_secs(1)));

        assert!(snapshot.truncated);
        assert_eq!(snapshot.bytes.len(), AGENT_STDERR_TAIL_MAX_BYTES);
        assert!(snapshot.bytes.ends_with(b"final-tail"));
        assert!(snapshot.read_error.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn agent_stderr_cleanup_detaches_when_a_descendant_retains_the_pipe() {
        use std::os::unix::net::UnixStream;

        let (reader, writer) = UnixStream::pair().unwrap();
        let capture = AgentStderrCapture::spawn(reader).unwrap();
        let started = Instant::now();

        assert!(!capture.finish_bounded(Duration::from_millis(20)));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stderr cleanup blocked on an inherited pipe"
        );
        drop(writer);
    }

    #[test]
    fn agent_transport_diagnostics_strip_terminal_controls() {
        let sanitized = sanitize_agent_error_text("line\r\n\t\x1b[31mred\x1b[0m\x7f\u{0085}done");

        assert!(!sanitized.chars().any(char::is_control), "{sanitized:?}");
        assert!(sanitized.contains("[31mred [0m"));
        assert!(sanitized.ends_with(" done"));
    }

    #[cfg(unix)]
    fn probe_health_with_fake_ssh(script: &str) -> Value {
        probe_health_with_fake_ssh_timeout(script, Duration::from_secs(3))
    }

    #[cfg(unix)]
    fn probe_health_with_fake_ssh_timeout(script: &str, timeout: Duration) -> Value {
        let dir = tempdir().unwrap();
        let fake_ssh = dir.path().join("fake-ssh");
        fs::write(&fake_ssh, format!("#!/bin/sh\n{script}\n")).unwrap();
        let mut permissions = fs::metadata(&fake_ssh).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_ssh, permissions).unwrap();
        let remote_root = dir.path().join("remote-root");
        fs::create_dir_all(&remote_root).unwrap();
        let mut client = AgentClient::new(
            "nrm-agent".to_owned(),
            None,
            RemoteTransport::Ssh(SshTransport {
                program: fake_ssh,
                target: "fake.example".to_owned(),
                connect_timeout_seconds: 1,
            }),
            remote_root,
            timeout,
            AgentInterrupt::default(),
        );
        *client.launch.remote_host_info.lock().unwrap() = Some(test_posix_host());

        let _ = client.request_with_timeout(
            Request::Hello {
                client_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: PROTOCOL_VERSION,
            },
            timeout,
        );
        client.remote_health().to_value()
    }

    #[cfg(unix)]
    #[test]
    fn fake_ssh_launch_diagnostics_authorize_only_the_first_exact_stdout_prelude() {
        for (kind, code, expected) in [
            ("missing", 127, "missing"),
            ("not_executable", 126, "not_executable"),
            ("root_missing", 66, "root_missing"),
        ] {
            let health = probe_health_with_fake_ssh(&format!(
                "printf 'NRM_AGENT_LAUNCH_V1\\tFAILURE\\t{kind}\\n'; exit {code}"
            ));
            assert_eq!(health["agent_launch_failure"], expected);
        }

        for script in [
            "printf 'nrm-agent: not found; package version mismatch; protocol version mismatch\\n' >&2; exit 127",
            "printf 'NRM_AGENT_LAUNCH_ERROR_V1\\tmissing\\n' >&2; exit 126",
            "printf 'NRM_AGENT_LAUNCH_ERROR_V1\\tmissing\\nNRM_AGENT_LAUNCH_ERROR_V1\\tmissing\\n' >&2; exit 127",
            "printf 'NRM_AGENT_LAUNCH_ERROR_V1\\tunknown\\n' >&2; exit 127",
            "printf 'NRM_AGENT_LAUNCH_V1\\tFAILURE\\tmissing\\n' >&2; exit 127",
            "printf 'NRM_AGENT_LAUNCH_V1\\tREADY\\n'; printf 'NRM_AGENT_LAUNCH_V1\\tFAILURE\\tmissing\\n' >&2; exit 127",
            "printf 'Permission denied\\n' >&2; exit 255",
        ] {
            let health = probe_health_with_fake_ssh(script);
            assert!(health.get("agent_launch_failure").is_none(), "{health}");
            assert!(
                health.get("agent_compatibility_failure").is_none(),
                "{health}"
            );
            assert_eq!(classify_remote_agent_status(&health), "unavailable");
        }
    }

    #[cfg(unix)]
    #[test]
    fn fake_ssh_separated_stderr_markers_never_authorize_install_mutation() {
        let started = Instant::now();
        let health = probe_health_with_fake_ssh(
            "printf 'NRM_AGENT_LAUNCH_V1\\tREADY\\n'; i=0; while [ \"$i\" -lt 4096 ]; do printf '0123456789abcdef0123456789abcdef' >&2; i=$((i+1)); done; printf '\\nNRM_AGENT_LAUNCH_V1\\tFAILURE\\tmissing\\n' >&2; exit 127",
        );

        assert!(health.get("agent_launch_failure").is_none(), "{health}");
        assert_eq!(classify_remote_agent_status(&health), "unavailable");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn fake_ssh_rejects_missing_malformed_and_oversized_launch_preludes() {
        let oversized = "x".repeat(AGENT_LAUNCH_PRELUDE_MAX_BYTES + 1);
        for script in [
            "exit 127".to_string(),
            "printf 'NRM_AGENT_LAUNCH_V1 READY\\n'; exit 127".to_string(),
            "printf 'NRM_AGENT_LAUNCH_V1\\tFAILURE\\tunknown\\n'; exit 127".to_string(),
            format!("printf '%s\\n' '{oversized}'; exit 127"),
        ] {
            let health = probe_health_with_fake_ssh(&script);
            assert!(health.get("agent_launch_failure").is_none(), "{health}");
            assert!(
                health.get("agent_compatibility_failure").is_none(),
                "{health}"
            );
            assert_eq!(classify_remote_agent_status(&health), "unavailable");
        }
    }

    #[cfg(unix)]
    #[test]
    fn fake_ssh_partial_launch_prelude_respects_the_request_timeout() {
        let started = Instant::now();
        let health = probe_health_with_fake_ssh_timeout(
            "printf 'NRM_AGENT_LAUNCH_V1\\tREADY'; sleep 60",
            Duration::from_millis(50),
        );

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(health.get("agent_launch_failure").is_none(), "{health}");
        assert_eq!(classify_remote_agent_status(&health), "unavailable");
        assert!(health["remote_error"]
            .as_str()
            .is_some_and(|error| error.contains("timed out")));
    }

    #[cfg(unix)]
    #[test]
    fn fake_ssh_transport_error_health_contains_no_terminal_controls() {
        let health = probe_health_with_fake_ssh(
            "printf 'line\\n\\033[31mred\\033[0m\\t\\177done\\n' >&2; exit 255",
        );
        let error = health["remote_error"].as_str().unwrap();

        assert!(!error.chars().any(char::is_control), "{error:?}");
        assert!(error.contains("[31mred [0m"));
    }

    #[cfg(unix)]
    #[test]
    fn agent_ssh_remote_command_preserves_agent_and_root_through_shell_parse() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let remote_root = dir.path().join("repo with 'quote' ; x");
        fs::create_dir_all(&remote_root).unwrap();
        let fake_agent = dir.path().join("fake agent 'quote'; x");
        fs::write(
            &fake_agent,
            "#!/bin/sh\nprintf 'ARG1=<%s>\\nARG2=<%s>\\nARG3=<%s>\\n' \"$1\" \"$2\" \"$3\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let fake_agent = fake_agent.to_string_lossy().to_string();
        let remote_command = posix_agent_remote_command(&fake_agent, &remote_root);
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(remote_command)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.starts_with("NRM_AGENT_LAUNCH_V1\tREADY\n"));
        assert!(stdout.contains("ARG1=<serve>"));
        assert!(stdout.contains("ARG2=<--root>"));
        assert!(stdout.contains(&format!("ARG3=<{}>", remote_root.display())));
    }

    #[cfg(unix)]
    #[test]
    fn managed_agent_ssh_remote_command_prepends_home_local_bin() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let bin = home.join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        let fake_agent = bin.join("nrm-agent");
        fs::write(
            &fake_agent,
            "#!/bin/sh\nprintf 'ARG1=<%s>\\nARG2=<%s>\\nARG3=<%s>\\n' \"$1\" \"$2\" \"$3\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let remote_root = dir.path().join("repo with spaces");
        fs::create_dir_all(&remote_root).unwrap();
        let remote_command = posix_agent_remote_command("nrm-agent", &remote_root);
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(remote_command)
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.starts_with("NRM_AGENT_LAUNCH_V1\tREADY\n"));
        assert!(stdout.contains("ARG1=<serve>"));
        assert!(stdout.contains("ARG2=<--root>"));
        assert!(stdout.contains(&format!("ARG3=<{}>", remote_root.display())));
    }

    #[cfg(unix)]
    #[test]
    fn posix_agent_launcher_reports_exact_pre_exec_failures() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir_all(&root).unwrap();
        let missing = dir.path().join("missing-agent");
        let non_executable = dir.path().join("non-executable-agent");
        fs::write(&non_executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o644)).unwrap();
        let missing_root = dir.path().join("missing-root");

        for (agent, remote_root, expected_code, expected_kind) in [
            (missing.as_path(), root.as_path(), 127, "missing"),
            (
                non_executable.as_path(),
                root.as_path(),
                126,
                "not_executable",
            ),
            (
                missing.as_path(),
                missing_root.as_path(),
                66,
                "root_missing",
            ),
        ] {
            let output = Command::new("sh")
                .arg("-c")
                .arg(posix_agent_remote_command(
                    agent.to_string_lossy().as_ref(),
                    remote_root,
                ))
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(expected_code));
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                format!("NRM_AGENT_LAUNCH_V1\tFAILURE\t{expected_kind}\n")
            );
            assert!(output.stderr.is_empty());
        }
    }

    #[cfg(unix)]
    fn probe_health_through_posix_launcher(agent: &Path, remote_root: &Path) -> Value {
        let dir = tempdir().unwrap();
        let fake_ssh = dir.path().join("fake-ssh-exec");
        fs::write(
            &fake_ssh,
            "#!/bin/sh\nfor remote_command do :; done\nexec sh -c \"$remote_command\"\n",
        )
        .unwrap();
        fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o755)).unwrap();
        let mut client = AgentClient::new(
            agent.to_string_lossy().into_owned(),
            None,
            RemoteTransport::Ssh(SshTransport {
                program: fake_ssh,
                target: "fake.example".to_owned(),
                connect_timeout_seconds: 1,
            }),
            remote_root.to_path_buf(),
            Duration::from_secs(3),
            AgentInterrupt::default(),
        );
        *client.launch.remote_host_info.lock().unwrap() = Some(test_posix_host());

        let _ = client.request_with_timeout(
            Request::Hello {
                client_version: env!("CARGO_PKG_VERSION").to_owned(),
                protocol_version: PROTOCOL_VERSION,
            },
            Duration::from_secs(3),
        );
        client.remote_health().to_value()
    }

    #[cfg(unix)]
    #[test]
    fn posix_exec_format_and_missing_loader_failures_are_safe_untyped_skips() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir_all(&root).unwrap();
        let garbage = dir.path().join("garbage-agent");
        fs::write(&garbage, b"\x7fnot-an-executable\0\n").unwrap();
        fs::set_permissions(&garbage, fs::Permissions::from_mode(0o755)).unwrap();
        let missing_loader = dir.path().join("missing-loader-agent");
        fs::write(
            &missing_loader,
            b"#!/definitely/missing/nrm-interpreter\nexit 0\n",
        )
        .unwrap();
        fs::set_permissions(&missing_loader, fs::Permissions::from_mode(0o755)).unwrap();

        for agent in [&garbage, &missing_loader] {
            let output = Command::new("sh")
                .arg("-c")
                .arg(posix_agent_remote_command(
                    agent.to_string_lossy().as_ref(),
                    &root,
                ))
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(output.stdout.starts_with(AGENT_LAUNCH_READY_RECORD));
            assert!(
                !output
                    .stdout
                    .windows(AGENT_LAUNCH_FAILURE_PREFIX.len())
                    .any(|window| window == AGENT_LAUNCH_FAILURE_PREFIX),
                "post-READY exec failure must not become a trusted launch failure"
            );

            let health = probe_health_through_posix_launcher(agent, &root);
            assert!(health.get("agent_launch_failure").is_none(), "{health}");
            assert_eq!(classify_remote_agent_status(&health), "unavailable");
        }
    }

    #[cfg(unix)]
    #[test]
    fn active_open_preemption_cleans_partial_hydration() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let remote_root = dir.path().join("remote");
        fs::create_dir_all(&remote_root).unwrap();

        let fake_agent = dir.path().join("fake-agent");
        fs::write(&fake_agent, "#!/bin/sh\nexec sleep 60\n").unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let interrupt = AgentInterrupt::default();
        let mut sidecar = Sidecar::new(
            remote_root,
            RemoteTransport::Local,
            fake_agent.to_string_lossy().to_string(),
            None,
            Some(dir.path().join("state")),
            30_000,
            interrupt.clone(),
        )
        .unwrap();

        let local_path = sidecar.mirror.local_path("src/main.rs").unwrap();
        let part_path = local_path.with_extension("nrm-part");
        let preempt = sidecar.agent.preempt_handle();
        let preempt_epoch = sidecar.agent.preempt_epoch();
        let handle =
            thread::spawn(move || sidecar.open(json!({"path": "src/main.rs"}), preempt_epoch));

        for _ in 0..100 {
            if interrupt.has_current_abort() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(interrupt.has_current_abort());

        preempt.request_preemption();

        let result = handle.join().unwrap().unwrap();
        assert_eq!(result["preempted"], true);
        assert_eq!(result["path"], "src/main.rs");
        assert!(!part_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn remote_probe_preemption_reports_noop_probe_result() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let remote_root = dir.path().join("remote");
        fs::create_dir_all(&remote_root).unwrap();

        let fake_agent = dir.path().join("fake-agent");
        fs::write(&fake_agent, "#!/bin/sh\nexec sleep 60\n").unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let interrupt = AgentInterrupt::default();
        let mut sidecar = Sidecar::new(
            remote_root,
            RemoteTransport::Local,
            fake_agent.to_string_lossy().to_string(),
            None,
            Some(dir.path().join("state")),
            30_000,
            interrupt.clone(),
        )
        .unwrap();

        let preempt = sidecar.agent.preempt_handle();
        let preempt_epoch = sidecar.agent.preempt_epoch();
        let handle = thread::spawn(move || sidecar.remote_probe(preempt_epoch));

        for _ in 0..100 {
            if interrupt.has_current_abort() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(interrupt.has_current_abort());

        preempt.request_preemption();

        let result = handle.join().unwrap();
        assert_eq!(result["preempted"], true);
        assert_eq!(result["remote_status"], "unchecked");
        assert_eq!(result["remote_checked"], false);
        assert_eq!(result["remote_available"], false);
    }

    #[test]
    fn agent_frame_requires_matching_response_id() {
        let response = RpcMessage::Response {
            id: 999,
            response: Response::Ack,
        };
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &response).unwrap();
        let mut stdout = BufReader::new(std::io::Cursor::new(encoded));
        let mut stdin = Vec::new();

        let error = send_agent_frame(&mut stdin, &mut stdout, 7, Request::Shutdown)
            .unwrap_err()
            .to_string();
        assert!(error.contains("response id mismatch"));
    }

    #[test]
    fn framed_agent_session_exchanges_request_and_response() {
        let mut inbound = Vec::new();
        write_frame(
            &mut inbound,
            &RpcMessage::Response {
                id: 7,
                response: Response::Ack,
            },
        )
        .unwrap();
        let mut session = FramedAgentSession::new(Vec::new(), io::Cursor::new(inbound));

        let reply = session.request(7, Request::Shutdown).unwrap();

        assert!(matches!(reply, AgentWorkerReply::Response(Response::Ack)));
        let outbound = session.into_writer();
        let mut outbound = BufReader::new(io::Cursor::new(outbound));
        let message: RpcMessage = read_frame(&mut outbound).unwrap();
        assert!(matches!(
            message,
            RpcMessage::Request {
                id: 7,
                request: Request::Shutdown
            }
        ));
    }

    #[test]
    fn framed_agent_session_consumes_ready_prelude_without_losing_binary_rpc_bytes() {
        let mut inbound = AGENT_LAUNCH_READY_RECORD.to_vec();
        write_frame(
            &mut inbound,
            &RpcMessage::Response {
                id: 7,
                response: Response::Ack,
            },
        )
        .unwrap();
        let mut session =
            FramedAgentSession::new_with_launch_prelude(Vec::new(), io::Cursor::new(inbound));

        let reply = session.request(7, Request::Shutdown).unwrap();

        assert!(matches!(reply, AgentWorkerReply::Response(Response::Ack)));
        let mut outbound = BufReader::new(io::Cursor::new(session.into_writer()));
        let message: RpcMessage = read_frame(&mut outbound).unwrap();
        assert!(matches!(
            message,
            RpcMessage::Request {
                id: 7,
                request: Request::Shutdown
            }
        ));
    }

    #[test]
    fn framed_agent_session_returns_launch_failure_without_sending_rpc() {
        let inbound = b"NRM_AGENT_LAUNCH_V1\tFAILURE\tmissing\n";
        let mut session = FramedAgentSession::new_with_launch_prelude(
            Vec::new(),
            io::Cursor::new(inbound.as_slice()),
        );

        let reply = session.request(7, Request::Shutdown).unwrap();

        assert!(matches!(
            reply,
            AgentWorkerReply::LaunchError(RemoteAgentLaunchFailure::Missing)
        ));
        assert!(session.into_writer().is_empty());
    }

    #[test]
    fn framed_agent_session_ignores_windows_ssh_transport_bom() {
        let mut inbound = vec![0xef, 0xbb, 0xbf];
        inbound.extend_from_slice(AGENT_LAUNCH_READY_RECORD);
        write_frame(
            &mut inbound,
            &RpcMessage::Response {
                id: 7,
                response: Response::Ack,
            },
        )
        .unwrap();
        let reader = LeadingBomReader::new(io::Cursor::new(inbound));
        let mut session = FramedAgentSession::new_with_launch_prelude(Vec::new(), reader);

        let reply = session.request(7, Request::Shutdown).unwrap();

        assert!(matches!(reply, AgentWorkerReply::Response(Response::Ack)));
    }

    #[test]
    fn lsp_reader_ignores_windows_ssh_transport_bom() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":null}"#;
        let mut inbound = vec![0xef, 0xbb, 0xbf];
        write_lsp_message(&mut inbound, body).unwrap();
        let mut reader = BufReader::new(LeadingBomReader::new(io::Cursor::new(inbound)));

        assert_eq!(read_lsp_message(&mut reader).unwrap().unwrap(), body);
    }

    #[test]
    fn framed_agent_session_reports_response_id_mismatch() {
        let mut inbound = Vec::new();
        write_frame(
            &mut inbound,
            &RpcMessage::Response {
                id: 999,
                response: Response::Ack,
            },
        )
        .unwrap();
        let mut session = FramedAgentSession::new(Vec::new(), io::Cursor::new(inbound));

        let error = session
            .request(7, Request::Shutdown)
            .unwrap_err()
            .to_string();

        assert!(error.contains("agent response id mismatch"));
    }

    #[test]
    fn framed_agent_session_rejects_unexpected_request_frame() {
        let mut inbound = Vec::new();
        write_frame(
            &mut inbound,
            &RpcMessage::Request {
                id: 7,
                request: Request::Shutdown,
            },
        )
        .unwrap();
        let mut session = FramedAgentSession::new(Vec::new(), io::Cursor::new(inbound));

        let error = session
            .request(7, Request::Shutdown)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unexpected agent frame"));
    }

    #[test]
    fn agent_request_after_shutdown_does_not_spawn_worker() {
        let interrupt = AgentInterrupt::default();
        interrupt.request_shutdown();
        let mut client = AgentClient::new(
            "unused-agent".to_string(),
            None,
            RemoteTransport::Local,
            PathBuf::from("/unused"),
            Duration::from_secs(30),
            interrupt.clone(),
        );

        let error = client.request(Request::Shutdown).unwrap_err().to_string();

        assert!(error.contains("shutdown"));
        assert!(!interrupt.has_current_abort());
    }

    #[test]
    fn agent_request_uses_backoff_after_launch_failure() {
        let dir = tempdir().unwrap();
        let mut client = AgentClient::new(
            dir.path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            AgentInterrupt::default(),
        );

        let first = client
            .request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap_err()
            .to_string();
        let second = client
            .request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap_err()
            .to_string();

        assert!(first.contains("failed to launch agent"));
        assert!(second.contains("remote unavailable; retry after"));
        assert!(second.contains("failed to launch agent"));
    }

    #[test]
    fn read_lane_backoff_does_not_block_write_lane_after_launch_failure() {
        let dir = tempdir().unwrap();
        let mut read_client = AgentClient::new(
            dir.path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            AgentInterrupt::default(),
        );
        let mut write_client = read_client.clone_for_lane(AgentInterrupt::default());

        let first = read_client
            .request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap_err()
            .to_string();
        let second = write_client
            .request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap_err()
            .to_string();

        assert!(first.contains("failed to launch agent"));
        assert!(second.contains("failed to launch agent"));
        assert!(!second.contains("remote unavailable; retry after"));
    }

    #[test]
    fn write_lane_backoff_blocks_subsequent_write_lane_attempts() {
        let dir = tempdir().unwrap();
        let read_client = AgentClient::new(
            dir.path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            AgentInterrupt::default(),
        );
        let mut write_client = read_client.clone_for_lane(AgentInterrupt::default());

        let first = write_client
            .request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap_err()
            .to_string();
        let second = write_client
            .request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap_err()
            .to_string();

        assert!(first.contains("failed to launch agent"));
        assert!(second.contains("remote unavailable; retry after"));
        assert!(second.contains("failed to launch agent"));
    }

    #[test]
    fn shared_remote_health_reports_write_lane_error() {
        let dir = tempdir().unwrap();
        let read_client = AgentClient::new(
            dir.path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            AgentInterrupt::default(),
        );
        let mut write_client = read_client.clone_for_lane(AgentInterrupt::default());

        let error = write_client
            .request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap_err()
            .to_string();
        let health = read_client.remote_health();

        assert!(error.contains("failed to launch agent"));
        assert_eq!(health.state, RemoteHealthState::Unavailable);
        assert!(health
            .error
            .as_deref()
            .unwrap()
            .contains("failed to launch agent"));
    }

    #[test]
    fn shared_remote_health_reports_latest_lane_error() {
        let dir = tempdir().unwrap();
        let mut read_client = AgentClient::new(
            dir.path().join("agent").to_string_lossy().to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            AgentInterrupt::default(),
        );
        let mut write_client = read_client.clone_for_lane(AgentInterrupt::default());

        let _ = write_client.mark_remote_unavailable("write lane failed first");
        thread::sleep(Duration::from_millis(1));
        let _ = read_client.mark_remote_unavailable("read lane failed second");

        let health = write_client.remote_health();

        assert_eq!(health.state, RemoteHealthState::Unavailable);
        assert_eq!(health.error.as_deref(), Some("read lane failed second"));
    }

    #[cfg(unix)]
    #[test]
    fn agent_request_times_out_when_agent_stalls() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let fake_agent = dir.path().join("fake-agent");
        fs::write(&fake_agent, "#!/bin/sh\nexec sleep 60\n").unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let mut client = AgentClient::new(
            fake_agent.to_string_lossy().to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            AgentInterrupt::default(),
        );
        let error = client
            .request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"));
    }

    #[cfg(unix)]
    #[test]
    fn agent_interrupt_kills_stalled_request_before_timeout() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let fake_agent = dir.path().join("fake-agent");
        fs::write(&fake_agent, "#!/bin/sh\nsleep 60\n").unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let interrupt = AgentInterrupt::default();
        let client_interrupt = interrupt.clone();
        let mut client = AgentClient::new(
            fake_agent.to_string_lossy().to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            client_interrupt,
        );
        let started = std::time::Instant::now();
        let handle = thread::spawn(move || {
            client.request(Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION,
            })
        });

        for _ in 0..100 {
            if interrupt.has_current_abort() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(interrupt.has_current_abort());
        interrupt.kill_current();

        let error = handle.join().unwrap().unwrap_err().to_string();
        assert!(!error.is_empty());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn agent_preemption_kills_stalled_background_request_before_timeout() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let fake_agent = dir.path().join("fake-agent");
        fs::write(&fake_agent, "#!/bin/sh\nsleep 60\n").unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let interrupt = AgentInterrupt::default();
        let mut client = AgentClient::new(
            fake_agent.to_string_lossy().to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            interrupt.clone(),
        );
        let preempt = client.preempt_handle();
        let started = Instant::now();
        let preempt_epoch = client.preempt_epoch();
        let handle = thread::spawn(move || {
            client.request_maybe_preemptible_since(
                Request::Hello {
                    client_version: "test".to_string(),
                    protocol_version: PROTOCOL_VERSION,
                },
                preempt_epoch,
            )
        });

        for _ in 0..100 {
            if interrupt.has_current_abort() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(interrupt.has_current_abort());

        preempt.request_preemption();

        assert!(matches!(
            handle.join().unwrap().unwrap(),
            AgentRequestOutcome::Preempted
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn agent_preemption_uses_epoch_captured_before_local_background_prep() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let fake_agent = dir.path().join("fake-agent");
        fs::write(&fake_agent, "#!/bin/sh\nsleep 60\n").unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let interrupt = AgentInterrupt::default();
        let mut client = AgentClient::new(
            fake_agent.to_string_lossy().to_string(),
            None,
            RemoteTransport::Local,
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            interrupt,
        );
        let preempt = client.preempt_handle();
        let preempt_epoch = client.preempt_epoch();
        preempt.request_preemption();
        let started = Instant::now();

        let outcome = client
            .request_maybe_preemptible_since(
                Request::Hello {
                    client_version: "test".to_string(),
                    protocol_version: PROTOCOL_VERSION,
                },
                preempt_epoch,
            )
            .unwrap();

        assert!(matches!(outcome, AgentRequestOutcome::Preempted));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
