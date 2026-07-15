use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ignore::{Walk, WalkBuilder};
use nrm_protocol::{
    read_frame, write_frame, BatchReadError, BatchReadFile, BatchValidateFile, CapabilitySet,
    FileMeta, GitCommandOutput, Request, Response, RpcError, RpcMessage, SaveApplied, SaveConflict,
    SaveOutcome, SearchHit, WriteStartOutcome, WriteStarted, MAX_CONFLICT_CONTENT_BYTES,
    MAX_FRAME_LEN, PROTOCOL_VERSION,
};
#[cfg(test)]
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AGENT_READ_RESPONSE_MAX_BYTES: u64 = (MAX_FRAME_LEN - (1024 * 1024)) as u64;
const AGENT_BATCH_TOTAL_MAX_BYTES: u64 = AGENT_READ_RESPONSE_MAX_BYTES;
const AGENT_GREP_HARD_MAX_FILES: usize = 50_000;
const AGENT_GREP_HARD_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const AGENT_GREP_HARD_MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const AGENT_GREP_HARD_MAX_HIT_TEXT_BYTES: usize = 4 * 1024 * 1024;
const AGENT_GREP_HARD_MAX_LINE_BYTES: usize = 64 * 1024;
const AGENT_GIT_OUTPUT_MAX_BYTES: u64 = 1024 * 1024;
const MAX_ACTIVE_UPLOADS: usize = 8;
const MAX_ACTIVE_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;
const UPLOAD_TTL: Duration = Duration::from_secs(10 * 60);

#[cfg(test)]
thread_local! {
    static FILE_META_CALLS: Cell<usize> = const { Cell::new(0) };
    static FILE_CONTENT_READS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug)]
struct BatchTotalCapExceeded {
    path: String,
    file_size: u64,
    remaining_total_bytes: u64,
}

impl std::fmt::Display for BatchTotalCapExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "batch total cap exceeded for {}: file_size={} remaining_total_bytes={}",
            self.path, self.file_size, self.remaining_total_bytes
        )
    }
}

impl std::error::Error for BatchTotalCapExceeded {}

struct AgentState {
    root: PathBuf,
    uploads: HashMap<String, PendingUpload>,
    active_write_targets: HashSet<String>,
    grep_sessions: HashMap<String, GrepSession>,
    next_grep_session: u64,
}

struct GrepSession {
    query: String,
    walk: Walk,
}

#[derive(Clone, Copy, Default)]
struct GrepCaps {
    max_files: Option<usize>,
    max_file_bytes: Option<u64>,
    max_total_bytes: Option<u64>,
}

const MAX_GREP_SESSIONS: usize = 8;

struct PendingUpload {
    path: String,
    target_abs: PathBuf,
    target_keys: Vec<String>,
    expected_hash: Option<String>,
    content_hash: String,
    size: u64,
    tmp_path: PathBuf,
    tmp_name: OsString,
    tmp_file: File,
    parent: WriteParent,
    written: u64,
    created_at: Instant,
    _lock: WriteLock,
}

struct WriteTarget {
    abs: PathBuf,
    #[cfg(any(unix, windows))]
    parent_abs: PathBuf,
}

struct WriteLock {
    _files: Vec<File>,
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        // Closing a descriptor also releases an advisory lock, but explicitly
        // unlock first so an immediate successor never depends on close timing
        // differences between supported filesystems and operating systems.
        for file in &self._files {
            let _ = fs4::FileExt::unlock(file);
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TempFileIdentity {
    #[cfg(windows)]
    windows: WindowsFileIdentity,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsFileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
struct WindowsObjectInformation {
    identity: WindowsFileIdentity,
    attributes: u32,
}

#[cfg(any(windows, test))]
#[derive(Debug)]
struct ReplacementRollbackFailed(String);

#[cfg(any(windows, test))]
impl std::fmt::Display for ReplacementRollbackFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "rollback_failed: {}", self.0)
    }
}

#[cfg(any(windows, test))]
impl std::error::Error for ReplacementRollbackFailed {}

struct OpenedContentFile {
    file: File,
    metadata: fs::Metadata,
}

struct WriteParent {
    #[cfg(unix)]
    dir: File,
    #[cfg(windows)]
    canonical_parent: PathBuf,
    #[cfg(windows)]
    pinned_directories: Vec<WindowsPinnedDirectory>,
}

#[cfg(windows)]
struct WindowsPinnedDirectory {
    path: PathBuf,
    identity: WindowsFileIdentity,
    _guard: File,
}

struct ActiveWriteRelease<'a> {
    active: &'a mut HashSet<String>,
    keys: Vec<String>,
}

impl Drop for ActiveWriteRelease<'_> {
    fn drop(&mut self) {
        for key in &self.keys {
            self.active.remove(key);
        }
    }
}

#[derive(Debug, Parser)]
#[command(version, about = "Remote workspace agent for nvim-remote-mirror")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        root: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { root } => serve(root),
    }
}

fn serve(root: PathBuf) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize root {}", root.display()))?;
    let mut state = AgentState {
        root,
        uploads: HashMap::new(),
        active_write_targets: HashSet::new(),
        grep_sessions: HashMap::new(),
        next_grep_session: 1,
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let message = match read_frame::<_, RpcMessage>(&mut reader) {
            Ok(message) => message,
            Err(error) => {
                eprintln!("nrm-agent: failed to read frame: {error}");
                break;
            }
        };

        let (id, request) = match message {
            RpcMessage::Request { id, request } => (id, request),
            RpcMessage::Cancel { id } => {
                write_frame(
                    &mut writer,
                    &RpcMessage::Error {
                        id,
                        error: RpcError {
                            code: nrm_protocol::RpcErrorCode::Cancelled,
                            message: "request cancellation is not active yet".to_string(),
                            retryable: true,
                        },
                    },
                )?;
                continue;
            }
            other => {
                eprintln!("nrm-agent: unexpected client frame: {other:?}");
                break;
            }
        };

        let shutdown = matches!(request, Request::Shutdown);
        let response = match handle_request(&mut state, request) {
            Ok(response) => RpcMessage::Response { id, response },
            Err(error) => RpcMessage::Error {
                id,
                error: RpcError::agent(error.to_string()),
            },
        };
        write_frame(&mut writer, &response)?;
        if shutdown {
            break;
        }
    }

    Ok(())
}

fn handle_request(state: &mut AgentState, request: Request) -> Result<Response> {
    match request {
        Request::Hello {
            client_version,
            protocol_version,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                bail!(
                    "protocol version mismatch: client={protocol_version} agent={PROTOCOL_VERSION}"
                );
            }
            if client_version != env!("CARGO_PKG_VERSION") {
                bail!(
                    "package version mismatch: client={client_version} agent={}",
                    env!("CARGO_PKG_VERSION")
                );
            }
            Ok(Response::Hello {
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: CapabilitySet::v1_agent(),
            })
        }
        Request::Scan { limit, after } => scan(&state.root, limit, after.as_deref()),
        Request::Stat { path } => {
            let abs = resolve_remote_path(&state.root, &path)?;
            let meta_path = existing_metadata_path(&state.root, &abs)?;
            Ok(Response::Stat {
                meta: if let Some(abs) = meta_path {
                    Some(file_meta(&state.root, &abs, false)?)
                } else {
                    None
                },
            })
        }
        Request::Checksum { path } => {
            let abs = resolve_remote_path(&state.root, &path)?;
            let hash = current_regular_file_hash(&state.root, &path, &abs)?;
            Ok(Response::Checksum { path, hash })
        }
        Request::ValidateFiles {
            paths,
            include_hash,
        } => validate_files(&state.root, paths, include_hash),
        Request::ReadFile { path, offset, len } => read_file(&state.root, path, offset, len),
        Request::ReadFiles {
            paths,
            max_file_bytes,
            max_total_bytes,
        } => read_files(&state.root, paths, max_file_bytes, max_total_bytes),
        Request::Grep {
            query,
            limit,
            after,
            max_files,
            max_file_bytes,
            max_total_bytes,
            session_id,
        } => grep_with_caps(
            state,
            &query,
            limit,
            after.as_deref(),
            session_id.as_deref(),
            GrepCaps {
                max_files,
                max_file_bytes,
                max_total_bytes,
            },
        ),
        Request::GitStatus {
            paths,
            max_output_bytes,
        } => git_status(&state.root, paths, max_output_bytes),
        Request::GitDiff {
            path,
            cached,
            max_output_bytes,
        } => git_diff(&state.root, path, cached, max_output_bytes),
        Request::GitBlame {
            path,
            max_output_bytes,
        } => git_blame(&state.root, path, max_output_bytes),
        Request::WriteFileCas {
            path,
            expected_hash,
            content,
        } => write_file_cas_state(state, path, expected_hash, content),
        Request::BeginWriteFileCas {
            path,
            expected_hash,
            content_hash,
            size,
        } => begin_write_file_cas(state, path, expected_hash, content_hash, size),
        Request::WriteFileChunk {
            upload_id,
            offset,
            content,
        } => write_file_chunk(state, upload_id, offset, content),
        Request::FinishWriteFileCas { upload_id } => finish_write_file_cas(state, upload_id),
        Request::AbortWriteFileCas { upload_id } => abort_write_file_cas(state, upload_id),
        Request::Shutdown => Ok(Response::Ack),
    }
}

fn scan(root: &Path, limit: usize, after: Option<&str>) -> Result<Response> {
    let mut entries = Vec::new();
    let mut truncated = false;
    let mut after_seen = after.is_none();

    for entry in WalkBuilder::new(root)
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_exclude(true)
        .sort_by_file_name(|a, b| a.cmp(b))
        .build()
    {
        let entry = entry?;
        let path = entry.path();
        if path == root {
            continue;
        }
        let relative = relative_path(root, path)?;
        if !after_seen {
            if after == Some(relative.as_str()) {
                after_seen = true;
            }
            continue;
        }
        if entries.len() >= limit {
            truncated = true;
            break;
        }
        let meta = file_meta(root, path, false)?;
        entries.push(meta);
    }

    Ok(Response::Scan { entries, truncated })
}

fn read_file(root: &Path, path: String, offset: u64, len: Option<u64>) -> Result<Response> {
    let mut opened = open_existing_content_file(root, &path)?;
    let file_len = opened.metadata.len();
    if offset > file_len {
        bail!("offset {offset} exceeds file length {file_len}");
    }
    opened.file.seek(SeekFrom::Start(offset))?;

    let read_len = len.unwrap_or(file_len - offset).min(file_len - offset);
    if read_len > AGENT_READ_RESPONSE_MAX_BYTES {
        bail!("read length {read_len} exceeds agent response cap {AGENT_READ_RESPONSE_MAX_BYTES}");
    }
    let mut content = vec![0_u8; read_len as usize];
    opened.file.read_exact(&mut content)?;
    let eof = offset + read_len >= file_len;
    let mut meta = file_meta_from_metadata(path.clone(), &opened.metadata, None);
    let hash = if eof {
        let hash = hash_open_file(&mut opened.file)?;
        meta.hash = Some(hash.clone());
        hash
    } else {
        String::new()
    };

    Ok(Response::ReadFile {
        path,
        offset,
        eof,
        content,
        hash,
        meta,
    })
}

fn read_files(
    root: &Path,
    paths: Vec<String>,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> Result<Response> {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut total_bytes = 0_u64;
    let mut truncated = false;
    let max_file_bytes = max_file_bytes.min(AGENT_READ_RESPONSE_MAX_BYTES);
    let max_total_bytes = max_total_bytes.min(AGENT_BATCH_TOTAL_MAX_BYTES);

    for path in paths {
        let remaining_total_bytes = max_total_bytes.saturating_sub(total_bytes);
        match read_file_for_batch(root, &path, max_file_bytes, remaining_total_bytes) {
            Ok(file) => {
                let next_total = total_bytes.saturating_add(file.content.len() as u64);
                total_bytes = next_total;
                files.push(file);
            }
            Err(error) => {
                let total_cap_exceeded = error.downcast_ref::<BatchTotalCapExceeded>().is_some();
                errors.push(BatchReadError {
                    path,
                    message: error.to_string(),
                });
                if total_cap_exceeded {
                    truncated = true;
                    break;
                }
            }
        }
    }

    Ok(Response::ReadFiles {
        files,
        errors,
        truncated,
    })
}

fn validate_files(root: &Path, paths: Vec<String>, include_hash: bool) -> Result<Response> {
    let mut files = Vec::new();
    let mut errors = Vec::new();

    for path in paths {
        match validate_one_file(root, &path, include_hash) {
            Ok(file) => files.push(file),
            Err(error) => errors.push(BatchReadError {
                path,
                message: error.to_string(),
            }),
        }
    }

    Ok(Response::ValidateFiles { files, errors })
}

fn validate_one_file(root: &Path, path: &str, include_hash: bool) -> Result<BatchValidateFile> {
    let abs = resolve_remote_path(root, path)?;
    let Some(abs) = existing_metadata_path(root, &abs)? else {
        return Ok(BatchValidateFile {
            path: path.to_string(),
            meta: None,
        });
    };
    let metadata = fs::symlink_metadata(&abs)?;
    if include_hash && metadata.is_file() {
        let mut opened = open_existing_content_file(root, path)?;
        let hash = hash_open_file(&mut opened.file)?;
        return Ok(BatchValidateFile {
            path: path.to_string(),
            meta: Some(file_meta_from_metadata(
                path.to_string(),
                &opened.metadata,
                Some(hash),
            )),
        });
    }
    Ok(BatchValidateFile {
        path: path.to_string(),
        meta: Some(file_meta(root, &abs, include_hash)?),
    })
}

fn git_status(root: &Path, paths: Vec<String>, max_output_bytes: u64) -> Result<Response> {
    let mut args = vec![
        OsString::from("status"),
        OsString::from("--porcelain=v1"),
        OsString::from("-z"),
        OsString::from("--branch"),
        OsString::from("--untracked-files=all"),
    ];
    args.push(OsString::from("--"));
    if !paths.is_empty() {
        for path in paths {
            args.push(normalize_relative_path(&path)?.into_os_string());
        }
    } else {
        args.push(OsString::from("."));
    }
    let prefix = git_worktree_prefix(root);
    let response = run_git(root, args, max_output_bytes)?;
    Ok(match response {
        Response::Git { mut output } => {
            if output.status_code == Some(0) {
                output.stdout = rebase_git_status_stdout(&output.stdout, prefix.as_deref());
            }
            Response::Git { output }
        }
        other => other,
    })
}

fn git_diff(
    root: &Path,
    path: Option<String>,
    cached: bool,
    max_output_bytes: u64,
) -> Result<Response> {
    let mut args = vec![
        OsString::from("diff"),
        OsString::from("--no-color"),
        OsString::from("--no-ext-diff"),
        OsString::from("--no-textconv"),
        OsString::from("--relative"),
    ];
    if cached {
        args.push(OsString::from("--cached"));
    }
    args.push(OsString::from("--"));
    if let Some(path) = path {
        args.push(normalize_relative_path(&path)?.into_os_string());
    }
    run_git(root, args, max_output_bytes)
}

fn git_blame(root: &Path, path: String, max_output_bytes: u64) -> Result<Response> {
    let path = normalize_relative_path(&path)?;
    run_git(
        root,
        vec![
            OsString::from("blame"),
            OsString::from("--no-textconv"),
            OsString::from("--"),
            path.into_os_string(),
        ],
        max_output_bytes,
    )
}

fn run_git(root: &Path, args: Vec<OsString>, max_output_bytes: u64) -> Result<Response> {
    let max_output_bytes = max_output_bytes
        .min(AGENT_GIT_OUTPUT_MAX_BYTES)
        .min(usize::MAX as u64) as usize;
    let mut command = git_command(root);
    let mut child = command.args(args).spawn().context("failed to launch git")?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("git stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("git stderr was not piped"))?;
    let cap_reached = Arc::new(AtomicBool::new(false));
    let stdout_reader = read_limited_pipe(stdout, max_output_bytes, Arc::clone(&cap_reached));
    let stderr_reader = read_limited_pipe(stderr, max_output_bytes, Arc::clone(&cap_reached));
    let status = loop {
        if let Some(status) = child.try_wait().context("failed to poll git")? {
            break status;
        }
        if cap_reached.load(Ordering::SeqCst) {
            let _ = child.kill();
            break child.wait().context("failed to wait for killed git")?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let (stdout, stdout_truncated) = join_limited_pipe(stdout_reader, "stdout")?;
    let (stderr, stderr_truncated) = join_limited_pipe(stderr_reader, "stderr")?;

    Ok(Response::Git {
        output: GitCommandOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            status_code: status.code(),
            truncated: stdout_truncated || stderr_truncated,
        },
    })
}

fn git_command(root: &Path) -> ProcessCommand {
    let mut command = ProcessCommand::new("git");
    command
        .current_dir(root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_LITERAL_PATHSPECS", "1")
        .env("GIT_PAGER", "cat")
        .env("NO_COLOR", "1")
        .arg("-c")
        .arg("color.ui=false")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("diff.external=")
        .arg("-c")
        .arg("diff.trustExitCode=false")
        .arg("--no-pager")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn git_worktree_prefix(root: &Path) -> Option<String> {
    let mut command = git_command(root);
    let output = command
        .arg("rev-parse")
        .arg("--show-prefix")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let prefix = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\r', '\n'])
        .to_string();
    (!prefix.is_empty()).then_some(prefix)
}

fn read_limited_pipe<R>(
    reader: R,
    max_bytes: usize,
    cap_reached: Arc<AtomicBool>,
) -> thread::JoinHandle<io::Result<(Vec<u8>, bool)>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = reader;
        let mut bytes = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let remaining = max_bytes.saturating_sub(bytes.len());
            if remaining == 0 {
                truncated = true;
                cap_reached.store(true, Ordering::SeqCst);
                continue;
            }
            let keep = read.min(remaining);
            bytes.extend_from_slice(&buffer[..keep]);
            if keep < read {
                truncated = true;
                cap_reached.store(true, Ordering::SeqCst);
            }
        }
        Ok((bytes, truncated))
    })
}

fn join_limited_pipe(
    handle: thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
    name: &str,
) -> Result<(Vec<u8>, bool)> {
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("git {name} reader panicked"))?
        .with_context(|| format!("failed to read git {name}"))
}

fn rebase_git_status_stdout(stdout: &str, prefix: Option<&str>) -> String {
    let Some(prefix) = prefix.filter(|value| !value.is_empty()) else {
        return stdout.to_string();
    };
    if stdout.as_bytes().contains(&0) {
        return rebase_git_status_nul_stdout(stdout, prefix);
    }
    let mut rebased = String::new();
    for line in stdout.lines() {
        if line.starts_with("##") {
            rebased.push_str(line);
            rebased.push('\n');
            continue;
        }
        if line.len() < 4 {
            continue;
        }
        let status = &line[..3];
        let path = &line[3..];
        if let Some((old, new)) = path.split_once(" -> ") {
            let Some(old) = old.strip_prefix(prefix) else {
                continue;
            };
            let Some(new) = new.strip_prefix(prefix) else {
                continue;
            };
            rebased.push_str(status);
            rebased.push_str(old);
            rebased.push_str(" -> ");
            rebased.push_str(new);
            rebased.push('\n');
            continue;
        }
        let Some(path) = path.strip_prefix(prefix) else {
            continue;
        };
        rebased.push_str(status);
        rebased.push_str(path);
        rebased.push('\n');
    }
    rebased
}

fn rebase_git_status_nul_stdout(stdout: &str, prefix: &str) -> String {
    let mut rebased = String::new();
    let mut records = stdout.split('\0').filter(|record| !record.is_empty());
    while let Some(record) = records.next() {
        if record.starts_with("##") {
            rebased.push_str(record);
            rebased.push('\0');
            continue;
        }
        if record.len() < 4 {
            continue;
        }
        let status = &record[..3];
        let path = &record[3..];
        let Some(path) = path.strip_prefix(prefix) else {
            continue;
        };
        rebased.push_str(status);
        rebased.push_str(path);
        rebased.push('\0');
        if status.starts_with('R') || status.starts_with('C') {
            let _old_path = records.next();
        }
    }
    rebased
}

fn read_file_for_batch(
    root: &Path,
    path: &str,
    max_file_bytes: u64,
    remaining_total_bytes: u64,
) -> Result<BatchReadFile> {
    let mut opened = open_existing_content_file(root, path)?;

    if opened.metadata.len() > max_file_bytes {
        bail!(
            "{path} is {} bytes, above batch max_file_bytes={max_file_bytes}",
            opened.metadata.len()
        );
    }
    if opened.metadata.len() > remaining_total_bytes {
        return Err(BatchTotalCapExceeded {
            path: path.to_string(),
            file_size: opened.metadata.len(),
            remaining_total_bytes,
        }
        .into());
    }

    let content = read_open_file_bytes_with_cap(
        &mut opened.file,
        path,
        max_file_bytes.min(remaining_total_bytes),
    )?;
    let hash = hash_bytes(&content);
    let mut meta = file_meta_from_metadata(path.to_string(), &opened.metadata, None);
    meta.hash = Some(hash.clone());
    Ok(BatchReadFile {
        path: path.to_string(),
        content,
        hash,
        meta,
    })
}

#[cfg(test)]
fn read_file_bytes_with_cap(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    #[cfg(test)]
    FILE_CONTENT_READS.with(|reads| reads.set(reads.get() + 1));

    let max_bytes = max_bytes.min(AGENT_READ_RESPONSE_MAX_BYTES);
    let file = File::open(path)?;
    read_reader_bytes_with_cap(file, &path.display().to_string(), max_bytes)
}

fn read_open_file_bytes_with_cap(file: &mut File, label: &str, max_bytes: u64) -> Result<Vec<u8>> {
    #[cfg(test)]
    FILE_CONTENT_READS.with(|reads| reads.set(reads.get() + 1));

    let max_bytes = max_bytes.min(AGENT_READ_RESPONSE_MAX_BYTES);
    file.seek(SeekFrom::Start(0))?;
    let content =
        read_reader_bytes_with_cap(file.take(max_bytes.saturating_add(1)), label, max_bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(content)
}

fn read_reader_bytes_with_cap<R: Read>(reader: R, label: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut content)?;
    if content.len() as u64 > max_bytes {
        bail!(
            "{} exceeded read cap: read_at_least={} max_bytes={}",
            label,
            content.len(),
            max_bytes
        );
    }
    Ok(content)
}

#[cfg(test)]
fn grep(
    state: &mut AgentState,
    query: &str,
    limit: usize,
    after: Option<&str>,
    max_files: Option<usize>,
    session_id: Option<&str>,
) -> Result<Response> {
    grep_with_caps(
        state,
        query,
        limit,
        after,
        session_id,
        GrepCaps {
            max_files,
            ..GrepCaps::default()
        },
    )
}

fn grep_with_caps(
    state: &mut AgentState,
    query: &str,
    limit: usize,
    after: Option<&str>,
    session_id: Option<&str>,
    caps: GrepCaps,
) -> Result<Response> {
    if query.is_empty() || limit == 0 {
        if let Some(session_id) = session_id {
            state.grep_sessions.remove(session_id);
        }
        return Ok(Response::Grep {
            hits: Vec::new(),
            truncated: false,
            next_after: None,
            session_id: None,
            scanned_files: 0,
        });
    }

    let mut session = session_id
        .and_then(|session_id| state.grep_sessions.remove(session_id))
        .filter(|session| session.query == query);
    let resumed_session = session.is_some();
    let mut walk = session
        .take()
        .map(|session| session.walk)
        .unwrap_or_else(|| grep_walk(&state.root));
    let mut after_seen = resumed_session;
    let mut active_session_id = if after_seen {
        session_id.map(ToOwned::to_owned)
    } else {
        None
    };
    if active_session_id.is_none() {
        after_seen = after.is_none();
    }

    let mut hits = Vec::new();
    let mut next_after = None;
    let mut scanned_files = 0_usize;
    let max_files = caps
        .max_files
        .unwrap_or(AGENT_GREP_HARD_MAX_FILES)
        .clamp(1, AGENT_GREP_HARD_MAX_FILES);
    let max_file_bytes = caps
        .max_file_bytes
        .unwrap_or(AGENT_GREP_HARD_MAX_FILE_BYTES)
        .min(AGENT_GREP_HARD_MAX_FILE_BYTES);
    let max_total_bytes = caps
        .max_total_bytes
        .unwrap_or(AGENT_GREP_HARD_MAX_TOTAL_BYTES)
        .min(AGENT_GREP_HARD_MAX_TOTAL_BYTES);
    let mut scanned_bytes = 0_u64;
    let mut hit_text_bytes = 0_usize;
    let mut exhausted = false;
    let mut hit_limit_reached = false;
    let mut byte_limit_reached = false;

    while scanned_files < max_files {
        let Some(entry) = walk.next() else {
            exhausted = true;
            break;
        };
        let entry = entry?;
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let relative = relative_path(&state.root, entry.path())?;
        if !after_seen {
            if after == Some(relative.as_str()) {
                after_seen = true;
            }
            continue;
        }
        let mut opened = match open_existing_content_file(&state.root, &relative) {
            Ok(opened) => opened,
            Err(_) => continue,
        };
        scanned_files += 1;
        next_after = Some(relative.clone());
        if opened.metadata.len() > max_file_bytes {
            byte_limit_reached = true;
            continue;
        }
        let remaining_total_bytes = max_total_bytes.saturating_sub(scanned_bytes);
        if opened.metadata.len() > remaining_total_bytes {
            byte_limit_reached = true;
            break;
        }
        if likely_binary_open_file(&mut opened.file)? {
            continue;
        }
        let content = match read_open_file_bytes_with_cap(
            &mut opened.file,
            &relative,
            max_file_bytes.min(remaining_total_bytes),
        ) {
            Ok(content) => content,
            Err(_) => {
                byte_limit_reached = true;
                continue;
            }
        };
        scanned_bytes = scanned_bytes.saturating_add(content.len() as u64);
        let text = match String::from_utf8(content) {
            Ok(text) => text,
            Err(_) => continue,
        };
        for (line_idx, line) in text.lines().enumerate() {
            if line.len() > AGENT_GREP_HARD_MAX_LINE_BYTES {
                byte_limit_reached = true;
                continue;
            }
            if let Some(byte_idx) = line.find(query) {
                let next_hit_text_bytes = hit_text_bytes.saturating_add(line.len());
                if next_hit_text_bytes > AGENT_GREP_HARD_MAX_HIT_TEXT_BYTES {
                    byte_limit_reached = true;
                    break;
                }
                hit_text_bytes = next_hit_text_bytes;
                hits.push(SearchHit {
                    path: relative.clone(),
                    line: line_idx as u64 + 1,
                    column: byte_idx as u64 + 1,
                    text: line.to_string(),
                });
                if hits.len() >= limit {
                    hit_limit_reached = true;
                    next_after = None;
                    break;
                }
            }
        }
        if hit_limit_reached {
            break;
        }
    }

    if active_session_id.is_none() && after.is_some() && !after_seen {
        bail!("grep cursor not found");
    }

    let truncated =
        hit_limit_reached || byte_limit_reached || (!exhausted && scanned_files >= max_files);
    let response_session_id = if truncated && next_after.is_some() {
        let id = active_session_id.take().unwrap_or_else(|| {
            let id = format!("grep-{}", state.next_grep_session);
            state.next_grep_session = state.next_grep_session.saturating_add(1).max(1);
            id
        });
        if state.grep_sessions.len() >= MAX_GREP_SESSIONS {
            if let Some(oldest) = state.grep_sessions.keys().next().cloned() {
                state.grep_sessions.remove(&oldest);
            }
        }
        state.grep_sessions.insert(
            id.clone(),
            GrepSession {
                query: query.to_string(),
                walk,
            },
        );
        Some(id)
    } else {
        next_after = None;
        None
    };

    Ok(Response::Grep {
        hits,
        truncated,
        next_after,
        session_id: response_session_id,
        scanned_files,
    })
}

fn grep_walk(root: &Path) -> Walk {
    WalkBuilder::new(root)
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_exclude(true)
        .sort_by_file_name(|a, b| a.cmp(b))
        .build()
}

#[cfg(test)]
fn write_file_cas(
    root: &Path,
    path: String,
    expected_hash: Option<String>,
    content: Vec<u8>,
) -> Result<Response> {
    write_file_cas_inner(root, path, expected_hash, content, || Ok(()))
}

fn write_file_cas_state(
    state: &mut AgentState,
    path: String,
    expected_hash: Option<String>,
    content: Vec<u8>,
) -> Result<Response> {
    let target = prepare_write_target(&state.root, &path)?;
    let target_keys = write_target_keys(&state.root, &target.abs)?;
    ensure_no_active_write(&state.active_write_targets, &target_keys, &path)?;
    let lock = acquire_write_locks(&target_keys, &path)?;
    write_file_cas_prepared(
        &state.root,
        path,
        expected_hash,
        content,
        target,
        lock,
        || Ok(()),
    )
}

#[cfg(test)]
fn write_file_cas_inner(
    root: &Path,
    path: String,
    expected_hash: Option<String>,
    content: Vec<u8>,
    before_rename: impl FnOnce() -> Result<()>,
) -> Result<Response> {
    let target = prepare_write_target(root, &path)?;
    let target_keys = write_target_keys(root, &target.abs)?;
    let lock = acquire_write_locks(&target_keys, &path)?;
    write_file_cas_prepared(
        root,
        path,
        expected_hash,
        content,
        target,
        lock,
        before_rename,
    )
}

fn write_file_cas_prepared(
    root: &Path,
    path: String,
    expected_hash: Option<String>,
    content: Vec<u8>,
    target: WriteTarget,
    _lock: WriteLock,
    before_rename: impl FnOnce() -> Result<()>,
) -> Result<Response> {
    let parent = open_write_parent(root, &target)?;
    let actual_hash = current_regular_file_hash(root, &path, &target.abs)?;
    if actual_hash != expected_hash {
        return Ok(Response::WriteFileCas {
            outcome: SaveOutcome::Conflict(save_conflict(root, path, expected_hash, actual_hash)),
        });
    }

    let tmp = target.abs.with_extension(format!(
        "nrm-tmp-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let tmp_name = temp_file_name(&tmp)?;
    verify_write_parent_current(root, &parent, &target)?;
    let mut file = create_temp_file(&parent, &tmp, &tmp_name)?;
    if let Err(error) = file.write_all(&content).and_then(|_| file.sync_all()) {
        let _ = remove_temp_file(&parent, &tmp, &tmp_name);
        return Err(error).with_context(|| format!("failed to write temp file {}", tmp.display()));
    }
    if let Err(error) = verify_temp_file_identity(&file, &tmp) {
        let _ = remove_temp_file(&parent, &tmp, &tmp_name);
        return Err(error);
    }
    if let Err(error) = before_rename() {
        let _ = remove_temp_file(&parent, &tmp, &tmp_name);
        return Err(error);
    }
    if let Err(error) = verify_write_parent_current(root, &parent, &target) {
        let _ = remove_temp_file(&parent, &tmp, &tmp_name);
        return Err(error);
    }
    let actual_hash = current_regular_file_hash(root, &path, &target.abs)?;
    if actual_hash != expected_hash {
        let _ = remove_temp_file(&parent, &tmp, &tmp_name);
        return Ok(Response::WriteFileCas {
            outcome: SaveOutcome::Conflict(save_conflict(root, path, expected_hash, actual_hash)),
        });
    }
    if let Err(error) = verify_write_parent_current(root, &parent, &target) {
        let _ = remove_temp_file(&parent, &tmp, &tmp_name);
        return Err(error);
    }
    let temp_identity = match capture_temp_file_identity(&file, &tmp) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = remove_temp_file(&parent, &tmp, &tmp_name);
            return Err(error);
        }
    };
    #[cfg(not(unix))]
    drop(file);
    rename_temp_into_target(&parent, &tmp, &tmp_name, &target, temp_identity)?;
    sync_write_parent(&parent, &target.abs)?;
    let new_hash = hash_file(&target.abs)?;
    let meta = file_meta(root, &target.abs, true)?;

    Ok(Response::WriteFileCas {
        outcome: SaveOutcome::Applied(SaveApplied {
            path,
            new_hash,
            size: meta.size,
            mtime_ms: meta.mtime_ms,
        }),
    })
}

fn begin_write_file_cas(
    state: &mut AgentState,
    path: String,
    expected_hash: Option<String>,
    content_hash: String,
    size: u64,
) -> Result<Response> {
    cleanup_expired_uploads(state);
    enforce_upload_limits(state, size)?;
    let target = prepare_write_target(&state.root, &path)?;
    let target_keys = write_target_keys(&state.root, &target.abs)?;
    ensure_no_active_write(&state.active_write_targets, &target_keys, &path)?;
    let lock = acquire_write_locks(&target_keys, &path)?;
    let parent = open_write_parent(&state.root, &target)?;
    let actual_hash = current_regular_file_hash(&state.root, &path, &target.abs)?;

    if actual_hash != expected_hash {
        return Ok(Response::BeginWriteFileCas {
            outcome: WriteStartOutcome::Conflict(save_conflict(
                &state.root,
                path,
                expected_hash,
                actual_hash,
            )),
        });
    }

    let upload_id = format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        hash_bytes(path.as_bytes())
    );
    let tmp_path = target.abs.with_extension(format!("nrm-upload-{upload_id}"));
    let tmp_name = temp_file_name(&tmp_path)?;
    verify_write_parent_current(&state.root, &parent, &target)?;
    let tmp_file = create_temp_file(&parent, &tmp_path, &tmp_name)?;
    state
        .active_write_targets
        .extend(target_keys.iter().cloned());
    state.uploads.insert(
        upload_id.clone(),
        PendingUpload {
            path,
            target_abs: target.abs,
            target_keys,
            expected_hash,
            content_hash,
            size,
            tmp_path,
            tmp_name,
            tmp_file,
            parent,
            written: 0,
            created_at: Instant::now(),
            _lock: lock,
        },
    );

    Ok(Response::BeginWriteFileCas {
        outcome: WriteStartOutcome::Started(WriteStarted { upload_id }),
    })
}

fn write_file_chunk(
    state: &mut AgentState,
    upload_id: String,
    offset: u64,
    content: Vec<u8>,
) -> Result<Response> {
    cleanup_expired_uploads(state);
    let upload = state
        .uploads
        .get_mut(&upload_id)
        .ok_or_else(|| anyhow::anyhow!("unknown upload id {upload_id}"))?;
    if offset != upload.written {
        bail!(
            "upload {upload_id} expected offset {}, got {offset}",
            upload.written
        );
    }
    let next = upload.written.saturating_add(content.len() as u64);
    if next > upload.size {
        bail!(
            "upload {upload_id} exceeds declared size: next={next} size={}",
            upload.size
        );
    }

    upload.tmp_file.seek(SeekFrom::Start(offset))?;
    upload.tmp_file.write_all(&content)?;
    upload.written = next;

    Ok(Response::WriteFileChunk {
        upload_id,
        accepted: next,
    })
}

fn finish_write_file_cas(state: &mut AgentState, upload_id: String) -> Result<Response> {
    cleanup_expired_uploads(state);
    let upload = state
        .uploads
        .remove(&upload_id)
        .ok_or_else(|| anyhow::anyhow!("unknown upload id {upload_id}"))?;
    let PendingUpload {
        path,
        target_abs,
        target_keys,
        expected_hash,
        content_hash,
        size,
        tmp_path,
        tmp_name,
        mut tmp_file,
        parent,
        written,
        created_at: _,
        _lock: write_lock,
    } = upload;
    let _write_lock = write_lock;
    let root = state.root.clone();
    let _active_release = ActiveWriteRelease {
        active: &mut state.active_write_targets,
        keys: target_keys,
    };
    if written != size {
        let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
        bail!(
            "upload {upload_id} incomplete: written={} size={}",
            written,
            size
        );
    }

    if let Err(error) = tmp_file.sync_all() {
        let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
        return Err(error).context(format!("failed to sync upload {upload_id} temp file"));
    }
    let tmp_hash = match hash_open_file(&mut tmp_file) {
        Ok(hash) => hash,
        Err(error) => {
            let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
            return Err(error);
        }
    };
    if tmp_hash != content_hash {
        let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
        bail!(
            "upload {upload_id} hash mismatch: expected={} actual={tmp_hash}",
            content_hash
        );
    }
    if let Err(error) = verify_temp_file_identity(&tmp_file, &tmp_path) {
        let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
        return Err(error);
    }

    if let Err(error) = verify_write_parent_current_path(&root, &parent, &target_abs) {
        let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
        return Err(error);
    }
    let actual_hash = current_regular_file_hash(&root, &path, &target_abs)?;
    if actual_hash != expected_hash {
        let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
        return Ok(Response::FinishWriteFileCas {
            outcome: SaveOutcome::Conflict(save_conflict(&root, path, expected_hash, actual_hash)),
        });
    }

    if let Err(error) = verify_write_parent_current_path(&root, &parent, &target_abs) {
        let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
        return Err(error);
    }
    let temp_identity = match capture_temp_file_identity(&tmp_file, &tmp_path) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
            return Err(error);
        }
    };
    #[cfg(not(unix))]
    drop(tmp_file);
    rename_temp_into_path(&parent, &tmp_path, &tmp_name, &target_abs, temp_identity)?;
    sync_write_parent(&parent, &target_abs)?;
    let meta = file_meta(&root, &target_abs, true)?;

    Ok(Response::FinishWriteFileCas {
        outcome: SaveOutcome::Applied(SaveApplied {
            path,
            new_hash: tmp_hash,
            size: meta.size,
            mtime_ms: meta.mtime_ms,
        }),
    })
}

fn abort_write_file_cas(state: &mut AgentState, upload_id: String) -> Result<Response> {
    cleanup_expired_uploads(state);
    if let Some(upload) = state.uploads.remove(&upload_id) {
        let _ = remove_temp_file(&upload.parent, &upload.tmp_path, &upload.tmp_name);
        for key in &upload.target_keys {
            state.active_write_targets.remove(key);
        }
    }
    Ok(Response::AbortWriteFileCas { upload_id })
}

fn cleanup_expired_uploads(state: &mut AgentState) {
    cleanup_expired_uploads_at(state, Instant::now());
}

fn cleanup_expired_uploads_at(state: &mut AgentState, now: Instant) {
    let expired = state
        .uploads
        .iter()
        .filter(|(_, upload)| {
            now.saturating_duration_since(upload.created_at)
                .gt(&UPLOAD_TTL)
        })
        .map(|(upload_id, _)| upload_id.clone())
        .collect::<Vec<_>>();
    for upload_id in expired {
        if let Some(upload) = state.uploads.remove(&upload_id) {
            let _ = remove_temp_file(&upload.parent, &upload.tmp_path, &upload.tmp_name);
            for key in &upload.target_keys {
                state.active_write_targets.remove(key);
            }
        }
    }
}

fn enforce_upload_limits(state: &AgentState, new_size: u64) -> Result<()> {
    if state.uploads.len() >= MAX_ACTIVE_UPLOADS {
        bail!("too many active uploads: max={MAX_ACTIVE_UPLOADS}");
    }
    let active_bytes = state
        .uploads
        .values()
        .fold(0_u64, |sum, upload| sum.saturating_add(upload.size));
    let next_bytes = active_bytes.saturating_add(new_size);
    if next_bytes > MAX_ACTIVE_UPLOAD_BYTES {
        bail!(
            "active upload bytes would exceed limit: next={next_bytes} max={MAX_ACTIVE_UPLOAD_BYTES}"
        );
    }
    Ok(())
}

fn save_conflict(
    root: &Path,
    path: String,
    expected_hash: Option<String>,
    actual_hash: Option<String>,
) -> SaveConflict {
    let (remote_content, remote_content_truncated, remote_size) =
        remote_conflict_content(root, &path);
    SaveConflict {
        path,
        expected_hash,
        actual_hash,
        remote_content,
        remote_content_truncated,
        remote_size,
    }
}

fn remote_conflict_content(root: &Path, path: &str) -> (Vec<u8>, bool, Option<u64>) {
    let Ok(mut opened) = open_existing_content_file(root, path) else {
        return (Vec::new(), false, None);
    };
    let remote_size = opened.metadata.len();
    let max_bytes = remote_size.min(MAX_CONFLICT_CONTENT_BYTES as u64);
    let remote_content =
        read_open_file_prefix(&mut opened.file, max_bytes).unwrap_or_else(|_| Vec::new());
    let remote_content_truncated = remote_size > remote_content.len() as u64;
    (remote_content, remote_content_truncated, Some(remote_size))
}

fn read_open_file_prefix(file: &mut File, max_bytes: u64) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut content = Vec::new();
    {
        let mut reader = (&mut *file).take(max_bytes);
        reader.read_to_end(&mut content)?;
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(content)
}

fn existing_metadata_path(root: &Path, abs: &Path) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(abs) {
        Ok(_) => {
            let canonical = abs
                .canonicalize()
                .with_context(|| format!("failed to resolve {}", abs.display()))?;
            ensure_path_within_root(root, &canonical)?;
            Ok(Some(abs.to_path_buf()))
        }
        Err(error) if is_missing_path_error(&error) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to stat {}", abs.display())),
    }
}

#[cfg(unix)]
fn open_existing_content_file(root: &Path, path: &str) -> Result<OpenedContentFile> {
    let relative = normalize_relative_path(path)?;
    let abs = root.join(relative);
    let file_name = abs
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("remote path must name a file"))?
        .to_owned();
    let parent = abs
        .parent()
        .ok_or_else(|| anyhow::anyhow!("remote path must have a parent directory"))?;
    let canonical_parent = parent
        .canonicalize()
        .with_context(|| format!("failed to resolve parent for {path}"))?;
    ensure_path_within_root(root, &canonical_parent)?;
    let parent_dir = open_parent_dir(&canonical_parent)?;
    verify_parent_dir_identity(&parent_dir, &canonical_parent)?;
    let name = c_path_name(&file_name)?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: `name` is a valid NUL-terminated path component, and
    // `parent_dir` pins the directory used by openat.
    let fd = unsafe { libc::openat(parent_dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            bail!("{path} is a symlink; content operations do not follow symlinks");
        }
        return Err(error).with_context(|| format!("failed to open {path}"));
    }
    // SAFETY: openat returned an owned descriptor on success.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to stat open file {path}"))?;
    if !metadata.is_file() {
        bail!("{path} is not a regular file");
    }
    verify_parent_dir_identity(&parent_dir, &canonical_parent)?;
    Ok(OpenedContentFile { file, metadata })
}

#[cfg(not(unix))]
fn open_existing_content_file(root: &Path, path: &str) -> Result<OpenedContentFile> {
    let abs = resolve_existing_content_path(root, path)?;
    let file = File::open(&abs)?;
    let metadata = file.metadata()?;
    Ok(OpenedContentFile { file, metadata })
}

#[cfg(not(unix))]
fn resolve_existing_content_path(root: &Path, path: &str) -> Result<PathBuf> {
    let abs = resolve_remote_path(root, path)?;
    let metadata = fs::symlink_metadata(&abs).with_context(|| format!("failed to stat {path}"))?;
    if metadata.file_type().is_symlink() {
        bail!("{path} is a symlink; content operations do not follow symlinks");
    }
    if !metadata.is_file() {
        bail!("{path} is not a regular file");
    }
    let canonical = abs
        .canonicalize()
        .with_context(|| format!("failed to resolve {path}"))?;
    ensure_path_within_root(root, &canonical)?;
    Ok(canonical)
}

fn prepare_write_target(root: &Path, path: &str) -> Result<WriteTarget> {
    let abs = resolve_remote_path(root, path)?;
    let file_name = abs
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("remote path must name a file"))?
        .to_owned();

    match fs::symlink_metadata(&abs) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("{path} is a symlink; remote saves do not replace symlinks");
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {path}"));
        }
    }

    let parent = abs
        .parent()
        .ok_or_else(|| anyhow::anyhow!("remote path must have a parent directory"))?;
    ensure_write_parent_inside_root(root, parent)?;
    let canonical_parent = parent
        .canonicalize()
        .with_context(|| format!("failed to resolve parent for {path}"))?;
    ensure_path_within_root(root, &canonical_parent)?;
    Ok(WriteTarget {
        abs: canonical_parent.join(&file_name),
        #[cfg(any(unix, windows))]
        parent_abs: canonical_parent,
    })
}

#[cfg(not(windows))]
fn ensure_write_parent_inside_root(root: &Path, parent: &Path) -> Result<()> {
    let mut ancestor = parent;
    while !ancestor.exists() {
        ancestor = ancestor
            .parent()
            .ok_or_else(|| anyhow::anyhow!("remote path parent is outside the workspace"))?;
    }
    let canonical_ancestor = ancestor
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", ancestor.display()))?;
    ensure_path_within_root(root, &canonical_ancestor)?;
    fs::create_dir_all(parent)?;
    Ok(())
}

#[cfg(windows)]
fn ensure_write_parent_inside_root(root: &Path, parent: &Path) -> Result<()> {
    // Pin every existing component while creating the next one. No pinned
    // ancestor grants delete sharing, so it cannot be renamed into a junction
    // or redirected while a descendant is created.
    let _ = pin_windows_directory_chain(root, parent, true)?;
    Ok(())
}

fn current_regular_file_hash(root: &Path, path: &str, abs: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(abs) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                bail!("{path} is a symlink; content operations do not follow symlinks");
            }
            if !metadata.is_file() {
                return Ok(None);
            }
            let mut opened = open_existing_content_file(root, path)?;
            Ok(Some(hash_open_file(&mut opened.file)?))
        }
        Err(error) if is_missing_path_error(&error) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to stat {path}")),
    }
}

fn is_missing_path_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn ensure_target_parent_inside_root(root: &Path, target_abs: &Path) -> Result<()> {
    let parent = target_abs
        .parent()
        .ok_or_else(|| anyhow::anyhow!("remote path must have a parent directory"))?;
    let metadata = fs::metadata(parent)
        .with_context(|| format!("failed to stat parent {}", parent.display()))?;
    if !metadata.is_dir() {
        bail!("remote path parent {} is not a directory", parent.display());
    }
    let canonical_parent = parent
        .canonicalize()
        .with_context(|| format!("failed to resolve parent {}", parent.display()))?;
    ensure_path_within_root(root, &canonical_parent)
}

fn open_write_parent(root: &Path, target: &WriteTarget) -> Result<WriteParent> {
    ensure_target_parent_inside_root(root, &target.abs)?;
    #[cfg(unix)]
    {
        let dir = open_parent_dir(&target.parent_abs)?;
        verify_parent_dir_identity(&dir, &target.parent_abs)?;
        Ok(WriteParent { dir })
    }
    #[cfg(windows)]
    {
        let (canonical_parent, pinned_directories) =
            pin_windows_directory_chain(root, &target.parent_abs, false)?;
        if canonical_parent != target.parent_abs {
            bail!(
                "Windows write parent changed from {} to {}",
                target.parent_abs.display(),
                canonical_parent.display()
            );
        }
        Ok(WriteParent {
            canonical_parent,
            pinned_directories,
        })
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        Ok(WriteParent {})
    }
}

#[cfg(unix)]
fn open_parent_dir(path: &Path) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("parent path contains a NUL byte")?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // SAFETY: `path` is a valid NUL-terminated pathname.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("failed to open parent directory");
    }
    // SAFETY: open returned an owned file descriptor on success.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn verify_parent_dir_identity(dir: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let handle_metadata = dir
        .metadata()
        .with_context(|| format!("failed to stat open parent {}", path.display()))?;
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat parent path {}", path.display()))?;
    if !path_metadata.is_dir() {
        bail!("parent path {} is not a directory", path.display());
    }
    if handle_metadata.dev() != path_metadata.dev() || handle_metadata.ino() != path_metadata.ino()
    {
        bail!("parent path {} was replaced", path.display());
    }
    Ok(())
}

fn verify_write_parent_current(
    root: &Path,
    parent: &WriteParent,
    target: &WriteTarget,
) -> Result<()> {
    verify_write_parent_current_path(root, parent, &target.abs)
}

fn verify_write_parent_current_path(
    root: &Path,
    parent: &WriteParent,
    target_abs: &Path,
) -> Result<()> {
    ensure_target_parent_inside_root(root, target_abs)?;
    #[cfg(unix)]
    {
        let parent_abs = target_abs
            .parent()
            .ok_or_else(|| anyhow::anyhow!("remote path must have a parent directory"))?;
        verify_parent_dir_identity(&parent.dir, parent_abs)?;
    }
    #[cfg(windows)]
    {
        let parent_abs = target_abs
            .parent()
            .ok_or_else(|| anyhow::anyhow!("remote path must have a parent directory"))?;
        verify_windows_write_parent(parent, parent_abs)?;
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = parent;
    }
    Ok(())
}

fn ensure_path_within_root(root: &Path, path: &Path) -> Result<()> {
    #[cfg(windows)]
    let contained = {
        let root = root
            .canonicalize()
            .with_context(|| format!("failed to canonicalize remote root {}", root.display()))?;
        let path = path
            .canonicalize()
            .with_context(|| format!("failed to canonicalize path {}", path.display()))?;
        path == root || path.starts_with(&root)
    };
    #[cfg(not(windows))]
    let contained = path == root || path.starts_with(root);

    if contained {
        return Ok(());
    }
    bail!(
        "{} resolves outside remote root {}",
        path.display(),
        root.display()
    )
}

#[cfg(windows)]
fn windows_path_text(path: &Path) -> String {
    let mut text = path.to_string_lossy().replace('/', "\\");
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("\\\\?\\unc\\") {
        text = format!("\\\\{}", &text[8..]);
    } else if lower.starts_with("\\\\?\\") {
        text.drain(..4);
    }
    text
}

#[cfg(windows)]
fn windows_ordinal_path_key_bytes(path: &Path) -> Result<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Globalization::{
        LCMapStringEx, LCMAP_UPPERCASE, LOCALE_NAME_INVARIANT,
    };

    let mut source: Vec<u16> = path.as_os_str().encode_wide().collect();
    if source.contains(&0) {
        bail!(
            "Windows lock path contains a NUL character: {}",
            path.display()
        );
    }
    for character in &mut source {
        if *character == b'/' as u16 {
            *character = b'\\' as u16;
        }
    }
    let ascii_upper = |value: u16| {
        if (b'a' as u16..=b'z' as u16).contains(&value) {
            value - (b'a' - b'A') as u16
        } else {
            value
        }
    };
    let starts_with_ascii_case = |value: &[u16], prefix: &[u8]| {
        value.len() >= prefix.len()
            && value
                .iter()
                .zip(prefix)
                .all(|(left, right)| ascii_upper(*left) == ascii_upper(*right as u16))
    };
    if starts_with_ascii_case(&source, br"\\?\UNC\") {
        source.splice(..8, [b'\\' as u16, b'\\' as u16]);
    } else if starts_with_ascii_case(&source, br"\\?\") {
        source.drain(..4);
    }
    let source_len = i32::try_from(source.len()).context("Windows lock path is too long")?;
    // CompareStringOrdinal provides comparison but no reusable sort key.
    // Invariant Win32 uppercasing gives absent targets a stable UTF-16 key
    // using the platform's own Unicode tables; existing targets additionally
    // lock by volume/file ID, so aliases do not depend on this path key alone.
    // SAFETY: the source slice is valid for `source_len` UTF-16 code units and
    // all optional mapping parameters are null as required for invariant case
    // conversion. The first call only queries the destination length.
    let mapped_len = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            source.as_ptr(),
            source_len,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if mapped_len == 0 {
        return Err(io::Error::last_os_error()).context("failed to normalize Windows lock path");
    }
    let mut mapped = vec![0_u16; mapped_len as usize];
    // SAFETY: `mapped` has the exact size returned by the query call and all
    // other arguments are unchanged.
    let written = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            source.as_ptr(),
            source_len,
            mapped.as_mut_ptr(),
            mapped_len,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if written != mapped_len {
        return Err(io::Error::last_os_error()).context("failed to normalize Windows lock path");
    }
    let mut bytes = Vec::with_capacity(mapped.len() * 2);
    for character in mapped {
        bytes.extend_from_slice(&character.to_le_bytes());
    }
    Ok(bytes)
}

fn write_target_keys(root: &Path, target_abs: &Path) -> Result<Vec<String>> {
    #[cfg(windows)]
    {
        let root_key = windows_ordinal_path_key_bytes(root)?;
        let target_key = windows_ordinal_path_key_bytes(target_abs)?;
        let mut path_material = b"windows-path-v2\0".to_vec();
        path_material.extend_from_slice(&(root_key.len() as u64).to_le_bytes());
        path_material.extend_from_slice(&root_key);
        path_material.extend_from_slice(&(target_key.len() as u64).to_le_bytes());
        path_material.extend_from_slice(&target_key);
        let mut keys = vec![hash_bytes(&path_material)];

        let target_parent = target_abs
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Windows lock target must have a parent"))?;
        let target_name = target_abs
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Windows lock target must name a file"))?;
        let parent_identity = open_windows_directory_guard(target_parent)?.identity;
        let name_key = windows_ordinal_path_key_bytes(Path::new(target_name))?;
        let mut directory_entry_material = b"windows-directory-entry-v1\0".to_vec();
        directory_entry_material
            .extend_from_slice(&parent_identity.volume_serial_number.to_le_bytes());
        directory_entry_material.extend_from_slice(&parent_identity.file_index.to_le_bytes());
        directory_entry_material.extend_from_slice(&(name_key.len() as u64).to_le_bytes());
        directory_entry_material.extend_from_slice(&name_key);
        keys.push(hash_bytes(&directory_entry_material));

        match fs::symlink_metadata(target_abs) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "{} is a symlink and cannot be locked for writing",
                    target_abs.display()
                )
            }
            Ok(metadata) if metadata.is_file() => {
                let identity = windows_existing_regular_identity(target_abs)?
                    .ok_or_else(|| anyhow::anyhow!("target disappeared before write locking"))?;
                let mut file_material = b"windows-file-v1\0".to_vec();
                file_material.extend_from_slice(&identity.volume_serial_number.to_le_bytes());
                file_material.extend_from_slice(&identity.file_index.to_le_bytes());
                keys.push(hash_bytes(&file_material));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to identify lock target {}", target_abs.display())
                })
            }
        }
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
    #[cfg(not(windows))]
    {
        let identity = format!("{}:{}", root.display(), target_abs.display());
        Ok(vec![hash_bytes(identity.as_bytes())])
    }
}

fn ensure_no_active_write(
    active: &HashSet<String>,
    target_keys: &[String],
    path: &str,
) -> Result<()> {
    if target_keys.iter().any(|key| active.contains(key)) {
        bail!("remote write already in progress for {path}");
    }
    Ok(())
}

#[cfg(unix)]
fn unix_effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and only returns process metadata.
    unsafe { libc::geteuid() }
}

fn write_lock_root_path() -> PathBuf {
    let temporary = std::env::temp_dir();
    #[cfg(unix)]
    {
        temporary.join(format!("nrm-agent-locks-v1-{}", unix_effective_uid()))
    }
    #[cfg(not(unix))]
    {
        temporary.join("nrm-agent-locks")
    }
}

#[cfg(unix)]
fn validate_unix_lock_root_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    expected_uid: u32,
    require_private_mode: bool,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.file_type().is_symlink() {
        bail!(
            "write lock directory must not be a symlink: {}",
            path.display()
        );
    }
    if !metadata.is_dir() {
        bail!("write lock path is not a directory: {}", path.display());
    }
    if metadata.uid() != expected_uid {
        bail!(
            "write lock directory {} is owned by uid {}, expected uid {expected_uid}",
            path.display(),
            metadata.uid()
        );
    }
    if require_private_mode && metadata.mode() & 0o7777 != 0o700 {
        bail!(
            "write lock directory {} has mode {:04o}, expected 0700",
            path.display(),
            metadata.mode() & 0o7777
        );
    }
    Ok(())
}

#[cfg(unix)]
fn open_private_unix_lock_root(path: &Path, expected_uid: u32) -> Result<File> {
    use std::os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    };

    let mut created = false;
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => created = true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to create write lock directory {}", path.display())
                    });
                }
            }
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect write lock directory {}", path.display())
            });
        }
    }
    if created {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to set private permissions on new write lock directory {}",
                path.display()
            )
        })?;
    }

    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect write lock directory {}", path.display()))?;
    validate_unix_lock_root_metadata(path, &path_metadata, expected_uid, false)?;

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open write lock directory {}", path.display()))?;
    let opened_metadata = directory.metadata().with_context(|| {
        format!(
            "failed to inspect opened write lock directory {}",
            path.display()
        )
    })?;
    validate_unix_lock_root_metadata(path, &opened_metadata, expected_uid, false)?;
    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        bail!(
            "write lock directory {} changed while it was opened",
            path.display()
        );
    }

    if opened_metadata.mode() & 0o7777 != 0o700 {
        directory
            .set_permissions(fs::Permissions::from_mode(0o700))
            .with_context(|| {
                format!(
                    "failed to make write lock directory private: {}",
                    path.display()
                )
            })?;
    }
    let opened_metadata = directory.metadata().with_context(|| {
        format!(
            "failed to validate opened write lock directory {}",
            path.display()
        )
    })?;
    validate_unix_lock_root_metadata(path, &opened_metadata, expected_uid, true)?;
    let current_metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to revalidate write lock directory {}",
            path.display()
        )
    })?;
    validate_unix_lock_root_metadata(path, &current_metadata, expected_uid, true)?;
    if current_metadata.dev() != opened_metadata.dev()
        || current_metadata.ino() != opened_metadata.ino()
    {
        bail!(
            "write lock directory {} changed after it was secured",
            path.display()
        );
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_private_unix_lock_file(
    directory: &File,
    directory_path: &Path,
    filename: &OsStr,
    expected_uid: u32,
) -> Result<File> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let filename = CString::new(filename.as_bytes())
        .map_err(|_| anyhow::anyhow!("write lock filename contains a NUL byte"))?;
    // SAFETY: `directory` is a live descriptor for the validated lock root,
    // `filename` is NUL-terminated, and the flags/mode are valid for `openat`.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            filename.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to open write lock in {}", directory_path.display()));
    }
    // SAFETY: successful `openat` returns a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect write lock in {}",
            directory_path.display()
        )
    })?;
    if !metadata.is_file() {
        bail!(
            "write lock entry in {} is not a regular file",
            directory_path.display()
        );
    }
    if metadata.uid() != expected_uid {
        bail!(
            "write lock entry in {} is owned by uid {}, expected uid {expected_uid}",
            directory_path.display(),
            metadata.uid()
        );
    }
    if metadata.mode() & 0o7777 != 0o600 {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to make write lock private in {}",
                    directory_path.display()
                )
            })?;
        let secured = file.metadata().with_context(|| {
            format!(
                "failed to validate write lock in {}",
                directory_path.display()
            )
        })?;
        if secured.mode() & 0o7777 != 0o600 {
            bail!(
                "write lock entry in {} has mode {:04o}, expected 0600",
                directory_path.display(),
                secured.mode() & 0o7777
            );
        }
    }
    Ok(file)
}

fn acquire_write_locks(target_keys: &[String], path: &str) -> Result<WriteLock> {
    let lock_root_path = write_lock_root_path();
    #[cfg(unix)]
    let lock_root = open_private_unix_lock_root(&lock_root_path, unix_effective_uid())?;
    #[cfg(not(unix))]
    let lock_root = {
        fs::create_dir_all(&lock_root_path)?;
        lock_root_path.clone()
    };
    let mut sorted_keys = target_keys.to_vec();
    sorted_keys.sort();
    sorted_keys.dedup();
    let mut files = Vec::with_capacity(sorted_keys.len());
    for target_key in sorted_keys {
        let lock_name = OsString::from(format!("{target_key}.lock"));
        #[cfg(unix)]
        let file = open_private_unix_lock_file(
            &lock_root,
            &lock_root_path,
            &lock_name,
            unix_effective_uid(),
        )?;
        #[cfg(not(unix))]
        let file = {
            let lock_path = lock_root.join(&lock_name);
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .with_context(|| format!("failed to open write lock {}", lock_path.display()))?
        };
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => files.push(file),
            Err(fs4::TryLockError::WouldBlock) => {
                bail!("remote write already in progress for {path}")
            }
            Err(fs4::TryLockError::Error(error)) => {
                bail!("failed to lock remote write {path}: {error}")
            }
        }
    }
    Ok(WriteLock { _files: files })
}

fn resolve_remote_path(root: &Path, path: &str) -> Result<PathBuf> {
    let relative = normalize_relative_path(path)?;
    Ok(root.join(relative))
}

#[cfg(unix)]
fn sync_write_parent(parent: &WriteParent, path: &Path) -> Result<()> {
    parent
        .dir
        .sync_all()
        .with_context(|| format!("failed to sync directory for {}", path.display()))
}

#[cfg(windows)]
fn sync_write_parent(parent: &WriteParent, path: &Path) -> Result<()> {
    let path_parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows target path must have a parent"))?;
    verify_windows_write_parent(parent, path_parent)
}

#[cfg(all(not(unix), not(windows)))]
fn sync_write_parent(_parent: &WriteParent, _path: &Path) -> Result<()> {
    Ok(())
}

fn temp_file_name(path: &Path) -> Result<OsString> {
    path.file_name()
        .map(OsStr::to_owned)
        .ok_or_else(|| anyhow::anyhow!("temp path must name a file"))
}

#[cfg(unix)]
fn c_path_name(name: &OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(name.as_bytes()).context("path component contains a NUL byte")
}

#[cfg(unix)]
fn create_temp_file(parent: &WriteParent, path: &Path, name: &OsStr) -> Result<File> {
    let name = c_path_name(name)?;
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
    // SAFETY: `name` is a valid NUL-terminated path component. `parent.dir`
    // remains open for the call and pins the directory used by openat.
    let fd = unsafe { libc::openat(parent.dir.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to create temp file {}", path.display()));
    }
    // SAFETY: openat returned an owned file descriptor on success.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(windows)]
fn create_temp_file(parent: &WriteParent, path: &Path, _name: &OsStr) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};

    // Readers and cleanup may access the staging file, but another process
    // cannot open it for writing while its contents are being assembled.
    // Delete sharing is required because error paths unlink the file before
    // the owning File is dropped; final file-ID checks detect such a swap.
    let path_parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows temp path must have a parent"))?;
    verify_windows_write_parent(parent, path_parent)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(path)
        .with_context(|| format!("failed to create temp file {}", path.display()))?;
    verify_windows_write_parent(parent, path_parent)?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn create_temp_file(_parent: &WriteParent, path: &Path, _name: &OsStr) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create temp file {}", path.display()))
}

#[cfg(unix)]
fn remove_temp_file(parent: &WriteParent, _path: &Path, name: &OsStr) -> Result<()> {
    let name = c_path_name(name)?;
    // SAFETY: `name` is a valid NUL-terminated path component. `parent.dir`
    // remains open for the call and pins the directory used by unlinkat.
    let result = unsafe { libc::unlinkat(parent.dir.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        return Err(io::Error::last_os_error()).context("failed to remove temp file");
    }
    Ok(())
}

#[cfg(windows)]
fn remove_temp_file(parent: &WriteParent, path: &Path, _name: &OsStr) -> Result<()> {
    let path_parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows temp path must have a parent"))?;
    verify_windows_write_parent(parent, path_parent)?;
    fs::remove_file(path)
        .with_context(|| format!("failed to remove temp file {}", path.display()))?;
    verify_windows_write_parent(parent, path_parent)
}

#[cfg(all(not(unix), not(windows)))]
fn remove_temp_file(_parent: &WriteParent, path: &Path, _name: &OsStr) -> Result<()> {
    fs::remove_file(path).with_context(|| format!("failed to remove temp file {}", path.display()))
}

fn rename_temp_into_target(
    parent: &WriteParent,
    tmp_path: &Path,
    tmp_name: &OsStr,
    target: &WriteTarget,
    temp_identity: TempFileIdentity,
) -> Result<()> {
    rename_temp_into_path(parent, tmp_path, tmp_name, &target.abs, temp_identity)
}

fn rename_temp_into_path(
    parent: &WriteParent,
    tmp_path: &Path,
    tmp_name: &OsStr,
    target_abs: &Path,
    temp_identity: TempFileIdentity,
) -> Result<()> {
    match replace_temp_into_path_raw(parent, tmp_path, tmp_name, target_abs, temp_identity) {
        Ok(()) => Ok(()),
        Err(replace_error) => cleanup_failed_replacement(parent, tmp_path, tmp_name, replace_error),
    }
}

fn cleanup_failed_replacement(
    parent: &WriteParent,
    tmp_path: &Path,
    tmp_name: &OsStr,
    replace_error: anyhow::Error,
) -> Result<()> {
    // A failed rollback deliberately preserves both the candidate and backup
    // for manual recovery. Ordinary failures are safe to clean because the
    // replacement helper verified that the original target is still present.
    #[cfg(any(windows, test))]
    if replace_error
        .downcast_ref::<ReplacementRollbackFailed>()
        .is_some()
    {
        return Err(replace_error);
    }
    match remove_temp_file(parent, tmp_path, tmp_name) {
        Ok(()) => Err(replace_error),
        Err(cleanup_error)
            if cleanup_error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
        {
            Err(replace_error)
        }
        Err(cleanup_error) => bail!(
            "{replace_error:#}; additionally failed to remove temp file {}: {cleanup_error:#}",
            tmp_path.display()
        ),
    }
}

#[cfg(unix)]
fn replace_temp_into_path_raw(
    parent: &WriteParent,
    tmp_path: &Path,
    tmp_name: &OsStr,
    target_abs: &Path,
    _temp_identity: TempFileIdentity,
) -> Result<()> {
    let tmp_name = c_path_name(tmp_name)?;
    let target_name = target_abs
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("target path must name a file"))
        .and_then(c_path_name)?;
    // SAFETY: both names are valid NUL-terminated path components. The same
    // pinned parent directory fd is used for source and destination.
    let result = unsafe {
        libc::renameat(
            parent.dir.as_raw_fd(),
            tmp_name.as_ptr(),
            parent.dir.as_raw_fd(),
            target_name.as_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to rename temp file into {} from {}",
                target_abs.display(),
                tmp_path.display()
            )
        });
    }
    Ok(())
}

#[cfg(windows)]
fn windows_wide_path(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut wide: Vec<_> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        bail!("Windows path contains a NUL character: {}", path.display());
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(windows)]
fn windows_replace_backup_path(tmp_path: &Path) -> Result<PathBuf> {
    let file_name = tmp_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("replacement temp path must name a file"))?;
    let mut backup_name = file_name.to_os_string();
    backup_name.push(".nrm-backup");
    Ok(tmp_path.with_file_name(backup_name))
}

#[cfg(windows)]
fn windows_object_information(file: &File, path: &Path) -> Result<WindowsObjectInformation> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a valid handle and `information` is writable for the
    // duration of the call.
    let result =
        unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) };
    if result == 0 {
        return Err(io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to read Windows file identity for {}",
                path.display()
            )
        });
    }
    Ok(WindowsObjectInformation {
        identity: WindowsFileIdentity {
            volume_serial_number: information.dwVolumeSerialNumber,
            file_index: ((information.nFileIndexHigh as u64) << 32)
                | information.nFileIndexLow as u64,
        },
        attributes: information.dwFileAttributes,
    })
}

#[cfg(windows)]
fn windows_file_identity(file: &File, path: &Path) -> Result<WindowsFileIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let information = windows_object_information(file, path)?;
    if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        bail!("{} is not a regular non-reparse file", path.display());
    }
    Ok(information.identity)
}

#[cfg(windows)]
fn open_windows_directory_guard(path: &Path) -> Result<WindowsPinnedDirectory> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    };

    let guard = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        // Deny write and delete sharing so the component cannot be renamed,
        // deleted, or converted into a reparse point while a CAS is active.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("failed to pin Windows directory {}", path.display()))?;
    let information = windows_object_information(&guard, path)?;
    if information.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!(
            "Windows write directory {} is not a non-reparse directory",
            path.display()
        );
    }
    Ok(WindowsPinnedDirectory {
        path: path.to_path_buf(),
        identity: information.identity,
        _guard: guard,
    })
}

#[cfg(windows)]
fn verify_windows_pinned_directory(directory: &WindowsPinnedDirectory) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let handle_information = windows_object_information(&directory._guard, &directory.path)?;
    if handle_information.identity != directory.identity
        || handle_information.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || handle_information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!(
            "pinned Windows directory {} changed identity or type",
            directory.path.display()
        );
    }
    let current = open_windows_directory_guard(&directory.path)?;
    if current.identity != directory.identity {
        bail!(
            "Windows directory path {} was redirected after pinning",
            directory.path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn pin_windows_directory_chain(
    root: &Path,
    parent: &Path,
    create_missing: bool,
) -> Result<(PathBuf, Vec<WindowsPinnedDirectory>)> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize Windows root {}", root.display()))?;
    let relative = parent
        .strip_prefix(root)
        .or_else(|_| parent.strip_prefix(&canonical_root))
        .with_context(|| {
            format!(
                "Windows write parent {} is not lexically below root {}",
                parent.display(),
                root.display()
            )
        })?;
    let mut current = canonical_root.clone();
    let mut pinned = vec![open_windows_directory_guard(&canonical_root)?];
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!(
                "Windows write parent {} contains a non-normal component",
                parent.display()
            );
        };
        current.push(component);
        if create_missing {
            match fs::symlink_metadata(&current) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match fs::create_dir(&current) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!("failed to create Windows directory {}", current.display())
                            })
                        }
                    }
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to inspect Windows directory {}", current.display())
                    })
                }
            }
        }
        pinned.push(open_windows_directory_guard(&current)?);
    }
    let canonical_parent = current.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize pinned Windows parent {}",
            current.display()
        )
    })?;
    ensure_path_within_root(&canonical_root, &canonical_parent)?;
    let last = pinned
        .last()
        .ok_or_else(|| anyhow::anyhow!("Windows directory chain is empty"))?;
    if open_windows_directory_guard(&canonical_parent)?.identity != last.identity {
        bail!(
            "Windows write parent {} changed during directory pinning",
            canonical_parent.display()
        );
    }
    Ok((canonical_parent, pinned))
}

#[cfg(windows)]
fn verify_windows_write_parent(parent: &WriteParent, expected_parent: &Path) -> Result<()> {
    let canonical_expected = expected_parent.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize guarded Windows parent {}",
            expected_parent.display()
        )
    })?;
    if canonical_expected != parent.canonical_parent {
        bail!(
            "Windows write parent changed from {} to {}",
            parent.canonical_parent.display(),
            canonical_expected.display()
        );
    }
    for directory in &parent.pinned_directories {
        verify_windows_pinned_directory(directory)?;
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_identity_guard(
    path: &Path,
    expected: Option<WindowsFileIdentity>,
    share_mode: u32,
) -> Result<(File, WindowsFileIdentity)> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let file = OpenOptions::new()
        .read(true)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("failed to guard Windows file {}", path.display()))?;
    let identity = windows_file_identity(&file, path)?;
    if expected.is_some_and(|expected| expected != identity) {
        bail!("{} was replaced before activation", path.display());
    }
    Ok((file, identity))
}

#[cfg(windows)]
fn windows_existing_regular_identity(path: &Path) -> Result<Option<WindowsFileIdentity>> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{} is not a regular non-reparse file", path.display())
        }
        Ok(_) => open_windows_identity_guard(path, None, FILE_SHARE_READ | FILE_SHARE_WRITE)
            .map(|(_, identity)| Some(identity)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to stat {}", path.display())),
    }
}

#[cfg(any(windows, test))]
fn windows_replace_failure_label(raw_os_error: Option<i32>) -> &'static str {
    match raw_os_error {
        Some(1175) => "ERROR_UNABLE_TO_REMOVE_REPLACED (1175)",
        Some(1176) => "ERROR_UNABLE_TO_MOVE_REPLACEMENT (1176)",
        Some(1177) => "ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 (1177)",
        _ => "Windows replacement error",
    }
}

#[cfg(windows)]
fn describe_windows_identity_locations(
    identity: WindowsFileIdentity,
    locations: &[(&str, &Path)],
) -> String {
    let mut matches = Vec::new();
    let mut inspection_errors = Vec::new();
    for (label, path) in locations {
        match windows_existing_regular_identity(path) {
            Ok(Some(found)) if found == identity => {
                matches.push(format!("{label}={}", path.display()));
            }
            Ok(_) => {}
            Err(error) => inspection_errors.push(format!("{label}: {error:#}")),
        }
    }
    if matches.is_empty() {
        matches.push("not found at verified candidate locations".to_string());
    }
    if !inspection_errors.is_empty() {
        matches.push(format!(
            "inspection errors: {}",
            inspection_errors.join("; ")
        ));
    }
    matches.join(", ")
}

#[cfg(windows)]
fn remove_windows_file_with_identity(
    parent: &WriteParent,
    path: &Path,
    expected: WindowsFileIdentity,
) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    let path_parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows cleanup path must have a parent"))?;
    verify_windows_write_parent(parent, path_parent)?;
    let (guard, _) = open_windows_identity_guard(path, Some(expected), FILE_SHARE_READ)?;
    verify_windows_write_parent(parent, path_parent)?;
    drop(guard);
    fs::remove_file(path)
        .with_context(|| format!("failed to remove verified Windows file {}", path.display()))?;
    verify_windows_write_parent(parent, path_parent)
}

#[cfg(windows)]
fn recover_windows_replace_failure(
    parent: &WriteParent,
    target_abs: &Path,
    candidate_path: &Path,
    backup_path: &Path,
    original_target_identity: WindowsFileIdentity,
    candidate_identity: WindowsFileIdentity,
    raw_os_error: Option<i32>,
) -> std::result::Result<(), String> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, FILE_SHARE_READ, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let label = windows_replace_failure_label(raw_os_error);
    verify_windows_write_parent(
        parent,
        target_abs
            .parent()
            .ok_or_else(|| format!("{label}: target has no parent"))?,
    )
    .map_err(|error| format!("{label}: parent chain is no longer trustworthy: {error:#}"))?;
    let target_identity = windows_existing_regular_identity(target_abs)
        .map_err(|error| format!("{label}: could not inspect target postcondition: {error:#}"))?;
    let backup_identity = windows_existing_regular_identity(backup_path)
        .map_err(|error| format!("{label}: could not inspect backup postcondition: {error:#}"))?;

    if target_identity == Some(original_target_identity) {
        match backup_identity {
            None => return Ok(()),
            Some(identity) if identity == original_target_identity => {
                remove_windows_file_with_identity(parent, backup_path, original_target_identity)
                    .map_err(|error| {
                    format!(
                        "{label}: original target is intact but backup {} could not be removed: {error}",
                        backup_path.display()
                    )
                })?;
                return Ok(());
            }
            Some(_) => {
                return Err(format!(
                    "{label}: original target is intact but backup {} has an unexpected identity",
                    backup_path.display()
                ));
            }
        }
    }

    if target_identity.is_some_and(|identity| {
        identity != original_target_identity && identity != candidate_identity
    }) {
        return Err(format!(
            "{label}: refusing to overwrite unknown target identity at {}; verified backup remains at {}; candidate location: {}",
            target_abs.display(),
            backup_path.display(),
            describe_windows_identity_locations(
                candidate_identity,
                &[("staging", candidate_path), ("target", target_abs)]
            )
        ));
    }

    if backup_identity != Some(original_target_identity) {
        return Err(format!(
            "{label}: original target is not at {} and no verified backup exists at {}; candidate location: {}",
            target_abs.display(),
            backup_path.display(),
            describe_windows_identity_locations(
                candidate_identity,
                &[("staging", candidate_path), ("target", target_abs)]
            )
        ));
    }

    let (backup_guard, _) = open_windows_identity_guard(
        backup_path,
        Some(original_target_identity),
        FILE_SHARE_READ,
    )
    .map_err(|error| format!("{label}: failed to guard backup before rollback: {error:#}"))?;
    let backup = windows_wide_path(backup_path)
        .map_err(|error| format!("{label}: invalid backup path: {error:#}"))?;
    let target = windows_wide_path(target_abs)
        .map_err(|error| format!("{label}: invalid target path: {error:#}"))?;
    let target_guard = if target_identity == Some(candidate_identity) {
        Some(
            open_windows_identity_guard(target_abs, Some(candidate_identity), FILE_SHARE_READ)
                .map_err(|error| {
                    format!(
                        "{label}: failed to guard candidate at target before rollback: {error:#}"
                    )
                })?,
        )
    } else {
        None
    };
    verify_windows_write_parent(
        parent,
        target_abs
            .parent()
            .ok_or_else(|| format!("{label}: target has no parent"))?,
    )
    .map_err(|error| format!("{label}: parent chain changed before rollback: {error:#}"))?;
    drop(target_guard);
    drop(backup_guard);
    // The full directory chain remains pinned, so only the final target and
    // backup names have a small same-user race after their guards are dropped.
    // Closing that last window requires a handle-relative rename API.
    // SAFETY: both buffers are valid NUL-terminated paths. The verified backup
    // lives beside the target, so rollback cannot cross volumes.
    let flags = if target_identity == Some(candidate_identity) {
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
    } else {
        MOVEFILE_WRITE_THROUGH
    };
    // SAFETY: `backup` and `target` are valid NUL-terminated path buffers that
    // remain alive for the call; the pinned parent chain keeps them on one
    // volume throughout this rollback attempt.
    let restored = unsafe { MoveFileExW(backup.as_ptr(), target.as_ptr(), flags) };
    if restored == 0 {
        return Err(format!(
            "{label}: could not restore verified backup {} to {}: {}",
            backup_path.display(),
            target_abs.display(),
            io::Error::last_os_error()
        ));
    }
    verify_windows_write_parent(
        parent,
        target_abs
            .parent()
            .ok_or_else(|| format!("{label}: target has no parent"))?,
    )
    .map_err(|error| format!("{label}: parent chain changed after rollback: {error:#}"))?;
    match windows_existing_regular_identity(target_abs) {
        Ok(Some(identity)) if identity == original_target_identity => Ok(()),
        Ok(_) => Err(format!(
            "{label}: rollback returned success but {} does not identify the original target",
            target_abs.display()
        )),
        Err(error) => Err(format!(
            "{label}: failed to verify restored target {}: {error:#}",
            target_abs.display()
        )),
    }
}

#[cfg(windows)]
fn replace_temp_into_path_raw(
    parent: &WriteParent,
    tmp_path: &Path,
    _tmp_name: &OsStr,
    target_abs: &Path,
    temp_identity: TempFileIdentity,
) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_WRITE_THROUGH,
    };

    let target_parent = target_abs
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Windows target path must have a parent"))?;
    verify_windows_write_parent(parent, target_parent)?;
    let target_exists = match fs::symlink_metadata(target_abs) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "target path {} became a symlink before replacement",
                target_abs.display()
            )
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("target path {} is not a regular file", target_abs.display())
        }
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to stat target {}", target_abs.display()))
        }
    };

    let backup_path = windows_replace_backup_path(tmp_path)?;
    match fs::symlink_metadata(&backup_path) {
        Ok(_) => bail!(
            "replacement backup path already exists: {}",
            backup_path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect replacement backup {}",
                    backup_path.display()
                )
            })
        }
    }
    let source = windows_wide_path(tmp_path)?;
    let target = windows_wide_path(target_abs)?;
    let backup = windows_wide_path(&backup_path)?;
    let (source_guard, _) =
        match open_windows_identity_guard(tmp_path, Some(temp_identity.windows), FILE_SHARE_READ) {
            Ok(guard) => guard,
            Err(error) if is_windows_sharing_violation(windows_error_raw_os_error(&error)) => {
                bail!(
                "process_in_use: replacement candidate {} is open by another process: {error:#}",
                tmp_path.display()
            )
            }
            Err(error) => return Err(error),
        };
    let target_guard = if target_exists {
        match open_windows_identity_guard(target_abs, None, FILE_SHARE_READ | FILE_SHARE_WRITE) {
            Ok(guard) => Some(guard),
            Err(error) if is_windows_sharing_violation(windows_error_raw_os_error(&error)) => {
                bail!(
                    "process_in_use: target {} is open by another process: {error:#}",
                    target_abs.display()
                )
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let original_target_identity = target_guard.as_ref().map(|(_, identity)| *identity);
    verify_windows_write_parent(parent, target_parent)?;
    drop(target_guard);
    drop(source_guard);
    // ReplaceFileW opens the replacement with share mode 0, so the identity
    // guards must be dropped immediately before this call. Every directory
    // component remains pinned without delete sharing, leaving only a narrow
    // same-user race on the final candidate/target names. Eliminating that
    // final window requires a handle-relative rename API.
    // SAFETY: all buffers are NUL-terminated and live through the call. Source,
    // target, and backup are in one directory and therefore one volume.
    let replaced = unsafe {
        if target_exists {
            ReplaceFileW(
                target.as_ptr(),
                source.as_ptr(),
                backup.as_ptr(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        } else {
            MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH)
        }
    };
    if replaced == 0 {
        let error = io::Error::last_os_error();
        if let Some(original_target_identity) = original_target_identity {
            if let Err(recovery_error) = recover_windows_replace_failure(
                parent,
                target_abs,
                tmp_path,
                &backup_path,
                original_target_identity,
                temp_identity.windows,
                error.raw_os_error(),
            ) {
                let candidate_location = describe_windows_identity_locations(
                    temp_identity.windows,
                    &[("staging", tmp_path), ("target", target_abs)],
                );
                return Err(anyhow::Error::new(ReplacementRollbackFailed(format!(
                    "replacement of {} failed with {error}; {recovery_error}; candidate location: {candidate_location}; any verified backup remains at {}",
                    target_abs.display(),
                    backup_path.display()
                ))));
            }
        }
        if is_windows_sharing_violation(error.raw_os_error()) {
            bail!(
                "process_in_use: target {} could not be replaced because it is open by another process: {error}",
                target_abs.display()
            );
        }
        return Err(error).with_context(|| {
            format!(
                "failed to replace {} from {}",
                target_abs.display(),
                tmp_path.display()
            )
        });
    }
    if let Some(original_target_identity) = original_target_identity {
        verify_windows_write_parent(parent, target_parent)?;
        match remove_windows_file_with_identity(parent, &backup_path, original_target_identity) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) => {}
            Err(cleanup_error) => {
                if let Err(recovery_error) = recover_windows_replace_failure(
                    parent,
                    target_abs,
                    tmp_path,
                    &backup_path,
                    original_target_identity,
                    temp_identity.windows,
                    None,
                ) {
                    let candidate_location = describe_windows_identity_locations(
                        temp_identity.windows,
                        &[("staging", tmp_path), ("target", target_abs)],
                    );
                    return Err(anyhow::Error::new(ReplacementRollbackFailed(format!(
                        "replacement of {} committed but recovery backup {} could not be removed: {cleanup_error}; {recovery_error}; candidate location: {candidate_location}; target and backup were preserved",
                        target_abs.display(),
                        backup_path.display()
                    ))));
                }
                bail!(
                    "replacement of {} was rolled back because recovery backup {} could not be removed: {cleanup_error}",
                    target_abs.display(),
                    backup_path.display()
                );
            }
        }
    }
    verify_windows_write_parent(parent, target_parent)?;
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn replace_temp_into_path_raw(
    _parent: &WriteParent,
    tmp_path: &Path,
    _tmp_name: &OsStr,
    target_abs: &Path,
    _temp_identity: TempFileIdentity,
) -> Result<()> {
    fs::rename(tmp_path, target_abs).with_context(|| {
        format!(
            "failed to rename temp file into {} from {}",
            target_abs.display(),
            tmp_path.display()
        )
    })
}

#[cfg(any(windows, test))]
fn is_windows_sharing_violation(raw_os_error: Option<i32>) -> bool {
    // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, and
    // ERROR_USER_MAPPED_FILE are the Windows replacement failures that mean
    // another process currently prevents replacement, rather than a path or
    // permission policy failure.
    matches!(raw_os_error, Some(32 | 33 | 1224))
}

#[cfg(windows)]
fn windows_error_raw_os_error(error: &anyhow::Error) -> Option<i32> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .and_then(io::Error::raw_os_error)
}

#[cfg(unix)]
fn verify_temp_file_identity(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let handle_metadata = file
        .metadata()
        .with_context(|| format!("failed to stat open temp file {}", path.display()))?;
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat temp path {}", path.display()))?;
    if !path_metadata.is_file() {
        bail!("temp path {} is not a regular file", path.display());
    }
    if handle_metadata.dev() != path_metadata.dev() || handle_metadata.ino() != path_metadata.ino()
    {
        bail!("temp path {} was replaced during upload", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn verify_temp_file_identity(file: &File, path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat temp path {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("temp path {} is not a regular file", path.display());
    }
    let handle_identity = windows_file_identity(file, path)?;
    let (_, path_identity) =
        open_windows_identity_guard(path, None, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
    if handle_identity != path_identity {
        bail!("temp path {} was replaced during upload", path.display());
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn verify_temp_file_identity(_file: &File, path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat temp path {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("temp path {} is not a regular file", path.display());
    }
    Ok(())
}

fn capture_temp_file_identity(file: &File, path: &Path) -> Result<TempFileIdentity> {
    verify_temp_file_identity(file, path)?;
    Ok(TempFileIdentity {
        #[cfg(windows)]
        windows: windows_file_identity(file, path)?,
    })
}

fn normalize_relative_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    if path.is_absolute() {
        bail!("remote paths must be workspace-relative");
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir => bail!("remote path must not contain '..'"),
            Component::RootDir | Component::Prefix(_) => bail!("remote path must be relative"),
        }
    }
    if clean.as_os_str().is_empty() {
        bail!("remote path must not be empty");
    }
    Ok(clean)
}

fn file_meta(root: &Path, path: &Path, include_hash: bool) -> Result<FileMeta> {
    #[cfg(test)]
    FILE_META_CALLS.with(|calls| calls.set(calls.get() + 1));

    let metadata = fs::symlink_metadata(path)?;
    let hash = if include_hash && metadata.is_file() {
        Some(hash_file(path)?)
    } else {
        None
    };
    Ok(file_meta_from_metadata(
        relative_path(root, path)?,
        &metadata,
        hash,
    ))
}

fn file_meta_from_metadata(
    path: String,
    metadata: &fs::Metadata,
    hash: Option<String>,
) -> FileMeta {
    FileMeta {
        path,
        size: metadata.len(),
        mtime_ms: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0),
        mode: platform_mode(metadata),
        is_dir: metadata.is_dir(),
        is_symlink: metadata.file_type().is_symlink(),
        hash,
    }
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    if let Ok(relative) = path.strip_prefix(root) {
        return Ok(relative.to_string_lossy().replace('\\', "/"));
    }
    #[cfg(windows)]
    {
        let root = windows_path_text(root);
        let path = windows_path_text(path);
        let root = root.trim_end_matches('\\');
        if path
            .get(..root.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(root))
            && path
                .get(root.len()..)
                .and_then(|suffix| suffix.chars().next())
                .is_some_and(|character| character == '\\')
        {
            let relative = path
                .get(root.len() + 1..)
                .ok_or_else(|| anyhow::anyhow!("relative Windows path is not valid UTF-8"))?;
            return Ok(relative.replace('\\', "/"));
        }
    }
    bail!(
        "{} cannot be expressed relative to remote root {}",
        path.display(),
        root.display()
    )
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    hash_open_file(&mut file)
}

fn hash_open_file(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn likely_binary_open_file(file: &mut File) -> Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = [0_u8; 1024];
    let read = file.read(&mut buffer)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(buffer[..read].contains(&0))
}

#[cfg(unix)]
fn platform_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn platform_mode(_: &fs::Metadata) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CanonicalTempDir {
        _inner: tempfile::TempDir,
        root: PathBuf,
    }

    impl CanonicalTempDir {
        fn path(&self) -> &Path {
            &self.root
        }
    }

    fn tempdir() -> io::Result<CanonicalTempDir> {
        let inner = tempfile::tempdir()?;
        let root = inner.path().canonicalize()?;
        Ok(CanonicalTempDir {
            _inner: inner,
            root,
        })
    }

    fn test_state(root: &Path) -> AgentState {
        AgentState {
            // Match the invariant established by `serve`. On macOS, temporary
            // directories may be reported through `/var` while canonical
            // descendants resolve through `/private/var`.
            root: root.canonicalize().unwrap(),
            uploads: HashMap::new(),
            active_write_targets: HashSet::new(),
            grep_sessions: HashMap::new(),
            next_grep_session: 1,
        }
    }

    #[test]
    fn temporary_roots_match_the_serving_root_invariant() {
        let dir = tempdir().unwrap();
        assert_eq!(dir.path(), dir.path().canonicalize().unwrap());
    }

    fn run_git_test_command(root: &Path, args: &[&str]) {
        let output = ProcessCommand::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_git_repo(root: &Path) {
        run_git_test_command(root, &["init", "-q"]);
        run_git_test_command(root, &["config", "user.email", "test@example.invalid"]);
        run_git_test_command(root, &["config", "user.name", "Test User"]);
        fs::write(root.join("tracked.txt"), "base\n").unwrap();
        run_git_test_command(root, &["add", "tracked.txt"]);
        run_git_test_command(root, &["commit", "-q", "-m", "base"]);
    }

    fn git_output(response: Response) -> GitCommandOutput {
        match response {
            Response::Git { output } => output,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(normalize_relative_path("../secret").is_err());
        assert!(normalize_relative_path("/secret").is_err());
    }

    #[test]
    fn git_status_reports_modified_and_untracked_files() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());
        fs::write(dir.path().join("tracked.txt"), "changed\n").unwrap();
        fs::write(dir.path().join("new.txt"), "new\n").unwrap();

        let output = git_output(git_status(dir.path(), Vec::new(), 4096).unwrap());

        assert_eq!(output.status_code, Some(0));
        assert!(!output.truncated);
        assert!(
            output.stdout.contains(" M tracked.txt"),
            "{}",
            output.stdout
        );
        assert!(output.stdout.contains("?? new.txt"), "{}", output.stdout);
    }

    #[test]
    fn git_status_filters_workspace_relative_paths() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());
        fs::write(dir.path().join("tracked.txt"), "changed\n").unwrap();
        fs::write(dir.path().join("new.txt"), "new\n").unwrap();

        let output =
            git_output(git_status(dir.path(), vec!["tracked.txt".to_string()], 4096).unwrap());

        assert_eq!(output.status_code, Some(0));
        assert!(
            output.stdout.contains(" M tracked.txt"),
            "{}",
            output.stdout
        );
        assert!(!output.stdout.contains("new.txt"), "{}", output.stdout);
    }

    #[test]
    fn git_status_treats_pathspecs_as_literals() {
        let dir = tempdir().unwrap();
        run_git_test_command(dir.path(), &["init", "-q"]);
        run_git_test_command(
            dir.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        run_git_test_command(dir.path(), &["config", "user.name", "Test User"]);
        fs::write(dir.path().join("literal[ab].txt"), "base\n").unwrap();
        fs::write(dir.path().join("literala.txt"), "base\n").unwrap();
        run_git_test_command(dir.path(), &["add", "."]);
        run_git_test_command(dir.path(), &["commit", "-q", "-m", "base"]);
        fs::write(dir.path().join("literal[ab].txt"), "changed\n").unwrap();
        fs::write(dir.path().join("literala.txt"), "changed\n").unwrap();

        let output =
            git_output(git_status(dir.path(), vec!["literal[ab].txt".to_string()], 4096).unwrap());

        assert_eq!(output.status_code, Some(0));
        assert!(
            output.stdout.contains(" M literal[ab].txt"),
            "{}",
            output.stdout
        );
        assert!(!output.stdout.contains("literala.txt"), "{}", output.stdout);
    }

    #[test]
    fn git_status_rebases_subdirectory_worktree_paths() {
        let dir = tempdir().unwrap();
        run_git_test_command(dir.path(), &["init", "-q"]);
        run_git_test_command(
            dir.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        run_git_test_command(dir.path(), &["config", "user.name", "Test User"]);
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::create_dir_all(dir.path().join("other")).unwrap();
        fs::write(dir.path().join("sub/a.txt"), "base\n").unwrap();
        fs::write(dir.path().join("other/o.txt"), "base\n").unwrap();
        run_git_test_command(dir.path(), &["add", "."]);
        run_git_test_command(dir.path(), &["commit", "-q", "-m", "base"]);
        fs::write(dir.path().join("sub/a.txt"), "changed\n").unwrap();
        fs::write(dir.path().join("other/o.txt"), "changed\n").unwrap();

        let output = git_output(git_status(&dir.path().join("sub"), Vec::new(), 4096).unwrap());

        assert_eq!(output.status_code, Some(0));
        assert!(output.stdout.contains(" M a.txt"), "{}", output.stdout);
        assert!(!output.stdout.contains("sub/a.txt"), "{}", output.stdout);
        assert!(!output.stdout.contains("other/o.txt"), "{}", output.stdout);
    }

    #[test]
    fn git_diff_truncates_large_output() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());
        fs::write(dir.path().join("tracked.txt"), "changed\n".repeat(64)).unwrap();

        let output =
            git_output(git_diff(dir.path(), Some("tracked.txt".to_string()), false, 32).unwrap());

        assert!(output.truncated);
        assert!(output.stdout.len() <= 32);
    }

    #[test]
    fn git_diff_uses_subdirectory_relative_headers() {
        let dir = tempdir().unwrap();
        run_git_test_command(dir.path(), &["init", "-q"]);
        run_git_test_command(
            dir.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        run_git_test_command(dir.path(), &["config", "user.name", "Test User"]);
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/a.txt"), "base\n").unwrap();
        run_git_test_command(dir.path(), &["add", "."]);
        run_git_test_command(dir.path(), &["commit", "-q", "-m", "base"]);
        fs::write(dir.path().join("sub/a.txt"), "changed\n").unwrap();

        let output = git_output(
            git_diff(
                &dir.path().join("sub"),
                Some("a.txt".to_string()),
                false,
                4096,
            )
            .unwrap(),
        );

        assert_eq!(output.status_code, Some(0));
        assert!(
            output.stdout.contains("diff --git a/a.txt b/a.txt"),
            "{}",
            output.stdout
        );
        assert!(!output.stdout.contains("sub/a.txt"), "{}", output.stdout);
    }

    #[test]
    fn git_blame_returns_committed_lines() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        let output = git_output(git_blame(dir.path(), "tracked.txt".to_string(), 4096).unwrap());

        assert_eq!(output.status_code, Some(0));
        assert!(!output.truncated);
        assert!(output.stdout.contains("base"), "{}", output.stdout);
    }

    #[test]
    fn git_commands_reject_traversal_paths() {
        let dir = tempdir().unwrap();
        init_git_repo(dir.path());

        assert!(git_status(dir.path(), vec!["../tracked.txt".to_string()], 4096).is_err());
        assert!(git_diff(dir.path(), Some("../tracked.txt".to_string()), false, 4096).is_err());
        assert!(git_blame(dir.path(), "../tracked.txt".to_string(), 4096).is_err());
    }

    #[test]
    fn git_status_reports_non_repo_error_without_panicking() {
        let dir = tempdir().unwrap();
        // Prevent discovery of an unrelated repository above the platform's
        // temporary directory (some Windows developer homes are Git roots).
        fs::write(dir.path().join(".git"), "not-a-gitdir\n").unwrap();

        let output = git_output(git_status(dir.path(), Vec::new(), 4096).unwrap());

        assert_ne!(output.status_code, Some(0));
        assert!(
            output.stderr.contains("not a git repository")
                || output.stderr.contains("invalid gitfile format"),
            "{}",
            output.stderr
        );
    }

    #[test]
    fn hello_rejects_incompatible_protocol_version() {
        let dir = tempdir().unwrap();
        let mut state = test_state(dir.path());

        let error = handle_request(
            &mut state,
            Request::Hello {
                client_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION + 1,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("protocol version mismatch"));
    }

    #[test]
    fn hello_accepts_exact_package_and_protocol_versions() {
        let dir = tempdir().unwrap();
        let mut state = test_state(dir.path());

        let response = handle_request(
            &mut state,
            Request::Hello {
                client_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .unwrap();

        assert!(matches!(
            response,
            Response::Hello {
                agent_version,
                protocol_version: PROTOCOL_VERSION,
                ..
            } if agent_version == env!("CARGO_PKG_VERSION")
        ));
    }

    #[test]
    fn hello_rejects_incompatible_package_version() {
        let dir = tempdir().unwrap();
        let mut state = test_state(dir.path());

        let error = handle_request(
            &mut state,
            Request::Hello {
                client_version: "0.0.0-incompatible".to_string(),
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("package version mismatch"));
        assert!(error.contains("0.0.0-incompatible"));
    }

    #[cfg(unix)]
    #[test]
    fn read_file_rejects_symlink_parent_escape() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir_all(outside.path().join("repo")).unwrap();
        fs::write(outside.path().join("repo/secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.path().join("repo"), dir.path().join("link")).unwrap();

        let error = read_file(dir.path(), "link/secret.txt".to_string(), 0, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("resolves outside remote root"));
    }

    #[cfg(unix)]
    #[test]
    fn write_cas_rejects_symlink_parent_escape() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();

        let error = write_file_cas(
            dir.path(),
            "link/new.txt".to_string(),
            None,
            b"secret".to_vec(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("resolves outside remote root"));
        assert!(!outside.path().join("new.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn content_operations_reject_final_symlinks() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("real.txt"), "real").unwrap();
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("link.txt")).unwrap();

        let read_error = read_file(root, "link.txt".to_string(), 0, None)
            .unwrap_err()
            .to_string();
        assert!(read_error.contains("is a symlink"));

        let write_error = write_file_cas(root, "link.txt".to_string(), None, b"new".to_vec())
            .unwrap_err()
            .to_string();
        assert!(write_error.contains("is a symlink"));
        assert_eq!(fs::read_to_string(root.join("real.txt")).unwrap(), "real");
    }

    #[cfg(unix)]
    #[test]
    fn conflict_capture_rejects_final_symlink_content() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("real.txt"), "remote secret").unwrap();
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("link.txt")).unwrap();

        let conflict = save_conflict(
            root,
            "link.txt".to_string(),
            Some("expected".to_string()),
            Some("actual".to_string()),
        );

        assert!(conflict.remote_content.is_empty());
        assert_eq!(conflict.remote_size, None);
        assert!(!conflict.remote_content_truncated);
    }

    #[cfg(unix)]
    #[test]
    fn checksum_rejects_symlink_parent_escape() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let mut state = test_state(dir.path());

        let error = handle_request(
            &mut state,
            Request::Checksum {
                path: "link/secret.txt".to_string(),
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("resolves outside remote root"));
    }

    #[cfg(unix)]
    #[test]
    fn stat_and_validate_reject_symlink_parent_escape() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let mut state = test_state(dir.path());

        let stat_error = handle_request(
            &mut state,
            Request::Stat {
                path: "link/secret.txt".to_string(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(stat_error.contains("resolves outside remote root"));

        let response =
            validate_files(dir.path(), vec!["link/secret.txt".to_string()], true).unwrap();
        match response {
            Response::ValidateFiles { files, errors } => {
                assert!(files.is_empty());
                assert_eq!(errors.len(), 1);
                assert!(errors[0].message.contains("resolves outside remote root"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn metadata_apis_treat_nested_path_under_file_as_missing() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("dir"), "not a directory").unwrap();
        let mut state = test_state(root);

        let stat = handle_request(
            &mut state,
            Request::Stat {
                path: "dir/file.txt".to_string(),
            },
        )
        .unwrap();
        match stat {
            Response::Stat { meta } => assert!(meta.is_none()),
            other => panic!("unexpected response: {other:?}"),
        }

        let checksum = handle_request(
            &mut state,
            Request::Checksum {
                path: "dir/file.txt".to_string(),
            },
        )
        .unwrap();
        match checksum {
            Response::Checksum { hash, .. } => assert!(hash.is_none()),
            other => panic!("unexpected response: {other:?}"),
        }

        let validate = validate_files(root, vec!["dir/file.txt".to_string()], true).unwrap();
        match validate {
            Response::ValidateFiles { files, errors } => {
                assert!(errors.is_empty());
                assert_eq!(files.len(), 1);
                assert!(files[0].meta.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn reads_preserve_requested_path_under_in_root_symlink_parent() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("real")).unwrap();
        fs::write(root.join("real/a.txt"), "content").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();

        let response = read_file(root, "link/a.txt".to_string(), 0, None).unwrap();
        match response {
            Response::ReadFile { path, meta, .. } => {
                assert_eq!(path, "link/a.txt");
                assert_eq!(meta.path, "link/a.txt");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let response = read_files(root, vec!["link/a.txt".to_string()], 1024, 1024).unwrap();
        match response {
            Response::ReadFiles { files, errors, .. } => {
                assert!(errors.is_empty());
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].path, "link/a.txt");
                assert_eq!(files[0].meta.path, "link/a.txt");
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn write_cas_reports_conflict_when_hash_changes() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "one").unwrap();
        let stale_hash = "not-current".to_string();

        let response = write_file_cas(
            root,
            "a.txt".to_string(),
            Some(stale_hash.clone()),
            b"two".to_vec(),
        )
        .unwrap();

        match response {
            Response::WriteFileCas {
                outcome: SaveOutcome::Conflict(conflict),
            } => {
                assert_eq!(conflict.expected_hash, Some(stale_hash));
                assert_eq!(conflict.remote_content, b"one");
                assert!(!conflict.remote_content_truncated);
                assert_eq!(conflict.remote_size, Some(3));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "one");
    }

    #[test]
    fn write_cas_rechecks_hash_before_rename() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "one").unwrap();
        let old_hash = hash_file(&root.join("a.txt")).unwrap();
        let external_hash = hash_bytes(b"external");

        let response = write_file_cas_inner(
            root,
            "a.txt".to_string(),
            Some(old_hash),
            b"two".to_vec(),
            || {
                fs::write(root.join("a.txt"), "external")?;
                Ok(())
            },
        )
        .unwrap();

        match response {
            Response::WriteFileCas {
                outcome: SaveOutcome::Conflict(conflict),
            } => {
                assert_eq!(
                    conflict.actual_hash.as_deref(),
                    Some(external_hash.as_str())
                );
                assert_eq!(conflict.remote_content, b"external");
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "external");
    }

    #[test]
    fn write_lock_is_exclusive_and_released_when_guard_drops() {
        let dir = tempdir().unwrap();
        let target_keys = write_target_keys(dir.path(), &dir.path().join("a.txt")).unwrap();
        let first = acquire_write_locks(&target_keys, "a.txt").unwrap();

        let error = acquire_write_locks(&target_keys, "a.txt")
            .err()
            .expect("a second writer must not acquire the same lock")
            .to_string();
        assert!(error.contains("write already in progress"));

        let other_keys = write_target_keys(dir.path(), &dir.path().join("b.txt")).unwrap();
        let _other = acquire_write_locks(&other_keys, "b.txt").unwrap();
        drop(first);
        let _reacquired = acquire_write_locks(&target_keys, "a.txt").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_write_lock_root_rejects_symlinks_and_wrong_owners() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = tempdir().unwrap();
        let actual = dir.path().join("actual-lock-root");
        fs::create_dir(&actual).unwrap();
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.path().join("linked-lock-root");
        symlink(&actual, &link).unwrap();

        let symlink_error = open_private_unix_lock_root(&link, unix_effective_uid())
            .unwrap_err()
            .to_string();
        assert!(symlink_error.contains("must not be a symlink"));

        let other_uid = unix_effective_uid().wrapping_add(1);
        let owner_error = open_private_unix_lock_root(&actual, other_uid)
            .unwrap_err()
            .to_string();
        assert!(owner_error.contains("is owned by uid"));
        assert!(owner_error.contains(&format!("expected uid {other_uid}")));
    }

    #[cfg(unix)]
    #[test]
    fn unix_write_lock_root_and_entries_are_tightened_to_private_modes() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = tempdir().unwrap();
        let lock_root = dir.path().join("permissive-lock-root");
        fs::create_dir(&lock_root).unwrap();
        fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o777)).unwrap();
        let lock_path = lock_root.join("test.lock");
        fs::write(&lock_path, []).unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o666)).unwrap();

        let directory = open_private_unix_lock_root(&lock_root, unix_effective_uid()).unwrap();
        assert_eq!(
            fs::symlink_metadata(&lock_root).unwrap().mode() & 0o7777,
            0o700
        );
        let lock = open_private_unix_lock_file(
            &directory,
            &lock_root,
            OsStr::new("test.lock"),
            unix_effective_uid(),
        )
        .unwrap();
        assert_eq!(lock.metadata().unwrap().mode() & 0o7777, 0o600);
        assert_eq!(
            fs::symlink_metadata(&lock_path).unwrap().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_write_lock_entry_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let lock_root = dir.path().join("lock-root");
        let directory = open_private_unix_lock_root(&lock_root, unix_effective_uid()).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, []).unwrap();
        symlink(&outside, lock_root.join("hostile.lock")).unwrap();

        let error = open_private_unix_lock_file(
            &directory,
            &lock_root,
            OsStr::new("hostile.lock"),
            unix_effective_uid(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("failed to open write lock"));
        assert!(fs::symlink_metadata(lock_root.join("hostile.lock"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(windows)]
    #[test]
    fn windows_write_lock_identity_normalizes_case_and_separators() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("Absent-Ångström.TXT");
        let alias_root = PathBuf::from(windows_path_text(&root).to_lowercase().replace('\\', "/"));
        let alias_target = alias_root.join("absent-ångström.txt");
        let mixed_case_keys = write_target_keys(&root, &target).unwrap();
        let alias_keys = write_target_keys(&alias_root, &alias_target).unwrap();
        assert_eq!(mixed_case_keys, alias_keys);

        let first = acquire_write_locks(&mixed_case_keys, "Foo.TXT").unwrap();
        let error = acquire_write_locks(&alias_keys, "foo.txt")
            .err()
            .expect("Windows path aliases must contend on the same lock")
            .to_string();
        assert!(error.contains("write already in progress"), "{error}");
        drop(first);
    }

    #[cfg(windows)]
    #[test]
    fn windows_existing_hardlink_aliases_share_file_identity_lock() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("a.txt");
        let alias = root.join("alias.txt");
        fs::write(&target, "content").unwrap();
        fs::hard_link(&target, &alias).unwrap();

        let target_keys = write_target_keys(&root, &target).unwrap();
        let alias_keys = write_target_keys(&root, &alias).unwrap();

        assert_eq!(target_keys.len(), 3);
        assert_eq!(alias_keys.len(), 3);
        assert_eq!(
            target_keys
                .iter()
                .filter(|key| alias_keys.contains(key))
                .count(),
            1,
            "hardlink aliases must share exactly the file-ID lock"
        );
        let first = acquire_write_locks(&target_keys, "a.txt").unwrap();
        let error = acquire_write_locks(&alias_keys, "alias.txt")
            .err()
            .expect("hardlink alias lock must contend")
            .to_string();
        assert!(error.contains("write already in progress"), "{error}");
        drop(first);
    }

    #[cfg(windows)]
    #[test]
    fn windows_lock_child_process_helper() {
        let Some(encoded_keys) = std::env::var_os("NRM_TEST_LOCK_CHILD_KEYS") else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os("NRM_TEST_LOCK_CHILD_READY").unwrap());
        let release = PathBuf::from(std::env::var_os("NRM_TEST_LOCK_CHILD_RELEASE").unwrap());
        let keys: Vec<String> = encoded_keys
            .to_string_lossy()
            .split(',')
            .map(str::to_string)
            .collect();
        let _lock = acquire_write_locks(&keys, "cross-process-child").unwrap();
        fs::write(&ready, "ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !release.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(release.exists(), "parent did not release lock child");
    }

    #[cfg(windows)]
    #[test]
    fn windows_hardlink_lock_contends_across_processes() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("target.txt");
        let alias = root.join("alias.txt");
        fs::write(&target, "content").unwrap();
        fs::hard_link(&target, &alias).unwrap();
        let child_keys = write_target_keys(&root, &target).unwrap();
        let parent_keys = write_target_keys(&root, &alias).unwrap();
        let ready = root.join("child-ready");
        let release = root.join("child-release");
        let mut child = ProcessCommand::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::windows_lock_child_process_helper")
            .arg("--nocapture")
            .env("NRM_TEST_LOCK_CHILD_KEYS", child_keys.join(","))
            .env("NRM_TEST_LOCK_CHILD_READY", &ready)
            .env("NRM_TEST_LOCK_CHILD_RELEASE", &release)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() && Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "lock child exited early"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "lock child did not become ready");

        let error = acquire_write_locks(&parent_keys, "cross-process-parent")
            .err()
            .expect("cross-process lock must contend")
            .to_string();
        assert!(error.contains("write already in progress"), "{error}");
        fs::write(&release, "release").unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[cfg(windows)]
    #[test]
    fn windows_verbatim_paths_compare_and_rebase_under_drive_roots() {
        let root = tempdir().unwrap();
        let source = root.path().join("Src");
        fs::create_dir(&source).unwrap();
        let child = source.join("Main.rs");
        fs::write(&child, "test").unwrap();
        let canonical_child = child.canonicalize().unwrap();

        ensure_path_within_root(root.path(), &canonical_child).unwrap();
        assert_eq!(
            relative_path(root.path(), &canonical_child).unwrap(),
            "Src/Main.rs"
        );

        let outside = tempdir().unwrap();
        assert!(ensure_path_within_root(root.path(), outside.path()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_write_parent_pins_every_component_against_rename() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ancestor = root.join("ancestor");
        let parent_path = ancestor.join("parent");
        let moved = root.join("moved-ancestor");
        fs::create_dir_all(&parent_path).unwrap();
        let target = WriteTarget {
            abs: parent_path.join("a.txt"),
            parent_abs: parent_path.clone(),
        };

        let parent = open_write_parent(&root, &target).unwrap();

        assert_eq!(parent.pinned_directories.len(), 3);
        let rename_error = fs::rename(&ancestor, &moved).unwrap_err();
        assert!(
            is_windows_sharing_violation(rename_error.raw_os_error())
                || rename_error.raw_os_error() == Some(5),
            "{rename_error}"
        );
        verify_windows_write_parent(&parent, &parent_path).unwrap();
        drop(parent);
        fs::rename(&ancestor, &moved).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_cas_blocks_ancestor_swap_and_leaves_no_staging_files() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ancestor = root.join("ancestor");
        let parent_path = ancestor.join("parent");
        let moved = root.join("moved-ancestor");
        let target = parent_path.join("a.txt");
        fs::create_dir_all(&parent_path).unwrap();
        fs::write(&target, "old").unwrap();
        let old_hash = hash_file(&target).unwrap();

        let response = write_file_cas_inner(
            &root,
            "ancestor/parent/a.txt".to_string(),
            Some(old_hash),
            b"new".to_vec(),
            || {
                let error = fs::rename(&ancestor, &moved).unwrap_err();
                assert!(
                    is_windows_sharing_violation(error.raw_os_error())
                        || error.raw_os_error() == Some(5),
                    "{error}"
                );
                Ok(())
            },
        )
        .unwrap();

        assert!(matches!(
            response,
            Response::WriteFileCas {
                outcome: SaveOutcome::Applied(_)
            }
        ));
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        let leftovers: Vec<_> = fs::read_dir(&parent_path)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("nrm-tmp") || name.contains("nrm-backup"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "leftover staging files: {leftovers:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_cas_creates_and_pins_missing_parent_chain() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();

        let response = write_file_cas(
            &root,
            "new/deep/a.txt".to_string(),
            None,
            b"content".to_vec(),
        )
        .unwrap();

        assert!(matches!(
            response,
            Response::WriteFileCas {
                outcome: SaveOutcome::Applied(_)
            }
        ));
        assert_eq!(
            fs::read_to_string(root.join("new/deep/a.txt")).unwrap(),
            "content"
        );
    }

    #[test]
    fn replacement_abstraction_replaces_existing_file_and_consumes_temp() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target_abs = root.join("a.txt");
        let tmp_path = root.join("a.nrm-replace-test");
        fs::write(&target_abs, "old").unwrap();
        fs::write(&tmp_path, "new").unwrap();
        let target = WriteTarget {
            abs: target_abs.clone(),
            #[cfg(any(unix, windows))]
            parent_abs: root.clone(),
        };
        let parent = open_write_parent(&root, &target).unwrap();
        let tmp_name = temp_file_name(&tmp_path).unwrap();
        let tmp_file = File::open(&tmp_path).unwrap();
        let temp_identity = capture_temp_file_identity(&tmp_file, &tmp_path).unwrap();
        drop(tmp_file);

        rename_temp_into_path(&parent, &tmp_path, &tmp_name, &target_abs, temp_identity).unwrap();

        assert_eq!(fs::read_to_string(&target_abs).unwrap(), "new");
        assert!(!tmp_path.exists());
        #[cfg(windows)]
        assert!(!windows_replace_backup_path(&tmp_path).unwrap().exists());
    }

    #[test]
    fn failed_replacement_cleans_temp_and_preserves_target() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target_abs = root.join("target-directory");
        let tmp_path = root.join("a.nrm-replace-test");
        fs::create_dir(&target_abs).unwrap();
        fs::write(&tmp_path, "new").unwrap();
        let target = WriteTarget {
            abs: target_abs.clone(),
            #[cfg(any(unix, windows))]
            parent_abs: root.clone(),
        };
        let parent = open_write_parent(&root, &target).unwrap();
        let tmp_name = temp_file_name(&tmp_path).unwrap();
        let tmp_file = File::open(&tmp_path).unwrap();
        let temp_identity = capture_temp_file_identity(&tmp_file, &tmp_path).unwrap();
        drop(tmp_file);

        assert!(
            rename_temp_into_path(&parent, &tmp_path, &tmp_name, &target_abs, temp_identity,)
                .is_err()
        );

        assert!(target_abs.is_dir());
        assert!(!tmp_path.exists());
    }

    #[test]
    fn windows_sharing_violation_codes_are_classified_narrowly() {
        assert!(is_windows_sharing_violation(Some(32)));
        assert!(is_windows_sharing_violation(Some(33)));
        assert!(is_windows_sharing_violation(Some(1224)));
        assert!(!is_windows_sharing_violation(Some(5)));
        assert!(!is_windows_sharing_violation(None));
    }

    #[test]
    fn windows_partial_replace_failure_codes_have_stable_labels() {
        assert_eq!(
            windows_replace_failure_label(Some(1175)),
            "ERROR_UNABLE_TO_REMOVE_REPLACED (1175)"
        );
        assert_eq!(
            windows_replace_failure_label(Some(1176)),
            "ERROR_UNABLE_TO_MOVE_REPLACEMENT (1176)"
        );
        assert_eq!(
            windows_replace_failure_label(Some(1177)),
            "ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 (1177)"
        );
        assert_eq!(
            windows_replace_failure_label(Some(5)),
            "Windows replacement error"
        );
    }

    #[test]
    fn rollback_failed_preserves_candidate_and_backup_artifacts() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target_abs = root.join("a.txt");
        let tmp_path = root.join("a.nrm-recovery-test");
        let backup_path = root.join("a.nrm-recovery-test.nrm-backup");
        fs::write(&tmp_path, "candidate").unwrap();
        fs::write(&backup_path, "original").unwrap();
        let target = WriteTarget {
            abs: target_abs,
            #[cfg(any(unix, windows))]
            parent_abs: root.clone(),
        };
        let parent = open_write_parent(&root, &target).unwrap();
        let tmp_name = temp_file_name(&tmp_path).unwrap();

        let error = cleanup_failed_replacement(
            &parent,
            &tmp_path,
            &tmp_name,
            anyhow::Error::new(ReplacementRollbackFailed(
                "simulated recovery failure".to_string(),
            )),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("rollback_failed"), "{error}");
        assert_eq!(fs::read_to_string(&tmp_path).unwrap(), "candidate");
        assert_eq!(fs::read_to_string(&backup_path).unwrap(), "original");
    }

    #[cfg(windows)]
    #[test]
    fn windows_1175_and_1176_confirm_intact_original_postcondition() {
        for error_code in [1175, 1176] {
            let dir = tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let target = root.join("a.txt");
            let candidate = root.join("a.nrm-recovery-test");
            let backup = windows_replace_backup_path(&candidate).unwrap();
            fs::write(&target, "original").unwrap();
            fs::write(&candidate, "candidate").unwrap();
            let write_target = WriteTarget {
                abs: target.clone(),
                parent_abs: root.clone(),
            };
            let parent = open_write_parent(&root, &write_target).unwrap();
            let original_identity = windows_existing_regular_identity(&target).unwrap().unwrap();
            let candidate_identity = windows_existing_regular_identity(&candidate)
                .unwrap()
                .unwrap();

            recover_windows_replace_failure(
                &parent,
                &target,
                &candidate,
                &backup,
                original_identity,
                candidate_identity,
                Some(error_code),
            )
            .unwrap();

            assert_eq!(fs::read_to_string(&target).unwrap(), "original");
            assert_eq!(fs::read_to_string(&candidate).unwrap(), "candidate");
            assert!(!backup.exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_1177_restores_verified_backup() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("a.txt");
        let candidate = root.join("a.nrm-recovery-test");
        let backup = windows_replace_backup_path(&candidate).unwrap();
        fs::write(&target, "original").unwrap();
        fs::write(&candidate, "candidate").unwrap();
        let write_target = WriteTarget {
            abs: target.clone(),
            parent_abs: root.clone(),
        };
        let parent = open_write_parent(&root, &write_target).unwrap();
        let original_identity = windows_existing_regular_identity(&target).unwrap().unwrap();
        let candidate_identity = windows_existing_regular_identity(&candidate)
            .unwrap()
            .unwrap();
        fs::rename(&target, &backup).unwrap();

        recover_windows_replace_failure(
            &parent,
            &target,
            &candidate,
            &backup,
            original_identity,
            candidate_identity,
            Some(1177),
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
        assert_eq!(fs::read_to_string(&candidate).unwrap(), "candidate");
        assert!(!backup.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_1177_rejects_unverified_backup_without_deleting_artifacts() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("a.txt");
        let original = root.join("original-recovery-copy");
        let candidate = root.join("a.nrm-recovery-test");
        let backup = windows_replace_backup_path(&candidate).unwrap();
        fs::write(&target, "original").unwrap();
        fs::write(&candidate, "candidate").unwrap();
        let write_target = WriteTarget {
            abs: target.clone(),
            parent_abs: root.clone(),
        };
        let parent = open_write_parent(&root, &write_target).unwrap();
        let original_identity = windows_existing_regular_identity(&target).unwrap().unwrap();
        let candidate_identity = windows_existing_regular_identity(&candidate)
            .unwrap()
            .unwrap();
        fs::rename(&target, &original).unwrap();
        fs::write(&backup, "impostor").unwrap();

        let error = recover_windows_replace_failure(
            &parent,
            &target,
            &candidate,
            &backup,
            original_identity,
            candidate_identity,
            Some(1177),
        )
        .unwrap_err();

        assert!(error.contains("no verified backup"), "{error}");
        assert!(error.contains("candidate location: staging="), "{error}");
        assert_eq!(fs::read_to_string(&original).unwrap(), "original");
        assert_eq!(fs::read_to_string(&candidate).unwrap(), "candidate");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "impostor");
        assert!(!target.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_1177_preserves_unknown_target_and_verified_backup() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("a.txt");
        let candidate = root.join("a.nrm-recovery-test");
        let backup = windows_replace_backup_path(&candidate).unwrap();
        fs::write(&target, "original").unwrap();
        fs::write(&candidate, "candidate").unwrap();
        let write_target = WriteTarget {
            abs: target.clone(),
            parent_abs: root.clone(),
        };
        let parent = open_write_parent(&root, &write_target).unwrap();
        let original_identity = windows_existing_regular_identity(&target).unwrap().unwrap();
        let candidate_identity = windows_existing_regular_identity(&candidate)
            .unwrap()
            .unwrap();
        fs::rename(&target, &backup).unwrap();
        fs::write(&target, "unknown-writer").unwrap();

        let error = recover_windows_replace_failure(
            &parent,
            &target,
            &candidate,
            &backup,
            original_identity,
            candidate_identity,
            Some(1177),
        )
        .unwrap_err();

        assert!(
            error.contains("refusing to overwrite unknown target"),
            "{error}"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "unknown-writer");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "original");
        assert_eq!(fs::read_to_string(&candidate).unwrap(), "candidate");
    }

    #[cfg(windows)]
    #[test]
    fn windows_temp_identity_rejects_path_replacement() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = WriteTarget {
            abs: root.join("a.txt"),
            parent_abs: root.clone(),
        };
        let parent = open_write_parent(&root, &target).unwrap();
        let tmp_path = root.join("a.nrm-identity-test");
        let moved_path = root.join("moved-original-temp");
        let tmp_name = temp_file_name(&tmp_path).unwrap();
        let mut file = create_temp_file(&parent, &tmp_path, &tmp_name).unwrap();
        file.write_all(b"candidate").unwrap();
        fs::rename(&tmp_path, &moved_path).unwrap();
        fs::write(&tmp_path, "impostor").unwrap();

        let error = verify_temp_file_identity(&file, &tmp_path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("replaced during upload"), "{error}");
        assert_eq!(fs::read_to_string(&moved_path).unwrap(), "candidate");
        assert_eq!(fs::read_to_string(&tmp_path).unwrap(), "impostor");
    }

    #[cfg(windows)]
    #[test]
    fn write_cas_reports_process_in_use_and_cleans_temp_on_windows() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let dir = tempdir().unwrap();
        let root = dir.path();
        let target = root.join("a.txt");
        fs::write(&target, "old").unwrap();
        let old_hash = hash_file(&target).unwrap();
        let _held_without_delete_sharing = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&target)
            .unwrap();

        let error = write_file_cas(root, "a.txt".to_string(), Some(old_hash), b"new".to_vec())
            .unwrap_err()
            .to_string();

        assert!(error.contains("process_in_use"), "{error}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "old");
        let leftovers: Vec<_> = fs::read_dir(root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| {
                let name = name.to_string_lossy();
                name.contains("nrm-tmp") || name.contains("nrm-backup")
            })
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    #[test]
    fn write_cas_bounds_large_conflict_content() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let remote_content = vec![b'x'; MAX_CONFLICT_CONTENT_BYTES + 17];
        fs::write(root.join("a.bin"), &remote_content).unwrap();

        let response = write_file_cas(
            root,
            "a.bin".to_string(),
            Some("not-current".to_string()),
            b"two".to_vec(),
        )
        .unwrap();

        match response {
            Response::WriteFileCas {
                outcome: SaveOutcome::Conflict(conflict),
            } => {
                assert_eq!(conflict.remote_content.len(), MAX_CONFLICT_CONTENT_BYTES);
                assert!(conflict.remote_content.iter().all(|byte| *byte == b'x'));
                assert!(conflict.remote_content_truncated);
                assert_eq!(
                    conflict.remote_size,
                    Some((MAX_CONFLICT_CONTENT_BYTES + 17) as u64)
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn write_cas_applies_when_hash_matches() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "one").unwrap();
        let hash = hash_file(&root.join("a.txt")).unwrap();

        let response =
            write_file_cas(root, "a.txt".to_string(), Some(hash), b"two".to_vec()).unwrap();

        assert!(matches!(
            response,
            Response::WriteFileCas {
                outcome: SaveOutcome::Applied(_)
            }
        ));
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "two");
    }

    #[test]
    fn read_files_batches_successes_and_per_file_errors() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "one").unwrap();
        fs::write(root.join("large.txt"), "abcdef").unwrap();

        let response = read_files(
            root,
            vec![
                "a.txt".to_string(),
                "missing.txt".to_string(),
                "large.txt".to_string(),
            ],
            3,
            1024,
        )
        .unwrap();

        match response {
            Response::ReadFiles {
                files,
                errors,
                truncated,
            } => {
                assert!(!truncated);
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].path, "a.txt");
                assert_eq!(files[0].content, b"one");
                assert_eq!(errors.len(), 2);
                assert_eq!(errors[0].path, "missing.txt");
                assert_eq!(errors[1].path, "large.txt");
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn read_files_stops_before_reading_file_that_exceeds_remaining_total_cap() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "1234").unwrap();
        fs::write(root.join("b.txt"), "56789").unwrap();

        FILE_CONTENT_READS.with(|reads| reads.set(0));
        let response =
            read_files(root, vec!["a.txt".to_string(), "b.txt".to_string()], 10, 4).unwrap();

        match response {
            Response::ReadFiles {
                files,
                errors,
                truncated,
            } => {
                assert!(truncated);
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].path, "a.txt");
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].path, "b.txt");
                assert!(errors[0].message.contains("remaining_total_bytes=0"));
                assert_eq!(FILE_CONTENT_READS.with(Cell::get), 1);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn bounded_file_read_rejects_content_above_cap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("large.txt");
        fs::write(&path, "abcdef").unwrap();

        FILE_CONTENT_READS.with(|reads| reads.set(0));
        let error = read_file_bytes_with_cap(&path, 5).unwrap_err().to_string();

        assert!(error.contains("exceeded read cap"));
        assert_eq!(FILE_CONTENT_READS.with(Cell::get), 1);
    }

    #[test]
    fn read_file_only_hashes_final_chunk() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("large.txt"), "abcdef").unwrap();
        let expected_hash = hash_file(&root.join("large.txt")).unwrap();

        let first = read_file(root, "large.txt".to_string(), 0, Some(3)).unwrap();
        match first {
            Response::ReadFile {
                eof,
                content,
                hash,
                meta,
                ..
            } => {
                assert!(!eof);
                assert_eq!(content, b"abc");
                assert_eq!(hash, "");
                assert_eq!(meta.hash, None);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let second = read_file(root, "large.txt".to_string(), 3, Some(3)).unwrap();
        match second {
            Response::ReadFile {
                eof,
                content,
                hash,
                meta,
                ..
            } => {
                assert!(eof);
                assert_eq!(content, b"def");
                assert_eq!(hash, expected_hash);
                assert_eq!(meta.hash.as_deref(), Some(hash.as_str()));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn scan_resumes_after_cursor() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "a").unwrap();
        fs::write(root.join("b.txt"), "b").unwrap();
        fs::write(root.join("c.txt"), "c").unwrap();

        let first = scan(root, 1, None).unwrap();
        let Response::Scan { entries, truncated } = first else {
            panic!("unexpected scan response");
        };
        assert!(truncated);
        assert_eq!(entries.len(), 1);

        let cursor = entries[0].path.clone();
        let second = scan(root, 10, Some(&cursor)).unwrap();
        let Response::Scan { entries, truncated } = second else {
            panic!("unexpected scan response");
        };
        assert!(!truncated);
        assert!(!entries.iter().any(|entry| entry.path == cursor));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn scan_resume_skips_metadata_for_already_scanned_prefix() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "a").unwrap();
        fs::write(root.join("b.txt"), "b").unwrap();
        fs::write(root.join("c.txt"), "c").unwrap();

        FILE_META_CALLS.with(|calls| calls.set(0));
        let response = scan(root, 10, Some("b.txt")).unwrap();
        let Response::Scan { entries, truncated } = response else {
            panic!("unexpected scan response");
        };

        assert!(!truncated);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "c.txt");
        assert_eq!(FILE_META_CALLS.with(Cell::get), 1);
    }

    #[test]
    fn grep_paginates_by_scanned_files_and_cursor() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "miss").unwrap();
        fs::write(root.join("b.txt"), "needle b").unwrap();
        fs::write(root.join("c.txt"), "needle c").unwrap();

        let mut state = test_state(root);
        let first = grep(&mut state, "needle", 10, None, Some(2), None).unwrap();
        let Response::Grep {
            hits,
            truncated,
            next_after,
            session_id,
            scanned_files,
        } = first
        else {
            panic!("unexpected grep response");
        };
        assert!(truncated);
        assert_eq!(scanned_files, 2);
        assert_eq!(next_after.as_deref(), Some("b.txt"));
        assert_eq!(session_id.as_deref(), Some("grep-1"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "b.txt");

        let second = grep(
            &mut state,
            "needle",
            10,
            next_after.as_deref(),
            Some(2),
            session_id.as_deref(),
        )
        .unwrap();
        let Response::Grep {
            hits,
            truncated,
            next_after,
            session_id,
            scanned_files,
        } = second
        else {
            panic!("unexpected grep response");
        };
        assert!(!truncated);
        assert_eq!(scanned_files, 1);
        assert!(next_after.is_none());
        assert!(session_id.is_none());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "c.txt");
    }

    #[test]
    fn grep_session_continues_when_path_cursor_file_disappears() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "miss").unwrap();
        fs::write(root.join("b.txt"), "miss").unwrap();
        fs::write(root.join("c.txt"), "needle c").unwrap();

        let mut state = test_state(root);
        let first = grep(&mut state, "needle", 10, None, Some(2), None).unwrap();
        let Response::Grep {
            truncated,
            next_after,
            session_id,
            ..
        } = first
        else {
            panic!("unexpected grep response");
        };
        assert!(truncated);
        assert_eq!(next_after.as_deref(), Some("b.txt"));
        let session_id = session_id.expect("expected grep session");
        fs::remove_file(root.join("b.txt")).unwrap();

        let second = grep(
            &mut state,
            "needle",
            10,
            next_after.as_deref(),
            Some(2),
            Some(&session_id),
        )
        .unwrap();
        let Response::Grep {
            hits,
            truncated,
            session_id,
            ..
        } = second
        else {
            panic!("unexpected grep response");
        };
        assert!(!truncated);
        assert!(session_id.is_none());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "c.txt");
    }

    #[test]
    fn grep_stops_without_cursor_when_hit_limit_is_reached() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "needle a").unwrap();
        fs::write(root.join("b.txt"), "needle b").unwrap();

        let mut state = test_state(root);
        let response = grep(&mut state, "needle", 1, None, Some(10), None).unwrap();
        let Response::Grep {
            hits,
            truncated,
            next_after,
            session_id,
            scanned_files,
        } = response
        else {
            panic!("unexpected grep response");
        };
        assert!(truncated);
        assert!(next_after.is_none());
        assert!(session_id.is_none());
        assert_eq!(scanned_files, 1);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn grep_errors_when_cursor_is_missing() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "needle a").unwrap();

        let mut state = test_state(root);
        let error = grep(
            &mut state,
            "needle",
            10,
            Some("missing.txt"),
            Some(10),
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("grep cursor not found"));
    }

    #[test]
    fn grep_clamps_zero_file_page_to_one() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "miss").unwrap();
        fs::write(root.join("b.txt"), "needle b").unwrap();

        let mut state = test_state(root);
        let response = grep(&mut state, "needle", 10, None, Some(0), None).unwrap();
        let Response::Grep {
            hits,
            truncated,
            next_after,
            session_id,
            scanned_files,
        } = response
        else {
            panic!("unexpected grep response");
        };

        assert!(truncated);
        assert_eq!(scanned_files, 1);
        assert_eq!(next_after.as_deref(), Some("a.txt"));
        assert_eq!(session_id.as_deref(), Some("grep-1"));
        assert!(hits.is_empty());
    }

    #[test]
    fn grep_searches_file_exactly_at_byte_cap() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "needle").unwrap();

        let mut state = test_state(root);
        FILE_CONTENT_READS.with(|reads| reads.set(0));
        let response = grep_with_caps(
            &mut state,
            "needle",
            10,
            None,
            None,
            GrepCaps {
                max_files: Some(10),
                max_file_bytes: Some(6),
                max_total_bytes: Some(6),
            },
        )
        .unwrap();

        let Response::Grep {
            hits,
            truncated,
            scanned_files,
            ..
        } = response
        else {
            panic!("unexpected grep response");
        };
        assert!(!truncated);
        assert_eq!(scanned_files, 1);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "a.txt");
        assert_eq!(FILE_CONTENT_READS.with(Cell::get), 1);
    }

    #[test]
    fn grep_skips_file_above_byte_cap_without_reading_content() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("large.txt"), "needle").unwrap();

        let mut state = test_state(root);
        FILE_CONTENT_READS.with(|reads| reads.set(0));
        let response = grep_with_caps(
            &mut state,
            "needle",
            10,
            None,
            None,
            GrepCaps {
                max_files: Some(10),
                max_file_bytes: Some(5),
                max_total_bytes: Some(1024),
            },
        )
        .unwrap();

        let Response::Grep {
            hits,
            truncated,
            next_after,
            session_id,
            scanned_files,
        } = response
        else {
            panic!("unexpected grep response");
        };
        assert!(truncated);
        assert_eq!(scanned_files, 1);
        assert_eq!(next_after.as_deref(), Some("large.txt"));
        assert!(session_id.is_some());
        assert!(hits.is_empty());
        assert_eq!(FILE_CONTENT_READS.with(Cell::get), 0);
    }

    #[test]
    fn grep_total_byte_cap_stops_before_reading_next_file() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "miss").unwrap();
        fs::write(root.join("b.txt"), "needle").unwrap();

        let mut state = test_state(root);
        FILE_CONTENT_READS.with(|reads| reads.set(0));
        let response = grep_with_caps(
            &mut state,
            "needle",
            10,
            None,
            None,
            GrepCaps {
                max_files: Some(10),
                max_file_bytes: Some(10),
                max_total_bytes: Some(4),
            },
        )
        .unwrap();

        let Response::Grep {
            hits,
            truncated,
            next_after,
            session_id,
            scanned_files,
        } = response
        else {
            panic!("unexpected grep response");
        };
        assert!(truncated);
        assert_eq!(scanned_files, 2);
        assert_eq!(next_after.as_deref(), Some("b.txt"));
        assert!(session_id.is_some());
        assert!(hits.is_empty());
        assert_eq!(FILE_CONTENT_READS.with(Cell::get), 1);
    }

    #[test]
    fn grep_skips_huge_matching_line_and_reports_truncation() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let huge_line = format!("needle{}", "x".repeat(AGENT_GREP_HARD_MAX_LINE_BYTES));
        fs::write(root.join("huge.txt"), huge_line).unwrap();
        let mut state = test_state(root);

        let response = grep_with_caps(
            &mut state,
            "needle",
            10,
            None,
            None,
            GrepCaps {
                max_files: Some(10),
                max_file_bytes: Some(AGENT_GREP_HARD_MAX_FILE_BYTES),
                max_total_bytes: Some(AGENT_GREP_HARD_MAX_TOTAL_BYTES),
            },
        )
        .unwrap();

        let Response::Grep {
            hits, truncated, ..
        } = response
        else {
            panic!("unexpected grep response");
        };
        assert!(truncated);
        assert!(hits.is_empty());
    }

    #[test]
    fn grep_sessions_are_bounded_when_clients_abandon_pages() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "miss").unwrap();
        fs::write(root.join("b.txt"), "miss").unwrap();
        let mut state = test_state(root);

        for index in 0..(MAX_GREP_SESSIONS + 3) {
            let response = grep(
                &mut state,
                &format!("needle-{index}"),
                10,
                None,
                Some(1),
                None,
            )
            .unwrap();
            assert!(matches!(
                response,
                Response::Grep {
                    session_id: Some(_),
                    ..
                }
            ));
        }

        assert!(state.grep_sessions.len() <= MAX_GREP_SESSIONS);
    }

    #[test]
    fn validate_files_reports_valid_and_deleted_paths() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.txt"), "one").unwrap();

        let response = validate_files(
            root,
            vec!["a.txt".to_string(), "deleted.txt".to_string()],
            true,
        )
        .unwrap();

        match response {
            Response::ValidateFiles { files, errors } => {
                assert!(errors.is_empty());
                assert_eq!(files.len(), 2);
                assert_eq!(files[0].path, "a.txt");
                assert!(files[0].meta.as_ref().unwrap().hash.is_some());
                assert_eq!(files[1].path, "deleted.txt");
                assert!(files[1].meta.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn chunked_write_cas_applies_when_hash_matches() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::write(root.join("large.bin"), "old").unwrap();
        let old_hash = hash_file(&root.join("large.bin")).unwrap();
        let content = b"new-content-in-two-chunks".to_vec();
        let content_hash = hash_bytes(&content);
        let mut state = test_state(&root);

        let begin = begin_write_file_cas(
            &mut state,
            "large.bin".to_string(),
            Some(old_hash),
            content_hash.clone(),
            content.len() as u64,
        )
        .unwrap();
        let upload_id = match begin {
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Started(started),
            } => started.upload_id,
            other => panic!("unexpected begin response: {other:?}"),
        };

        write_file_chunk(&mut state, upload_id.clone(), 0, content[..8].to_vec()).unwrap();
        write_file_chunk(&mut state, upload_id.clone(), 8, content[8..].to_vec()).unwrap();
        let finish = finish_write_file_cas(&mut state, upload_id).unwrap();

        match finish {
            Response::FinishWriteFileCas {
                outcome: SaveOutcome::Applied(applied),
            } => {
                assert_eq!(applied.path, "large.bin");
                assert_eq!(applied.new_hash, content_hash);
            }
            other => panic!("unexpected finish response: {other:?}"),
        }
        assert_eq!(fs::read(root.join("large.bin")).unwrap(), content);
    }

    #[test]
    fn chunked_write_cas_conflicts_when_remote_changes_after_begin() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::write(root.join("large.bin"), "old").unwrap();
        let old_hash = hash_file(&root.join("large.bin")).unwrap();
        let content = b"new-content".to_vec();
        let content_hash = hash_bytes(&content);
        let external_hash = hash_bytes(b"external");
        let mut state = test_state(&root);

        let begin = begin_write_file_cas(
            &mut state,
            "large.bin".to_string(),
            Some(old_hash),
            content_hash,
            content.len() as u64,
        )
        .unwrap();
        let upload_id = match begin {
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Started(started),
            } => started.upload_id,
            other => panic!("unexpected begin response: {other:?}"),
        };
        let tmp_path = state.uploads.get(&upload_id).unwrap().tmp_path.clone();

        write_file_chunk(&mut state, upload_id.clone(), 0, content).unwrap();
        fs::write(root.join("large.bin"), "external").unwrap();
        let finish = finish_write_file_cas(&mut state, upload_id).unwrap();

        match finish {
            Response::FinishWriteFileCas {
                outcome: SaveOutcome::Conflict(conflict),
            } => {
                assert_eq!(
                    conflict.actual_hash.as_deref(),
                    Some(external_hash.as_str())
                );
                assert_eq!(conflict.remote_content, b"external");
            }
            other => panic!("unexpected finish response: {other:?}"),
        }
        assert_eq!(
            fs::read_to_string(root.join("large.bin")).unwrap(),
            "external"
        );
        assert!(state.uploads.is_empty());
        assert!(state.active_write_targets.is_empty());
        assert!(!tmp_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn chunked_write_tracks_active_target_by_canonical_path() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::create_dir(root.join("real")).unwrap();
        fs::write(root.join("real/a.txt"), "old").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let old_hash = hash_file(&root.join("real/a.txt")).unwrap();
        let content = b"new-content".to_vec();
        let mut state = test_state(&root);

        let begin = begin_write_file_cas(
            &mut state,
            "link/a.txt".to_string(),
            Some(old_hash.clone()),
            hash_bytes(&content),
            content.len() as u64,
        )
        .unwrap();
        let upload_id = match begin {
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Started(started),
            } => started.upload_id,
            other => panic!("unexpected begin response: {other:?}"),
        };

        let error = begin_write_file_cas(
            &mut state,
            "real/a.txt".to_string(),
            Some(old_hash),
            hash_bytes(b"other"),
            5,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("write already in progress"));
        assert_eq!(state.uploads.len(), 1);
        abort_write_file_cas(&mut state, upload_id).unwrap();
        assert!(state.uploads.is_empty());
        assert!(state.active_write_targets.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn chunked_write_does_not_follow_replaced_upload_temp_symlink() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let victim = outside.path().join("victim.txt");
        fs::write(root.join("large.bin"), "old").unwrap();
        fs::write(&victim, "victim").unwrap();
        let old_hash = hash_file(&root.join("large.bin")).unwrap();
        let content = b"new-content".to_vec();
        let mut state = test_state(&root);

        let begin = begin_write_file_cas(
            &mut state,
            "large.bin".to_string(),
            Some(old_hash),
            hash_bytes(&content),
            content.len() as u64,
        )
        .unwrap();
        let upload_id = match begin {
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Started(started),
            } => started.upload_id,
            other => panic!("unexpected begin response: {other:?}"),
        };
        let tmp_path = state.uploads.get(&upload_id).unwrap().tmp_path.clone();
        fs::remove_file(&tmp_path).unwrap();
        std::os::unix::fs::symlink(&victim, &tmp_path).unwrap();

        write_file_chunk(&mut state, upload_id.clone(), 0, content).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "victim");

        let error = finish_write_file_cas(&mut state, upload_id)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a regular file") || error.contains("was replaced"));
        assert_eq!(fs::read_to_string(root.join("large.bin")).unwrap(), "old");
        assert!(!tmp_path.exists());
        assert!(state.uploads.is_empty());
        assert!(state.active_write_targets.is_empty());
    }

    #[test]
    fn chunked_write_cas_conflicts_before_upload() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::write(root.join("large.bin"), "remote").unwrap();
        let mut state = test_state(&root);

        let begin = begin_write_file_cas(
            &mut state,
            "large.bin".to_string(),
            Some("stale".to_string()),
            hash_bytes(b"new"),
            3,
        )
        .unwrap();

        match begin {
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Conflict(conflict),
            } => {
                assert_eq!(conflict.expected_hash.as_deref(), Some("stale"));
                assert_eq!(conflict.remote_content, b"remote");
                assert!(!conflict.remote_content_truncated);
                assert_eq!(conflict.remote_size, Some(6));
            }
            other => panic!("unexpected begin response: {other:?}"),
        }
        assert!(state.uploads.is_empty());
    }

    #[test]
    fn chunked_uploads_enforce_active_count_limit() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut state = test_state(&root);
        for index in 0..MAX_ACTIVE_UPLOADS {
            let path = format!("file-{index}.bin");
            let response =
                begin_write_file_cas(&mut state, path, None, hash_bytes(b"x"), 1).unwrap();
            assert!(matches!(
                response,
                Response::BeginWriteFileCas {
                    outcome: WriteStartOutcome::Started(_)
                }
            ));
        }

        let error = begin_write_file_cas(
            &mut state,
            "too-many.bin".to_string(),
            None,
            hash_bytes(b"x"),
            1,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("too many active uploads"));
    }

    #[test]
    fn abandoned_chunked_upload_ttl_releases_lock_and_temp_state() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut state = test_state(&root);
        let begin = begin_write_file_cas(
            &mut state,
            "old.bin".to_string(),
            None,
            hash_bytes(b"old"),
            3,
        )
        .unwrap();
        let upload_id = match begin {
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Started(started),
            } => started.upload_id,
            other => panic!("unexpected begin response: {other:?}"),
        };
        let tmp_path = state.uploads.get(&upload_id).unwrap().tmp_path.clone();
        let created_at = state.uploads.get(&upload_id).unwrap().created_at;
        cleanup_expired_uploads_at(&mut state, created_at + UPLOAD_TTL);
        assert!(state.uploads.contains_key(&upload_id));
        assert!(tmp_path.exists());
        cleanup_expired_uploads_at(&mut state, created_at + UPLOAD_TTL + Duration::from_secs(1));

        let next = begin_write_file_cas(
            &mut state,
            "new.bin".to_string(),
            None,
            hash_bytes(b"new"),
            3,
        )
        .unwrap();

        assert!(matches!(
            next,
            Response::BeginWriteFileCas {
                outcome: WriteStartOutcome::Started(_)
            }
        ));
        assert!(!state.uploads.contains_key(&upload_id));
        assert!(!tmp_path.exists());
        let expected_active: HashSet<_> = state
            .uploads
            .values()
            .flat_map(|upload| upload.target_keys.iter().cloned())
            .collect();
        assert_eq!(state.active_write_targets, expected_active);
    }
}
