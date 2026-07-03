use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ignore::{Walk, WalkBuilder};
use nrm_protocol::{
    read_frame, write_frame, BatchReadError, BatchReadFile, BatchValidateFile, CapabilitySet,
    FileMeta, Request, Response, RpcError, RpcMessage, SaveApplied, SaveConflict, SaveOutcome,
    SearchHit, WriteStartOutcome, WriteStarted, MAX_CONFLICT_CONTENT_BYTES, MAX_FRAME_LEN,
    PROTOCOL_VERSION,
};
#[cfg(test)]
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AGENT_READ_RESPONSE_MAX_BYTES: u64 = (MAX_FRAME_LEN - (1024 * 1024)) as u64;
const AGENT_BATCH_TOTAL_MAX_BYTES: u64 = AGENT_READ_RESPONSE_MAX_BYTES;
const AGENT_GREP_HARD_MAX_FILES: usize = 50_000;
const AGENT_GREP_HARD_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const AGENT_GREP_HARD_MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
const AGENT_GREP_HARD_MAX_HIT_TEXT_BYTES: usize = 4 * 1024 * 1024;
const AGENT_GREP_HARD_MAX_LINE_BYTES: usize = 64 * 1024;
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
    target_key: String,
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
    parent_abs: PathBuf,
}

struct WriteLock {
    #[cfg(unix)]
    _file: File,
}

struct OpenedContentFile {
    file: File,
    metadata: fs::Metadata,
}

struct WriteParent {
    #[cfg(unix)]
    dir: File,
}

struct ActiveWriteRelease<'a> {
    active: &'a mut HashSet<String>,
    key: String,
}

impl Drop for ActiveWriteRelease<'_> {
    fn drop(&mut self) {
        self.active.remove(&self.key);
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
            protocol_version, ..
        } => {
            if protocol_version != PROTOCOL_VERSION {
                bail!(
                    "protocol version mismatch: client={protocol_version} agent={PROTOCOL_VERSION}"
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
    let target_key = write_target_key(&state.root, &target.abs);
    ensure_no_active_write(&state.active_write_targets, &target_key, &path)?;
    let lock = acquire_write_lock(&target_key, &path)?;
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
    let target_key = write_target_key(root, &target.abs);
    let lock = acquire_write_lock(&target_key, &path)?;
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
    if let Err(error) = verify_temp_file_identity(&file, &tmp) {
        let _ = remove_temp_file(&parent, &tmp, &tmp_name);
        return Err(error);
    }
    #[cfg(not(unix))]
    drop(file);
    rename_temp_into_target(&parent, &tmp, &tmp_name, &target)?;
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
    let target_key = write_target_key(&state.root, &target.abs);
    ensure_no_active_write(&state.active_write_targets, &target_key, &path)?;
    let lock = acquire_write_lock(&target_key, &path)?;
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
    state.active_write_targets.insert(target_key.clone());
    state.uploads.insert(
        upload_id.clone(),
        PendingUpload {
            path,
            target_abs: target.abs,
            target_key,
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
        target_key,
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
        key: target_key,
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
    if let Err(error) = verify_temp_file_identity(&tmp_file, &tmp_path) {
        let _ = remove_temp_file(&parent, &tmp_path, &tmp_name);
        return Err(error);
    }
    #[cfg(not(unix))]
    drop(tmp_file);
    rename_temp_into_path(&parent, &tmp_path, &tmp_name, &target_abs)?;
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
        state.active_write_targets.remove(&upload.target_key);
    }
    Ok(Response::AbortWriteFileCas { upload_id })
}

fn cleanup_expired_uploads(state: &mut AgentState) {
    let now = Instant::now();
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
            state.active_write_targets.remove(&upload.target_key);
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
        parent_abs: canonical_parent,
    })
}

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
    #[cfg(not(unix))]
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
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

fn ensure_path_within_root(root: &Path, path: &Path) -> Result<()> {
    if path == root || path.starts_with(root) {
        return Ok(());
    }
    bail!(
        "{} resolves outside remote root {}",
        path.display(),
        root.display()
    )
}

fn write_target_key(root: &Path, target_abs: &Path) -> String {
    hash_bytes(format!("{}:{}", root.display(), target_abs.display()).as_bytes())
}

fn ensure_no_active_write(active: &HashSet<String>, target_key: &str, path: &str) -> Result<()> {
    if active.contains(target_key) {
        bail!("remote write already in progress for {path}");
    }
    Ok(())
}

#[cfg(unix)]
fn acquire_write_lock(target_key: &str, path: &str) -> Result<WriteLock> {
    let lock_root = std::env::temp_dir().join("nrm-agent-locks");
    fs::create_dir_all(&lock_root)?;
    let lock_path = lock_root.join(format!("{target_key}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open write lock {}", lock_path.display()))?;
    // SAFETY: flock only uses the valid file descriptor borrowed from `file`;
    // the file is kept alive in WriteLock until the critical section ends.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            bail!("remote write already in progress for {path}");
        }
        bail!("failed to lock remote write {}: {}", path, error);
    }
    Ok(WriteLock { _file: file })
}

#[cfg(not(unix))]
fn acquire_write_lock(_target_key: &str, _path: &str) -> Result<WriteLock> {
    Ok(WriteLock {})
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

#[cfg(not(unix))]
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

#[cfg(not(unix))]
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

#[cfg(not(unix))]
fn remove_temp_file(_parent: &WriteParent, path: &Path, _name: &OsStr) -> Result<()> {
    fs::remove_file(path).with_context(|| format!("failed to remove temp file {}", path.display()))
}

fn rename_temp_into_target(
    parent: &WriteParent,
    tmp_path: &Path,
    tmp_name: &OsStr,
    target: &WriteTarget,
) -> Result<()> {
    rename_temp_into_path(parent, tmp_path, tmp_name, &target.abs)
}

#[cfg(unix)]
fn rename_temp_into_path(
    parent: &WriteParent,
    tmp_path: &Path,
    tmp_name: &OsStr,
    target_abs: &Path,
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

#[cfg(not(unix))]
fn rename_temp_into_path(
    _parent: &WriteParent,
    tmp_path: &Path,
    _tmp_name: &OsStr,
    target_abs: &Path,
) -> Result<()> {
    fs::rename(tmp_path, target_abs).with_context(|| {
        format!(
            "failed to rename temp file into {} from {}",
            target_abs.display(),
            tmp_path.display()
        )
    })
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

#[cfg(not(unix))]
fn verify_temp_file_identity(_file: &File, path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat temp path {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("temp path {} is not a regular file", path.display());
    }
    Ok(())
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
    let relative = path.strip_prefix(root)?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
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
    use tempfile::tempdir;

    fn test_state(root: &Path) -> AgentState {
        AgentState {
            root: root.to_path_buf(),
            uploads: HashMap::new(),
            active_write_targets: HashSet::new(),
            grep_sessions: HashMap::new(),
            next_grep_session: 1,
        }
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(normalize_relative_path("../secret").is_err());
        assert!(normalize_relative_path("/secret").is_err());
    }

    #[test]
    fn hello_rejects_incompatible_protocol_version() {
        let dir = tempdir().unwrap();
        let mut state = test_state(dir.path());

        let error = handle_request(
            &mut state,
            Request::Hello {
                client_version: "test".to_string(),
                protocol_version: PROTOCOL_VERSION + 1,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("protocol version mismatch"));
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
        state.uploads.get_mut(&upload_id).unwrap().created_at =
            Instant::now() - UPLOAD_TTL - Duration::from_secs(1);

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
        assert_eq!(state.active_write_targets.len(), 1);
    }
}
