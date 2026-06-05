use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ignore::WalkBuilder;
use nrm_protocol::{
    read_frame, write_frame, BatchReadError, BatchReadFile, BatchValidateFile, CapabilitySet,
    FileMeta, Request, Response, RpcError, RpcMessage, SaveApplied, SaveConflict, SaveOutcome,
    SearchHit, WriteStartOutcome, WriteStarted, PROTOCOL_VERSION,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct AgentState {
    root: PathBuf,
    uploads: HashMap<String, PendingUpload>,
}

struct PendingUpload {
    path: String,
    expected_hash: Option<String>,
    content_hash: String,
    size: u64,
    tmp_path: PathBuf,
    written: u64,
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
            Ok(Response::Stat {
                meta: if abs.exists() {
                    Some(file_meta(&state.root, &abs, false)?)
                } else {
                    None
                },
            })
        }
        Request::Checksum { path } => {
            let abs = resolve_remote_path(&state.root, &path)?;
            let hash = if abs.is_file() {
                Some(hash_file(&abs)?)
            } else {
                None
            };
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
        Request::Grep { query, limit } => grep(&state.root, &query, limit),
        Request::WriteFileCas {
            path,
            expected_hash,
            content,
        } => write_file_cas(&state.root, path, expected_hash, content),
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
        .build()
    {
        let entry = entry?;
        let path = entry.path();
        if path == root {
            continue;
        }
        let meta = file_meta(root, path, false)?;
        if !after_seen {
            if after == Some(meta.path.as_str()) {
                after_seen = true;
            }
            continue;
        }
        if entries.len() >= limit {
            truncated = true;
            break;
        }
        entries.push(meta);
    }

    Ok(Response::Scan { entries, truncated })
}

fn read_file(root: &Path, path: String, offset: u64, len: Option<u64>) -> Result<Response> {
    let abs = resolve_remote_path(root, &path)?;
    if !abs.is_file() {
        bail!("{path} is not a regular file");
    }

    let mut file = File::open(&abs)?;
    let file_len = file.metadata()?.len();
    if offset > file_len {
        bail!("offset {offset} exceeds file length {file_len}");
    }
    file.seek(SeekFrom::Start(offset))?;

    let read_len = len.unwrap_or(file_len - offset).min(file_len - offset);
    let mut content = vec![0_u8; read_len as usize];
    file.read_exact(&mut content)?;
    let eof = offset + read_len >= file_len;
    let hash = hash_file(&abs)?;
    let meta = file_meta(root, &abs, true)?;

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

    for path in paths {
        match read_file_for_batch(root, &path, max_file_bytes) {
            Ok(file) => {
                let next_total = total_bytes.saturating_add(file.content.len() as u64);
                if next_total > max_total_bytes {
                    errors.push(BatchReadError {
                        path,
                        message: format!(
                            "batch total cap exceeded: next_total={next_total} max_total_bytes={max_total_bytes}"
                        ),
                    });
                    truncated = true;
                    break;
                }
                total_bytes = next_total;
                files.push(file);
            }
            Err(error) => errors.push(BatchReadError {
                path,
                message: error.to_string(),
            }),
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
    if !abs.exists() {
        return Ok(BatchValidateFile {
            path: path.to_string(),
            meta: None,
        });
    }
    Ok(BatchValidateFile {
        path: path.to_string(),
        meta: Some(file_meta(root, &abs, include_hash)?),
    })
}

fn read_file_for_batch(root: &Path, path: &str, max_file_bytes: u64) -> Result<BatchReadFile> {
    let abs = resolve_remote_path(root, path)?;
    if !abs.is_file() {
        bail!("{path} is not a regular file");
    }

    let metadata = fs::metadata(&abs)?;
    if metadata.len() > max_file_bytes {
        bail!(
            "{path} is {} bytes, above batch max_file_bytes={max_file_bytes}",
            metadata.len()
        );
    }

    let content = fs::read(&abs)?;
    let hash = hash_bytes(&content);
    let mut meta = file_meta(root, &abs, false)?;
    meta.hash = Some(hash.clone());
    Ok(BatchReadFile {
        path: path.to_string(),
        content,
        hash,
        meta,
    })
}

fn grep(root: &Path, query: &str, limit: usize) -> Result<Response> {
    if query.is_empty() {
        return Ok(Response::Grep {
            hits: Vec::new(),
            truncated: false,
        });
    }

    let mut hits = Vec::new();
    let mut truncated = false;
    for entry in WalkBuilder::new(root)
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_exclude(true)
        .build()
    {
        let entry = entry?;
        if hits.len() >= limit {
            truncated = true;
            break;
        }
        let path = entry.path();
        if !path.is_file() || likely_binary(path)? {
            continue;
        }
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(_) => continue,
        };
        for (line_idx, line) in text.lines().enumerate() {
            if let Some(byte_idx) = line.find(query) {
                hits.push(SearchHit {
                    path: relative_path(root, path)?,
                    line: line_idx as u64 + 1,
                    column: byte_idx as u64 + 1,
                    text: line.to_string(),
                });
                if hits.len() >= limit {
                    truncated = true;
                    break;
                }
            }
        }
    }

    Ok(Response::Grep { hits, truncated })
}

fn write_file_cas(
    root: &Path,
    path: String,
    expected_hash: Option<String>,
    content: Vec<u8>,
) -> Result<Response> {
    let abs = resolve_remote_path(root, &path)?;
    let actual_hash = if abs.exists() && abs.is_file() {
        Some(hash_file(&abs)?)
    } else {
        None
    };

    if actual_hash != expected_hash {
        let remote_content = if abs.is_file() {
            fs::read(&abs).unwrap_or_default()
        } else {
            Vec::new()
        };
        return Ok(Response::WriteFileCas {
            outcome: SaveOutcome::Conflict(SaveConflict {
                path,
                expected_hash,
                actual_hash,
                remote_content,
            }),
        });
    }

    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = abs.with_extension(format!(
        "nrm-tmp-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&content)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &abs)?;
    let new_hash = hash_file(&abs)?;
    let meta = file_meta(root, &abs, true)?;

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
    let abs = resolve_remote_path(&state.root, &path)?;
    let actual_hash = if abs.exists() && abs.is_file() {
        Some(hash_file(&abs)?)
    } else {
        None
    };

    if actual_hash != expected_hash {
        let remote_content = if abs.is_file() {
            fs::read(&abs).unwrap_or_default()
        } else {
            Vec::new()
        };
        return Ok(Response::BeginWriteFileCas {
            outcome: WriteStartOutcome::Conflict(SaveConflict {
                path,
                expected_hash,
                actual_hash,
                remote_content,
            }),
        });
    }

    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent)?;
    }
    let upload_id = format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        hash_bytes(path.as_bytes())
    );
    let tmp_path = abs.with_extension(format!("nrm-upload-{upload_id}"));
    File::create(&tmp_path)?;
    state.uploads.insert(
        upload_id.clone(),
        PendingUpload {
            path,
            expected_hash,
            content_hash,
            size,
            tmp_path,
            written: 0,
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

    let mut file = fs::OpenOptions::new().write(true).open(&upload.tmp_path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&content)?;
    upload.written = next;

    Ok(Response::WriteFileChunk {
        upload_id,
        accepted: next,
    })
}

fn finish_write_file_cas(state: &mut AgentState, upload_id: String) -> Result<Response> {
    let upload = state
        .uploads
        .remove(&upload_id)
        .ok_or_else(|| anyhow::anyhow!("unknown upload id {upload_id}"))?;
    if upload.written != upload.size {
        let _ = fs::remove_file(&upload.tmp_path);
        bail!(
            "upload {upload_id} incomplete: written={} size={}",
            upload.written,
            upload.size
        );
    }

    let tmp_hash = hash_file(&upload.tmp_path)?;
    if tmp_hash != upload.content_hash {
        let _ = fs::remove_file(&upload.tmp_path);
        bail!(
            "upload {upload_id} hash mismatch: expected={} actual={tmp_hash}",
            upload.content_hash
        );
    }

    let abs = resolve_remote_path(&state.root, &upload.path)?;
    let actual_hash = if abs.exists() && abs.is_file() {
        Some(hash_file(&abs)?)
    } else {
        None
    };
    if actual_hash != upload.expected_hash {
        let remote_content = if abs.is_file() {
            fs::read(&abs).unwrap_or_default()
        } else {
            Vec::new()
        };
        let _ = fs::remove_file(&upload.tmp_path);
        return Ok(Response::FinishWriteFileCas {
            outcome: SaveOutcome::Conflict(SaveConflict {
                path: upload.path,
                expected_hash: upload.expected_hash,
                actual_hash,
                remote_content,
            }),
        });
    }

    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent)?;
    }
    {
        let file = File::open(&upload.tmp_path)?;
        file.sync_all()?;
    }
    fs::rename(&upload.tmp_path, &abs)?;
    let meta = file_meta(&state.root, &abs, true)?;

    Ok(Response::FinishWriteFileCas {
        outcome: SaveOutcome::Applied(SaveApplied {
            path: upload.path,
            new_hash: tmp_hash,
            size: meta.size,
            mtime_ms: meta.mtime_ms,
        }),
    })
}

fn abort_write_file_cas(state: &mut AgentState, upload_id: String) -> Result<Response> {
    if let Some(upload) = state.uploads.remove(&upload_id) {
        let _ = fs::remove_file(upload.tmp_path);
    }
    Ok(Response::AbortWriteFileCas { upload_id })
}

fn resolve_remote_path(root: &Path, path: &str) -> Result<PathBuf> {
    let relative = normalize_relative_path(path)?;
    Ok(root.join(relative))
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
    let metadata = fs::symlink_metadata(path)?;
    let hash = if include_hash && metadata.is_file() {
        Some(hash_file(path)?)
    } else {
        None
    };
    Ok(FileMeta {
        path: relative_path(root, path)?,
        size: metadata.len(),
        mtime_ms: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0),
        mode: platform_mode(&metadata),
        is_dir: metadata.is_dir(),
        is_symlink: metadata.file_type().is_symlink(),
        hash,
    })
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root)?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
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

fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn likely_binary(path: &Path) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut buffer = [0_u8; 1024];
    let read = file.read(&mut buffer)?;
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

    #[test]
    fn rejects_path_traversal() {
        assert!(normalize_relative_path("../secret").is_err());
        assert!(normalize_relative_path("/secret").is_err());
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
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "one");
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
        let mut state = AgentState {
            root: root.clone(),
            uploads: HashMap::new(),
        };

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
    fn chunked_write_cas_conflicts_before_upload() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::write(root.join("large.bin"), "remote").unwrap();
        let mut state = AgentState {
            root,
            uploads: HashMap::new(),
        };

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
            }
            other => panic!("unexpected begin response: {other:?}"),
        }
        assert!(state.uploads.is_empty());
    }
}
