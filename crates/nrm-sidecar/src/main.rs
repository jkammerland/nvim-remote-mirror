use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use nrm_protocol::{
    read_frame, write_frame, FileMeta, Request, RequestId, Response, RpcError, RpcMessage,
    SaveOutcome, MAX_FRAME_LEN, PROTOCOL_VERSION,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_CHUNK_SIZE: u64 = 1024 * 1024;
const MAX_SAVE_PAYLOAD_BYTES: usize = MAX_FRAME_LEN - (1024 * 1024);

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
        state_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 30_000)]
        request_timeout_ms: u64,
        #[arg(long, default_value_t = 10)]
        ssh_connect_timeout_seconds: u64,
    },
    LspProxy {
        #[arg(long)]
        remote_root: PathBuf,
        #[arg(long)]
        local_root: PathBuf,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Clone)]
struct SaveQueueEntry {
    id: i64,
    relative_path: String,
    expected_hash: Option<String>,
    local_hash: String,
    snapshot_path: PathBuf,
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
    },
    Queued {
        path: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
struct AgentLaunch {
    agent: String,
    ssh: Option<String>,
    remote_root: PathBuf,
    request_timeout: Duration,
    ssh_connect_timeout_seconds: u64,
}

struct AgentWorker {
    tx: mpsc::Sender<AgentWorkerCommand>,
    child: Arc<Mutex<Child>>,
}

struct AgentWorkerCommand {
    id: RequestId,
    request: Request,
    reply: mpsc::Sender<AgentWorkerReply>,
}

#[derive(Debug)]
enum AgentWorkerReply {
    Response(Response),
    Error(String),
}

struct AgentClient {
    launch: AgentLaunch,
    worker: Option<AgentWorker>,
    next_id: RequestId,
}

impl AgentClient {
    fn new(
        agent: String,
        ssh: Option<String>,
        remote_root: PathBuf,
        request_timeout: Duration,
        ssh_connect_timeout_seconds: u64,
    ) -> Self {
        Self {
            launch: AgentLaunch {
                agent,
                ssh,
                remote_root,
                request_timeout,
                ssh_connect_timeout_seconds,
            },
            worker: None,
            next_id: 1,
        }
    }

    fn spawn_worker(launch: &AgentLaunch) -> Result<AgentWorker> {
        let mut command = if let Some(target) = launch.ssh.as_deref() {
            let mut command = Command::new("ssh");
            command
                .arg("-o")
                .arg("BatchMode=yes")
                .arg("-o")
                .arg(format!(
                    "ConnectTimeout={}",
                    launch.ssh_connect_timeout_seconds
                ))
                .arg("-o")
                .arg("ServerAliveInterval=15")
                .arg("-o")
                .arg("ServerAliveCountMax=2")
                .arg(target)
                .arg(&launch.agent)
                .arg("serve")
                .arg("--root")
                .arg(&launch.remote_root);
            command
        } else {
            let mut command = Command::new(&launch.agent);
            command.arg("serve").arg("--root").arg(&launch.remote_root);
            command
        };

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to launch agent `{}`{}",
                    launch.agent,
                    launch
                        .ssh
                        .as_deref()
                        .map(|target| format!(" through ssh target `{target}`"))
                        .unwrap_or_default()
                )
            })?;

        let stdin = child.stdin.take().context("agent stdin was not piped")?;
        let stdout = child.stdout.take().context("agent stdout was not piped")?;
        let child = Arc::new(Mutex::new(child));
        let (tx, rx) = mpsc::channel::<AgentWorkerCommand>();
        let worker_child = Arc::clone(&child);
        thread::spawn(move || {
            let mut stdin = stdin;
            let mut stdout = BufReader::new(stdout);
            while let Ok(command) = rx.recv() {
                let response =
                    send_agent_frame(&mut stdin, &mut stdout, command.id, command.request)
                        .unwrap_or_else(|error| AgentWorkerReply::Error(error.to_string()));
                let _ = command.reply.send(response);
            }
            let _ = worker_child.lock().map(|mut child| {
                let _ = child.kill();
                let _ = child.wait();
            });
        });

        Ok(AgentWorker { tx, child })
    }

    fn request(&mut self, request: Request) -> Result<Response> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let (reply, reply_rx) = mpsc::channel();

        for attempt in 0..2 {
            let tx = self.ensure_worker()?.tx.clone();
            let command = AgentWorkerCommand {
                id,
                request: request.clone(),
                reply: reply.clone(),
            };
            if tx.send(command).is_ok() {
                break;
            }
            self.worker = None;
            if attempt == 1 {
                bail!("agent worker exited before request {id} could be sent");
            }
        }

        match reply_rx.recv_timeout(self.launch.request_timeout) {
            Ok(AgentWorkerReply::Response(Response::Error { message })) => Err(anyhow!(message)),
            Ok(AgentWorkerReply::Response(response)) => Ok(response),
            Ok(AgentWorkerReply::Error(message)) => {
                self.worker = None;
                Err(anyhow!(message))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let timeout = self.launch.request_timeout;
                self.kill_worker();
                Err(anyhow!(
                    "agent request {id} timed out after {} ms",
                    timeout.as_millis()
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.worker = None;
                Err(anyhow!(
                    "agent worker exited while request {id} was pending"
                ))
            }
        }
    }

    fn ensure_worker(&mut self) -> Result<&AgentWorker> {
        if self.worker.is_none() {
            self.worker = Some(Self::spawn_worker(&self.launch)?);
        }
        Ok(self.worker.as_ref().expect("worker was just initialized"))
    }

    fn shutdown(&mut self) {
        let _ = self.request(Request::Shutdown);
        self.kill_worker();
    }

    fn kill_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            drop(worker.tx);
            if let Ok(mut child) = worker.child.lock() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

impl Drop for AgentClient {
    fn drop(&mut self) {
        self.kill_worker();
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
        } if response_id == id => Ok(AgentWorkerReply::Error(format_rpc_error(error))),
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
        let files_root = root.join("files");
        let conflicts_root = root.join("conflicts");
        let save_snapshots_root = root.join("save-snapshots");
        fs::create_dir_all(&files_root)?;
        fs::create_dir_all(&conflicts_root)?;
        fs::create_dir_all(&save_snapshots_root)?;
        let db = Connection::open(root.join("mirror.sqlite"))?;
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
              created_at_ms INTEGER NOT NULL,
              updated_at_ms INTEGER NOT NULL
            );
            ",
        )?;
        self.add_missing_column("files", "validated_at_ms", "INTEGER NOT NULL DEFAULT 0")?;
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
              relative_path, local_path, size, mtime_ms, mode, remote_hash,
              local_hash, state, dirty, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, 0, ?8)
            ON CONFLICT(relative_path) DO UPDATE SET
              local_path=excluded.local_path,
              size=excluded.size,
              mtime_ms=excluded.mtime_ms,
              mode=excluded.mode,
              remote_hash=COALESCE(excluded.remote_hash, files.remote_hash),
              state=CASE WHEN files.state = 'hydrated' THEN files.state ELSE excluded.state END,
              updated_at_ms=excluded.updated_at_ms
            ",
            params![
                meta.path,
                local_path.to_string_lossy(),
                meta.size as i64,
                meta.mtime_ms,
                meta.mode as i64,
                meta.hash,
                state,
                now_ms()
            ],
        )?;
        Ok(())
    }

    fn record_hydrated(&self, meta: &FileMeta, remote_hash: &str, local_hash: &str) -> Result<()> {
        let local_path = self.local_path(&meta.path)?;
        self.db.execute(
            "
            INSERT INTO files (
              relative_path, local_path, size, mtime_ms, mode, remote_hash,
              local_hash, state, dirty, validated_at_ms, validation_state, last_error, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'hydrated', 0, ?8, 'valid', NULL, ?8)
            ON CONFLICT(relative_path) DO UPDATE SET
              local_path=excluded.local_path,
              size=excluded.size,
              mtime_ms=excluded.mtime_ms,
              mode=excluded.mode,
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
                |row| {
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
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn enqueue_save(
        &self,
        relative_path: &str,
        local_hash: &str,
        expected_hash: Option<&str>,
        content: &[u8],
    ) -> Result<SaveQueueEntry> {
        let entry = self
            .get(relative_path)?
            .ok_or_else(|| anyhow!("{relative_path} is not known in the mirror"))?;
        let relative_path = entry.relative_path;
        let effective_expected_hash = self
            .latest_unresolved_save_hash(&relative_path)?
            .or_else(|| expected_hash.map(ToOwned::to_owned));
        let snapshot_path = self.write_save_snapshot(&relative_path, local_hash, content)?;
        self.db.execute(
            "
            UPDATE files SET
              local_hash=?2,
              dirty=1,
              validation_state='dirty',
              last_error=NULL,
              updated_at_ms=?3
            WHERE relative_path=?1
            ",
            params![relative_path, local_hash, now_ms()],
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
                now_ms()
            ],
        )?;
        Ok(SaveQueueEntry {
            id: self.db.last_insert_rowid(),
            relative_path: relative_path.to_string(),
            expected_hash: effective_expected_hash,
            local_hash: local_hash.to_string(),
            snapshot_path,
        })
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
        let tmp = path.with_extension("snapshot.tmp");
        {
            let mut file = File::create(&tmp)?;
            file.write_all(content)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(path)
    }

    fn latest_unresolved_save_hash(&self, relative_path: &str) -> Result<Option<String>> {
        self.db
            .query_row(
                "
                SELECT local_hash FROM save_queue
                WHERE relative_path=?1 AND state IN ('pending', 'failed')
                ORDER BY id DESC LIMIT 1
                ",
                params![relative_path],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn pending_save_entries(&self) -> Result<Vec<SaveQueueEntry>> {
        let mut statement = self.db.prepare(
            "
            SELECT id, relative_path, expected_hash, local_hash, snapshot_path
            FROM save_queue
            WHERE state IN ('pending', 'failed') AND snapshot_path IS NOT NULL
            ORDER BY id ASC
            ",
        )?;
        let rows = statement.query_map([], |row| {
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

    fn unresolved_save_count(&self, relative_path: &str) -> Result<i64> {
        self.db
            .query_row(
                "
                SELECT COUNT(*) FROM save_queue
                WHERE relative_path=?1 AND state IN ('pending', 'failed')
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
    }

    fn mark_save_failed(&self, queue_id: i64, relative_path: &str, error: &str) -> Result<()> {
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
    }

    fn record_save_conflict(
        &self,
        queue_id: i64,
        relative_path: &str,
        remote_content: &[u8],
        message: &str,
    ) -> Result<PathBuf> {
        let safe_name = relative_path.replace(['/', '\\'], "__");
        let path = self
            .conflicts_root
            .join(format!("{safe_name}.remote.{}", now_ms()));
        fs::write(&path, remote_content)?;
        self.db.execute(
            "
            UPDATE save_queue SET
              state='conflict',
              attempts=attempts+1,
              last_error=?2,
              remote_conflict_path=?3,
              updated_at_ms=?4
            WHERE id=?1
            ",
            params![queue_id, message, path.to_string_lossy(), now_ms()],
        )?;
        self.db.execute(
            "
            UPDATE files SET
              validation_state='conflict',
              last_error=?2,
              updated_at_ms=?3
            WHERE relative_path=?1
            ",
            params![relative_path, message, now_ms()],
        )?;
        Ok(path)
    }

    fn status(&self) -> Result<Value> {
        let cached: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM files WHERE state='hydrated'",
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
            "SELECT COUNT(*) FROM save_queue WHERE state='pending'",
            [],
            |row| row.get(0),
        )?;
        let failed: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM save_queue WHERE state='failed'",
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
        Ok(json!({
            "mirror_root": self.root.to_string_lossy(),
            "known_files": known,
            "cached_files": cached,
            "dirty_files": dirty,
            "pending_saves": pending,
            "failed_saves": failed,
            "conflicted_saves": conflicted,
            "stale_files": stale
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
}

struct Sidecar {
    agent: AgentClient,
    mirror: Mirror,
    remote_root: PathBuf,
    workspace_key: String,
}

impl Sidecar {
    fn new(
        remote_root: PathBuf,
        ssh: Option<String>,
        agent: String,
        state_dir: Option<PathBuf>,
        request_timeout_ms: u64,
        ssh_connect_timeout_seconds: u64,
    ) -> Result<Self> {
        let workspace_key = workspace_key(ssh.as_deref(), &remote_root);
        let mirror = Mirror::open(state_dir, &workspace_key)?;
        let mut agent = AgentClient::new(
            agent,
            ssh,
            remote_root.clone(),
            Duration::from_millis(request_timeout_ms),
            ssh_connect_timeout_seconds,
        );
        let hello = agent.request(Request::Hello {
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
        })?;
        if !matches!(hello, Response::Hello { .. }) {
            bail!("unexpected hello response from agent: {hello:?}");
        }
        let mut sidecar = Self {
            agent,
            mirror,
            remote_root,
            workspace_key,
        };
        let _ = sidecar.replay_queued_saves();
        Ok(sidecar)
    }

    fn handle(&mut self, method: &str, params: Value) -> Result<Value> {
        match method {
            "hello" => Ok(json!({
                "sidecar_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": PROTOCOL_VERSION,
                "workspace_key": self.workspace_key,
                "remote_root": self.remote_root.to_string_lossy(),
                "mirror_root": self.mirror.root().to_string_lossy(),
                "files_root": self.mirror.files_root().to_string_lossy()
            })),
            "status" => self.mirror.status(),
            "scan" => self.scan(params),
            "open" => self.open(params),
            "prefetch" => self.prefetch(params),
            "grep" => self.grep(params),
            "flush" => self.flush(params),
            "flush_queue" => self.flush_queue(),
            "validate" => self.validate(params),
            "shutdown" | "disconnect" => {
                self.agent.shutdown();
                Ok(json!({"shutdown": true}))
            }
            other => bail!("unknown method `{other}`"),
        }
    }

    fn scan(&mut self, params: Value) -> Result<Value> {
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(10_000) as usize;
        let response = self.agent.request(Request::Scan { limit })?;
        match response {
            Response::Scan { entries, truncated } => {
                for entry in &entries {
                    self.mirror.upsert_metadata(entry, "metadata")?;
                }
                Ok(json!({ "entries": entries, "truncated": truncated }))
            }
            other => bail!("unexpected scan response: {other:?}"),
        }
    }

    fn open(&mut self, params: Value) -> Result<Value> {
        let path = required_string(&params, "path")?;
        let force = params
            .get("force")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !force {
            if let Some(entry) = self.mirror.get(path)? {
                if entry.state == "hydrated"
                    && entry.local_path.exists()
                    && !entry.dirty
                    && entry.validation_state != "stale"
                {
                    return Ok(json!({
                        "path": entry.relative_path,
                        "local_path": entry.local_path.to_string_lossy(),
                        "hash": entry.remote_hash,
                        "local_hash": entry.local_hash,
                        "size": entry.size,
                        "validation_state": entry.validation_state,
                        "validated_at_ms": entry.validated_at_ms,
                        "last_error": entry.last_error,
                        "cached": true
                    }));
                }
            }
        }
        let hydrated = self.hydrate(path)?;
        Ok(json!({
            "path": hydrated.relative_path,
            "local_path": hydrated.local_path.to_string_lossy(),
            "hash": hydrated.remote_hash,
            "size": hydrated.size,
            "validation_state": hydrated.validation_state,
            "validated_at_ms": hydrated.validated_at_ms,
            "cached": false
        }))
    }

    fn prefetch(&mut self, params: Value) -> Result<Value> {
        let paths = params
            .get("paths")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("prefetch requires params.paths array"))?;
        let mut hydrated = 0;
        let mut errors = Vec::new();
        for value in paths {
            let Some(path) = value.as_str() else {
                errors.push(json!({"path": null, "error": "path must be a string"}));
                continue;
            };
            match self.hydrate(path) {
                Ok(_) => hydrated += 1,
                Err(error) => errors.push(json!({"path": path, "error": error.to_string()})),
            }
        }
        Ok(json!({ "hydrated": hydrated, "errors": errors }))
    }

    fn grep(&mut self, params: Value) -> Result<Value> {
        let query = required_string(&params, "query")?;
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
        let response = self.agent.request(Request::Grep {
            query: query.to_string(),
            limit,
        })?;
        match response {
            Response::Grep { hits, truncated } => Ok(json!({
                "hits": hits,
                "truncated": truncated
            })),
            other => bail!("unexpected grep response: {other:?}"),
        }
    }

    fn flush(&mut self, params: Value) -> Result<Value> {
        let path = required_string(&params, "path")?;
        let entry = self
            .mirror
            .get(path)?
            .ok_or_else(|| anyhow!("{path} is not known in the mirror"))?;
        let content = fs::read(&entry.local_path).with_context(|| {
            format!(
                "failed to read local mirror file {}",
                entry.local_path.display()
            )
        })?;
        let local_hash = hash_bytes(&content);
        let queued =
            self.mirror
                .enqueue_save(path, &local_hash, entry.remote_hash.as_deref(), &content)?;
        Self::save_attempt_to_json(self.apply_save_entry(queued)?)
    }

    fn flush_queue(&mut self) -> Result<Value> {
        let attempts = self.replay_queued_saves()?;
        Ok(json!({ "attempts": attempts }))
    }

    fn replay_queued_saves(&mut self) -> Result<Vec<Value>> {
        let entries = self.mirror.pending_save_entries()?;
        let mut attempts = Vec::new();
        for entry in entries {
            attempts.push(Self::save_attempt_to_json(self.apply_save_entry(entry)?)?);
        }
        Ok(attempts)
    }

    fn apply_save_entry(&mut self, entry: SaveQueueEntry) -> Result<SaveAttempt> {
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
                });
            }
        };
        let actual_local_hash = hash_bytes(&content);
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
            });
        }
        if content.len() > MAX_SAVE_PAYLOAD_BYTES {
            let reason = format!(
                "queued save is {} bytes; current whole-file CAS payload limit is {} bytes",
                content.len(),
                MAX_SAVE_PAYLOAD_BYTES
            );
            self.mirror
                .mark_save_failed(entry.id, &entry.relative_path, &reason)?;
            return Ok(SaveAttempt::Queued {
                path: entry.relative_path,
                reason,
            });
        }

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
                });
            }
        };

        match response {
            Response::WriteFileCas {
                outcome: SaveOutcome::Applied(applied),
            } => {
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
            Response::WriteFileCas {
                outcome: SaveOutcome::Conflict(conflict),
            } => {
                let message = "remote content changed before queued save was applied";
                let conflict_path = self.mirror.record_save_conflict(
                    entry.id,
                    &conflict.path,
                    &conflict.remote_content,
                    message,
                )?;
                Ok(SaveAttempt::Conflict {
                    path: conflict.path,
                    expected_hash: conflict.expected_hash,
                    actual_hash: conflict.actual_hash,
                    remote_path: conflict_path,
                })
            }
            other => bail!("unexpected flush response: {other:?}"),
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
            } => json!({
                "status": "conflict",
                "path": path,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "remote_path": remote_path.to_string_lossy()
            }),
            SaveAttempt::Queued { path, reason } => json!({
                "status": "queued",
                "path": path,
                "reason": reason
            }),
        })
    }

    fn validate(&mut self, params: Value) -> Result<Value> {
        let path = required_string(&params, "path")?;
        let entry = self
            .mirror
            .get(path)?
            .ok_or_else(|| anyhow!("{path} is not known in the mirror"))?;
        let response = self.agent.request(Request::Checksum {
            path: entry.relative_path.clone(),
        })?;
        match response {
            Response::Checksum { hash, .. } => {
                let state = if hash == entry.remote_hash {
                    "valid"
                } else {
                    "stale"
                };
                let error = if state == "stale" {
                    Some("remote hash differs from local mirror metadata")
                } else {
                    None
                };
                let recorded_remote_hash = if state == "valid" {
                    hash.as_deref()
                } else {
                    None
                };
                self.mirror.record_validation(
                    &entry.relative_path,
                    state,
                    recorded_remote_hash,
                    error,
                )?;
                Ok(json!({
                    "path": entry.relative_path,
                    "status": state,
                    "remote_hash": hash,
                    "local_hash": entry.local_hash
                }))
            }
            other => bail!("unexpected checksum response: {other:?}"),
        }
    }

    fn hydrate(&mut self, path: &str) -> Result<MirrorEntry> {
        let local_path = self.mirror.local_path(path)?;
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let part_path = local_path.with_extension("nrm-part");
        let mut part = File::create(&part_path)?;
        let mut offset = 0_u64;

        let (meta, remote_hash) = loop {
            let response = self.agent.request(Request::ReadFile {
                path: path.to_string(),
                offset,
                len: Some(DEFAULT_CHUNK_SIZE),
            })?;
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
                        break (meta, hash);
                    }
                }
                other => bail!("unexpected read response: {other:?}"),
            }
        };
        part.sync_all()?;
        drop(part);
        fs::rename(&part_path, &local_path)?;

        let local_hash = hash_file(&local_path)?;
        if local_hash != remote_hash {
            bail!(
                "local hydration hash mismatch for {path}: local={local_hash} remote={remote_hash}"
            );
        }
        self.mirror
            .record_hydrated(&meta, &remote_hash, &local_hash)?;
        self.mirror
            .get(path)?
            .ok_or_else(|| anyhow!("hydrated file was not recorded in mirror metadata"))
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        CommandKind::Serve {
            remote_root,
            ssh,
            agent,
            state_dir,
            request_timeout_ms,
            ssh_connect_timeout_seconds,
        } => run_server(
            remote_root,
            ssh,
            agent,
            state_dir,
            request_timeout_ms,
            ssh_connect_timeout_seconds,
        ),
        CommandKind::LspProxy {
            remote_root,
            local_root,
            ssh,
            command,
        } => run_lsp_proxy(remote_root, local_root, ssh, command),
    }
}

fn run_server(
    remote_root: PathBuf,
    ssh: Option<String>,
    agent: String,
    state_dir: Option<PathBuf>,
    request_timeout_ms: u64,
    ssh_connect_timeout_seconds: u64,
) -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut sidecar = Sidecar::new(
        remote_root,
        ssh,
        agent,
        state_dir,
        request_timeout_ms,
        ssh_connect_timeout_seconds,
    )?;

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request: ClientRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string(&ClientResponse {
                        id: 0,
                        ok: false,
                        result: None,
                        error: Some(format!("invalid request JSON: {error}")),
                    })?
                )?;
                stdout.flush()?;
                continue;
            }
        };

        let should_shutdown = matches!(request.method.as_str(), "shutdown" | "disconnect");
        let response = match sidecar.handle(&request.method, request.params) {
            Ok(result) => ClientResponse {
                id: request.id,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => ClientResponse {
                id: request.id,
                ok: false,
                result: None,
                error: Some(error.to_string()),
            },
        };
        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
        if should_shutdown {
            break;
        }
    }

    Ok(())
}

fn run_lsp_proxy(
    remote_root: PathBuf,
    local_root: PathBuf,
    ssh: Option<String>,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        bail!("lsp-proxy requires a language server command after --");
    }

    let mut child_command = if let Some(target) = ssh {
        let mut child_command = Command::new("ssh");
        child_command.arg(target).args(&command);
        child_command
    } else {
        let mut child_command = Command::new(&command[0]);
        child_command.args(&command[1..]);
        child_command
    };

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

    let _upstream = thread::spawn(move || -> Result<()> {
        let stdin = io::stdin();
        let mut client_reader = BufReader::new(stdin.lock());
        while let Some(body) = read_lsp_message(&mut client_reader)? {
            let rewritten = rewrite_lsp_body(&body, &upstream_local, &upstream_remote)?;
            write_lsp_message(&mut server_stdin, &rewritten)?;
        }
        Ok(())
    });

    let stdout = io::stdout();
    let mut client_writer = stdout.lock();
    let mut server_reader = BufReader::new(server_stdout);
    while let Some(body) = read_lsp_message(&mut server_reader)? {
        let rewritten = rewrite_lsp_body(&body, &remote_prefix, &local_prefix)?;
        write_lsp_message(&mut client_writer, &rewritten)?;
    }

    let status = child.wait()?;
    if !status.success() {
        bail!("language server exited with {status}");
    }
    Ok(())
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

fn rewrite_lsp_body(body: &[u8], from_prefix: &str, to_prefix: &str) -> Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(body)?;
    rewrite_json_strings(&mut value, from_prefix, to_prefix);
    Ok(serde_json::to_vec(&value)?)
}

fn rewrite_json_strings(value: &mut Value, from_prefix: &str, to_prefix: &str) {
    match value {
        Value::String(text) => {
            let from_uri = path_to_file_uri_prefix(from_prefix);
            let to_uri = path_to_file_uri_prefix(to_prefix);
            if text.starts_with(&from_uri) {
                *text = text.replacen(&from_uri, &to_uri, 1);
            } else if text.starts_with(from_prefix) {
                *text = text.replacen(from_prefix, to_prefix, 1);
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite_json_strings(value, from_prefix, to_prefix);
            }
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                rewrite_json_strings(value, from_prefix, to_prefix);
            }
        }
        _ => {}
    }
}

fn path_to_file_uri_prefix(path: &str) -> String {
    format!("file://{}", path)
}

fn required_string<'a>(params: &'a Value, key: &str) -> Result<&'a str> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing required string params.{key}"))
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

fn default_state_dir() -> PathBuf {
    if let Some(value) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(value).join("nvim-remote-mirror")
    } else if let Some(value) = std::env::var_os("HOME") {
        PathBuf::from(value).join(".local/state/nvim-remote-mirror")
    } else {
        PathBuf::from(".nrm-state")
    }
}

fn workspace_key(ssh: Option<&str>, remote_root: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ssh.unwrap_or("local").as_bytes());
    hasher.update(b"\0");
    hasher.update(remote_root.to_string_lossy().as_bytes());
    hasher.finalize().to_hex()[..24].to_string()
}

fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
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

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn local_paths_reject_traversal() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        assert!(mirror.local_path("../x").is_err());
        assert!(mirror.local_path("/x").is_err());
    }

    #[test]
    fn mirror_records_hydrated_files() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = FileMeta {
            path: "src/main.rs".to_string(),
            size: 5,
            mtime_ms: 10,
            mode: 0,
            is_dir: false,
            is_symlink: false,
            hash: Some("abc".to_string()),
        };
        mirror.record_hydrated(&meta, "abc", "abc").unwrap();
        let entry = mirror.get("src/main.rs").unwrap().unwrap();
        assert_eq!(entry.relative_path, "src/main.rs");
        assert_eq!(entry.remote_hash.as_deref(), Some("abc"));
        assert_eq!(entry.state, "hydrated");
        assert_eq!(entry.validation_state, "valid");
    }

    #[test]
    fn queued_saves_keep_exact_snapshots_and_chain_expected_hashes() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = FileMeta {
            path: "src/main.rs".to_string(),
            size: 3,
            mtime_ms: 10,
            mode: 0,
            is_dir: false,
            is_symlink: false,
            hash: Some("base".to_string()),
        };
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
    fn validation_can_mark_cached_file_stale() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        let meta = FileMeta {
            path: "a.txt".to_string(),
            size: 3,
            mtime_ms: 10,
            mode: 0,
            is_dir: false,
            is_symlink: false,
            hash: Some("local".to_string()),
        };
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
    fn workspace_key_changes_by_host() {
        let path = PathBuf::from("/repo");
        assert_ne!(
            workspace_key(Some("host-a"), &path),
            workspace_key(Some("host-b"), &path)
        );
    }

    #[test]
    fn rewrites_lsp_uri_prefixes() {
        let body = br#"{"params":{"textDocument":{"uri":"file:///local/mirror/src/main.rs"},"rootPath":"/local/mirror"}}"#;
        let rewritten = rewrite_lsp_body(body, "/local/mirror", "/remote/repo").unwrap();
        let value: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(
            value["params"]["textDocument"]["uri"],
            "file:///remote/repo/src/main.rs"
        );
        assert_eq!(value["params"]["rootPath"], "/remote/repo");
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

    #[cfg(unix)]
    #[test]
    fn agent_request_times_out_when_agent_stalls() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let fake_agent = dir.path().join("fake-agent");
        fs::write(&fake_agent, "#!/bin/sh\nsleep 60\n").unwrap();
        let mut permissions = fs::metadata(&fake_agent).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fake_agent, permissions).unwrap();

        let mut client = AgentClient::new(
            fake_agent.to_string_lossy().to_string(),
            None,
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            1,
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
}
