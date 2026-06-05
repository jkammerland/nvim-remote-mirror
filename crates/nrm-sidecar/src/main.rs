use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use nrm_protocol::{
    read_frame, write_frame, BatchReadFile, BatchValidateFile, FileMeta, Request, RequestId,
    Response, RpcError, RpcMessage, SaveOutcome, WriteStartOutcome, MAX_FRAME_LEN,
    PROTOCOL_VERSION,
};
use rusqlite::Row;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Condvar, Mutex,
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
const REMOTE_UNAVAILABLE_BACKOFF_MS: u64 = 2_000;
const MAX_SAVE_PAYLOAD_BYTES: usize = MAX_FRAME_LEN - (1024 * 1024);
const REMOTE_INTERACTIVE_QUEUE_CAPACITY: usize = 128;
const REMOTE_BACKGROUND_QUEUE_CAPACITY: usize = 128;

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
        #[arg(long, default_value_t = 10)]
        ssh_connect_timeout_seconds: u64,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
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

#[derive(Debug, Clone, Default)]
struct AgentInterrupt {
    child: Arc<Mutex<Option<Arc<Mutex<Child>>>>>,
    shutdown_requested: Arc<AtomicBool>,
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

    fn set_child(&self, child: Arc<Mutex<Child>>) {
        if let Ok(mut current) = self.child.lock() {
            *current = Some(child);
        }
    }

    fn clear_child(&self, child: &Arc<Mutex<Child>>) {
        if let Ok(mut current) = self.child.lock() {
            if current
                .as_ref()
                .is_some_and(|current_child| Arc::ptr_eq(current_child, child))
            {
                *current = None;
            }
        }
    }

    fn kill_current(&self) {
        let child = self
            .child
            .lock()
            .ok()
            .and_then(|current| current.as_ref().map(Arc::clone));
        if let Some(child) = child {
            if let Ok(mut child) = child.lock() {
                kill_child_tree(&mut child);
            }
        }
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

#[derive(Debug)]
enum AgentRequestOutcome {
    Response(Response),
    Preempted,
}

struct AgentClient {
    launch: AgentLaunch,
    interrupt: AgentInterrupt,
    preempt: AgentPreempt,
    worker: Option<AgentWorker>,
    handshake_complete: bool,
    unavailable_until: Option<Instant>,
    last_remote_error: Option<String>,
    next_id: RequestId,
}

impl AgentClient {
    fn new(
        agent: String,
        ssh: Option<String>,
        remote_root: PathBuf,
        request_timeout: Duration,
        ssh_connect_timeout_seconds: u64,
        interrupt: AgentInterrupt,
    ) -> Self {
        Self {
            launch: AgentLaunch {
                agent,
                ssh,
                remote_root,
                request_timeout,
                ssh_connect_timeout_seconds,
            },
            interrupt,
            preempt: AgentPreempt::default(),
            worker: None,
            handshake_complete: false,
            unavailable_until: None,
            last_remote_error: None,
            next_id: 1,
        }
    }

    fn spawn_worker(launch: &AgentLaunch, interrupt: AgentInterrupt) -> Result<AgentWorker> {
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

        configure_agent_process(&mut command);

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
        interrupt.set_child(Arc::clone(&child));
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
                kill_child_tree(&mut child);
                let _ = child.wait();
            });
            interrupt.clear_child(&worker_child);
        });

        Ok(AgentWorker { tx, child })
    }

    fn request(&mut self, request: Request) -> Result<Response> {
        self.request_inner(request, false)
    }

    fn request_maybe_preemptible_since(
        &mut self,
        request: Request,
        preempt_epoch: u64,
    ) -> Result<AgentRequestOutcome> {
        self.request_outcome_inner(request, true, preempt_epoch)
    }

    fn preempt_handle(&self) -> AgentPreempt {
        self.preempt.clone()
    }

    fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    fn remote_backoff(&self) -> Option<(u64, String)> {
        let until = self.unavailable_until?;
        let now = Instant::now();
        if now >= until {
            return None;
        }
        let remaining_ms = until
            .duration_since(now)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let error = self
            .last_remote_error
            .clone()
            .unwrap_or_else(|| "last remote attempt failed".to_string());
        Some((remaining_ms, error))
    }

    fn check_remote_backoff(&mut self) -> Result<()> {
        if let Some((remaining_ms, error)) = self.remote_backoff() {
            bail!("remote unavailable; retry after {remaining_ms} ms: {error}");
        }
        self.unavailable_until = None;
        Ok(())
    }

    fn mark_remote_unavailable(&mut self, error: impl Into<String>) -> anyhow::Error {
        self.handshake_complete = false;
        let error = error.into();
        self.last_remote_error = Some(error.clone());
        self.unavailable_until =
            Some(Instant::now() + Duration::from_millis(REMOTE_UNAVAILABLE_BACKOFF_MS));
        anyhow!(error)
    }

    fn clear_remote_unavailable(&mut self) {
        self.unavailable_until = None;
        self.last_remote_error = None;
    }

    fn preempt_epoch(&self) -> u64 {
        self.preempt.epoch()
    }

    fn request_inner(&mut self, request: Request, preemptible: bool) -> Result<Response> {
        let preempt_epoch = self.preempt.epoch();
        match self.request_outcome_inner(request, preemptible, preempt_epoch)? {
            AgentRequestOutcome::Response(response) => Ok(response),
            AgentRequestOutcome::Preempted => bail!("agent request preempted by interactive work"),
        }
    }

    fn request_outcome_inner(
        &mut self,
        request: Request,
        preemptible: bool,
        preempt_epoch: u64,
    ) -> Result<AgentRequestOutcome> {
        self.check_remote_backoff()?;
        if !matches!(request, Request::Hello { .. }) && !self.handshake_complete {
            if let Some(outcome) = self.ensure_handshake(preemptible, preempt_epoch)? {
                return Ok(outcome);
            }
        }
        let is_hello = matches!(request, Request::Hello { .. });
        let outcome = self.send_request_outcome(request, preemptible, preempt_epoch)?;
        if is_hello {
            self.record_handshake_outcome(&outcome)?;
        }
        Ok(outcome)
    }

    fn ensure_handshake(
        &mut self,
        preemptible: bool,
        preempt_epoch: u64,
    ) -> Result<Option<AgentRequestOutcome>> {
        let outcome = self.send_request_outcome(
            Request::Hello {
                client_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION,
            },
            preemptible,
            preempt_epoch,
        )?;
        match outcome {
            AgentRequestOutcome::Response(Response::Hello { .. }) => {
                self.handshake_complete = true;
                self.clear_remote_unavailable();
                Ok(None)
            }
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
            AgentRequestOutcome::Response(Response::Hello { .. }) => {
                self.handshake_complete = true;
                self.clear_remote_unavailable();
                Ok(())
            }
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
    ) -> Result<AgentRequestOutcome> {
        if self.interrupt.is_shutdown_requested() {
            bail!("agent request cancelled by shutdown");
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let (reply, reply_rx) = mpsc::channel();
        for attempt in 0..2 {
            let tx = match self.ensure_worker() {
                Ok(worker) => worker.tx.clone(),
                Err(error) => return Err(self.mark_remote_unavailable(error.to_string())),
            };
            let command = AgentWorkerCommand {
                id,
                request: request.clone(),
                reply: reply.clone(),
            };
            if tx.send(command).is_ok() {
                break;
            }
            self.worker = None;
            self.handshake_complete = false;
            if attempt == 1 {
                return Err(self.mark_remote_unavailable(format!(
                    "agent worker exited before request {id} could be sent"
                )));
            }
        }

        self.wait_for_reply(id, reply_rx, preemptible, preempt_epoch)
    }

    fn wait_for_reply(
        &mut self,
        id: RequestId,
        reply_rx: mpsc::Receiver<AgentWorkerReply>,
        preemptible: bool,
        preempt_epoch: u64,
    ) -> Result<AgentRequestOutcome> {
        let started = Instant::now();
        loop {
            if preemptible && self.preempt.changed_since(preempt_epoch) {
                self.kill_worker();
                return Ok(AgentRequestOutcome::Preempted);
            }

            let timeout = self.launch.request_timeout;
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                self.kill_worker();
                return Err(self.mark_remote_unavailable(format!(
                    "agent request {id} timed out after {} ms",
                    timeout.as_millis()
                )));
            }
            let remaining = timeout.saturating_sub(elapsed);
            let wait = remaining.min(Duration::from_millis(25));

            match reply_rx.recv_timeout(wait) {
                Ok(reply) => return self.handle_worker_reply(reply),
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.worker = None;
                    self.handshake_complete = false;
                    return Err(self.mark_remote_unavailable(format!(
                        "agent worker exited while request {id} was pending"
                    )));
                }
            }
        }
    }

    fn handle_worker_reply(&mut self, reply: AgentWorkerReply) -> Result<AgentRequestOutcome> {
        match reply {
            AgentWorkerReply::Response(Response::Error { message }) => Err(anyhow!(message)),
            AgentWorkerReply::Response(response) => Ok(AgentRequestOutcome::Response(response)),
            AgentWorkerReply::Error(message) => {
                self.worker = None;
                self.handshake_complete = false;
                Err(self.mark_remote_unavailable(message))
            }
        }
    }

    fn ensure_worker(&mut self) -> Result<&AgentWorker> {
        if self.interrupt.is_shutdown_requested() {
            bail!("agent worker is shut down");
        }
        if self.worker.is_none() {
            self.worker = Some(Self::spawn_worker(&self.launch, self.interrupt.clone())?);
        }
        Ok(self.worker.as_ref().expect("worker was just initialized"))
    }

    fn shutdown(&mut self) {
        if self.worker.is_some() {
            let _ = self.request(Request::Shutdown);
        }
        self.kill_worker();
    }

    fn kill_worker(&mut self) {
        self.handshake_complete = false;
        if let Some(worker) = self.worker.take() {
            drop(worker.tx);
            if let Ok(mut child) = worker.child.lock() {
                kill_child_tree(&mut child);
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

#[cfg(unix)]
fn configure_agent_process(command: &mut Command) {
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
            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
    }
    let _ = child.kill();
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
              created_at_ms INTEGER NOT NULL,
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
              size=?3,
              local_hash=?2,
              dirty=1,
              validation_state='dirty',
              last_error=NULL,
              updated_at_ms=?4
            WHERE relative_path=?1
            ",
            params![relative_path, local_hash, content.len() as i64, now_ms()],
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

    fn enqueue_local_save(&self, relative_path: &str) -> Result<SaveQueueEntry> {
        let entry = self
            .get(relative_path)?
            .ok_or_else(|| anyhow!("{relative_path} is not known in the mirror"))?;
        let content = fs::read(&entry.local_path).with_context(|| {
            format!(
                "failed to read local mirror file {}",
                entry.local_path.display()
            )
        })?;
        let local_hash = hash_bytes(&content);
        self.enqueue_save(
            relative_path,
            &local_hash,
            entry.remote_hash.as_deref(),
            &content,
        )
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
        fs::rename(&part_path, &entry.local_path)?;
        Ok(())
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
        let deleted: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM files WHERE validation_state='deleted'",
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
            "stale_files": stale,
            "deleted_files": deleted
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
            .unwrap_or(DEFAULT_GREP_CACHE_MAX_FILE_BYTES);
        let max_total_bytes = params
            .get("max_total_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_GREP_CACHE_MAX_TOTAL_BYTES);
        let mut hits = Vec::new();
        let mut searched_files = 0_usize;
        let mut searched_bytes = 0_u64;
        let mut skipped_files = 0_usize;
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
            let file = match File::open(&entry.local_path) {
                Ok(file) => file,
                Err(_) => {
                    skipped_files += 1;
                    continue;
                }
            };
            searched_bytes = searched_bytes.saturating_add(file_len);
            let mut reader = BufReader::new(file);
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
                let line = line.trim_end_matches(&['\r', '\n'][..]);
                if let Some(byte_idx) = line.find(query) {
                    hits.push(json!({
                        "path": entry.relative_path,
                        "local_path": entry.local_path.to_string_lossy(),
                        "line": line_number,
                        "column": byte_idx as u64 + 1,
                        "text": line,
                        "cached": true,
                        "dirty": entry.dirty,
                        "validation_state": entry.validation_state
                    }));
                    if hits.len() >= limit {
                        truncated = true;
                        break;
                    }
                }
            }
            if invalid_text {
                skipped_files += 1;
            } else {
                searched_files += 1;
            }
        }

        Ok(json!({
            "hits": hits,
            "truncated": truncated,
            "searched_files": searched_files,
            "searched_bytes": searched_bytes,
            "skipped_files": skipped_files,
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

struct Sidecar {
    agent: AgentClient,
    mirror: Mirror,
    remote_root: PathBuf,
    workspace_key: String,
}

#[derive(Debug, Clone)]
struct FastState {
    mirror_root: PathBuf,
    files_root: PathBuf,
    remote_root: PathBuf,
    workspace_key: String,
    pending_remote: Arc<Mutex<PendingRemote>>,
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
}

struct StartedRemoteWork {
    work: RemoteWork,
    preempt_epoch: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RemotePriority {
    Interactive,
    Background,
}

struct RemoteQueue {
    state: Mutex<RemoteQueueState>,
    ready: Condvar,
    interactive_capacity: usize,
    background_capacity: usize,
}

struct RemoteQueueState {
    queue: VecDeque<RemoteWork>,
    interactive_len: usize,
    background_len: usize,
    closed: bool,
}

impl RemotePriority {
    fn for_request(request: &ClientRequest) -> Self {
        match request.method.as_str() {
            "prefetch" | "prefetch_related" | "refresh" | "scan" | "remote_probe" => {
                Self::Background
            }
            "flush_queue" if request_background_flag(request) => Self::Background,
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

impl RemoteQueue {
    fn new(interactive_capacity: usize, background_capacity: usize) -> Self {
        Self {
            state: Mutex::new(RemoteQueueState {
                queue: VecDeque::new(),
                interactive_len: 0,
                background_len: 0,
                closed: false,
            }),
            ready: Condvar::new(),
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
        if state.closed {
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

    fn pop(&self) -> Option<RemoteWork> {
        self.pop_started_with_epoch(None)
            .map(|started| started.work)
    }

    fn pop_started(&self, preempt: &AgentPreempt) -> Option<StartedRemoteWork> {
        self.pop_started_with_epoch(Some(preempt))
    }

    fn pop_started_with_epoch(&self, preempt: Option<&AgentPreempt>) -> Option<StartedRemoteWork> {
        let mut state = self.state.lock().expect("remote queue mutex poisoned");
        loop {
            if let Some(index) = state.next_ready_index() {
                let preempt_epoch = preempt.map(AgentPreempt::epoch).unwrap_or(0);
                return Some(StartedRemoteWork {
                    work: state.remove(index),
                    preempt_epoch,
                });
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
            "flush" | "flush_queued" => {
                path_hazard(request.params.get("path").and_then(Value::as_str))
            }
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
            workspace_key: sidecar.workspace_key.clone(),
            pending_remote,
        }
    }

    fn try_handle(&self, request: &ClientRequest) -> FastHandle {
        match request.method.as_str() {
            "hello" => FastHandle::Handled(Ok(json!({
                "sidecar_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": PROTOCOL_VERSION,
                "workspace_key": self.workspace_key,
                "remote_root": self.remote_root.to_string_lossy(),
                "mirror_root": self.mirror_root.to_string_lossy(),
                "files_root": self.files_root.to_string_lossy(),
                "remote_status": "unchecked",
                "remote_checked": false,
                "remote_available": false
            }))),
            "status" => FastHandle::Handled(
                Mirror::open_root(self.mirror_root.clone()).and_then(|mirror| mirror.status()),
            ),
            "open" => self.try_open(&request.params),
            "grep_cache" => FastHandle::Handled(
                Mirror::open_root(self.mirror_root.clone())
                    .and_then(|mirror| mirror.grep_cache(&request.params)),
            ),
            _ => FastHandle::Defer,
        }
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

    fn prepare_flush(&self, request: &ClientRequest) -> Result<ClientRequest> {
        let path = required_string(&request.params, "path")?;
        let mirror = Mirror::open_root(self.mirror_root.clone())?;
        let queued = mirror.enqueue_local_save(path)?;
        Ok(ClientRequest {
            id: request.id,
            method: "flush_queued".to_string(),
            params: json!({
                "queue_id": queued.id,
                "path": queued.relative_path
            }),
        })
    }
}

impl Sidecar {
    fn new(
        remote_root: PathBuf,
        ssh: Option<String>,
        agent: String,
        state_dir: Option<PathBuf>,
        request_timeout_ms: u64,
        ssh_connect_timeout_seconds: u64,
        agent_interrupt: AgentInterrupt,
    ) -> Result<Self> {
        let workspace_key = workspace_key(ssh.as_deref(), &remote_root);
        let mirror = Mirror::open(state_dir, &workspace_key)?;
        let agent = AgentClient::new(
            agent,
            ssh,
            remote_root.clone(),
            Duration::from_millis(request_timeout_ms),
            ssh_connect_timeout_seconds,
            agent_interrupt,
        );
        let sidecar = Self {
            agent,
            mirror,
            remote_root,
            workspace_key,
        };
        Ok(sidecar)
    }

    fn handle(&mut self, method: &str, params: Value, preempt_epoch: u64) -> Result<Value> {
        match method {
            "hello" => Ok(json!({
                "sidecar_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": PROTOCOL_VERSION,
                "workspace_key": self.workspace_key,
                "remote_root": self.remote_root.to_string_lossy(),
                "mirror_root": self.mirror.root().to_string_lossy(),
                "files_root": self.mirror.files_root().to_string_lossy(),
                "remote_status": "unchecked",
                "remote_checked": false,
                "remote_available": false
            })),
            "status" => self.mirror.status(),
            "remote_probe" => Ok(self.remote_probe()),
            "scan" => self.scan(params, preempt_epoch),
            "open" => self.open(params),
            "prefetch" => self.prefetch(params, preempt_epoch),
            "prefetch_related" => self.prefetch_related(params, preempt_epoch),
            "grep" => self.grep(params),
            "grep_cache" => self.mirror.grep_cache(&params),
            "flush" => self.flush(params),
            "flush_queued" => self.flush_queued(params),
            "flush_queue" => self.flush_queue(params),
            "validate" => self.validate(params),
            "refresh" => self.refresh(params, preempt_epoch),
            "shutdown" | "disconnect" => {
                self.agent.shutdown();
                Ok(json!({"shutdown": true}))
            }
            other => bail!("unknown method `{other}`"),
        }
    }

    fn remote_probe(&mut self) -> Value {
        if self.agent.handshake_complete() {
            return json!({
                "remote_status": "connected",
                "remote_checked": true,
                "remote_available": true
            });
        }
        if let Some((retry_after_ms, error)) = self.agent.remote_backoff() {
            return json!({
                "remote_status": "unavailable",
                "remote_checked": true,
                "remote_available": false,
                "retry_after_ms": retry_after_ms,
                "remote_error": error
            });
        }

        match self.agent.request(Request::Hello {
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
        }) {
            Ok(Response::Hello {
                agent_version,
                protocol_version,
                capabilities,
            }) => json!({
                "remote_status": "connected",
                "remote_checked": true,
                "remote_available": true,
                "agent_version": agent_version,
                "protocol_version": protocol_version,
                "capabilities": capabilities
            }),
            Ok(other) => json!({
                "remote_status": "unavailable",
                "remote_checked": true,
                "remote_available": false,
                "remote_error": format!("unexpected hello response from agent: {other:?}")
            }),
            Err(error) => json!({
                "remote_status": "unavailable",
                "remote_checked": true,
                "remote_available": false,
                "retry_after_ms": self.agent.remote_backoff().map(|(remaining, _)| remaining).unwrap_or(0),
                "remote_error": error.to_string()
            }),
        }
    }

    fn scan(&mut self, params: Value, preempt_epoch: u64) -> Result<Value> {
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(10_000) as usize;
        let response = match self
            .agent
            .request_maybe_preemptible_since(Request::Scan { limit }, preempt_epoch)?
        {
            AgentRequestOutcome::Response(response) => response,
            AgentRequestOutcome::Preempted => {
                return Ok(json!({"entries": [], "truncated": true, "preempted": true}));
            }
        };
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
        if let Some(entry) = self.mirror.get(&file.path)? {
            let (entry, _) = self.mirror.sync_cached_file_integrity(&entry)?;
            if entry.dirty {
                bail!("skipped dirty local mirror file");
            }
        }
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let part_path = local_path.with_extension("nrm-batch-part");
        {
            let mut part = File::create(&part_path)?;
            part.write_all(&file.content)?;
            part.sync_all()?;
        }
        let local_hash = hash_file(&part_path)?;
        if local_hash != file.hash {
            let _ = fs::remove_file(&part_path);
            bail!(
                "batch hydration hash mismatch for {}: local={local_hash} remote={}",
                file.path,
                file.hash
            );
        }
        fs::rename(&part_path, &local_path)?;
        self.mirror
            .record_hydrated(&file.meta, &file.hash, &local_hash)?;
        Ok(())
    }

    fn grep(&mut self, params: Value) -> Result<Value> {
        let query = required_string(&params, "query")?;
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
        let hydrate = params
            .get("hydrate")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let max_file_bytes = params
            .get("max_file_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_FILE_BYTES);
        let max_total_bytes = params
            .get("max_total_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_BATCH_MAX_TOTAL_BYTES);
        let response = self.agent.request(Request::Grep {
            query: query.to_string(),
            limit,
        })?;
        match response {
            Response::Grep { hits, truncated } => {
                let mut hydrated = 0;
                let mut hydrate_errors = Vec::new();
                let mut hydrate_truncated = false;
                if hydrate {
                    let paths = self.grep_hydration_paths(&hits)?;
                    let result =
                        self.batch_hydrate(paths, max_file_bytes, max_total_bytes, None)?;
                    hydrated = result.0;
                    hydrate_errors = result.1;
                    hydrate_truncated = result.2;
                }
                let hits = self.grep_hits_with_local_paths(hits)?;
                Ok(json!({
                    "hits": hits,
                    "truncated": truncated,
                    "hydrated": hydrated,
                    "hydrate_errors": hydrate_errors,
                    "hydrate_truncated": hydrate_truncated
                }))
            }
            other => bail!("unexpected grep response: {other:?}"),
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

    fn flush(&mut self, params: Value) -> Result<Value> {
        let path = required_string(&params, "path")?;
        let queued = self.mirror.enqueue_local_save(path)?;
        Self::save_attempt_to_json(self.apply_save_entry(queued)?)
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

    fn replay_queued_saves(&mut self, limit: Option<usize>) -> Result<Vec<Value>> {
        let entries = self.mirror.pending_save_entries(limit)?;
        let mut attempts = Vec::new();
        for entry in entries {
            attempts.push(Self::save_attempt_to_json(self.apply_save_entry(entry)?)?);
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
            });
        }
        if snapshot_size as usize > MAX_SAVE_PAYLOAD_BYTES {
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
                });
            }
        };

        match response {
            Response::WriteFileCas { outcome } => self.record_save_outcome(entry.id, outcome),
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
                return self.record_save_outcome(entry.id, SaveOutcome::Conflict(conflict));
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
                });
            }
        };

        match finish {
            Response::FinishWriteFileCas { outcome } => self.record_save_outcome(entry.id, outcome),
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

    fn record_save_outcome(&self, queue_id: i64, outcome: SaveOutcome) -> Result<SaveAttempt> {
        match outcome {
            SaveOutcome::Applied(applied) => {
                self.mirror.mark_save_applied(
                    queue_id,
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
                let message = "remote content changed before queued save was applied";
                let conflict_path = self.mirror.record_save_conflict(
                    queue_id,
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

    fn hydrate(&mut self, path: &str) -> Result<MirrorEntry> {
        let local_path = self.mirror.local_path(path)?;
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let part_path = local_path.with_extension("nrm-part");
        let hydrated = (|| -> Result<(FileMeta, String, String)> {
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

            let local_hash = hash_file(&part_path)?;
            if local_hash != remote_hash {
                bail!(
                    "local hydration hash mismatch for {path}: local={local_hash} remote={remote_hash}"
                );
            }
            Ok((meta, remote_hash, local_hash))
        })();
        let (meta, remote_hash, local_hash) = match hydrated {
            Ok(hydrated) => hydrated,
            Err(error) => {
                let _ = fs::remove_file(&part_path);
                return Err(error);
            }
        };
        fs::rename(&part_path, &local_path)?;
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
            ssh_connect_timeout_seconds,
            command,
        } => run_lsp_proxy(
            remote_root,
            local_root,
            ssh,
            ssh_connect_timeout_seconds,
            command,
        ),
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
    let agent_interrupt = AgentInterrupt::default();
    let sidecar = Sidecar::new(
        remote_root,
        ssh,
        agent,
        state_dir,
        request_timeout_ms,
        ssh_connect_timeout_seconds,
        agent_interrupt.clone(),
    )?;
    let pending_remote = Arc::new(Mutex::new(PendingRemote::default()));
    let fast_state = FastState::from_sidecar(&sidecar, Arc::clone(&pending_remote));
    let agent_preempt = sidecar.agent.preempt_handle();
    let (response_tx, response_rx) = mpsc::sync_channel::<ClientResponse>(1024);
    let writer = thread::spawn(move || -> Result<()> {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        for response in response_rx {
            writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
            stdout.flush()?;
        }
        Ok(())
    });

    let remote_queue = Arc::new(RemoteQueue::new(
        REMOTE_INTERACTIVE_QUEUE_CAPACITY,
        REMOTE_BACKGROUND_QUEUE_CAPACITY,
    ));
    let remote_response_tx = response_tx.clone();
    let remote_pending = Arc::clone(&pending_remote);
    let remote_interrupt = agent_interrupt.clone();
    let remote_worker_queue = Arc::clone(&remote_queue);
    let remote_worker_preempt = agent_preempt.clone();
    let remote_worker = thread::spawn(move || {
        let mut sidecar = sidecar;
        while let Some(started) = remote_worker_queue.pop_started(&remote_worker_preempt) {
            let preempt_epoch = started.preempt_epoch;
            let RemoteWork {
                request, hazard, ..
            } = started.work;
            if remote_interrupt.is_shutdown_requested() {
                if let Ok(mut pending) = remote_pending.lock() {
                    pending.clear(&hazard);
                }
                clear_pending_hazards(&remote_pending, remote_worker_queue.shutdown_and_drain());
                break;
            }
            let should_shutdown = matches!(request.method.as_str(), "shutdown" | "disconnect");
            let response = handle_client_request(&mut sidecar, request, preempt_epoch);
            if let Ok(mut pending) = remote_pending.lock() {
                pending.clear(&hazard);
            }
            send_client_response(&remote_response_tx, response);
            if should_shutdown || remote_interrupt.is_shutdown_requested() {
                clear_pending_hazards(&remote_pending, remote_worker_queue.shutdown_and_drain());
                break;
            }
        }
    });

    for line in stdin.lock().lines() {
        let line = line?;
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

        let should_shutdown = matches!(request.method.as_str(), "shutdown" | "disconnect");
        if should_shutdown {
            agent_interrupt.request_shutdown();
            clear_pending_hazards(&pending_remote, remote_queue.shutdown_and_drain());
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
        if request.method == "flush" {
            request = match fast_state.prepare_flush(&request) {
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
                send_client_response(&response_tx, result_to_client_response(request.id, result));
            }
            FastHandle::Defer => {
                let hazard = PendingHazard::for_request(&request);
                if let Ok(mut pending) = pending_remote.lock() {
                    pending.register(&hazard);
                }
                let priority = RemotePriority::for_request(&request);
                let work = RemoteWork {
                    request,
                    hazard,
                    priority,
                };
                let preempt = (priority == RemotePriority::Interactive).then_some(&agent_preempt);
                match remote_queue.try_push(work, preempt) {
                    Ok(canceled) => {
                        clear_pending_hazard_refs(&pending_remote, &canceled);
                        send_preempted_responses(&response_tx, canceled);
                    }
                    Err(work) => {
                        if let Ok(mut pending) = pending_remote.lock() {
                            pending.clear(&work.hazard);
                        }
                        let response = if work.request.method == "flush_queued" {
                            result_to_client_response(
                                work.request.id,
                                Ok(json!({
                                    "status": "queued",
                                    "path": work.request.params.get("path").and_then(Value::as_str).unwrap_or(""),
                                    "reason": format!(
                                        "remote {} queue is full or not available; saved locally",
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
                                    "remote {} queue is full or not available",
                                    work.priority.label()
                                )),
                            }
                        };
                        send_client_response(&response_tx, response);
                    }
                }
            }
        }
        if should_shutdown {
            break;
        }
    }

    clear_pending_hazards(&pending_remote, remote_queue.close_and_drain_background());
    let _ = remote_worker.join();
    drop(response_tx);
    match writer.join() {
        Ok(result) => result?,
        Err(_) => bail!("server writer thread panicked"),
    }
    Ok(())
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

fn clear_pending_hazard_refs(pending_remote: &Arc<Mutex<PendingRemote>>, works: &[RemoteWork]) {
    if works.is_empty() {
        return;
    }
    if let Ok(mut pending) = pending_remote.lock() {
        for work in works {
            pending.clear(&work.hazard);
        }
    }
}

fn send_preempted_responses(tx: &mpsc::SyncSender<ClientResponse>, works: Vec<RemoteWork>) {
    for work in works {
        send_client_response(tx, preempted_client_response(work));
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
        _ => json!({"preempted": true}),
    }
}

fn send_client_response(tx: &mpsc::SyncSender<ClientResponse>, response: ClientResponse) -> bool {
    tx.send(response).is_ok()
}

fn run_lsp_proxy(
    remote_root: PathBuf,
    local_root: PathBuf,
    ssh: Option<String>,
    ssh_connect_timeout_seconds: u64,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        bail!("lsp-proxy requires a language server command after --");
    }

    let launch = LspLaunch::new(
        remote_root.clone(),
        ssh,
        ssh_connect_timeout_seconds,
        command,
    );
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

struct LspLaunch {
    program: String,
    args: Vec<String>,
    current_dir: Option<PathBuf>,
}

impl LspLaunch {
    fn new(
        remote_root: PathBuf,
        ssh: Option<String>,
        ssh_connect_timeout_seconds: u64,
        command: Vec<String>,
    ) -> Self {
        if let Some(target) = ssh {
            let mut args = vec![
                "-o".to_string(),
                "BatchMode=yes".to_string(),
                "-o".to_string(),
                format!("ConnectTimeout={ssh_connect_timeout_seconds}"),
                "-o".to_string(),
                "ServerAliveInterval=15".to_string(),
                "-o".to_string(),
                "ServerAliveCountMax=2".to_string(),
                target,
            ];
            args.push(lsp_remote_command(remote_root, command));
            Self {
                program: "ssh".to_string(),
                args,
                current_dir: None,
            }
        } else {
            Self {
                program: command[0].clone(),
                args: command[1..].to_vec(),
                current_dir: Some(remote_root),
            }
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }
        command
    }
}

fn lsp_remote_command(remote_root: PathBuf, command: Vec<String>) -> String {
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

    fn test_sidecar(mirror: Mirror) -> Sidecar {
        Sidecar {
            agent: AgentClient::new(
                "unused-agent".to_string(),
                None,
                PathBuf::from("/unused"),
                Duration::from_millis(1),
                1,
                AgentInterrupt::default(),
            ),
            mirror,
            remote_root: PathBuf::from("/unused"),
            workspace_key: "test".to_string(),
        }
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

    #[test]
    fn local_paths_reject_traversal() {
        let dir = tempdir().unwrap();
        let mirror = Mirror::open(Some(dir.path().to_path_buf()), "test").unwrap();
        assert!(mirror.local_path("../x").is_err());
        assert!(mirror.local_path("/x").is_err());
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
        assert_eq!(rx.recv().unwrap().id, 1);
        assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        sender.join().unwrap();
        assert_eq!(rx.recv().unwrap().id, 2);
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
        let key = workspace_key(None, &remote_root);
        let mirror = Mirror::open(Some(state_dir.path().to_path_buf()), &key).unwrap();
        let local_path = record_hydrated_content(&mirror, "src/main.rs", b"main");
        drop(mirror);

        let mut sidecar = Sidecar::new(
            remote_root,
            None,
            state_dir
                .path()
                .join("missing-agent")
                .to_string_lossy()
                .to_string(),
            Some(state_dir.path().to_path_buf()),
            1,
            1,
            AgentInterrupt::default(),
        )
        .unwrap();

        let hello = sidecar.handle("hello", json!({}), 0).unwrap();
        assert_eq!(hello["remote_status"], "unchecked");
        assert_eq!(hello["remote_checked"], false);
        assert_eq!(hello["remote_available"], false);

        let opened = sidecar
            .open(json!({"path": "src/main.rs", "force": false}))
            .unwrap();
        assert_eq!(opened["cached"], true);
        assert_eq!(
            opened["local_path"].as_str().unwrap(),
            local_path.to_string_lossy()
        );

        let probe = sidecar.remote_probe();
        assert_eq!(probe["remote_status"], "unavailable");
        assert_eq!(probe["remote_checked"], true);
        assert_eq!(probe["remote_available"], false);
        assert!(probe["retry_after_ms"].as_u64().unwrap() > 0);
        let probe = sidecar.remote_probe();
        assert_eq!(probe["remote_status"], "unavailable");
        assert!(probe["retry_after_ms"].as_u64().unwrap() > 0);

        let error = sidecar
            .scan(json!({"limit": 1}), 0)
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to launch agent"));
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
            .open(json!({"path": "a.txt", "force": true}))
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
        let result = sidecar.open(json!({"path": "a.txt"})).unwrap();
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
            .open(json!({"path": "a.txt", "force": true}))
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
        let result = sidecar.open(json!({"path": "a.txt"})).unwrap();

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
        let result = sidecar.open(json!({"path": "a.txt"})).unwrap();

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
        let result = sidecar.validate(json!({"path": "a.txt"})).unwrap();

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
        let result = sidecar.validate(json!({"path": "a.txt"})).unwrap();
        let entry = sidecar.mirror.get("a.txt").unwrap().unwrap();

        assert_eq!(result["status"], "dirty");
        assert_eq!(result["skipped"], true);
        assert_eq!(sidecar.mirror.pending_save_count().unwrap(), 1);
        assert!(entry.dirty);
        assert_eq!(entry.validation_state, "dirty");
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
        assert_eq!(sidecar.mirror.pending_save_count().unwrap(), 1);
        assert!(sidecar.mirror.get("a.txt").unwrap().unwrap().dirty);
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
        assert_eq!(result.unwrap()["cached_files"], 1);
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
        let prepared = fast.prepare_flush(&request).unwrap();
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
        RemoteWork {
            request,
            hazard,
            priority,
        }
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
    fn lsp_local_launch_runs_in_remote_root() {
        let launch = LspLaunch::new(
            PathBuf::from("/repo"),
            None,
            10,
            vec!["rust-analyzer".to_string(), "--stdio".to_string()],
        );

        assert_eq!(launch.program, "rust-analyzer");
        assert_eq!(launch.args, vec!["--stdio"]);
        assert_eq!(launch.current_dir.as_deref(), Some(Path::new("/repo")));
    }

    #[test]
    fn lsp_ssh_launch_uses_remote_root_and_connection_options() {
        let launch = LspLaunch::new(
            PathBuf::from("/tmp/repo with 'quote' ; x"),
            Some("host".to_string()),
            7,
            vec![
                "rust-analyzer".to_string(),
                "--config".to_string(),
                "check.command=\"clippy\"; $(echo no)".to_string(),
            ],
        );

        assert_eq!(launch.program, "ssh");
        assert_eq!(launch.current_dir, None);
        assert_eq!(
            launch.args,
            vec![
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=7",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "host",
                "'sh' '-lc' 'cd \"$1\" && shift && exec \"$@\"' 'nrm-lsp-proxy' '/tmp/repo with '\\''quote'\\'' ; x' 'rust-analyzer' '--config' 'check.command=\"clippy\"; $(echo no)'"
            ]
        );
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

    #[test]
    fn lsp_ssh_remote_command_preserves_cwd_and_args_through_shell_parse() {
        let dir = tempdir().unwrap();
        let remote_root = dir.path().join("repo with 'quote' ; x");
        fs::create_dir_all(&remote_root).unwrap();
        let remote_command = lsp_remote_command(
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
    fn agent_request_after_shutdown_does_not_spawn_worker() {
        let interrupt = AgentInterrupt::default();
        interrupt.request_shutdown();
        let mut client = AgentClient::new(
            "unused-agent".to_string(),
            None,
            PathBuf::from("/unused"),
            Duration::from_secs(30),
            1,
            interrupt.clone(),
        );

        let error = client.request(Request::Shutdown).unwrap_err().to_string();

        assert!(error.contains("shutdown"));
        assert!(interrupt.child.lock().unwrap().is_none());
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
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            1,
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
            dir.path().to_path_buf(),
            Duration::from_millis(50),
            1,
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
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            1,
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
            if interrupt.child.lock().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(interrupt.child.lock().unwrap().is_some());
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
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            1,
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
            if interrupt.child.lock().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(interrupt.child.lock().unwrap().is_some());

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
            dir.path().to_path_buf(),
            Duration::from_secs(30),
            1,
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
