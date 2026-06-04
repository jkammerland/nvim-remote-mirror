use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use nrm_protocol::{
    read_frame, write_frame, FileMeta, Request, Response, SaveOutcome, PROTOCOL_VERSION,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_CHUNK_SIZE: u64 = 1024 * 1024;

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
}

struct AgentClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl AgentClient {
    fn spawn(agent: &str, ssh: Option<&str>, remote_root: &Path) -> Result<Self> {
        let mut command = if let Some(target) = ssh {
            let mut command = Command::new("ssh");
            command
                .arg(target)
                .arg(agent)
                .arg("serve")
                .arg("--root")
                .arg(remote_root);
            command
        } else {
            let mut command = Command::new(agent);
            command.arg("serve").arg("--root").arg(remote_root);
            command
        };

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to launch agent `{agent}`{}",
                    ssh.map(|target| format!(" through ssh target `{target}`"))
                        .unwrap_or_default()
                )
            })?;

        let stdin = child.stdin.take().context("agent stdin was not piped")?;
        let stdout = child.stdout.take().context("agent stdout was not piped")?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn request(&mut self, request: Request) -> Result<Response> {
        write_frame(&mut self.stdin, &request).context("failed to write agent request")?;
        let response: Response =
            read_frame(&mut self.stdout).context("failed to read agent response")?;
        match response {
            Response::Error { message } => Err(anyhow!(message)),
            other => Ok(other),
        }
    }

    fn shutdown(&mut self) {
        let _ = self.request(Request::Shutdown);
        let _ = self.child.wait();
    }
}

impl Drop for AgentClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Mirror {
    root: PathBuf,
    files_root: PathBuf,
    conflicts_root: PathBuf,
    db: Connection,
}

impl Mirror {
    fn open(state_dir: Option<PathBuf>, workspace_key: &str) -> Result<Self> {
        let state_dir = state_dir.unwrap_or_else(default_state_dir);
        let root = state_dir.join("workspaces").join(workspace_key);
        let files_root = root.join("files");
        let conflicts_root = root.join("conflicts");
        fs::create_dir_all(&files_root)?;
        fs::create_dir_all(&conflicts_root)?;
        let db = Connection::open(root.join("mirror.sqlite"))?;
        let mirror = Self {
            root,
            files_root,
            conflicts_root,
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
              updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS save_queue (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              relative_path TEXT NOT NULL,
              expected_hash TEXT,
              local_hash TEXT NOT NULL,
              state TEXT NOT NULL,
              created_at_ms INTEGER NOT NULL,
              updated_at_ms INTEGER NOT NULL
            );
            ",
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
              local_hash, state, dirty, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'hydrated', 0, ?8)
            ON CONFLICT(relative_path) DO UPDATE SET
              local_path=excluded.local_path,
              size=excluded.size,
              mtime_ms=excluded.mtime_ms,
              mode=excluded.mode,
              remote_hash=excluded.remote_hash,
              local_hash=excluded.local_hash,
              state='hydrated',
              dirty=0,
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
                SELECT relative_path, local_path, size, remote_hash, local_hash, state, dirty
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
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn mark_dirty(
        &self,
        relative_path: &str,
        local_hash: &str,
        expected_hash: Option<&str>,
    ) -> Result<()> {
        let entry = self
            .get(relative_path)?
            .ok_or_else(|| anyhow!("{relative_path} is not known in the mirror"))?;
        self.db.execute(
            "
            UPDATE files SET local_hash=?2, dirty=1, updated_at_ms=?3
            WHERE relative_path=?1
            ",
            params![entry.relative_path, local_hash, now_ms()],
        )?;
        self.db.execute(
            "
            INSERT INTO save_queue (
              relative_path, expected_hash, local_hash, state, created_at_ms, updated_at_ms
            )
            VALUES (?1, ?2, ?3, 'pending', ?4, ?4)
            ",
            params![relative_path, expected_hash, local_hash, now_ms()],
        )?;
        Ok(())
    }

    fn mark_clean_after_save(
        &self,
        relative_path: &str,
        new_hash: &str,
        size: u64,
        mtime_ms: i64,
    ) -> Result<()> {
        self.db.execute(
            "
            UPDATE files SET
              size=?2,
              mtime_ms=?3,
              remote_hash=?4,
              local_hash=?4,
              dirty=0,
              state='hydrated',
              updated_at_ms=?5
            WHERE relative_path=?1
            ",
            params![relative_path, size as i64, mtime_ms, new_hash, now_ms()],
        )?;
        self.db.execute(
            "
            UPDATE save_queue SET state='applied', updated_at_ms=?2
            WHERE relative_path=?1 AND state='pending'
            ",
            params![relative_path, now_ms()],
        )?;
        Ok(())
    }

    fn record_conflict(&self, relative_path: &str, remote_content: &[u8]) -> Result<PathBuf> {
        let safe_name = relative_path.replace(['/', '\\'], "__");
        let path = self
            .conflicts_root
            .join(format!("{safe_name}.remote.{}", now_ms()));
        fs::write(&path, remote_content)?;
        self.db.execute(
            "
            UPDATE save_queue SET state='conflict', updated_at_ms=?2
            WHERE relative_path=?1 AND state='pending'
            ",
            params![relative_path, now_ms()],
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
        Ok(json!({
            "mirror_root": self.root.to_string_lossy(),
            "known_files": known,
            "cached_files": cached,
            "dirty_files": dirty,
            "pending_saves": pending
        }))
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
    ) -> Result<Self> {
        let workspace_key = workspace_key(ssh.as_deref(), &remote_root);
        let mirror = Mirror::open(state_dir, &workspace_key)?;
        let mut agent = AgentClient::spawn(&agent, ssh.as_deref(), &remote_root)?;
        let hello = agent.request(Request::Hello {
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: PROTOCOL_VERSION,
        })?;
        if !matches!(hello, Response::Hello { .. }) {
            bail!("unexpected hello response from agent: {hello:?}");
        }
        Ok(Self {
            agent,
            mirror,
            remote_root,
            workspace_key,
        })
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
                if entry.state == "hydrated" && entry.local_path.exists() && !entry.dirty {
                    return Ok(json!({
                        "path": entry.relative_path,
                        "local_path": entry.local_path.to_string_lossy(),
                        "hash": entry.remote_hash,
                        "local_hash": entry.local_hash,
                        "size": entry.size,
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
        self.mirror
            .mark_dirty(path, &local_hash, entry.remote_hash.as_deref())?;

        let response = self.agent.request(Request::WriteFileCas {
            path: path.to_string(),
            expected_hash: entry.remote_hash.clone(),
            content,
        })?;
        match response {
            Response::WriteFileCas {
                outcome: SaveOutcome::Applied(applied),
            } => {
                self.mirror.mark_clean_after_save(
                    &applied.path,
                    &applied.new_hash,
                    applied.size,
                    applied.mtime_ms,
                )?;
                Ok(json!({
                    "status": "applied",
                    "path": applied.path,
                    "hash": applied.new_hash,
                    "size": applied.size
                }))
            }
            Response::WriteFileCas {
                outcome: SaveOutcome::Conflict(conflict),
            } => {
                let conflict_path = self
                    .mirror
                    .record_conflict(&conflict.path, &conflict.remote_content)?;
                Ok(json!({
                    "status": "conflict",
                    "path": conflict.path,
                    "expected_hash": conflict.expected_hash,
                    "actual_hash": conflict.actual_hash,
                    "remote_path": conflict_path.to_string_lossy()
                }))
            }
            other => bail!("unexpected flush response: {other:?}"),
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
        } => run_server(remote_root, ssh, agent, state_dir),
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
) -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut sidecar = Sidecar::new(remote_root, ssh, agent, state_dir)?;

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
}
