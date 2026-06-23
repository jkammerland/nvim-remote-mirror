use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use nrm_protocol::{read_frame, write_frame, Request, Response, RpcMessage};
use std::hint::black_box;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use tempfile::{tempdir, TempDir};

struct AgentClient {
    child: Child,
    reader: BufReader<ChildStdout>,
    writer: ChildStdin,
    next_id: u64,
}

impl AgentClient {
    fn start(root: &Path) -> Self {
        let mut child = Command::new(agent_bin())
            .arg("serve")
            .arg("--root")
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn nrm-agent benchmark process");
        let reader = BufReader::new(child.stdout.take().expect("agent stdout"));
        let writer = child.stdin.take().expect("agent stdin");
        Self {
            child,
            reader,
            writer,
            next_id: 1,
        }
    }

    fn request(&mut self, request: Request) -> Response {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(&mut self.writer, &RpcMessage::Request { id, request }).unwrap();
        self.writer.flush().unwrap();
        match read_frame::<_, RpcMessage>(&mut self.reader).unwrap() {
            RpcMessage::Response {
                id: response_id,
                response,
            } if response_id == id => response,
            RpcMessage::Error {
                id: response_id,
                error,
            } if response_id == id => {
                panic!("agent request failed: {error:?}");
            }
            other => panic!("unexpected agent frame: {other:?}"),
        }
    }
}

impl Drop for AgentClient {
    fn drop(&mut self) {
        let _ = write_frame(
            &mut self.writer,
            &RpcMessage::Request {
                id: self.next_id,
                request: Request::Shutdown,
            },
        );
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn agent_bin() -> PathBuf {
    option_env!("CARGO_BIN_EXE_nrm-agent")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/release/nrm-agent"))
}

fn large_mode() -> bool {
    std::env::var("NRM_PERF_LARGE").ok().as_deref() == Some("1")
}

fn synthetic_workspace(file_count: usize) -> TempDir {
    let dir = tempdir().unwrap();
    let root = dir.path();
    std::fs::write(root.join(".gitignore"), "ignored/\n").unwrap();
    std::fs::create_dir(root.join("ignored")).unwrap();
    std::fs::write(root.join("ignored").join("skip.rs"), "needle\n").unwrap();

    for index in 0..file_count {
        let shard = root.join("src").join(format!("{:03}", index / 1000));
        std::fs::create_dir_all(&shard).unwrap();
        let mut text = format!("fn item_{index}() {{}}\n");
        if index % 97 == 0 {
            text.push_str("needle\n");
        }
        std::fs::write(shard.join(format!("file_{index:05}.rs")), text).unwrap();
    }

    let huge_line = format!("needle{}\n", "x".repeat(128 * 1024));
    std::fs::write(root.join("src").join("huge_line.rs"), huge_line).unwrap();
    dir
}

fn scan_all(client: &mut AgentClient, limit: usize) -> usize {
    let mut after = None;
    let mut scanned = 0;
    loop {
        let response = client.request(Request::Scan {
            limit,
            after: after.clone(),
        });
        let Response::Scan { entries, truncated } = response else {
            panic!("unexpected scan response");
        };
        scanned += entries.len();
        after = entries.last().map(|entry| entry.path.clone());
        if !truncated {
            break;
        }
    }
    scanned
}

fn agent_cli(c: &mut Criterion) {
    let file_count = if large_mode() { 50_000 } else { 10_000 };
    let page_limit = if large_mode() { 1_000 } else { 512 };
    let workspace = synthetic_workspace(file_count);
    let mut client = AgentClient::start(workspace.path());

    let mut group = c.benchmark_group("agent_cli");
    group.sample_size(if large_mode() { 10 } else { 20 });

    group.throughput(Throughput::Elements(file_count as u64));
    group.bench_function(format!("scan_all_{file_count}_files"), |b| {
        b.iter(|| black_box(scan_all(&mut client, page_limit)))
    });

    group.throughput(Throughput::Elements(page_limit as u64));
    group.bench_function("grep_many_small_files", |b| {
        b.iter(|| {
            let response = client.request(Request::Grep {
                query: "needle".to_string(),
                limit: 100,
                after: None,
                max_files: Some(page_limit),
                max_file_bytes: Some(512 * 1024),
                max_total_bytes: Some(8 * 1024 * 1024),
                session_id: None,
            });
            black_box(response)
        })
    });

    group.bench_function("grep_huge_matching_line_cap", |b| {
        b.iter(|| {
            let response = client.request(Request::Grep {
                query: "needle".to_string(),
                limit: 100,
                after: None,
                max_files: Some(file_count + 2),
                max_file_bytes: Some(512 * 1024),
                max_total_bytes: Some(16 * 1024 * 1024),
                session_id: None,
            });
            black_box(response)
        })
    });

    group.finish();
}

criterion_group!(benches, agent_cli);
criterion_main!(benches);
