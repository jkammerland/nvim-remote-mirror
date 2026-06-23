#!/usr/bin/env bash
set -euo pipefail

mode="small"
if [[ "${1:-}" == "--large" || "${NRM_PERF_LARGE:-}" == "1" ]]; then
  mode="large"
fi
if [[ "${1:-}" == "--small" ]]; then
  mode="small"
fi

if command -v rustup >/dev/null 2>&1; then
  cargo_cmd=("$(rustup which --toolchain 1.95.0 cargo)")
  export RUSTC RUSTDOC
  RUSTC="$(rustup which --toolchain 1.95.0 rustc)"
  RUSTDOC="$(rustup which --toolchain 1.95.0 rustdoc)"
else
  cargo_cmd=("$(command -v cargo)")
  export RUSTC RUSTDOC
  RUSTC="$(command -v rustc)"
  RUSTDOC="$(command -v rustdoc)"
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/rustup-1.95.0}"
"${cargo_cmd[@]}" build --release --locked >/dev/null

python3 - "$mode" "$CARGO_TARGET_DIR" <<'PY'
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

mode = sys.argv[1]
target_dir = pathlib.Path(sys.argv[2])
repo = pathlib.Path.cwd()
sidecar_bin = repo / target_dir / "release" / "nrm-sidecar"
agent_bin = repo / target_dir / "release" / "nrm-agent"
file_count = 50_000 if mode == "large" else 1_000
scan_limit = 1_000 if mode == "large" else 256


def rss_kib(pid: int) -> int:
    try:
        for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except FileNotFoundError:
        return 0
    return 0


def start_sidecar(remote_root: pathlib.Path, state_dir: pathlib.Path):
    return subprocess.Popen(
        [
            str(sidecar_bin),
            "serve",
            "--remote-root",
            str(remote_root),
            "--agent",
            str(agent_bin),
            "--state-dir",
            str(state_dir),
            "--request-timeout-ms",
            "30000",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


class Client:
    def __init__(self, proc):
        self.proc = proc
        self.next_id = 1

    def request(self, method, params=None):
        request_id = self.next_id
        self.next_id += 1
        payload = {"id": request_id, "method": method, "params": params or {}}
        start = time.perf_counter()
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                stderr = self.proc.stderr.read()
                raise RuntimeError(f"sidecar exited while waiting for {method}: {stderr}")
            response = json.loads(line)
            if response.get("id") == request_id:
                break
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if not response.get("ok"):
            raise RuntimeError(f"{method} failed: {response.get('error')}")
        return elapsed_ms, response.get("result") or {}

    def shutdown(self):
        try:
            self.request("shutdown", {})
        finally:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def record(metrics, name, elapsed_ms, proc, extra=None):
    item = {
        "name": name,
        "elapsed_ms": round(elapsed_ms, 3),
        "rss_kib": rss_kib(proc.pid),
    }
    if extra:
        item.update(extra)
    metrics.append(item)


tmp = pathlib.Path(tempfile.mkdtemp(prefix="nrm-perf-"))
try:
    remote_root = tmp / "remote"
    state_dir = tmp / "state"
    (remote_root / "src").mkdir(parents=True)
    for index in range(file_count):
        shard = remote_root / "src" / f"{index // 1000:03d}"
        shard.mkdir(exist_ok=True)
        text = f"fn item_{index}() {{}}\n"
        if index % 97 == 0:
            text += "needle\n"
        (shard / f"file_{index:05d}.rs").write_text(text)

    proc = start_sidecar(remote_root, state_dir)
    client = Client(proc)
    metrics = []

    elapsed, result = client.request("hello", {})
    record(metrics, "hello", elapsed, proc, {"remote_status": result.get("remote_status")})

    pages = 0
    scanned = 0
    after = None
    scan_start = time.perf_counter()
    while True:
        params = {"limit": scan_limit}
        if after:
            params["after"] = after
        _, result = client.request("scan", params)
        pages += 1
        scanned += len(result.get("entries") or [])
        after = result.get("next_after")
        if not result.get("truncated"):
            break
    record(
        metrics,
        "scan_all",
        (time.perf_counter() - scan_start) * 1000.0,
        proc,
        {"files": scanned, "pages": pages, "limit": scan_limit},
    )

    target = f"src/{(file_count // 2) // 1000:03d}/file_{file_count // 2:05d}.rs"
    elapsed, opened = client.request("open", {"path": target, "batch_max_file_bytes": 4 * 1024 * 1024})
    record(metrics, "open", elapsed, proc, {"path": target, "bytes": opened.get("size")})

    elapsed, grep = client.request(
        "grep",
        {
            "query": "needle",
            "limit": 100,
            "max_files": scan_limit,
            "max_file_bytes": 512 * 1024,
            "max_total_bytes": 8 * 1024 * 1024,
        },
    )
    record(metrics, "grep", elapsed, proc, {"hits": len(grep.get("hits") or []), "truncated": grep.get("truncated")})

    local_path = pathlib.Path(opened["local_path"])
    local_path.write_text("fn changed() {}\n")
    elapsed, flushed = client.request("flush", {"path": target})
    record(metrics, "flush", elapsed, proc, {"status": flushed.get("status")})
    client.shutdown()

    proc = start_sidecar(remote_root, state_dir)
    client = Client(proc)
    elapsed, status = client.request("status", {})
    record(metrics, "reconnect_status", elapsed, proc, {"known_files": status.get("known_files")})
    client.shutdown()

    print(json.dumps({"mode": mode, "file_count": file_count, "metrics": metrics}, indent=2, sort_keys=True))
finally:
    shutil.rmtree(tmp, ignore_errors=True)
PY
