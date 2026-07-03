# Architecture User Stories

This backlog turns the current design review risks into implementation-sized
user stories. Each story includes a code example that shows the intended shape,
not a required exact patch.

## 1. Split Sidecar Internals

**User story:** As a maintainer, I want `nrm-sidecar` split into focused modules
so queueing, mirror DB, agent IO, saves, and LSP changes can be reviewed
independently.

**Acceptance criteria:**

- No behavior change.
- `crates/nrm-sidecar/src/main.rs` becomes orchestration-heavy rather than
  implementation-heavy.
- Existing tests still pass with `just check`.

**Status:** Started. Pure LSP JSON/path rewriting now lives in
`crates/nrm-sidecar/src/lsp_rewrite.rs`. Larger follow-up extractions should
target mirror DB, agent client, remote queue, save queue, and server session
code separately.

**Code example:**

```rust
mod agent_client;
mod lsp_proxy;
mod mirror;
mod remote_queue;
mod save_queue;
mod server;

fn main() -> anyhow::Result<()> {
    server::run_cli()
}
```

## 2. Add Remote Queue Race Coverage

**User story:** As a remote editor user, I want opens and saves to stay correct
while background scan/prefetch/refresh runs so background work never corrupts or
delays foreground edits.

**Acceptance criteria:**

- Tests cover interactive `open` preempting background hydration.
- Tests cover `flush` routing through the write lane when a conflicting
  background read is pending.
- Tests cover background `flush_queue` not blocking cached clean opens.

**Status:** Implemented with focused sidecar queue regression coverage.

**Code example:**

```rust
#[test]
fn interactive_open_preempts_conflicting_background_prefetch() {
    let queue = RemoteQueue::new(8, 8);
    let preempt = AgentPreempt::default();

    queue.try_push(test_remote_work(1, "prefetch"), Some(&preempt)).unwrap();
    queue.try_push(test_remote_work(2, "open"), Some(&preempt)).unwrap();

    assert_eq!(preempt.epoch(), 1);
    assert_eq!(queue.pop().unwrap().request.id, 2);
}
```

## 3. Define Multi-Client Socket Semantics

**User story:** As a user with multiple Neovim instances, I want socket sidecar
mode to reject or coordinate additional clients explicitly so two editors cannot
accidentally race on the same mirror state.

**Acceptance criteria:**

- `workspace_info` exposes the current socket client policy.
- Docs state that socket sessions are sequential single-writer sessions.
- Future multi-client work has a stable field to extend.

**Status:** Implemented with `workspace_info.client_mode`,
`workspace_info.client_policy`, and `capabilities.single_writer_sessions`.

**Code example:**

```json
{
  "client_mode": "single_writer",
  "client_policy": {
    "mode": "single_writer",
    "concurrency": "sequential",
    "write_owner": "current_session"
  }
}
```

## 4. Harden LSP Path Rewriting

**User story:** As a user running remote LSP, I want path and URI rewriting to
be conservative so valid LSP locations are translated without rewriting normal
prose or unrelated strings.

**Acceptance criteria:**

- Tests cover `uri`, `targetUri`, workspace edit map keys, `rootPath`, and
  plain message strings.
- Rewriter only rewrites file URI strings or path-like keys.
- Boundary behavior is tested for `/repo` vs `/repository`.

**Status:** Implemented with additional target URI, workspace edit, prose, and
boundary regression coverage.

**Code example:**

```rust
#[test]
fn lsp_rewrite_does_not_touch_prose_strings() {
    let body = br#"{
      "params": {
        "message": "/local/mirror appears in prose",
        "textDocument": {"uri": "file:///local/mirror/src/main.rs"}
      }
    }"#;

    let rewritten = rewrite_lsp_body(body, "/local/mirror", "/remote/repo").unwrap();
    let value: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();

    assert_eq!(value["params"]["message"], "/local/mirror appears in prose");
    assert_eq!(value["params"]["textDocument"]["uri"], "file:///remote/repo/src/main.rs");
}
```

## 5. Tighten Protocol Compatibility

**User story:** As a developer changing the agent boundary, I want protocol
version and capability negotiation tests so sidecar and agent fail clearly when
their wire contracts diverge.

**Acceptance criteria:**

- Protocol changes require round-trip tests in `nrm-protocol`.
- Incompatible request/response changes bump `PROTOCOL_VERSION`.
- Sidecar surfaces version mismatch as remote unavailable, not as a vague
  transport failure.

**Status:** Implemented with agent hello mismatch coverage and sidecar remote
health/backoff coverage for protocol mismatch probe failures.

**Code example:**

```rust
#[test]
fn hello_rejects_incompatible_protocol_version() {
    let mut state = test_state(tempdir().unwrap().path());

    let err = handle_request(&mut state, Request::Hello {
        client_version: "test".into(),
        protocol_version: PROTOCOL_VERSION + 1,
    })
    .unwrap_err()
    .to_string();

    assert!(err.contains("protocol version mismatch"));
}
```
