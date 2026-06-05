# nvim-remote-mirror

`nvim-remote-mirror` is a local-first remote development prototype for Neovim.
It keeps editing and cached navigation local while a remote agent lazily reads,
searches, hashes, and writes files near the source tree.

Goal statement:

> Make Neovim feel local over slow or unstable SSH links by gradually building a
> checksum-verified local mirror, lazily hydrating content by user intent, and
> using conflict-safe asynchronous saves against the remote workspace.

## Current Shape

- `nrm-agent`: remote binary. Serves length-prefixed binary RPC on stdio.
- `nrm-sidecar`: local binary. Starts the agent locally or through SSH, owns the
  local mirror and SQLite metadata, and exposes JSON-line RPC for Neovim.
- `lua/nvim_remote_mirror`: Neovim plugin facade.

This first implementation covers:

- SSH or local agent launch.
- versioned hello/capability handshake.
- request-id framed sidecar/agent RPC with typed remote errors.
- configurable request and SSH connect timeouts.
- remote scan.
- lazy file open/hydration into a local mirror with dirty/stale cached opens.
- batched prefetch hydration with per-file and total byte caps.
- batched mirror refresh to mark cached files valid, stale, or deleted.
- remote grep that batch-hydrates result files for local quickfix jumps.
- durable local save snapshots with checksum-aware flush/retry and conflict detection.
- chunked compare-and-swap uploads for large remote saves.
- basic Neovim commands.
- basic LSP stdio proxying with local/remote path translation.

Remote terminals, DAP, plugin remoting, and non-SSH transports are intentionally
left behind the same sidecar boundary for later work.

## Build

```sh
cargo build
```

## Run Locally

Start Neovim with the plugin on `runtimepath`:

```sh
nvim --cmd 'set rtp+=/path/to/nvim-remote-mirror'
```

Then connect to a local workspace:

```vim
:RemoteConnect /path/to/workspace
:RemoteOpen README.md
:RemoteGrep main
:RemoteStatus
```

Or connect through SSH:

```vim
:RemoteConnect ssh://myhost/home/me/project
```

If the sidecar exits unexpectedly, the plugin fails pending callbacks and can
reconnect to the last target with capped retries. Use `:RemoteReconnect` to
resume the last target manually; reconnect startup reuses the durable mirror and
retries queued saves.

By default the plugin expects these binaries:

```text
target/debug/nrm-sidecar
target/debug/nrm-agent
```

Override them from Lua:

```lua
require("nvim_remote_mirror").setup({
  sidecar = "/path/to/nrm-sidecar",
  agent = "/path/to/nrm-agent",
  request_timeout_ms = 30000,
  ssh_connect_timeout_seconds = 10,
  prefetch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_total_bytes = 16 * 1024 * 1024,
  open_prefetch_related = false,
  open_prefetch_related_limit = 16,
  auto_reconnect = true,
  reconnect_delay_ms = 1000,
  reconnect_max_attempts = 3,
  reconnect_stable_ms = 10000,
})
```

## LSP Proxy

After connecting, build a Neovim LSP config from a remote language-server
command:

```lua
local nrm = require("nvim_remote_mirror")
nrm.connect("ssh://myhost/home/me/project")

-- Run rust-analyzer on the remote host, while Neovim sees local mirror paths.
vim.defer_fn(function()
  vim.lsp.start(nrm.lsp_client_config({ "rust-analyzer" }, {
    name = "remote-rust-analyzer",
  }))
end, 500)
```

The proxy rewrites JSON LSP `file://` URI and absolute path prefixes between
the local mirror and the remote workspace.

## Save Recovery

Writes are preserved locally before any remote upload attempt. `:RemoteFlush`
creates a content-addressed snapshot in the workspace state directory, then
tries a remote compare-and-swap write. If the upload fails, `:RemoteStatus`
shows the queued or failed save and `:RemoteFlushQueue` retries it.

Small saves use one RPC request. Large saves stream through a chunked
compare-and-swap upload: the agent checks the remote base hash before accepting
chunks, verifies the uploaded content hash, rechecks the remote base hash, then
renames the temp file into place.

Use `:RemoteValidate [path]` to compare cached mirror metadata with the remote
hash. Stale cached files are marked in the mirror and opened from cache by
default; use `:RemoteOpen!` to force a remote rehydrate when you intentionally
want to replace a clean cached copy.

Use `:RemoteRefresh [path...]` to validate many cached files in one remote
request. Without arguments it refreshes a batch of clean cached files from the
local mirror, oldest validation first.

`:RemotePrefetch` uses a batched remote read request by default. Files larger
than `prefetch_max_file_bytes` are skipped from the batch so explicit
`:RemoteOpen` can hydrate them through the chunked path.

`:RemoteOpen` prefers an existing clean or dirty local mirror file, including
entries previously marked stale or deleted, so navigation does not block on a
slow or unreachable remote. `:RemoteOpen!` forces a remote rehydrate for clean
cached files. Dirty cached files are never overwritten by force; if their local
file is missing, the sidecar restores the latest queued save snapshot instead.
After opening, the plugin can issue an opt-in small related-file prefetch from
existing mirror metadata, prioritizing same-directory and same-extension files.
Enable that with `open_prefetch_related = true` and tune the batch with
`open_prefetch_related_limit`.

`:RemoteGrep` runs search on the remote agent, batch-hydrates matching files
within the prefetch byte caps, and populates quickfix with local mirror paths
when hydration succeeds.

## Protocol Notes

Neovim talks to the sidecar through newline-delimited JSON:

```json
{"id":1,"method":"open","params":{"path":"src/main.rs"}}
```

The sidecar talks to the agent using a 4-byte big-endian length prefix followed
by a bincode-encoded `RpcMessage`. Every request has a request ID and every
agent reply carries the matching ID. That boundary is transport-agnostic, so a
future QUIC/UDP transport over WireGuard can replace SSH without changing the
mirror model.

Current transport state:

- active: request IDs, typed remote errors, request timeout, SSH connect timeout,
  batched small-file read for prefetch, batched mirror validation, chunked
  compare-and-swap writes, and sidecar fast-path responses for cached mirror
  opens/status while remote worker requests are in flight. Disconnect interrupts
  the current agent/SSH process group on Unix so shutdown is not pinned to the
  normal request timeout. Deferred sidecar work uses separate interactive and
  background queues so explicit opens/saves are not rejected by, or drained
  behind, queued prefetch, scan, or refresh work. Active background maintenance
  requests can be preempted by interactive work by restarting the serial
  SSH/agent worker; save and explicit interactive requests are not preempted.
- pending: general per-request cancellation, true multiplexing, streaming
  results, and broader backpressure.
