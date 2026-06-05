# nvim-remote-mirror

`nvim-remote-mirror` is a local-first remote development prototype for Neovim.
It keeps editing and cached navigation local while a remote agent lazily reads,
searches, hashes, and writes files near the source tree.

Goal statement:

> Build `nvim-remote-mirror` into a local-first Neovim remote workspace system
> that keeps cached navigation, opening, status, and provisional search
> responsive even over slow, unstable, or offline SSH links by operating from a
> durable checksum-verified local mirror; lazily hydrates missing or
> intent-adjacent content in bounded prioritized batches; runs source-adjacent
> workflows such as LSP near the remote tree with correct local/remote path
> translation; preserves every local save through recoverable snapshots,
> checksum compare-and-swap uploads, retry queues, and explicit conflict
> reporting; and keeps the sidecar-agent protocol transport-neutral so SSH
> remains the default today while QUIC/UDP over WireGuard can be added later
> without changing Neovim-facing behavior.

Completion criteria:

- cached open, status, and provisional grep do not wait on SSH availability.
- remote-dependent work is bounded by configured timeouts, backoff, and
  interactive/background prioritization.
- mirror entries are validated by checksums and classified as valid, stale,
  deleted, dirty, queued, or conflicted.
- missing and related files hydrate lazily in size-capped batches, with durable
  progress that can resume after disconnects.
- saves are snapshotted before remote upload and can be replayed or reported as
  conflicts without losing local edits.
- LSP and later source-adjacent tools run near the remote source while exposing
  local mirror paths to Neovim.
- the transport boundary is narrow enough that SSH stdio can be replaced by a
  future QUIC/UDP-over-WireGuard transport without changing plugin APIs.

## Current Shape

- `nrm-agent`: remote binary. Serves length-prefixed binary RPC on stdio.
- `nrm-sidecar`: local binary. Starts the agent locally or through SSH, owns the
  local mirror and SQLite metadata, and exposes JSON-line RPC for Neovim.
- `lua/nvim_remote_mirror`: Neovim plugin facade.

This first implementation covers:

- SSH or local agent launch.
- lazy versioned hello/capability handshake on first remote agent request.
- request-id framed sidecar/agent RPC with typed remote errors.
- configurable request and SSH connect timeouts.
- remote scan.
- lazy file open/hydration into a local mirror with dirty/stale cached opens.
- batched prefetch hydration with per-file and total byte caps.
- cursor-based background mirror scan and known-file prefetch in small
  preemptible batches.
- batched mirror refresh to mark cached files valid, stale, or deleted.
- remote grep that batch-hydrates result files for local quickfix jumps.
- persisted local line/trigram index for faster provisional cached grep.
- local mirror rehash before cached reads or batch overwrites, with
  out-of-band local edits snapshotted and queued as dirty saves.
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
:RemoteFind readme
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
retries queued saves in small background batches after a remote probe succeeds.
If a remote buffer is saved while the sidecar is unavailable, the plugin marks
that path for replay and asks the next sidecar session to flush the saved local
mirror file into the durable queue.

`:RemoteConnect` starts from the durable local mirror and does not block on an
SSH agent handshake. Cached opens, cached grep, and status remain available if
the remote is unreachable; status also reports the last known remote health
without probing SSH. The first operation that needs the remote agent performs
the protocol handshake and reports connection failures normally.
Pending Neovim requests are also bounded by `request_timeout_ms`, so lost or
stalled sidecar replies clear their callback state instead of hanging forever.
When a Neovim-side timeout fires, the plugin sends a best-effort sidecar
cancel request so remote work that has not started yet is dropped from the
queue and no longer blocks cached reads for the same path.

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
  find_limit = 200,
  grep_limit = 200,
  grep_cache_max_files = 2000,
  grep_cache_max_file_bytes = 512 * 1024,
  grep_cache_max_total_bytes = 8 * 1024 * 1024,
  prefetch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_total_bytes = 16 * 1024 * 1024,
  open_prefetch_related = false,
  open_prefetch_related_limit = 16,
  auto_hydrate_mirror_buffers = true,
  auto_reconnect = true,
  reconnect_delay_ms = 1000,
  reconnect_max_attempts = 3,
  reconnect_stable_ms = 10000,
  flush_queue_on_connect = true,
  flush_queue_on_connect_delay_ms = 500,
  flush_queue_on_connect_limit = 1,
  background_mirror = true,
  background_mirror_interval_ms = 5000,
  background_mirror_scan_limit = 256,
  background_mirror_prefetch_limit = 4,
  background_mirror_refresh_limit = 32,
  background_mirror_max_file_bytes = 128 * 1024,
  background_mirror_max_total_bytes = 512 * 1024,
})
```

## LSP Proxy

After connecting, start a remote language server through the probe-gated helper:

```lua
local nrm = require("nvim_remote_mirror")
nrm.connect("ssh://myhost/home/me/project")

-- Run rust-analyzer on the remote host, while Neovim sees local mirror paths.
nrm.start_lsp({ "rust-analyzer" }, {
  name = "remote-rust-analyzer",
})
```

`start_lsp()` probes the remote first, refreshes the cached remote status, and
skips `vim.lsp.start()` when SSH is still in backoff or unavailable. If you need
manual control, `lsp_client_config()` remains available as the low-level config
builder once the remote is reachable.

The proxy rewrites JSON LSP `file://` URI and absolute path prefixes between
the local mirror and the remote workspace. Local targets launch the language
server with `remote_root` as the process working directory; SSH targets launch
through SSH with the configured connect timeout and `cd` to `remote_root` before
starting the language server.

## Save Recovery

Writes are preserved locally before any remote upload attempt. `:RemoteFlush`
creates a content-addressed snapshot in the workspace state directory, then
tries a remote compare-and-swap write. If the upload fails, `:RemoteStatus`
shows the queued or failed save and `:RemoteFlushQueue` retries it.
If `:RemoteFlush` or automatic `BufWritePost` runs while disconnected, the path
is kept in memory and replayed after reconnect so the sidecar can snapshot the
already-written local mirror file.

Small saves use one RPC request. Large saves stream through a chunked
compare-and-swap upload: the agent checks the remote base hash before accepting
chunks, verifies the uploaded content hash, rechecks the remote base hash, then
renames the temp file into place.

Before cached opens, cached grep, validation, or batch hydration overwrites use
an existing local mirror file, the sidecar rehashes the local bytes against the
recorded mirror hash. If the file changed outside the normal save path, the
current bytes are snapshotted, queued as a dirty save, and served as local truth
instead of being reported as a clean cache hit or overwritten by background
hydration.

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

When `background_mirror` is enabled, the plugin starts a conservative idle
mirror builder after connect. Each tick probes the remote, scans the next
metadata cursor batch, and hydrates a small set of clean uncached metadata paths
through `prefetch_known`. It then validates a small batch of clean cached files
oldest-check first, so the mirror gradually checksums itself against the remote
without blocking navigation. Use `:RemoteMirrorStart` and `:RemoteMirrorStop`
to control the scheduler manually on very slow links.

`:RemoteOpen` prefers an existing clean or dirty local mirror file, including
entries previously marked stale or deleted, so navigation does not block on a
slow or unreachable remote. `:RemoteOpen!` forces a remote rehydrate for clean
cached files. Dirty cached files are never overwritten by force; if their local
file is missing, the sidecar restores the latest queued save snapshot instead.
After opening, the plugin can issue an opt-in small related-file prefetch from
existing mirror metadata, prioritizing same-directory and same-extension files.
Enable that with `open_prefetch_related = true` and tune the batch with
`open_prefetch_related_limit`.

When `auto_hydrate_mirror_buffers` is enabled, Neovim edits under the local
mirror root are mapped back to workspace-relative remote paths. This lets LSP
definition/reference jumps into not-yet-cached mirror files hydrate through the
sidecar instead of opening an empty local path.

`:RemoteFind [query]` searches known mirror metadata locally and fills quickfix
with mirror paths. Selecting an uncached result hydrates it through the same
mirror-buffer autohydration path, so path navigation remains useful while SSH is
slow or temporarily unavailable after metadata has been scanned.

`:RemoteGrep` queues the authoritative remote search first, then searches a
bounded slice of already hydrated local mirror files. Cached hits are
provisional and can populate quickfix while the remote search is still running.
The cached search uses a persisted SQLite line index, plus byte trigrams for
literal queries of at least three bytes, and verifies matches in Rust so
case-sensitive literal behavior and byte-based columns stay stable. Dirty saves
and out-of-band local edits update the index from the exact local bytes.
The final quickfix refresh uses only safe local mirror paths from the remote
result, preserving dirty cached matches as local truth.

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

Agent and LSP process creation goes through the same transport command planner:
local targets spawn the requested binary directly, while SSH targets use the
configured connection options and a single shell-quoted remote command. This
keeps SSH-specific launch details outside the Neovim-facing JSON API and the
agent protocol frame format.

Current transport state:

- active: request IDs, typed remote errors, request timeout, SSH connect timeout,
  cursor-based scan, batched small-file read for prefetch, batched mirror
  validation, chunked compare-and-swap writes, and sidecar fast-path responses for cached mirror
  opens/status while remote worker requests are in flight. Neovim-side JSON RPC
  requests also use the configured request timeout to clean up pending callbacks
  when a sidecar reply is lost. Sidecar response delivery applies backpressure
  instead of dropping completed replies when the writer is saturated. Sidecar
  startup is local-mirror-only; the remote agent handshake is lazy so cached
  work survives disconnected SSH. Failed remote attempts enter a short
  unavailable backoff so repeated remote-dependent commands fail quickly while
  cached operations stay local. Disconnect interrupts
  the current agent/SSH process group on Unix so shutdown is not pinned to the
  normal request timeout. Deferred sidecar work uses separate interactive and
  background queues so explicit opens/saves are not rejected by, or drained
  behind, queued prefetch, scan, or refresh work. Active background maintenance
  requests can be preempted by interactive work by restarting the serial
  SSH/agent worker; save and explicit interactive requests are not preempted.
  Agent and LSP launches share a transport command planner, keeping SSH stdio as
  a replaceable implementation detail behind the sidecar-agent frame boundary.
  Timed-out Neovim requests send a best-effort sidecar cancellation for queued
  remote work, clearing pending path hazards before that work reaches SSH.
- pending: active in-flight agent cancellation, true multiplexing, streaming
  results, and transport-level flow control.
