# nvim-remote-mirror

`nvim-remote-mirror` is a local-first remote development prototype for Neovim.
It keeps editing and cached navigation local while a remote agent lazily reads,
searches, hashes, and writes files near the source tree.

Goal statement:

> Build `nvim-remote-mirror` into a local-first reusable remote workspace
> daemon, with Neovim as the first and only client for now, that keeps cached
> navigation, opening, status, and provisional search responsive even over
> slow, unstable, or offline SSH links by operating from a durable
> checksum-verified local mirror; lazily hydrates missing or intent-adjacent
> content in bounded prioritized batches; runs source-adjacent workflows such
> as LSP near the remote tree with correct local/remote path translation;
> preserves every local save through recoverable snapshots, checksum
> compare-and-swap uploads, retry queues, and explicit conflict reporting; and
> keeps the sidecar-agent protocol transport-neutral so SSH remains the default
> today while QUIC/UDP over WireGuard can be added later without changing
> client-facing behavior.

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
  future QUIC/UDP-over-WireGuard transport without changing client APIs.

## Current Shape

- `nrm-agent`: remote binary. Serves length-prefixed binary RPC on stdio.
- `nrm-sidecar`: local reusable remote workspace daemon. Starts the agent
  locally or through SSH, owns the local mirror and SQLite metadata, and exposes
  JSON-line RPC. Neovim is the only client today.
- `lua/nvim_remote_mirror`: Neovim client facade.

By default the Neovim facade launches one stdio sidecar process per editor
session. For a reusable endpoint, set `connection = "socket"`; Neovim will
connect to a Unix-domain sidecar listener or start one with the same JSON
command/notification protocol and durable workspace state.

This first implementation covers:

- SSH or local agent launch.
- lazy versioned hello/capability handshake on first remote agent request.
- request-id framed sidecar/agent RPC with typed remote errors.
- sidecar command responses plus optional server notifications for remote
  health changes.
- opt-in Unix-domain sidecar listener mode for a reusable daemon endpoint.
- fast local `workspace_info` daemon introspection with workspace paths,
  transport metadata, supported commands, notifications, and capabilities.
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
the remote is unreachable; status reports plugin connection state, pending
reconnect attempts or explicit disconnects, background metadata scan progress
or recent completion, and the last known remote health without probing SSH. The
first operation that needs the remote agent performs the protocol handshake and
reports connection failures normally.
Pending Neovim requests are also bounded by `request_timeout_ms`, so lost or
stalled sidecar replies clear their callback state instead of hanging forever.
If Neovim cannot write to the sidecar channel because the job has already
closed, the request fails immediately and reconnect handling starts without
waiting for that timeout.
When a Neovim-side timeout fires, the plugin sends a best-effort sidecar
cancel request so remote work that has not started yet is dropped from the
queue and no longer blocks cached reads for the same path. If the matching
request is active read-only work, such as `open`, `grep`, `validate`,
background scan, refresh, or prefetch, the sidecar preempts the serial
SSH/agent worker. Newer interactive remote requests can also supersede active
read-only/background work; `preempted` results are expected no-op responses.
Active save/flush work is not interrupted.

By default the plugin expects these binaries:

```text
target/debug/nrm-sidecar
target/debug/nrm-agent
```

Override them from Lua:

```lua
require("nvim_remote_mirror").setup({
  sidecar = "/path/to/nrm-sidecar",
  agent = "/path/to/local/nrm-agent",
  remote_agent = "nrm-agent",
  connection = "stdio",
  socket_path = nil,
  socket_dir = nil,
  daemon_start_timeout_ms = 1000,
  request_timeout_ms = 30000,
  ssh_connect_timeout_seconds = 10,
  find_limit = 200,
  grep_limit = 200,
  grep_remote_page_files = 512,
  grep_remote_max_file_bytes = 512 * 1024,
  grep_remote_max_total_bytes = 8 * 1024 * 1024,
  grep_cache_max_files = 2000,
  grep_cache_max_file_bytes = 512 * 1024,
  grep_cache_max_total_bytes = 8 * 1024 * 1024,
  open_batch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_file_bytes = 4 * 1024 * 1024,
  prefetch_max_total_bytes = 16 * 1024 * 1024,
  open_prefetch_related = false,
  open_prefetch_related_limit = 16,
  auto_hydrate_mirror_buffers = true,
  auto_reconnect = true,
  reconnect_delay_ms = 1000,
  reconnect_max_attempts = 3,
  reconnect_stable_ms = 10000,
  recover_local_edits_on_connect = true,
  recover_local_edits_limit = 256,
  flush_queue_on_connect = true,
  flush_queue_on_connect_delay_ms = 500,
  flush_queue_on_connect_limit = 1,
  background_mirror = true,
  background_mirror_interval_ms = 5000,
  background_mirror_rescan_interval_ms = 300000,
  background_mirror_scan_limit = 256,
  background_mirror_prefetch_limit = 4,
  background_mirror_refresh_limit = 32,
  background_mirror_max_file_bytes = 128 * 1024,
  background_mirror_max_total_bytes = 512 * 1024,
})
```

For `ssh://` targets, `remote_agent` is executed on the remote host. The local
`agent` path is used only for local targets, so a checkout-local
`target/debug/nrm-agent` is not accidentally sent to SSH hosts.
Set `connection = "socket"` to connect through a reusable Unix-domain sidecar
listener. If `socket_path` is unset, the plugin derives a stable path under
`socket_dir`, `state_dir/sockets`, or the system temp directory from the target
and daemon-affecting config. The listener is detached from Neovim and currently
serves one active client session at a time; `:RemoteDisconnect` closes the
client session but leaves the listener available for the next editor.

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

The proxy rewrites JSON LSP `file://` URI values, URI object keys such as
workspace-edit `changes`, and known path fields between the local mirror and the
remote workspace. It leaves unrelated prose strings alone and checks path
boundaries so similarly named sibling directories are not rewritten. Local
targets launch the language server with `remote_root` as the process working
directory; SSH targets launch through SSH with the configured connect timeout
and `cd` to `remote_root` before starting the language server.

## Save Recovery

Writes are preserved locally before any remote upload attempt. `:RemoteFlush`
creates a content-addressed snapshot in the workspace state directory, then
tries a remote compare-and-swap write. If the upload fails, `:RemoteStatus`
shows the queued or failed save counts, `:RemoteSaveQueue` lists pending,
failed, and conflicted saves from the local durable queue, and
`:RemoteFlushQueue` retries retryable entries.
If `:RemoteFlush` or automatic `BufWritePost` runs while disconnected, the path
is kept in memory and replayed after reconnect so the sidecar can snapshot the
already-written local mirror file. On reconnect the sidecar also runs a bounded
local recovery scan over hydrated mirror files. If Neovim saved a mirror file
while the sidecar was unavailable and then crashed before replay, changed local
bytes are snapshotted into the durable save queue before queued saves are
flushed. Tune this with `recover_local_edits_on_connect` and
`recover_local_edits_limit`, or call `recover_local_edits()` manually before
`flush_queue()`.
Remote buffers are tagged with the workspace that opened them. If you connect
to another target and save an older remote buffer, the plugin defers that save
instead of flushing the same relative path into the wrong workspace; it replays
when the original workspace is active again.

Saves up to 4 MiB use one RPC request. Larger saves stream through a 1 MiB
chunked compare-and-swap upload: the agent checks the remote base hash before
accepting chunks, verifies the uploaded content hash, rechecks the remote base
hash, then renames the temp file into place.
If a compare-and-swap conflict occurs, the local save snapshot stays preserved
as local truth. Small remote conflict copies are stored completely under
`conflicts/`; large remote conflict copies are capped to a protocol-bounded
prefix and reported with `remote_content_truncated`, `remote_size`, and
`remote_content_bytes` so a conflict cannot exceed the agent frame budget.

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

Direct uncached `:RemoteOpen` uses a single batched remote read for files at or
below `open_batch_max_file_bytes`, avoiding one SSH round trip per chunk on
high-latency links. Larger opens fall back to the chunked path. `:RemotePrefetch`
also uses a batched remote read request by default; files larger than
`prefetch_max_file_bytes` are skipped from that batch so explicit `:RemoteOpen`
can hydrate them through the chunked path. Both hydration paths write a
temporary mirror file, verify the full remote hash, re-check that the
destination is not dirty, and then atomically install the local file.

When `background_mirror` is enabled, the plugin starts a conservative idle
mirror builder after connect. Each tick probes the remote, scans the next
metadata cursor batch, and hydrates a small set of clean uncached metadata paths
through `prefetch_known`. It then validates a small batch of clean cached files
oldest-check first, so the mirror gradually checksums itself against the remote
without blocking navigation. The sidecar persists the background scan cursor in
the mirror database, so reconnects continue building metadata from the last
completed batch instead of restarting every scan from the root. Once a
resumable scan reaches the end, the completion timestamp is persisted and
`background_mirror_rescan_interval_ms` prevents the next idle ticks from
rewalking the full tree immediately. Use `:RemoteMirrorStart` and
`:RemoteMirrorStop` to control the scheduler manually on very slow links.

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
sidecar instead of opening an empty local path. Pending or failed hydrations are
kept read-only and are not treated as remote-save buffers, so an empty failed
hydrate cannot be flushed over the remote file.

`:RemoteFind [query]` searches known mirror metadata locally and fills quickfix
with mirror paths. Selecting an uncached result hydrates it through the same
mirror-buffer autohydration path, so path navigation remains useful while SSH is
slow or temporarily unavailable after metadata has been scanned.

`:RemoteGrep` queues the authoritative remote search first, then searches a
bounded slice of already hydrated local mirror files. Cached hits are
provisional and can populate quickfix while the remote search is still running.
Remote grep walks the tree in deterministic pages bounded by
`grep_remote_page_files`, `grep_remote_max_file_bytes`, and
`grep_remote_max_total_bytes`, so sparse or no-hit searches can refresh
quickfix progressively instead of waiting for one full remote tree pass or one
large log/generated file. Files above the per-file cap are skipped without
reading their contents, and the total byte cap stops the current page before it
can monopolize the SSH worker. Consecutive pages use a live agent continuation
session to avoid re-walking the same remote prefix; the path cursor is still
sent as a restart fallback if the SSH/agent session is lost. Each page hydrates
safe result files before it is merged into the displayed remote result.
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

Responses keep the same request ID:

```json
{"id":1,"ok":true,"result":{"path":"src/main.rs"}}
```

The sidecar may also emit notification lines without an `id`; clients can
consume or ignore them independently of command responses:

```json
{"method":"workspace/remote_health","params":{"workspace_key":"...","remote_status":"unavailable","remote_checked":true,"remote_available":false}}
```

Clients can call `workspace_info` immediately after starting the sidecar to get
the local workspace identity, mirror paths, transport kind, supported command
names, notification names, daemon capabilities, and last-known remote health.
Transport metadata includes a generic `kind`, `endpoint`,
`connect_timeout_ms`, and `agent_io`, while preserving SSH-specific aliases such
as `target` and `ssh_connect_timeout_seconds` for compatibility.
The legacy `commands` list reports every implemented method for compatibility.
New daemon clients should check `capabilities.command_metadata`, then prefer
`public_commands` for callable client API and `command_specs` for visibility
plus execution class (`local`, `remote`, `hybrid`, or `control`), remote lane,
mutation, fast-path, and preemption metadata. If the capability is absent, fall
back to `commands`. In this schema, `local` means no remote dependency; it does
not imply read-only or free. Internal helpers such as `flush_queued` remain
callable by the sidecar's own request rewriting path but are not listed as
public API. Compatibility aliases such as `hello` can still be public and
callable. Clients should ignore unknown `command_specs` fields so the daemon can
add transport metadata without changing the Neovim-facing protocol.
`capabilities.agent_abort_scope` is currently `lane_worker`: preemption and
shutdown abort and replace the active serial worker for that lane, ignore late
per-request replies from the replaced worker, and reset handshake state through
the same lifecycle as an SSH worker restart.
`workspace_info` is served from local state and does not start or probe SSH.
`hello` remains a compatibility alias for the same payload.

The reusable workspace daemon surface is this command/response plus
notification protocol. The current LSP proxy is an optional Neovim integration
helper for forwarding one language-server stdio session; it is not required for
generic mirror clients and should not be expanded into a second mirror-control
API.

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

Workspace state keys intentionally preserve the legacy identity material:
`local` for local workspaces and the bare SSH target string for SSH workspaces.
That keeps existing mirrors stable, including the historical collision between
local workspaces and an SSH target literally named `local`. Future non-SSH
transports must define namespaced identity material before sharing durable
mirror state.

Current transport state:

- active: request IDs, typed remote errors, request timeout, SSH connect timeout,
  cursor-based scan, session-backed remote grep continuation, batched small-file
  read for direct opens and prefetch, batched mirror
  validation, chunked compare-and-swap writes, and sidecar fast-path responses for cached mirror
  opens/status while remote worker requests are in flight. Neovim-side JSON RPC
  requests also use the configured request timeout to clean up pending callbacks
  when a sidecar reply is lost. Sidecar response delivery applies backpressure
  instead of dropping completed replies when the writer is saturated, and the
  same ordered writer carries optional workspace notifications. Sidecar
  startup is local-mirror-only; the remote agent handshake is lazy so cached
  work survives disconnected SSH. Failed remote attempts enter a capped adaptive
  unavailable backoff per lane, so repeated remote-dependent commands fail
  quickly and fragile links are not retried aggressively while cached operations
  stay local. Disconnect interrupts
  the current agent/SSH process group on Unix so shutdown is not pinned to the
  normal request timeout. Deferred sidecar work uses separate interactive and
  background queues so explicit opens/saves are not rejected by, or drained
  behind, queued prefetch, scan, or refresh work. Remote execution is split into
  read and write lanes with separate agent sessions, so unrelated opens, grep,
  validation, and probes can continue while save/flush work is in flight; reads
  that could conflict with pending writes are routed through the write lane to
  preserve ordering. Lane backoff is also separated, so a failed background
  scan, grep, or probe does not immediately reject write-lane save replay;
  status still reports the latest lane error. Active background maintenance
  requests and read-only remote work can be preempted by newer interactive work
  or explicit cancellation by restarting that lane's serial SSH/agent worker;
  `preempted` responses are normal no-op client results, and save/flush
  requests are not preempted once started.
  Agent and LSP launches share a transport command planner. Sidecar request
  scheduling exchanges agent frames through an AgentSession abstraction and
  interrupts active work through an abort-handle boundary. Stdio-backed
  local/SSH child processes are the current session and abort implementation. A
  future QUIC or UDP over WireGuard session must provide reliable ordered
  delivery per lane, preserve matching request IDs, honor today's serial request
  semantics unless multiplexing is explicitly added, surface
  timeout/backoff-compatible errors, and expose an abort path equivalent to
  restarting the current lane worker. A future non-process transport should add
  a session factory that returns the AgentSession and AgentAbortHandle pair for a
  lane while preserving the same `lane_worker` abort scope.
  Timed-out Neovim requests send a best-effort sidecar cancellation for queued
  remote work, clearing pending path hazards before that work reaches SSH, and
  can preempt matching active read-only/background work. Active save/flush work
  still runs to completion once started.
- pending: true multiplexing within a single transport session, streaming
  results, and transport-level flow control.
