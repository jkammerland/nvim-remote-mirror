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
- lazy file open/hydration into a local mirror.
- batched prefetch hydration with per-file and total byte caps.
- remote grep with streamed-style result payloads.
- durable local save snapshots with checksum-aware flush/retry and conflict detection.
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

Use `:RemoteValidate [path]` to compare cached mirror metadata with the remote
hash. Stale cached files are marked in the mirror and rehydrated on the next
open instead of being treated as silently valid.

`:RemotePrefetch` uses a batched remote read request by default. Files larger
than `prefetch_max_file_bytes` are skipped from the batch so explicit
`:RemoteOpen` can hydrate them through the chunked path.

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
  batched small-file read for prefetch.
- pending: true multiplexing, cancellation, streaming results, reconnect resume,
  and backpressure.
