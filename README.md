# nvim-remote-mirror

`nvim-remote-mirror` is a local-first remote workspace prototype for Neovim.
It keeps navigation and editing on a local mirror while a small remote agent
reads, searches, checksums, and writes files near the source tree.

The default transport is SSH. Socket sidecar mode is recommended for daily use
because the local daemon can survive editor reconnects and reuse durable mirror
state.

## Status

This is dogfooding software. It is useful for testing the remote mirror model,
but it is not a polished replacement for SSHFS or VS Code Remote yet.

| Area | State |
| --- | --- |
| Local and SSH workspaces | Working |
| Local mirror open/find/grep | Working |
| Save queue and conflicts | Working |
| Socket sidecar mode | Working, one active Neovim client |
| Remote LSP proxy | Basic |
| Terminals, DAP, plugin remoting | Not built |
| Non-SSH transports | Not built |

## Requirements

| Tool | Where | Notes |
| --- | --- | --- |
| Neovim 0.10+ | local | Neovim 0.11+ is preferred |
| Rust toolchain | local | Builds `nrm-sidecar` and `nrm-agent` |
| SSH | local and remote | Used for `ssh://host/path` targets |
| `nrm-agent` | remote | Must be executable on the remote host |

## Install

Build the local binaries:

```sh
cargo build --release
```

Install the remote agent on each remote host:

```sh
scp target/release/nrm-agent myhost:~/.local/bin/nrm-agent
ssh myhost 'chmod +x ~/.local/bin/nrm-agent'
```

Add the plugin from a local checkout:

```lua
{
  dir = vim.fn.expand("~/repos/nvim-remote-mirror"),
  name = "nvim-remote-mirror",
  config = function()
    require("nvim_remote_mirror").setup({
      sidecar = vim.fn.expand("~/repos/nvim-remote-mirror/target/release/nrm-sidecar"),
      agent = vim.fn.expand("~/repos/nvim-remote-mirror/target/release/nrm-agent"),
      remote_agent = "nrm-agent",
      connection = "socket",
    })
  end,
}
```

For early testing from this repo, you can also start Neovim with the checkout
on `runtimepath`:

```sh
nvim --cmd "set rtp+=/path/to/nvim-remote-mirror"
```

## Quick Start

Open the dashboard:

```vim
:RemoteWorkspace
```

Connect to a remote workspace:

```vim
:RemoteConnect ssh://myhost/home/me/project
```

Use the UI commands for normal work:

| Command | Purpose |
| --- | --- |
| `:RemoteWorkspace` | Open the workspace dashboard |
| `:RemoteConnectUI` | Prompt for a target and connect |
| `:RemoteFiles` | Search known remote paths and open one |
| `:RemoteGrepUI` | Prompt for grep text and run remote grep |
| `:RemoteQueue` | Inspect queued saves |
| `:RemoteConflicts` | Inspect save conflicts |

Dashboard keys:

| Key | Action |
| --- | --- |
| `c` | Connect |
| `o` | Open remote path |
| `f` | Find file |
| `g` | Grep |
| `s` | Save queue |
| `C` | Conflicts |
| `r` | Refresh dashboard |
| `R` | Reconnect |
| `d` | Disconnect |
| `q` / `x` | Close dashboard |

## Command Reference

| Command | Purpose |
| --- | --- |
| `:RemoteConnect [target]` | Connect to local path or `ssh://host/absolute/path` |
| `:RemoteDisconnect` | Close the current client session |
| `:RemoteReconnect` | Reconnect to the last target |
| `:RemoteOpen {path}` | Open a workspace-relative file |
| `:RemoteOpen! {path}` | Force remote rehydrate for clean cached files |
| `:RemoteFind [query]` | Put known remote paths in quickfix |
| `:RemoteGrep {query}` | Search remote and cached mirror files |
| `:RemotePrefetch {path...}` | Hydrate files into the mirror |
| `:RemoteStatus` | Print a status summary |
| `:RemoteSaveQueue [limit]` | Put queued saves in quickfix |
| `:RemoteFlush` | Flush current remote buffer |
| `:RemoteFlushQueue` | Retry queued saves |
| `:RemoteValidate [path]` | Compare cached file metadata with remote hash |
| `:RemoteRefresh [path...]` | Validate cached files in batches |
| `:RemoteMirrorStart` | Start background mirror building |
| `:RemoteMirrorStop` | Stop background mirror building |

## Common Configuration

| Option | Default | Use |
| --- | --- | --- |
| `connection` | `"stdio"` | Set to `"socket"` for reusable sidecar mode |
| `remote_agent` | `"nrm-agent"` | Remote command run over SSH |
| `request_timeout_ms` | `30000` | Neovim-to-sidecar request timeout |
| `ssh_connect_timeout_seconds` | `10` | SSH connection timeout |
| `find_limit` | `200` | Max file picker results |
| `grep_limit` | `200` | Max grep results |
| `open_prefetch_related` | `false` | Prefetch nearby known files after open |
| `background_mirror` | `true` | Gradually scan, hydrate, and validate in idle batches |

See [docs/configuration.md](docs/configuration.md) for the larger option list.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `not connected` | Run `:RemoteWorkspace` or `:RemoteConnect ...` |
| SSH target fails | Confirm `ssh myhost` works without prompts |
| Remote agent missing | Confirm `ssh myhost 'command -v nrm-agent'` |
| Opens are stale | Use `:RemoteValidate` or `:RemoteOpen! path` |
| Saves are queued | Open `:RemoteQueue`, then retry with `:RemoteFlushQueue` |
| Save conflict | Open `:RemoteConflicts` and inspect local vs remote copy |
| UI feels empty | Run `:RemoteScan` or leave background mirror enabled |

## More Docs

| Doc | Contents |
| --- | --- |
| [docs/design.md](docs/design.md) | Goal, architecture, and next milestones |
| [docs/configuration.md](docs/configuration.md) | Configuration options |
| [docs/save-recovery.md](docs/save-recovery.md) | Save queue and conflict behavior |
| [docs/protocol.md](docs/protocol.md) | Sidecar and agent protocol notes |
| [doc/nvim-remote-mirror.txt](doc/nvim-remote-mirror.txt) | Vim help |
