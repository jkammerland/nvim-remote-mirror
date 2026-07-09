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
| Remote agent health/install/update | Explicit commands |
| Remote LSP proxy | Basic |
| Remote git status/diff/blame | Basic |
| Terminals, DAP, plugin remoting | Not built |
| Non-SSH transports | Not built |

## Requirements

| Tool | Where | Notes |
| --- | --- | --- |
| Neovim 0.10+ | local | Neovim 0.11+ is preferred |
| Rust toolchain | local | Builds `nrm-sidecar` and `nrm-agent` |
| SSH | local and remote | Used for `ssh://host/path` targets |
| `nrm-agent` | remote | Must be executable on the remote host; can be installed with `:RemoteInstallAgent` |

## Install

Build the local binaries:

```sh
cargo build --release
```

Install the remote agent on each remote host manually:

```sh
scp target/release/nrm-agent myhost:~/.local/bin/nrm-agent
ssh myhost 'chmod +x ~/.local/bin/nrm-agent'
```

Or connect and run an explicit repair command from Neovim:

```vim
:RemoteConnect ssh://myhost/home/me/project
:RemoteHealth
:RemoteInstallAgent
```

The plugin does not silently install or update the remote agent during connect.
`:RemoteInstallAgent[!]` and `:RemoteUpdateAgent[!]` upload the configured local
`agent` binary to the remote host over SSH. For a bare `remote_agent =
"nrm-agent"`, the managed install path defaults to
`$HOME/.local/bin/nrm-agent`, and SSH launches prepend `$HOME/.local/bin` to
`PATH` so non-interactive sessions can find it.

Non-interactive SSH often skips shell startup files. If this fails:

```sh
ssh myhost 'command -v nrm-agent'
```

set `remote_agent` to an absolute remote path such as
`/home/me/.local/bin/nrm-agent`.

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

For cwd-based local plugins, switch the current tab to the mirror files root:

```vim
:RemoteCd
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
| `z` | Set current tab cwd to the mirror files root |
| `h` | Check remote agent health |
| `s` | Save queue |
| `C` | Conflicts |
| `F` | Flush queued saves |
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
| `:RemoteCd` | Set the current tab cwd to the mirror files root |
| `:RemoteOpen {path}` | Open a workspace-relative file |
| `:RemoteOpen! {path}` | Force remote rehydrate for clean cached files |
| `:RemoteScan [limit]` | Scan remote metadata into the local mirror index |
| `:RemoteFind [query]` | Put known remote paths in quickfix |
| `:RemoteGrep {query}` | Search remote and cached mirror files |
| `:RemotePrefetch {path...}` | Hydrate files into the mirror |
| `:RemoteStatus` | Print a status summary |
| `:RemoteHealth` | Probe remote agent health and compatibility |
| `:RemoteInstallAgent[!] [path]` | Upload the local `agent` binary to the remote host |
| `:RemoteUpdateAgent[!] [path]` | Replace the remote agent when health reports mismatch |
| `:RemoteGitStatus [path...]` | Put remote git status entries in quickfix |
| `:RemoteGitDiff [path]` | Open a remote git diff scratch buffer |
| `:RemoteGitBlame [path]` | Put remote git blame output in quickfix |
| `:RemoteLspStart {cmd...}` | Start a simple remote LSP command |
| `:RemoteLspStop` | Stop active remote LSP clients for the current workspace |
| `:RemoteLspRestart [cmd...]` | Restart the last or provided remote LSP command |
| `:RemoteLspStatus` | Print remote LSP client/status details |
| `:RemoteSaveQueue [limit]` | Put queued saves in quickfix |
| `:RemoteFlush` | Flush current remote buffer |
| `:RemoteAdopt [path]` | Explicitly create or take over a new mirror-root path |
| `:RemoteFlushQueue` | Retry queued saves |
| `:RemoteAcceptLocalConflict {queue_id}` | Resolve the latest conflict by uploading its saved local snapshot |
| `:RemoteAcceptRemoteConflict {queue_id}` | Resolve the latest conflict by discarding local queued bytes for the full saved remote copy |
| `:RemoteValidate [path]` | Compare cached file metadata with remote hash |
| `:RemoteRefresh [path...]` | Validate cached files in batches |
| `:RemoteMirrorStart` | Start background mirror building |
| `:RemoteMirrorStop` | Stop background mirror building |

## Common Configuration

| Option | Default | Use |
| --- | --- | --- |
| `connection` | `"stdio"` | Set to `"socket"` for reusable sidecar mode |
| `state_dir` | `nil` | Durable mirror state root; default is Neovim state data |
| `agent` | local checkout/debug path or `"nrm-agent"` | Local agent and SSH upload source |
| `remote_agent` | `"nrm-agent"` | Remote command run over SSH |
| `remote_agent_install_path` | `nil` | Optional default remote path for `:RemoteInstallAgent` and `:RemoteUpdateAgent` |
| `request_timeout_ms` | `30000` | Neovim-to-sidecar request timeout |
| `ssh_connect_timeout_seconds` | `10` | SSH connection timeout |
| `find_limit` | `200` | Max file picker results |
| `grep_limit` | `200` | Max grep results |
| `git_output_max_bytes` | `1048576` | Max stdout/stderr captured for each remote git command |
| `open_prefetch_related` | `false` | Prefetch nearby known files after open |
| `adoption_policy` | `"tracked_or_explicit"` | Require `:RemoteAdopt` for untracked mirror files |
| `background_mirror` | `true` | Gradually scan, hydrate, and validate in idle batches |

See [docs/configuration.md](docs/configuration.md) for the larger option list.

## Picker API

The generic picker adapter uses sidecar-backed remote results with builtin
`vim.ui.select` selection. Plugin-specific Telescope/fzf/snacks sources are not
implemented yet; non-builtin provider names warn and use the builtin selector.

```lua
local pickers = require("nvim_remote_mirror.pickers")

pickers.files({
  query = "src",
  on_select = function(item)
    require("nvim_remote_mirror").open(item.path)
  end,
})

pickers.grep({ query = "TODO" })
```

For data-only integrations, call `require("nvim_remote_mirror").grep_async()`
to receive grep hits without quickfix side effects.

Mirror files live under the sidecar state directory, typically below
`~/.local/state/nvim-remote-mirror` on Linux when `state_dir` is unset. Open
`:RemoteWorkspace` to inspect the active mirror root and files root.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `not connected` | Run `:RemoteWorkspace` or `:RemoteConnect ...` |
| SSH target fails | Confirm `ssh myhost` works without prompts |
| Remote agent missing | Run `:RemoteHealth`, then `:RemoteInstallAgent`; or confirm `ssh myhost 'command -v nrm-agent'` |
| Opens are stale | Use `:RemoteValidate` or `:RemoteOpen! path` |
| Saves are queued | Open `:RemoteQueue`, then retry with `:RemoteFlushQueue` |
| Save conflict | Open `:RemoteConflicts`; accept-local uploads the saved local snapshot, accept-remote is blocked for partial remote copies |
| New mirror file did not upload | Use `:RemoteAdopt` or set `adoption_policy = "auto"` |
| UI feels empty | Run `:RemoteScan` or leave background mirror enabled |

## Development Checks

```sh
just check
just ci
just lint-extra
just audit
just audit-strict
just fuzz-protocol
cargo bench --workspace --no-run --locked
scripts/perf_smoke.sh --small
NRM_PERF_LARGE=1 scripts/perf_smoke.sh --large
```

`just check` runs Rust fmt, clippy, Rust tests, Lua syntax checks, headless
Neovim tests, Bash syntax checks, and whitespace checks. The Criterion
benchmarks cover protocol frames and agent scan/grep paths; run them without
`--no-run` for manual before/after measurements. The small perf smoke runs in
CI and through `just ci`; the large mode is intended for local before/after
timing on bigger synthetic workspaces.
`just lint-extra`, `just audit-strict`, `just miri-protocol`, and
`just fuzz-protocol` are local quality gates for release or riskier changes; see
[docs/quality-gates.md](docs/quality-gates.md).

Set `NRM_TRACE=1` when starting the sidecar to emit JSON trace events for
request queueing, agent round trips, preemption, truncation, and remote backoff
to stderr.

## More Docs

| Doc | Contents |
| --- | --- |
| [docs/design.md](docs/design.md) | Goal, architecture, and next milestones |
| [docs/v1-roadmap.md](docs/v1-roadmap.md) | Daily-driver v1 sprint plan and acceptance gates |
| [docs/configuration.md](docs/configuration.md) | Configuration options |
| [docs/plugin-compatibility.md](docs/plugin-compatibility.md) | How normal plugins should interact with mirror paths |
| [docs/save-recovery.md](docs/save-recovery.md) | Save queue and conflict behavior |
| [docs/protocol.md](docs/protocol.md) | Sidecar and agent protocol notes |
| [docs/quality-gates.md](docs/quality-gates.md) | Required and optional checks for local and release validation |
| [doc/nvim-remote-mirror.txt](doc/nvim-remote-mirror.txt) | Vim help |
