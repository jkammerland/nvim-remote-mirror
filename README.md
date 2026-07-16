# nvim-remote-mirror

> [!WARNING]
> **Work in progress.** This project is being dogfooded, and its configuration,
> protocol, signed-agent registry, and release process may change before the
> first stable release.

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
| Remote agent health/install/update | Signed automatic repair on SSH connect when opted into a registry; explicit commands retained |
| Remote LSP proxy | Basic |
| Remote git status/diff/blame | Basic |
| Workspace process runtime | Attached pipe processes and PTYs on local/Linux/macOS/Windows hosts |
| Detached terminals, workspace watch, DAP | Not built |
| Non-SSH transports | Not built |

## Requirements

| Tool | Where | Notes |
| --- | --- | --- |
| Neovim 0.10+ | local | Neovim 0.11+ is preferred |
| Rust toolchain | local | Builds `nrm-sidecar` and `nrm-agent` |
| SSH | local and remote | Used for `ssh://host/path` targets |
| `nrm-agent` | remote | Must be executable on the remote host, or installable from a configured trusted signed registry |

## Install

Build the local binaries:

```sh
cargo build --release
```

For example, install the remote agent manually on a POSIX host:

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

No registry URL is configured by default, so connecting does not install or
replace anything in the default configuration. When an SSH target, a trusted
signed registry, and the default `remote_agent_auto_install = true` are all in
effect, connect probes the remote agent and automatically installs or repairs
it from the matching verified release. Set `remote_agent_auto_install = false`
to keep registry-backed repair explicit.

Automatic repair is deliberately narrow. It installs a missing agent and
replaces a non-executable, package-version-mismatched, or
protocol-version-mismatched agent. It skips an already compatible agent without
fetching an artifact, and it does not mutate the host for other health states,
including a missing remote root or an unavailable/unclassified remote. A
verification, download, or installation failure leaves the editor connected in
a degraded local-first state and is shown separately from connection health.

`:RemoteInstallAgent[!]` and `:RemoteUpdateAgent[!]` remain available. With no
registry configured these explicit commands upload the configured local
`agent` binary. With a signed registry configured they use only the matching
verified build and fail closed instead of falling back to an unsigned local
binary.

Installation is transactional: the sidecar stages a unique same-directory
candidate, checks its exact version and full Hello compatibility, preserves the
previous executable, activates the candidate, and checks Hello again through
the normal launch path. A failed post-activation check restores and reprobes the
previous executable. `process_in_use` and `rollback_failed` remain distinct
errors. A per-target remote lease serializes concurrent sidecars; a second
automatic connection either observes the first connection's compatible result
or reports `install_in_progress` without starting another mutation.
On POSIX hosts, adjacent per-process claim files protect the short lease-owner
and operation-owner publication windows. An ownerless directory is reaped only
after every well-formed claim identity is proven dead. Malformed claim names or
file types fail closed; a dead partial claim is reaped from its strict
token/PID filename without trusting its contents.
On Windows, lease release uses a token-bound same-directory marker sent over a
separate SSH command. The holder validates and deletes that marker atomically;
a watchdog bounded by a snapshot of the remaining bootstrap budget releases
the anchor if the sidecar disappears.

The installer also publishes a stable same-directory transaction journal
before upload. The next lease holder recovers an interrupted transaction before
probing or starting a new one: it discards only the exact partial candidate from
an interrupted upload, or restores the prior executable/finishes committed
cleanup only when the recorded paths, file types, and journal-recorded digests
still match. The verified digest for a newer release authorizes only its
subsequent transaction, so an older valid crash journal remains recoverable.
Malformed, ambiguous, or file-digest-mismatched state is preserved and fails
closed for inspection.

On POSIX hosts, missing install-directory components are created one at a time
with mode `0700`. The final directory must be owned by the remote login UID and
must not be group/world writable; ancestors must be owned by that UID or root,
with sticky shared physical ancestors allowed. The final directory cannot be a
symlink; an ancestor symlink is accepted only when it is root/login-owned and
its resolved physical chain passes the same checks. Non-private (`0600`)
recovery journals are rejected.

| Remote OS | Install support | Notes |
| --- | --- | --- |
| Linux | x64 and ARM64 | POSIX shell; registry builds use static musl targets |
| macOS | x64 and ARM64 | POSIX shell and a matching Darwin binary |
| Windows | x64 and ARM64 | Windows OpenSSH with PowerShell 5.1; defaults to `%LOCALAPPDATA%\nrm\bin\nrm-agent.exe` |

For local-binary mode, the installer uploads bytes from the local `agent` path
exactly as configured; it does not cross-compile. A Linux editor targeting
macOS or Windows must point `agent` at a binary built for that remote OS and
architecture. Registry mode selects one of the six supported native targets
automatically.

For a safe bare `remote_agent`, POSIX installs under `$HOME/.local/bin` with
the same command name and SSH launch prepends that directory to `PATH`.
Windows installs under `%LOCALAPPDATA%\nrm\bin` with an `.exe` suffix. Relative
agent paths containing a slash are rejected; use a bare name or an absolute
path. Use canonical Windows targets such as `ssh://host/B:/repos/project`; UNC
paths, drive-relative paths, and backslashes in the target URL are unsupported.
Native Windows transport also covers agent/LSP launch, cross-platform mirror
locking and replacement, and LSP rewriting for drive paths and `file:///B:/...`
URIs. LSP launch resolves native executables and `.cmd`/`.bat` shims from
`PATH`; batch arguments containing `"` or `%` are rejected instead of being
passed through unsafe `cmd.exe` expansion.

To opt into signed native builds, configure a versioned manifest URL and
out-of-band trusted key:

```lua
require("nvim_remote_mirror").setup({
  -- Automatic repair is active only for SSH when this trusted registry is set.
  remote_agent_auto_install = true,
  remote_agent_registry_url =
    "https://github.com/jkammerland/nvim-remote-mirror/releases/download/v{version}/nrm-agent-manifest-v1.json",
  remote_agent_registry_public_keys = {
    ["release-2026-q3"] = "o70a35HCIieJ/B0jatGVvNB/6l3X2W4InbioQjIFHbY=",
  },
})
```

See [signed agent registry operations](docs/agent-registry.md) for verification,
cache fallback, trust bootstrap, and key rotation.
Install/update results and `:RemoteWorkspace` expose the selected platform and
target, redacted manifest URL, signing key IDs, digests, cache source, and stable
registry error codes. A registry failure is tracked separately and does not
replace the health of an already working agent.

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

Socket mode requires the directory immediately containing the Unix socket to
be owned by the current user with mode `0700`; existing sockets must be owned
by the current user with permissions no broader than `0600`. The plugin creates
an absent leaf directory securely, but rejects symlinked, shared, or
foreign-owned leaves. Its lexical and resolved ancestors must be owned by the
current user or root and cannot be group/world-writable unless the ancestor is
sticky and protects the next entry. A private leaf below sticky `/tmp` is
supported; placing the socket directly in `/tmp` is not.

## Quick Start

Open the dashboard:

```vim
:RemoteWorkspace
```

Connect to a remote workspace:

```vim
:RemoteConnect ssh://myhost/home/me/project
```

For a native Windows SSH host, use the drive-root form:

```vim
:RemoteConnect ssh://windows-host/B:/repos/project
```

For cwd-based local plugins, switch the current tab to the mirror files root:

```vim
:RemoteCd
```

Open the remote account's default shell in an attached terminal (the new split
enters terminal-input mode immediately):

```vim
:RemoteTerminal
```

The first runtime request prompts to trust the workspace by default. Connect
itself never runs an arbitrary workspace command or grants that trust.

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
| `:RemoteConnect [target]` | Connect to a local path, POSIX `ssh://host/absolute/path`, or Windows `ssh://host/B:/absolute/path` |
| `:RemoteDisconnect` | Close the current client session |
| `:RemoteReconnect` | Reconnect to the last target |
| `:RemoteCd` | Set the current tab cwd to the mirror files root |
| `:RemoteTrustWorkspace[!]` | Persist runtime trust for the current workspace; `[!]` skips confirmation |
| `:RemoteUntrustWorkspace` | Remove persisted runtime trust for the current workspace |
| `:RemoteTerminal [cmd...]` | Open an attached remote PTY; no arguments start the default remote shell |
| `:RemoteTerminal! [cmd...]` | Request detached persistence; currently fails closed until the persistent broker is implemented |
| `:RemoteOpen {path}` | Open a workspace-relative file |
| `:RemoteOpen! {path}` | Force remote rehydrate for clean cached files |
| `:RemoteScan [limit]` | Scan remote metadata into the local mirror index |
| `:RemoteFind [query]` | Put known remote paths in quickfix |
| `:RemoteGrep {query}` | Search remote and cached mirror files |
| `:RemotePrefetch {path...}` | Hydrate files into the mirror |
| `:RemoteStatus` | Print a status summary |
| `:RemoteHealth` | Probe remote agent health and compatibility |
| `:RemoteInstallAgent[!] [path]` | Transactionally install from the signed registry, or from local `agent` when registry mode is disabled |
| `:RemoteUpdateAgent[!] [path]` | Transactionally replace an incompatible remote agent; skip a compatible agent unless forced |
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
| `agent` | local checkout/debug path or `"nrm-agent"` | Local agent and SSH upload source when registry mode is disabled |
| `remote_agent` | `"nrm-agent"` | Remote command run over SSH |
| `remote_agent_install_path` | `nil` | Optional remote path for automatic bootstrap and explicit install/update commands |
| `remote_agent_auto_install` | `true` | On SSH connect, repair known agent failures from a configured trusted signed registry; inert when the registry URL is `nil` |
| `remote_agent_registry_url` | `nil` | Opt-in `https://` or absolute `file://` manifest URL with one `{version}` placeholder |
| `remote_agent_registry_public_keys` | `{}` | Trusted key-ID to standard-base64 Ed25519 public-key map |
| `remote_agent_registry_signature_threshold` | `1` | Required distinct trusted signatures |
| `remote_agent_registry_cache_dir` | `nil` | Verified-cache directory; defaults below sidecar state |
| `remote_agent_registry_cache_max_bytes` | `536870912` | Registry cache budget |
| `remote_agent_registry_timeout_ms` | `120000` | Whole install/update deadline in registry mode |
| `request_timeout_ms` | `30000` | Ordinary request timeout and whole local-binary install/update deadline |
| `ssh_connect_timeout_seconds` | `10` | SSH connection timeout |
| `find_limit` | `200` | Max file picker results |
| `grep_limit` | `200` | Max grep results |
| `git_output_max_bytes` | `1048576` | Max stdout/stderr captured for each remote git command |
| `open_prefetch_related` | `false` | Prefetch nearby known files after open |
| `adoption_policy` | `"tracked_or_explicit"` | Require `:RemoteAdopt` for untracked mirror files |
| `background_mirror` | `true` | Gradually scan, hydrate, and validate in idle batches |
| `remote_runtime.enabled` | `true` | Expose explicit workspace process/terminal execution; connect still runs no arbitrary command |
| `remote_runtime.trust` | `"prompt"` | Runtime authorization policy: `prompt`, `always`, or `never` |
| `remote_runtime.ticket_create_timeout_ms` | `5000` | Bound private local bridge-ticket creation |

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

## Workspace Runtime API

The provider-neutral Lua API resolves an immutable workspace context, maps
editor paths/URIs to authority paths/URIs, authorizes execution, and provides
three integration surfaces:

```lua
local context = assert(require("nvim_remote_mirror").workspace({ bufnr = 0 }))

context:authorize("process", function(err, granted)
  if err or not granted then
    return
  end

  local handle = assert(context:spawn({
    command = { argv = { "cargo", "check" } },
    cwd = { space = "workspace", path = "" },
  }))
  -- handle:signal("interrupt")
end)
```

Use `context:job_spec()` when another plugin owns the local job lifecycle,
including argv- or string-only terminal APIs, and `context:open_pty()` for a
managed PTY. Arguments and environment values remain structured until the
private sidecar bridge; they are never interpolated into the SSH command.
Arguments are control-free UTF-8. Pipe output defaults to a 4 MiB cumulative
limit; PTYs are live backpressured streams and reject that pipe-only option.

Contexts become stale across reconnect epochs. Integrations can resolve again
on `NrmWorkspaceConnected`, `NrmWorkspaceDisconnected`, and
`NrmWorkspaceEpochChanged` `User` events. Only attached execution is available
today: detached/reconnectable sessions and workspace watching are not
advertised. See [Workspace Runtime API v1](docs/workspace-runtime.md) for the
complete contract and a ToggleTerm example that needs no plugin-specific nrm
patch.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `not connected` | Run `:RemoteWorkspace` or `:RemoteConnect ...` |
| SSH target fails | Confirm `ssh myhost` works without prompts |
| Remote agent missing | With a signed registry configured, check the automatic-bootstrap state in `:RemoteWorkspace`; otherwise run `:RemoteHealth`, then `:RemoteInstallAgent` |
| Automatic registry install fails | The local mirror remains connected but remote work is degraded; check `:RemoteWorkspace` Bootstrap/Registry state and the stable error code; unsigned fallback remains forbidden |
| Windows target is rejected | Use `ssh://host/B:/absolute/path`, not UNC, drive-relative, or backslash syntax |
| Windows runtime rejects local state ACLs | Point `state_dir` at a pre-provisioned directory with inheritance disabled and access limited to the current user and `SYSTEM`, or repair the unsafe ancestor; runtime state fails closed and does not create a drive-root workaround |
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
just fuzz-registry
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
`just lint-extra`, `just audit-strict`, `just miri-protocol`,
`just fuzz-protocol`, and `just fuzz-registry` are local quality gates for
release or riskier changes; see [docs/quality-gates.md](docs/quality-gates.md).

The manual **UNSIGNED six-target release dry run** builds, executes, attests,
and assembles Linux, macOS, and Windows x64/ARM64 agents without signing or
publishing a release:

```sh
gh workflow run release-dry-run.yml --ref master
```

Its short-lived Actions bundle is test-only and cannot be used as a trusted
registry because it deliberately has no detached signature. See
[docs/releasing.md](docs/releasing.md#github-unsigned-release-dry-run).

Set `NRM_TRACE=1` when starting the sidecar to emit JSON trace events for
request queueing, agent round trips, preemption, truncation, and remote backoff
to stderr.

## More Docs

| Doc | Contents |
| --- | --- |
| [docs/design.md](docs/design.md) | Goal, architecture, and next milestones |
| [docs/v1-roadmap.md](docs/v1-roadmap.md) | Daily-driver v1 sprint plan and acceptance gates |
| [docs/configuration.md](docs/configuration.md) | Configuration options |
| [docs/agent-registry.md](docs/agent-registry.md) | Signed manifests, cache policy, and key rotation |
| [docs/releasing.md](docs/releasing.md) | Protected six-target build, signing, provenance, and release procedure |
| [docs/plugin-compatibility.md](docs/plugin-compatibility.md) | How normal plugins should interact with mirror paths |
| [docs/save-recovery.md](docs/save-recovery.md) | Save queue and conflict behavior |
| [docs/protocol.md](docs/protocol.md) | Sidecar and agent protocol notes |
| [docs/quality-gates.md](docs/quality-gates.md) | Required and optional checks for local and release validation |
| [doc/nvim-remote-mirror.txt](doc/nvim-remote-mirror.txt) | Vim help |

## License

Copyright (C) 2026 Jonathan Kammerland.

This project is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 2 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).
