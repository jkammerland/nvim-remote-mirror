# Configuration

Configure the plugin from Lua:

```lua
require("nvim_remote_mirror").setup({
  connection = "socket",
  agent = "/path/to/local/nrm-agent",
  remote_agent = "nrm-agent",
  remote_agent_install_path = "$HOME/.local/bin/nrm-agent",
})
```

## Binaries

| Option | Default | Notes |
| --- | --- | --- |
| `sidecar` | `target/debug/nrm-sidecar` or `nrm-sidecar` | Local sidecar binary |
| `agent` | `target/debug/nrm-agent` or `nrm-agent` | Agent for local targets and SSH install/update source when registry mode is disabled |
| `remote_agent` | `nrm-agent` | Command executed on SSH hosts |
| `remote_agent_install_path` | `nil` | Optional default target path for explicit SSH agent install/update |

For `ssh://` targets, `remote_agent` is the remote command. Connect is
local-first and never installs or updates it. Run `:RemoteHealth` to classify a
failure, then run `:RemoteInstallAgent[!]` or `:RemoteUpdateAgent[!]` explicitly.
When no registry URL is configured, those commands use the local `agent` file.
When registry mode is configured, they use only a verified registry artifact
and never fall back to the local file.

On POSIX, a bare `remote_agent` such as `nrm-agent` installs to
`$HOME/.local/bin/nrm-agent`, and SSH launch prepends `$HOME/.local/bin` to
`PATH`. On Windows it installs to
`%LOCALAPPDATA%\nrm\bin\nrm-agent.exe`. An absolute `remote_agent`,
`remote_agent_install_path`, or the optional command argument overrides the
platform default:

```vim
:RemoteInstallAgent /opt/nrm/bin/nrm-agent
:RemoteUpdateAgent!
```

Non-interactive SSH may not load the same PATH as your login shell. If
`:RemoteHealth` reports `missing_agent`, either run `:RemoteInstallAgent` or set
`remote_agent` to an absolute remote path.

### Remote Install Platform Support

`:RemoteInstallAgent` is an upload/install command, not a build command. The
sidecar detects the host, stages the candidate beside the destination, verifies
its exact `--version` and full Hello, preserves the old executable, activates
the candidate, and performs a second Hello through the normal launch path. A
post-activation failure restores and reprobes the previous executable.

| Remote OS | Status | Details |
| --- | --- | --- |
| Linux x64/ARM64 | Supported | POSIX shell; signed releases select static musl artifacts |
| macOS x64/ARM64 | Supported | POSIX shell and matching Darwin artifacts |
| Windows x64/ARM64 | Supported | Windows OpenSSH and PowerShell 5.1; binary-safe forced-SFTP staging |

If your local editor is Linux but the remote target is macOS, build the agent on
the Mac and copy the artifact back to a Linux-local path that the sidecar can
read:

```sh
ssh mac-builder.example 'cd /path/to/nvim-remote-mirror && cargo build --release'
mkdir -p target/remote-agents
scp mac-builder.example:/path/to/nvim-remote-mirror/target/release/nrm-agent \
  target/remote-agents/nrm-agent-darwin-arm64
```

Then point `agent` at that artifact for the macOS SSH session:

```lua
require("nvim_remote_mirror").setup({
  agent = vim.fn.expand("~/repos/nvim-remote-mirror/target/remote-agents/nrm-agent-darwin-arm64"),
  remote_agent = "nrm-agent",
})
```

Because `agent` is global in local-binary mode, switch it back before using a
local workspace or a target with a different OS/CPU. Registry mode avoids that
manual selection by mapping detected hosts to one of six fixed Rust targets.

Windows SSH targets use forward slashes and an absolute drive root, for
example:

```vim
:RemoteConnect ssh://windows-host/B:/repos/project
```

UNC paths, drive-relative paths, and backslash target syntax are unsupported.
The Windows planner is shared by agent and LSP launch. Mirror writes use
cross-platform cooperative locks and native replacement, while LSP rewriting
recognizes drive paths and `file:///B:/...` URIs. Native executables and
`.cmd`/`.bat` LSP shims are resolved from `PATH`. Batch arguments containing
`"` or `%` are rejected because those characters cannot be represented safely
through `cmd.exe`; use a native executable or a fixed wrapper for such values.

## Signed Agent Registry

Registry mode is disabled unless `remote_agent_registry_url` is set. Trusted
keys are bootstrapped out of band; a registry response cannot add trust.

```lua
require("nvim_remote_mirror").setup({
  remote_agent_registry_url =
    "https://github.com/owner/repo/releases/download/v{version}/nrm-agent-manifest-v1.json",
  remote_agent_registry_public_keys = {
    ["release-2026-q3"] = "<standard-base64-encoded-32-byte-Ed25519-key>",
  },
  remote_agent_registry_signature_threshold = 1,
  remote_agent_registry_cache_dir = nil,
  remote_agent_registry_cache_max_bytes = 512 * 1024 * 1024,
  remote_agent_registry_timeout_ms = 120000,
})
```

| Option | Default | Notes |
| --- | --- | --- |
| `remote_agent_registry_url` | `nil` | Exactly one `{version}` placeholder; only `https://` or a local absolute `file://` URL |
| `remote_agent_registry_public_keys` | `{}` | At most 32 distinct key IDs mapped to canonical standard-base64 32-byte Ed25519 keys |
| `remote_agent_registry_signature_threshold` | `1` | Number of distinct trusted signatures required |
| `remote_agent_registry_cache_dir` | `nil` | Defaults to `registry-cache` below sidecar state |
| `remote_agent_registry_cache_max_bytes` | `512 MiB` | Cache budget for verified registry data |
| `remote_agent_registry_timeout_ms` | `120000` | Whole explicit install/update deadline in registry mode |

HTTPS templates must name a manifest file and cannot contain credentials,
queries, fragments, localhost, or non-global literal hosts. Public-key IDs and
key material must be distinct, and the threshold cannot exceed the trusted key
count. Lua performs early encoding and known-small-order checks; the Rust
sidecar is authoritative for Ed25519 curve-point validation and refuses to
start with any noncanonical, invalid, or weak trusted key.

The expanded URL, trust policy, cache policy, and timeout are part of socket
daemon identity, so a differently configured Neovim refuses to reuse a stale
daemon. Manifest and signature bytes are verified on every use. A cached raw
manifest/signature pair is eligible as fallback only after a timeout,
connection failure, rate limit, or 5xx response; malformed data, bad signatures
or hashes, other 4xx responses, and policy violations never use that fallback.
Content-addressed artifacts can be normal cache hits after a fresh manifest is
verified. Cache fallback is best-effort: budget eviction, or a budget too small
for both an artifact and its manifest/signature pair, can make later offline
fallback unavailable. An absolute `file://` registry is read by the local
sidecar, and its artifacts must remain inside the manifest directory.

An explicit install/update has one sidecar deadline from request acceptance
through host detection, retrieval, queue drain, staging, validation, activation,
rollback, and cleanup. Registry mode uses
`remote_agent_registry_timeout_ms`; local-binary mode uses
`request_timeout_ms`. Each nested operation receives only the remaining budget,
and the sidecar reserves part of it for recovery after activation. Neovim's
bootstrap callback timer uses the same configured deadline plus a one-second
delivery grace. A `bootstrap_timeout` failure therefore cannot start new forward
work, although recovery may continue within its reserved part of the same
deadline.
Portable Rust cannot interrupt an individual filesystem syscall already inside
the kernel. Local registry/cache work checks the deadline immediately before
and after each syscall and between 64 KiB chunks, so a kernel-stalled call can
delay timeout observation but no later phase is started after expiry.

Timeout and registry policy are snapshotted when a client connects. Calling
`setup()` again changes the next connection; reconnect before installing or
updating if those settings changed.

The install/update response and `registry_health` in health, workspace, hello,
and remote-health notifications report the selected platform/target, source,
redacted manifest URL, verified signing key IDs, artifact and manifest digests,
cache state, and stable error code. Registry state is one of `disabled`,
`not_checked`, `fetching`, `verified`, or `error`. It remains separate from
working-agent health, so a failed explicit update does not make an unchanged
agent appear unavailable.

See [Signed agent registry operations](agent-registry.md) for cache policy,
manifest format, trust limitations, and safe key rotation.

## Transport

| Option | Default | Notes |
| --- | --- | --- |
| `connection` | `stdio` | Use `socket` for reusable daemon mode |
| `socket_path` | `nil` | Explicit Unix socket path |
| `socket_dir` | `nil` | Directory for derived socket paths |
| `state_dir` | `nil` | Durable mirror state root |
| `daemon_start_timeout_ms` | `1000` | Wait for socket daemon startup |
| `request_timeout_ms` | `30000` | Ordinary request timeout and whole local-binary bootstrap deadline |
| `ssh_connect_timeout_seconds` | `10` | SSH connect timeout |

Socket listener sessions are single-writer and sequential today. The sidecar
reports this through `workspace_info.client_mode = "single_writer"` and
`workspace_info.client_policy`; a disconnected client leaves the listener
available for the next editor session.

When `state_dir` is unset, sidecar state uses the platform state directory.
On a normal Linux Neovim install this is typically
`~/.local/state/nvim-remote-mirror`. Use `:RemoteWorkspace` to inspect the
active mirror root and files root before cleaning or scripting against mirror
files.

## Search and Mirror Limits

| Option | Default |
| --- | --- |
| `find_limit` | `200` |
| `grep_limit` | `200` |
| `grep_remote_page_files` | `512` |
| `grep_remote_max_file_bytes` | `512 KiB` |
| `grep_remote_max_total_bytes` | `8 MiB` |
| `grep_cache_max_files` | `2000` |
| `grep_cache_max_file_bytes` | `512 KiB` |
| `grep_cache_max_total_bytes` | `8 MiB` |
| `git_output_max_bytes` | `1 MiB` |
| `open_batch_max_file_bytes` | `4 MiB` |
| `prefetch_max_file_bytes` | `4 MiB` |
| `prefetch_max_total_bytes` | `16 MiB` |

## Picker Integration

| Option | Default | Notes |
| --- | --- | --- |
| `picker.provider` | `auto` | `auto` and `builtin` use `vim.ui.select`; non-builtin providers are reserved for future adapters and currently warn before using builtin |

## Save Adoption

| Option | Default | Notes |
| --- | --- | --- |
| `adoption_policy` | `tracked_or_explicit` | `tracked_or_explicit` only saves buffers that were opened by nrm or explicitly adopted with `:RemoteAdopt`; `auto` restores legacy mirror-root auto-adoption |

The default avoids accidentally creating remote files when another plugin writes
cache, scratch, or generated files under the mirror files root. Use
`:RemoteAdopt [path]` for intentional new remote files or recreating a remote
file that validation marked deleted.

## Reconnect and Recovery

| Option | Default | Notes |
| --- | --- | --- |
| `auto_reconnect` | `true` | Retry after unexpected sidecar exit |
| `reconnect_delay_ms` | `1000` | Delay between reconnect attempts |
| `reconnect_max_attempts` | `3` | Max automatic attempts |
| `reconnect_stable_ms` | `10000` | Reset attempt count after stable connection |
| `recover_local_edits_on_connect` | `true` | Scan mirror for unsnapshotted local edits |
| `recover_local_edits_limit` | `256` | Recovery scan batch size |
| `flush_queue_on_connect` | `true` | Retry queued saves after connect |
| `flush_queue_on_connect_limit` | `1` | Bounded replay on connect |

## Background Mirror

| Option | Default | Notes |
| --- | --- | --- |
| `background_mirror` | `true` | Enable idle mirror building |
| `background_mirror_interval_ms` | `5000` | Tick interval |
| `background_mirror_rescan_interval_ms` | `300000` | Delay before full rescan |
| `background_mirror_scan_limit` | `256` | Metadata paths per scan batch |
| `background_mirror_prefetch_limit` | `4` | Known files to hydrate per tick |
| `background_mirror_refresh_limit` | `32` | Cached files to validate per tick |
| `background_mirror_max_file_bytes` | `128 KiB` | Per-file idle hydrate cap |
| `background_mirror_max_total_bytes` | `512 KiB` | Per-tick idle hydrate cap |
