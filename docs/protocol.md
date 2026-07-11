# Protocol Notes

Neovim talks to the local sidecar with newline-delimited JSON. The sidecar talks
to the agent with length-prefixed postcard-encoded binary RPC.

## Neovim to Sidecar

Request:

```json
{"id":1,"method":"open","params":{"path":"src/main.rs"}}
```

Response:

```json
{"id":1,"ok":true,"result":{"path":"src/main.rs"}}
```

Notification:

```json
{"method":"workspace/remote_health","params":{"remote_status":"unavailable"}}
```

Notifications do not have request IDs. Clients may ignore unknown
notifications.

## Workspace Info

`workspace_info` is local-first. It returns mirror paths, workspace identity,
transport metadata, command names, notification names, capabilities, and the
last known remote health. It must not block on SSH.

Clients that understand command metadata should check
`capabilities.remote_agent_bootstrap == true` before presenting remote agent
repair actions. The public commands are:

| Method | Lane | Mutates | Behavior |
| --- | --- | --- | --- |
| `remote_health` | read/control | no | Actively probes the agent and decorates health with `agent_status`, expected versions, local/remote agent paths, install/update availability, and a suggested `repair_command` |
| `remote_agent_install` | write/control | yes | Transactionally installs a verified registry artifact, or the configured local binary when registry mode is disabled |
| `remote_agent_update` | write/control | yes | Transactionally replaces an incompatible/missing SSH agent, skipping when already compatible unless `force = true` |

`remote_agent_install` and `remote_agent_update` are explicit user actions. The
sidecar must not silently install or update the remote agent during
`workspace_info` or connect. During replacement, the sidecar drains queued
remote work, preempts both agent lanes, and waits for their workers to exit. It
then transfers the candidate to a unique same-directory staging path, checks
exact `--version` output and a complete Hello, preserves the
previous executable, activates the candidate, and checks Hello again through
the normal launch path. A failed post-activation check restores and reprobes the
previous executable. Ambiguous activation replies are reconciled before a
result is returned; `process_in_use` and `rollback_failed` are distinct errors.

The POSIX planner supports Linux and macOS x64/ARM64 and streams the artifact
over SSH stdin. The Windows planner uses PowerShell 5.1 encoded commands and a
forced-SFTP `scp` transfer, avoiding PowerShell's large-stdin buffering on
Windows OpenSSH x64/ARM64. Windows roots use canonical drive syntax such as
`B:/repos/project`; UNC and drive-relative roots are rejected.

Install/update params:

```json
{"force":true,"install_path":"$HOME/.local/bin/nrm-agent"}
```

For bare remote agent commands such as `nrm-agent`, POSIX SSH launches prepend
`$HOME/.local/bin` to `PATH`, and the managed default install path is
`$HOME/.local/bin/nrm-agent`. Windows defaults to
`%LOCALAPPDATA%\nrm\bin\nrm-agent.exe`. Absolute `remote_agent` values default
their install path to the same absolute path.

## Registry Source

Registry mode is enabled only when the sidecar starts with a registry URL and
out-of-band trusted Ed25519 keys. Connect and `workspace_info` do not fetch it.
`workspace_info.registry_policy_fingerprint` covers URL, sorted key
fingerprints, threshold, cache policy, and timeout; the Lua client refuses a
socket daemon with a different policy.
For an explicit install/update, the sidecar detects the remote host and selects
one of:

```text
x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
x86_64-apple-darwin
aarch64-apple-darwin
x86_64-pc-windows-msvc
aarch64-pc-windows-msvc
```

It expands exactly one `{version}` placeholder, verifies detached signatures
over the immutable manifest bytes, checks package/protocol/version/target/size
and digest policy, and uploads the selected locally verified artifact. Registry
mode never falls back to `local_agent`; local upload is available only when no
registry URL is configured.

On success, the install/update result includes `agent_source`,
`registry_target`, `registry_manifest_sha256`,
`registry_signing_key_ids`, artifact/manifest source, cache state, and the
candidate `source_sha256`. `registry_health` is also attached to status,
workspace, hello, and remote-health notification objects. It carries only a
redacted manifest origin plus structured platform, target, signing-key, digest,
source/cache, state, and stable error-code fields. A registry update failure
does not replace the health of an already working remote agent.

An install/update uses one absolute deadline beginning when the sidecar accepts
the request. Registry mode uses `remote_agent_registry_timeout_ms`; local mode
uses `request_timeout_ms`. Registry fetches, SSH processes, agent probes, and
transaction phases are clipped to the remaining budget. A bounded reserve is
kept for post-activation reconciliation or rollback. The Neovim callback timer
uses that same configured duration plus one second for reply delivery.

See [Signed agent registry operations](agent-registry.md) for exact manifest,
redirect, cache-fallback, and key-rotation policy.

## Agent Boundary

The sidecar sends framed binary RPC to `nrm-agent`. Each request has an ID and
each response carries the same ID. Current SSH transport runs the agent process
over stdio.

Current agent protocol version: `7`.

Remote git primitives are agent RPCs, not local mirror operations:

| Request | Behavior |
| --- | --- |
| `GitStatus { paths, max_output_bytes }` | Runs remote `git status --porcelain=v1 -z --branch --untracked-files=all` with optional workspace-relative pathspecs |
| `GitDiff { path, cached, max_output_bytes }` | Runs remote `git diff --no-color --no-ext-diff [--cached] -- [path]` |
| `GitBlame { path, max_output_bytes }` | Runs remote `git blame -- path` |

All git responses use `Response::Git { output }` with bounded stdout/stderr,
an optional process status code, and a truncation flag. The agent invokes `git`
with explicit argv, disables the pager/color, and validates user paths as
workspace-relative before passing them after `--`.

Future transports must preserve:

| Requirement | Reason |
| --- | --- |
| Ordered delivery per lane | Keep save/read ordering predictable |
| Request IDs | Match responses to pending work |
| Timeout-compatible errors | Preserve reconnect/backoff behavior |
| Abort support | Replace active read/background work when preempted |
| Same agent command model | Avoid changing Neovim-facing APIs |

## Compatibility

`Request::Hello` is the sidecar-agent compatibility gate. Both package version
and protocol version must match exactly before ordinary remote work begins. The
sidecar reports mismatch as `remote_status = "unavailable"` in `remote_probe`,
`workspace_info`, and `workspace/remote_health` notifications so Neovim can
keep serving local mirror operations while the agent is fixed. `remote_health`
classifies `version_mismatch` and `protocol_mismatch` separately so clients can
suggest `RemoteUpdateAgent`; health/install/update remain available for repair.
