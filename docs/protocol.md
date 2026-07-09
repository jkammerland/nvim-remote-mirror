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
| `remote_agent_install` | write/control | yes | Uploads the configured local agent binary to an SSH target and then probes health |
| `remote_agent_update` | write/control | yes | Replaces an incompatible/missing SSH agent, skipping when already compatible unless `force = true` |

`remote_agent_install` and `remote_agent_update` are explicit user actions. The
sidecar must not silently install or update the remote agent during
`workspace_info` or connect. During replacement, the sidecar cancels queued
remote work, preempts active lane workers, uploads over SSH stdin to a temporary
file, validates the installed binary with `--version`, then starts a fresh agent
probe.

Bootstrap is currently a POSIX SSH capability. The remote install script assumes
`sh -lc`, POSIX paths, `dirname`, `mkdir`, `chmod`, and `mv`. It uploads the
configured local agent bytes as-is, so cross-OS installs require the caller to
provide a local path to a binary already built for the remote OS/CPU. Windows
OpenSSH/PowerShell remotes need a separate future command planner and installer.

Install/update params:

```json
{"force":true,"install_path":"$HOME/.local/bin/nrm-agent"}
```

For bare remote agent commands such as `nrm-agent`, SSH launches prepend
`$HOME/.local/bin` to `PATH`, and the managed default install path is
`$HOME/.local/bin/nrm-agent`. Absolute `remote_agent` values default their
install path to the same absolute path.

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

`Request::Hello` is the sidecar-agent compatibility gate. Incompatible
sidecar/agent protocol versions must fail with a clear protocol version mismatch
message. The sidecar reports that failure as `remote_status = "unavailable"` in
`remote_probe`, `workspace_info`, and `workspace/remote_health` notifications so
Neovim can keep serving local mirror operations while the remote agent is fixed.
`remote_health` additionally reports `agent_status = "protocol_mismatch"` for
this case so clients can suggest `RemoteUpdateAgent`.
