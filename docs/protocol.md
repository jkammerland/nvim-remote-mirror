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
repair actions. Automatic mutation additionally requires the versioned
`capabilities.remote_agent_automatic_bootstrap_v1 == true`; the generic
capability predates automatic-request enforcement and is not sufficient. The
public commands are:

| Method | Lane | Mutates | Behavior |
| --- | --- | --- | --- |
| `remote_health` | read/control | no | Actively probes the agent and decorates health with `agent_status`, expected versions, local/remote agent paths, install/update availability, and a suggested `repair_command` |
| `remote_agent_install` | write/control | yes | Transactionally installs a verified registry artifact, or the configured local binary when registry mode is disabled |
| `remote_agent_update` | write/control | yes | Transactionally replaces an incompatible/missing SSH agent; also provides the guarded signed-registry repair operation used on connect |

The user commands exposing `remote_agent_install` and `remote_agent_update`
remain available as explicit actions. `workspace_info` itself is local-only and
never retrieves or installs an artifact. After it returns, a Lua client may
issue `remote_agent_update` with `automatic = true` when SSH, a configured
trusted signed registry, and the client's automatic-install option are all
enabled, and only when the versioned automatic-bootstrap capability is present.
The sidecar independently rejects automatic requests for local
transports, without a registry, through install rather than update semantics,
or with `force = true`.

The Lua client also refuses automatic bootstrap through a configured fixed
`socket_path`, because that path cannot encode the current sidecar executable
identity. Derived socket paths remain eligible. Once an automatic update is
accepted, it is a bounded non-cancellable transaction: disconnect detaches the
editor and queues `disconnect`, but a stdio sidecar is kept alive through the
snapshotted bootstrap callback deadline so activation or rollback can finish.
A socket client can close its channel without terminating the detached daemon.

An automatic update first classifies agent health. It skips `ok` without
fetching, installs `missing_agent`, and transactionally repairs
`agent_not_executable`, `version_mismatch`, or `protocol_mismatch`. Every other
status is skipped without host mutation, including `remote_root_missing`,
unavailable, and unclassified failures.

An automatic result echoes `automatic = true` and includes `remote_health`.
`updated` results, and `skipped` results that claim `agent_status = "ok"`, are
accepted as ready only when health is checked and available and its actual agent
and protocol versions exactly match their expected values. Every skipped result
must include a non-empty reason. Other malformed or inconsistent results leave
the connection degraded instead of being treated as successful.

During replacement, the sidecar drains queued remote work, preempts both agent
lanes, and waits for their workers to exit. It then transfers the candidate to
a unique same-directory staging path, checks exact `--version` output and a
complete Hello, preserves the previous executable, activates the candidate,
and checks Hello again through the normal launch path. A failed post-activation
check restores and reprobes the previous executable. Ambiguous activation
replies are reconciled before a result is returned; `process_in_use` and
`rollback_failed` are distinct errors. A per-target remote lease spans the
post-lease health probe and every mutation/recovery phase. Concurrent sidecars
therefore either observe the compatible result of the first installer or fail
with the distinct `install_in_progress` error; ambiguous stale lease state is
never treated as permission to mutate.
POSIX claim files are published before each fixed lease or operation directory.
A live claim protects the owner-publication window; an ownerless directory is
reaped only after every well-formed claim identity is proven dead. Malformed
claim names or file types fail closed; dead partial contents are reaped using
the strict token/PID filename.
Windows releases the exclusive lease through a separately transported,
token-bound marker rather than delayed PowerShell stdin. The holder validates
and consumes that marker with delete-on-close and has a remaining-budget
watchdog so a lost sidecar cannot retain the lease indefinitely.

Before artifact upload, the installer publishes a stable same-directory
transaction journal. The next lease holder reconciles it before running the
post-lease health probe: an exact partial staging file may be discarded, while
an interrupted activation is restored or committed cleanup is completed only
when recorded state and the journal's own candidate/previous SHA-256 digests
agree. The verified digest for a newer request binds only the new transaction;
invalid, ambiguous, or file-hash-mismatched journals are preserved and fail
closed.

The POSIX planner supports Linux and macOS x64/ARM64 and streams the artifact
over SSH stdin. The Windows planner uses PowerShell 5.1 encoded commands and a
forced-SFTP `scp` transfer, avoiding PowerShell's large-stdin buffering on
Windows OpenSSH x64/ARM64. Windows roots use canonical drive syntax such as
`B:/repos/project`; UNC and drive-relative roots are rejected.

Install/update params:

```json
{"force":true,"install_path":"$HOME/.local/bin/nrm-agent"}
```

Automatic connection-time repair uses update semantics and a separate guarded
flag; it never combines that flag with force:

```json
{"automatic":true,"install_path":"$HOME/.local/bin/nrm-agent"}
```

For safe bare remote agent commands, POSIX SSH launches prepend
`$HOME/.local/bin` to `PATH`, and the managed default install path keeps the
same command name in that directory. Windows keeps the name under
`%LOCALAPPDATA%\nrm\bin` and adds `.exe` when needed. Absolute `remote_agent`
values default their install path to the same absolute path. Relative command
paths containing a slash are rejected for default installation.

An SSH agent stream begins with exactly one bounded stdout launch record before
the first binary RPC frame: `NRM_AGENT_LAUNCH_V1\tREADY` or
`NRM_AGENT_LAUNCH_V1\tFAILURE\t<typed-reason>`. Only a failure produced before
the child process starts can authorize automatic repair; child stderr is
diagnostic only. Missing, malformed, oversized, or post-`READY` records are
ordinary untyped transport failures and therefore fail closed. POSIX failures
that occur inside `exec` after `READY` (for example a missing dynamic loader)
also remain untyped.

## Registry Source

Registry mode is enabled only when the sidecar starts with a registry URL and
out-of-band trusted Ed25519 keys. `workspace_info` does not fetch it; an
eligible connect may start an automatic update request immediately afterward.
`workspace_info.registry_policy_fingerprint` covers URL, sorted key
fingerprints, threshold, cache policy, and timeout; the Lua client refuses a
socket daemon with a different policy.
For an automatic bootstrap or explicit install/update, the sidecar detects the
remote host and selects one of:

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
does not replace the health of an already working remote agent. An automatic
bootstrap error is retained by the Lua client while connect finishes in a
degraded local-first state.

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

Current agent protocol version: `8`.

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

## Workspace Runtime Boundary

Workspace runtime execution is intentionally separate from the ordinary
newline-JSON sidecar server and serial filesystem lanes. Lua workspace API v1
validates the structured process specification and explicit workspace trust,
then asks a short-lived local sidecar command to publish a private single-use
ticket. The consumer starts only:

```text
nrm-sidecar runtime-proxy [--state-dir <private-state>] --ticket <opaque-id>
```

The ticket, not the local argv, carries the authority identity, remote argv,
contained cwd, environment delta, capability, limits, and transport metadata.
The proxy atomically consumes it, launches `nrm-agent runtime --root ...`
locally or through the platform SSH planner, completes an exact
package/protocol/capability Hello, and relays framed runtime messages and raw
stdio. Remote user values are never interpolated into an SSH command.

Runtime frames are length-prefixed and bounded separately from ordinary agent
RPC. API-v1 attached execution uses `ClientHello`/`ServerHello`,
`StartProcess`, `ProcessStarted`, offset-checked `Input`/`Output` plus
acknowledgements, `CloseInput`, `Resize`, `Signal`, and `Exited`. Pipe output
keeps stdout and stderr distinct; PTY output uses one PTY stream. The sidecar
acknowledges output only after the corresponding local write and flush. The
agent limits each stream to 1 MiB of unacknowledged output and, after process
exit, waits up to two seconds for worker completion and final acknowledgements.
A missed drain deadline produces a typed runtime error rather than a successful
exit with silently truncated output. The sidecar's bounded local-output pump
keeps signal/control polling independent from a stalled terminal consumer.
The sidecar
publishes a bounded private structured result so managed Lua `on_exit`
callbacks can distinguish the local bridge status from the authority process
status.

The runtime wire and sidecar bridge preserve raw stdio bytes. The convenience
Lua `Context:spawn()` callbacks deliberately inherit Neovim's line/list job
semantics and are not the binary API; `job_spec()` is the escape hatch for a
consumer that can own raw local process streams.

Capabilities fail closed. Compatible agents currently advertise only
`runtime_process_v1` and `runtime_pty_v1`, corresponding to attached pipe and
PTY execution. The protocol reserves detach/attach and workspace-watch message
types, but the agent returns `PersistenceUnavailable` for detachment and does
not advertise `workspace_watch_v1` until the persistent broker and watcher
lifecycle exist. Clients must check advertised capability bits rather than
inferring support from protocol types.

Runtime trust/ticket/control/result files are private local state with bounded
sizes, entry counts, ages, atomic publication/consumption, and fail-closed
permissions. Control messages carry only the opaque ticket identity, nonce,
and typed signal; process argv and environment are not repeated in signal
helper command lines. See [Workspace Runtime API v1](workspace-runtime.md) for
the editor-facing contract.

## Compatibility

`Request::Hello` is the sidecar-agent compatibility gate. Both package version
and protocol version must match exactly before ordinary remote work begins. The
sidecar reports mismatch as `remote_status = "unavailable"` in `remote_probe`,
`workspace_info`, and `workspace/remote_health` notifications so Neovim can
keep serving local mirror operations while the agent is fixed. `remote_health`
classifies `version_mismatch` and `protocol_mismatch` separately so clients can
suggest `RemoteUpdateAgent`; health/install/update remain available for repair.
