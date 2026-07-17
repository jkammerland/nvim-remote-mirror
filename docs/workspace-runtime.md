# Workspace Runtime Readiness API v2

The workspace runtime is a provider-neutral Lua contract for plugins that need
to run a command beside the authoritative project tree. It keeps workspace
identity, path translation, authorization, process validation, and lifecycle
handling outside individual plugin integrations.

API v2 is a breaking contract revision. It separates three facts that API v1
collapsed into capability booleans:

- **support** is static: the provider implements a capability;
- **readiness** is dynamic: the authority was checked and can provide it now;
- **authorization** is explicit: the user permits this workspace to execute it.

This is a strict v2 surface: `supports()`, `capability_status()`, `prepare()`,
prepared-facade enforcement, readiness revisions, and the callback rules below
are one atomic contract. There is no additive API-v1 compatibility layer and
no fallback after a v2 error.

The built-in `local` and `nrm` providers support attached pipe processes and
attached PTYs on the editor host, Linux SSH, macOS SSH, and native Windows SSH
workspaces. Detached or reconnectable sessions and workspace watching are not
advertised yet.

Connecting never runs an arbitrary workspace command, opens a terminal, or
grants runtime trust. Runtime execution starts only after an explicit API call
or `:RemoteTerminal` passes the v2 readiness and trust checks. The prepared
facade is the recommended path; the direct-call matrix below is the other
defined v2 path. The one automatic remote mutation remains the separately
configured, signed connect-time agent repair described below.

## Migrating from API v1

Earlier integrations commonly called `context:authorize()` and then called
`job_spec()`, `spawn()`, or `open_pty()` directly on the context. API v2
replaces that two-step contract with a capability-scoped prepared facade:

```lua
context:prepare("terminal", function(err, prepared)
  if err then
    vim.notify(err.message, vim.log.levels.ERROR)
    return
  end
  local bridge, bridge_err = prepared:job_spec({
    command = { shell = "default" },
    stdio = "pty",
  })
  if not bridge then
    vim.notify(bridge_err.message, vim.log.levels.ERROR)
  end
end)
```

Do not retry through `authorize()` or reinterpret legacy capability booleans
after a v2 readiness, trust, or stale-preparation error. That v2 result is
authoritative and must fail closed. Direct context execution still exists as a
v2 late-check path under the matrix below; it is not an API-v1 adapter.

## Resolve a context

Use the authority-aware broker to resolve an immutable API-v2 context:

```lua
local runtime = require("nvim_remote_mirror.workspace_runtime")

local context, err = runtime.resolve({ authority = "auto", bufnr = 0 })
if not context then
  vim.notify(err.message, vim.log.levels.ERROR)
  return
end

vim.print({
  api_version = context.api_version, -- 2
  workspace_id = context.workspace_id,
  state = context.state,             -- online/offline/connecting/reconnecting/error
  mode = context.mode,               -- local, mirror, or remote_nvim
  authority = context.authority,     -- kind, path_style, OS/CPU/shell/target hints
  roots = context.roots,             -- editor and authority roots
  process_supported = context:supports("process"),
  process_status = context:capability_status("process"),
})
```

The `authority` field is optional and accepts `auto`, `local`, or `remote`.
An explicit `local` or `remote` choice overrides automatic selection. `auto`
resolves in this order:

1. remote ownership recorded on the selected/current buffer;
2. the current tab's NRM binding; and
3. the built-in local provider rooted at that tab's cwd.

Once remote evidence is selected, every offline, malformed, untrusted, stale,
or readiness error is authoritative. The broker never retries locally. A
successful connection binds the tab where `connect()` started, not whichever
tab happens to be current after its asynchronous handshake. Disconnect keeps
that binding so it resolves offline and fails closed. `:RemoteUseLocal` clears
the current tab's binding and invalidates pending authority-aware preparation;
it does not disconnect, change cwd, or remove remote ownership from buffers.

Explicit `authority = "local"` is the escape hatch for a remote-owned buffer.
Explicit `authority = "remote"` chooses a remote buffer, then the current tab
binding, then the active NRM workspace. `require("nvim_remote_mirror").workspace()`
remains the remote-only compatibility resolver with its original active-NRM
fallback.

The local provider is rooted at the captured tab cwd. It is immediately ready
and trusted because it starts processes directly as the editor user, without a
sidecar or remote trust prompt. Local argv, contained cwd, and environment
changes still pass through the same v2 validation. Changing that tab's cwd
makes the retained local context stale.

The query accepts at most one selector:

| Selector | Meaning |
| --- | --- |
| none | Current buffer, tab binding, or local tab cwd according to authority selection |
| `bufnr` | Authority recorded on that buffer, including an offline remote buffer |
| `path` | A contained mirror-local or local-tab path |
| `workspace_id` / `workspace_key` | A known remote workspace identity |

An offline buffer still provides static `supports()` information. Its local
supported-capability status is `unchecked` (or `disabled` when runtime policy is
off), while `prepare()` and every execution path fail with `workspace_offline`;
resolving a context never implies that its authority is reachable.

The context captures one provider epoch plus the broker's tab/buffer selection
revision. Reconnect, disconnect, transport replacement, `:RemoteUseLocal`, and
buffer authority changes can make it stale. Before retaining a context across
asynchronous work, call `context:is_current()`; resolve a new context after a
`stale_context` error. Readiness has a separate monotonically increasing
revision because an authority can become unavailable without changing
workspace identity. A readiness change does not advance the workspace epoch.

API v2 removes public `context.capabilities`; those legacy wire-shaped booleans
mixed support with readiness. Plugin integrations call `supports()` and
`capability_status()` instead.

## Map paths and file URIs

`context:map_path(path, { from = ..., to = ... })` crosses between the editor
mirror and the authoritative workspace. The four spaces are `editor`,
`authority`, `editor_uri`, and `authority_uri`:

```lua
local remote_path = assert(context:map_path(vim.api.nvim_buf_get_name(0), {
  from = "editor",
  to = "authority",
}))

local local_uri = assert(context:map_path("file:///B:/repos/project/src/main.rs", {
  from = "authority_uri",
  to = "editor_uri",
}))
```

Mappings must cross from editor to authority or the reverse. They reject paths
outside either root, malformed percent encoding, controls, invalid UTF-8,
unsupported UNC paths, and invalid Windows drive roots or reserved segments.
Windows authority paths are normalized to forward-slash drive form.

## Support, status, and preparation

The implemented capability names are `process` and `terminal`. `watch` is
reserved for a later workspace-watch provider and currently reports
`unsupported` with the `nrm` provider.

`context:supports(capability)` is synchronous and local. It answers only
whether the provider implements that capability; it never probes SSH, checks
an agent, prompts for trust, or predicts whether execution will succeed. It
returns `true` for supported names and `false` for unsupported or unknown names.

`context:capability_status(capability)` is also synchronous and local. It
returns the latest immutable readiness snapshot, or `nil, invalid_argument`
for an unknown name:

```lua
local status, status_err = context:capability_status("terminal")
-- status = {
--   name = "terminal",
--   supported = true,
--   enabled = true,
--   state = "unchecked", -- unsupported, disabled, unchecked, checking, ready, unavailable
--   effective = nil,      -- true/false only when definitively known
--   revision = 0,
--   reason = nil,         -- bounded provider diagnostic when available
--   retry_after_ms = nil,
-- }
```

`capability_status()` never starts a probe. `unchecked` is not `unsupported`,
and a last-known capability must not be treated as ready when `state` is
`unavailable`. The `epoch` and readiness `revision` together identify a
snapshot.

`context:prepare(capability, callback)` is the recommended revision-bound
API-v2 execution gate. The direct v2 path described below remains
available, but it does not produce a facade that can be safely retained. For a
well-formed prepare call, the provider:

1. verifies the captured workspace epoch and static provider support;
2. performs a provider-owned, read-only authority probe when needed;
3. verifies the negotiated remote capability;
4. applies the configured workspace trust policy; and
5. rechecks the workspace epoch and readiness revision before returning a
   capability-scoped prepared facade.

```lua
local accepted, prepare_err = context:prepare("process", function(err, prepared)
  if err then
    vim.notify(err.message, vim.log.levels.ERROR)
    return
  end

  local handle, spawn_err = prepared:spawn({
    command = { argv = { "cargo", "check" } },
    cwd = { space = "workspace", path = "" },
  })
  if not handle then
    vim.notify(spawn_err.message, vim.log.levels.ERROR)
  end
end)
if not accepted then
  vim.notify(prepare_err.message, vim.log.levels.ERROR)
end
```

Invalid arguments, including a non-function callback, return `nil, err`
synchronously and do not invoke the callback. Once a well-formed call is
accepted, its callback is invoked exactly once as `(err, prepared)`. It may run
inline before `prepare()` returns when readiness and trust are cached, or later
after a probe or prompt. Callers must initialize callback-visible state before
invoking `prepare()` and must not depend on either timing. Disconnect, timeout,
denial, cancellation by workspace replacement, and provider failure all still
complete the callback exactly once. A callback exception is reported once and
does not cause redelivery.

Preparation may probe health and may update the private local trust store after
an explicit user decision. It never installs, updates, uploads, or replaces a
remote executable. Automatic agent repair remains restricted to
`:RemoteConnect` when SSH, a trusted signed registry, and
`remote_agent_auto_install = true` are all configured. `prepare()` resolves an
unchecked state with its read-only probe; a missing, incompatible, or
unavailable agent then returns a typed readiness error instead of initiating
repair. Explicit `:RemoteInstallAgent` and `:RemoteUpdateAgent` remain separate
user actions.

The default `remote_runtime.trust = "prompt"` asks before first execution and
stores an accepted grant in private local sidecar state. `"never"` denies runtime
execution. `"always"` is an explicit configuration opt-in that bypasses the
per-workspace prompt. The commands `:RemoteTrustWorkspace` and
`:RemoteUntrustWorkspace` manage the current workspace's persisted trust;
`:RemoteTrustWorkspace!` skips its confirmation and should be reserved for
intentional scripted setup.

Trust allows arbitrary programs in that workspace to execute as the remote
login account. It is an authorization boundary, not a sandbox. In particular,
on POSIX a program that deliberately daemonizes into another session may
outlive attached signal handling.

Runtime trust and bridge records require private local sidecar state. On
Windows the runtime fails closed if an existing `state_dir` ancestor grants an
untrusted principal write-data, write-attributes, delete, child-delete, DACL,
or owner mutation. If a profile has permissive or stale ACLs, point `state_dir`
at a pre-provisioned directory with inheritance disabled and access limited to
the current user and `SYSTEM`, or repair the unsafe ancestor. Production code
does not create a drive-root directory to bypass that policy.

Private state reduces cross-principal exposure; it is not a sandbox against
another process already running as the same account, or against a Windows
handle opened before an ACL was tightened.

## Process specification

All runtime entry points use the same structured process table:

```lua
local process = {
  command = { argv = { "rg", "--json", "TODO", "src" } },
  cwd = { space = "workspace", path = "tools" },
  env = {
    clear = false,
    set = { NO_COLOR = "1" },
    unset = { "PAGER" },
  },
  stdio = "pipe",             -- pipe or pty
  persistence = "attached",   -- detached is reserved, but unavailable today
  max_output_bytes = 4 * 1024 * 1024,
  timeout_ms = 30000,
}
```

Use `{ command = { shell = "default" } }` for the remote account's default
shell. A shell program must otherwise be explicit argv, for example
`{ "sh", "-lc", "make test" }`; arbitrary text is never accepted in the
`shell` field.

`cwd.space` can be:

- `workspace`: a forward-slash path relative to the authority root;
- `buffer`: the directory of the buffer used to resolve the context;
- `editor`: an absolute path below the mirror files root; or
- `authority`: an absolute path below the authoritative root.

The API normalizes every form to a contained workspace-relative directory.
Command arguments and remote environment values remain structured data through
the private, single-use sidecar ticket and binary runtime protocol. They are
not concatenated into an SSH command or exposed in the local bridge argv.
Arguments must be UTF-8 and control-free on every platform. This keeps one
portable contract even though native process APIs differ in which control
characters they can represent.

`max_output_bytes` applies only to pipe processes. It defaults to 4 MiB and is
bounded by a 128 MiB hard limit. Omit it for PTYs: PTY output is a live,
backpressured stream without a cumulative byte limit, and supplying the option
for a PTY is rejected rather than silently ignored.

Backpressure uses per-stream acknowledgements with at most 1 MiB in flight.
Acknowledgements follow the local bridge write/flush, not merely network
receipt. If final output cannot drain within the bounded shutdown deadline,
the request fails with a runtime error instead of reporting a clean exit with
lost bytes.

## Prepared facades and direct-call rules

A prepared facade is immutable and internally bound to one workspace identity,
epoch, readiness revision, and capability. Treat it as an opaque execution
receiver, not a transferable trust token: every ticket creation still rechecks
workspace identity, current trust, and the captured epoch/revision. The runtime
bridge then performs the definitive package/protocol/capability handshake
immediately before starting the process.

A workspace epoch or readiness-revision change makes an unused facade stale.
Its next execution method returns `stale_preparation`; resolve and prepare
again. A change after a bridge process has started does not
retroactively invalidate that attached process. Each `job_spec()` ticket is
still single-use, even when it came from the same prepared facade.

API v2 also defines direct context execution as a late-check path. It applies
the current capability state before it can mint a ticket:

| Receiver or capability state | API-v2 result |
| --- | --- |
| `context:supports(name)` | Static, local provider support |
| `context:capability_status(name)` | Latest local readiness snapshot; no probe |
| `context:prepare(name, callback)` | Asynchronous readiness and authorization gate |
| direct execution while `unchecked` | Allowed after validation and existing trust; the bridge handshake is definitive |
| direct execution while `ready` with `effective = true` | Allowed after validation and existing trust |
| direct execution while `checking`, or while the authority is unavailable | `capability_not_ready` |
| disabled capability | `capability_disabled` |
| unsupported capability | `unsupported` |
| ready authority that explicitly did not negotiate the capability | `capability_unavailable` |
| process facade `job_spec()` / `spawn()` with pipe stdio | Allowed |
| process facade `open_pty()` or PTY stdio | `unsupported` |
| terminal facade `job_spec()` / `spawn()` with PTY stdio | Allowed |
| terminal facade `open_pty()` | Allowed |
| terminal facade with pipe stdio | `unsupported` |
| facade after its epoch or readiness revision changes | `stale_preparation` |

The prepared path is recommended because one object binds the successful
readiness and authorization result to the execution receiver. The direct path
is intentionally a late-check v2 path; it must never interpret
`checking` or unavailable state as permission to fall back to an unchecked
assumption. `watch` will receive its own facade when a provider implements the
complete watcher lifecycle.

## Bridge for argv- or string-only plugin APIs

Use `prepared:job_spec(process)` when another plugin owns the local
job/terminal lifecycle. It returns:

- `argv`: authoritative local bridge argv;
- `command`: a canonical shell-escaped rendering for string-only local APIs;
- optional local `cwd`, `env`, and `clear_env` launch fields;
- broker-authored public `authority` identity; and
- `input.newline` for the authority shell.

For NRM, the executable bridge contains only the local sidecar path and an
opaque ticket ID. Remote cwd and environment remain private in that ticket;
the exposed cwd is only the local editor root and no remote environment is
returned. Local-provider environment changes are validated local job options.
Each NRM ticket is single-use, so create a new job spec for every start or
restart. Use `argv` whenever the consumer accepts a list; use `command` only
when its API is string-only. Do not reconstruct it or append
remote/user-provided shell text.

The broker derives `input.newline` from the authority shell. In particular,
Windows PowerShell uses `"\r"`, Windows cmd uses `"\r\n"`, and ordinary POSIX
shells use `"\n"`. This is authority metadata, not remote input embedded in the
local command.

The optional ToggleTerm integration consumes this contract without making
ToggleTerm a dependency of NRM:

```lua
require("nvim_remote_mirror.integrations.toggleterm").toggle({
  key = "shell",
  direction = "float",
  query = { authority = "auto" },
})
```

ToggleTerm's own `setup()` must have completed before the adapter is called. A
lazy-loading command stub is not sufficient; the adapter returns
`toggleterm_not_initialized` without replacing it. The adapter coalesces
repeated actions while preparation is pending, passes
`input.newline` as ToggleTerm's `newline_chr`, reuses one live attached PTY when
hidden/reopened, and creates a fresh prepared facade, ticket, and `Terminal`
after exit. The supported and CI-tested compatibility baseline is ToggleTerm
v2.13.1. Authority or tab-selection changes fail closed before a terminal is
created. It never falls back to a local shell. Broker-owned terminals are
registered as hidden with IDs outside Neovim's Ex-count range, and the adapter
replaces the raw `:ToggleTerm` command with a local-only path. That command
remains an explicitly local escape hatch. Advanced upstream commands that
explicitly include hidden terminals or a private managed ID are intentional
low-level access, not part of that escape-hatch guarantee. Public registration
for third-party workspace providers is not exported by this contract yet.

## Managed process and PTY handles

Use `prepared:spawn(process, handlers)` when the caller wants a managed pipe or
PTY process, or `prepared:open_pty(process, handlers)` on a terminal facade.
`open_pty()` sets `stdio = "pty"` and otherwise uses the same process schema.

Managed `on_stdout` and `on_stderr` handlers intentionally use Neovim's
line/list job-callback semantics; they are not a binary-transparent byte API
(Neovim represents embedded NUL bytes as line breaks). The sidecar/agent
runtime protocol and the `job_spec()` bridge remain byte-preserving. Consumers
that need raw bytes should own the bridge process through an argv-capable raw
process API rather than use managed handlers.

The built-in local provider enforces `timeout_ms` and the cumulative pipe
`max_output_bytes` limit, and starts managed PTYs with the requested character
dimensions. Neovim's local PTY primitive cannot set pixel dimensions, so a
local managed spawn that supplies them returns `unsupported` before starting a
process. A plugin using `job_spec()` owns the resulting bridge lifecycle and is
responsible for applying lifecycle limits supported by its own process API.

```lua
local handle, spawn_err = prepared:spawn({
  command = { argv = { "cargo", "check" } },
  cwd = { space = "workspace", path = "" },
}, {
  on_stdout = function(_, lines) vim.print(lines) end,
  on_stderr = function(_, lines) vim.print(lines) end,
  on_exit = function(_, local_code, _, result)
    -- result contains the authoritative runtime exit/error metadata when it
    -- could be read; local_code is the local bridge's exit status.
    vim.print({ local_code = local_code, runtime = result })
  end,
})
if not handle then
  vim.notify(spawn_err.message, vim.log.levels.ERROR)
  return
end

handle:write("input")
handle:close_stdin()
handle:signal("interrupt") -- interrupt, terminate, kill, or hangup
-- handle:kill()
```

Attached handles expose `write`, `close_stdin`, `signal`, and `kill`. PTY
handles also expose `resize({ cols = ..., rows = ... })`. No session ID or
reattach token is exposed for attached work.

For a ready-made split, use `:RemoteTerminal [cmd...]` or
`require("nvim_remote_mirror").open_terminal()`. In API v2 the Lua helper uses
a callback because it resolves and prepares terminal readiness before it
creates a split:

```lua
local accepted, terminal_err = require("nvim_remote_mirror").open_terminal({
  command = { "bash", "--noprofile" },
}, function(err, handle)
  if err then
    vim.notify(err.message, vim.log.levels.ERROR)
    return
  end
  -- The split is active; handle exposes the attached PTY controls.
end)
if not accepted then
  vim.notify(terminal_err.message, vim.log.levels.ERROR)
end
```

The helper follows the same acceptance and exactly-once callback rules as
`prepare()`: cached readiness and trust may let it open the split and invoke
the callback inline, while a probe or prompt completes later. Initialize any
callback-visible state before calling it and treat an accepted return as a
delivery promise, not a completion signal. With no command it opens the remote
default shell and enters terminal-input mode. The local bridge disables its own
terminal echo and input processing, so only the authoritative PTY echoes input
and handles control keys. Arguments are passed as an argv list, not as shell
text. `:RemoteTerminal` uses the same flow and reports preparation or launch
failures through Neovim notification regardless of callback timing.

`:RemoteTerminal!` requests detached persistence but currently fails with the
typed `persistence_unavailable` error until the persistent broker exists.

## Lifecycle events

Provider-neutral integrations can invalidate cached contexts with `User`
autocommands:

```lua
vim.api.nvim_create_autocmd("User", {
  pattern = {
    "NrmWorkspaceConnected",
    "NrmWorkspaceDisconnected",
    "NrmWorkspaceEpochChanged",
    "NrmWorkspaceReadinessChanged",
  },
  callback = function(event)
    -- Readiness events add readiness_state, readiness_revision, and effective
    -- to the normal epoch/workspace_key/target/state workspace event fields.
  end,
})
```

Treat event data as a hint. Connected, disconnected, and epoch-changed events
invalidate cached contexts. A readiness event does not change workspace
identity or epoch; discard prepared facades, call `capability_status()` for
current state, and call `prepare()` before the next execution. Readiness events
are coalesced for semantically identical authority state and effective
capabilities; a decreasing retry timer alone does not increment the revision.

A prepare result is rechecked against both captured epoch and readiness
revision. Disconnect or reconnect during preparation produces
`stale_context`; an already returned facade whose epoch or capability revision
changes produces `stale_preparation`. Neither case can execute in the old
authority state.

## Current limits

- Only attached pipe and PTY processes are available. Detached sessions,
  reattachment, and `workspace_watch_v1` are not advertised.
- Runtime execution requires an online, compatible, capability-negotiated
  agent, a current prepared facade or an allowed direct-call state, and explicit
  trust.
- `job_spec()` intentionally gives string-only consumers no structured final
  result callback; use `spawn()` when authoritative exit metadata matters.
- Output, input, argv, environment, path, timeout, and terminal-size limits are
  bounded and invalid specifications fail before a ticket is created.
- This is process orchestration, not code isolation. Remote commands run with
  the remote account's permissions.

Workspace context errors are tables with stable `code`, human-readable
`message`, and optional `details`; `tostring(err)` returns the message. Common
recoverable codes include
`workspace_not_found`, `workspace_offline`, `workspace_untrusted`,
`stale_context`, `stale_preparation`, `unsupported`, `capability_disabled`,
`capability_not_ready`, `capability_unavailable`, `invalid_path`,
`invalid_process_spec`, and `persistence_unavailable`.
