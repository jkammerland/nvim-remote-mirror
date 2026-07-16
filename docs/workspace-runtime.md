# Workspace Runtime API v1

The workspace runtime is a provider-neutral Lua contract for plugins that need
to run a command beside the authoritative project tree. It keeps workspace
identity, path translation, authorization, process validation, and lifecycle
handling outside individual plugin integrations.

The current `nrm` provider supports attached pipe processes and attached PTYs
on local, Linux SSH, macOS SSH, and native Windows SSH workspaces. Detached or
reconnectable sessions and workspace watching are not advertised yet.

Connecting never runs an arbitrary workspace command, opens a terminal, or
grants runtime trust. Runtime execution starts only after an explicit API call
or `:RemoteTerminal`, and only after the workspace has been authorized.

## Resolve a context

Use `require("nvim_remote_mirror").workspace(query)` to resolve an immutable
API-v1 context:

```lua
local nrm = require("nvim_remote_mirror")

local context, err = nrm.workspace({ bufnr = 0 })
if not context then
  vim.notify(err.message, vim.log.levels.ERROR)
  return
end

vim.print({
  api_version = context.api_version, -- 1
  workspace_id = context.workspace_id,
  state = context.state,             -- online/offline/connecting/reconnecting/error
  mode = context.mode,               -- mirror or remote_nvim
  authority = context.authority,     -- kind, path_style, OS/CPU/shell/target hints
  roots = context.roots,             -- editor and authority roots
  capabilities = context.capabilities,
})
```

The query accepts at most one selector:

| Selector | Meaning |
| --- | --- |
| none | Current remote buffer, falling back to the active workspace |
| `bufnr` | Workspace recorded on that buffer, including an offline buffer |
| `path` | A mirror-local path inside a known workspace |
| `workspace_id` / `workspace_key` | A known workspace identity |

The context captures one provider epoch. Reconnect, disconnect, and transport
replacement advance the epoch. Before retaining a context across asynchronous
work, call `context:is_current()`; resolve a new context after a
`stale_context` error. Execution methods also reject stale or offline contexts.

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

## Authorize execution

Authorization is explicit and capability-specific:

```lua
context:authorize("process", function(err, granted)
  if err or not granted then
    vim.notify(err and err.message or "workspace execution denied", vim.log.levels.ERROR)
    return
  end

  -- Create or start the process here. job_spec(), spawn(), and open_pty()
  -- fail closed if called before the workspace is trusted.
end)
```

The implemented capability names are `process` and `terminal`. `watch` is
reserved for a later workspace-watch provider and currently returns
`unsupported` with the `nrm` provider.

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

## Bridge for argv- or string-only plugin APIs

Use `context:job_spec(process)` when another plugin owns the local job/terminal
lifecycle. It returns:

- `argv`: authoritative local bridge argv;
- `command`: a canonical shell-escaped rendering for string-only local APIs;
- optional `cwd`; and
- no remote environment or private lifecycle metadata.

The bridge contains only the local sidecar path and an opaque ticket ID. Each
ticket is single-use, so create a new job spec for every start or restart. Use
`argv` whenever the consumer accepts a list; use `command` only when its API is
string-only. Do not reconstruct it or append remote/user-provided shell text.
A string-only consumer may add only its own fixed local bookkeeping syntax
according to that consumer's documented command rules.

For example, ToggleTerm can consume the generic bridge without an nrm-specific
patch:

```lua
local Terminal = require("toggleterm.terminal").Terminal
local nrm = require("nvim_remote_mirror")

local function open_remote_toggleterm()
  local context, resolve_err = nrm.workspace({ bufnr = 0 })
  if not context then
    vim.notify(resolve_err.message, vim.log.levels.ERROR)
    return
  end

  context:authorize("terminal", function(auth_err, granted)
    if auth_err or not granted then
      vim.notify(auth_err and auth_err.message or "workspace execution denied", vim.log.levels.ERROR)
      return
    end

    local bridge, bridge_err = context:job_spec({
      command = { shell = "default" },
      cwd = { space = "workspace", path = "" },
      stdio = "pty",
      persistence = "attached",
    })
    if not bridge then
      vim.notify(bridge_err.message, vim.log.levels.ERROR)
      return
    end

    Terminal:new({
      cmd = bridge.command, -- ToggleTerm's command option is string-only
      dir = bridge.cwd,
      close_on_exit = true,
    }):toggle()
  end)
end
```

ToggleTerm appends its own fixed separator/comment marker to identify the local
terminal buffer; it does not append remote data or change the private ticket.
The ticket is one-shot, so every process respawn must call `job_spec()` again
and construct a fresh `Terminal` (the function above does this). The validation
contract itself is provider-neutral. Public registration for third-party
workspace providers is not exported in API v1 yet.

## Managed process and PTY handles

Use `context:spawn(process, handlers)` when the caller wants a managed pipe
process, or `context:open_pty(process, handlers)` for a PTY. `open_pty()` sets
`stdio = "pty"` and otherwise uses the same process schema.

Managed `on_stdout` and `on_stderr` handlers intentionally use Neovim's
line/list job-callback semantics; they are not a binary-transparent byte API
(Neovim represents embedded NUL bytes as line breaks). The sidecar/agent
runtime protocol and the `job_spec()` bridge remain byte-preserving. Consumers
that need raw bytes should own the bridge process through an argv-capable raw
process API rather than use managed handlers.

```lua
local handle, spawn_err = context:spawn({
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
`require("nvim_remote_mirror").open_terminal()`. With no command it opens the
remote default shell and enters terminal-input mode. The local bridge disables
its own terminal echo and input processing, so only the authoritative PTY
echoes input and handles control keys. Arguments are passed as an argv list,
not as shell text.
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
  },
  callback = function(event)
    -- event.data contains epoch, workspace_key, target, and state, plus a
    -- reconnect/reason field when applicable.
  end,
})
```

Treat event data as a hint and resolve a fresh context before executing. An
async authorization result is also rechecked against the captured epoch, so a
disconnect or reconnect turns it into `stale_context` instead of executing in
the wrong workspace.

## Current limits

- Only attached pipe and PTY processes are available. Detached sessions,
  reattachment, and `workspace_watch_v1` are not advertised.
- Runtime execution requires an online, compatible agent and explicit trust.
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
`stale_context`, `unsupported`, `invalid_path`, `invalid_process_spec`, and
`persistence_unavailable`.
