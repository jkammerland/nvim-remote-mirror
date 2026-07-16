# Plugin Compatibility

`nvim-remote-mirror` should make ordinary local Neovim plugins work against a
remote workspace whenever they can operate on local files and buffers.

The compatibility contract is the local mirror. Plugins see local paths under
the mirror files root. The sidecar keeps those paths connected to the remote
workspace through hydration, checksums, and the save queue.

## Public Lua Helpers

| Helper | Use |
| --- | --- |
| `current_workspace()` | Return the active workspace table, or `nil` |
| `workspace(query)` | Resolve an immutable provider-neutral workspace API-v2 context |
| `mirror_root()` | Return the workspace mirror state root |
| `files_root()` | Return the local mirror files root |
| `remote_root()` | Return the remote workspace root |
| `is_remote_buffer(bufnr)` | Test whether a buffer belongs to a remote mirror workspace |
| `remote_path(bufnr_or_local_path)` | Convert a remote buffer or mirror-local path to a workspace-relative path |
| `local_path(remote_path)` | Convert a workspace-relative path to a mirror-local path |
| `open_terminal(opts, callback)` | Asynchronously prepare and open an attached remote PTY in a split |

Path helpers intentionally operate on the current connected workspace. They
return `nil` for disconnected sessions, paths outside the mirror files root, or
workspace-relative paths that would escape the mirror root.

## Cwd Strategy

Use `:RemoteCd` to set the current tab's working directory to the mirror files
root. This makes cwd-based plugins behave like they are inside the project:

| Plugin behavior | Expected result after `:RemoteCd` |
| --- | --- |
| File tree rooted at cwd | Shows mirror files |
| Local file search | Searches hydrated mirror files |
| Buffer operations | Work normally on mirror buffers |
| Quickfix navigation | Opens mirror-local files |

`:RemoteCd` is tab-local. It does not change cwd in other tabs.

## Plugin Classes

| Plugin class | Current strategy |
| --- | --- |
| Motions, text objects, syntax | Work on local buffers |
| File pickers | Use mirror files or `require("nvim_remote_mirror.pickers").files()` |
| Grep/search | Prefer sidecar-backed `:RemoteGrep` or `pickers.grep()`; local grep only sees hydrated files |
| LSP | Run remote server through the LSP proxy with path translation |
| Formatters/linters | May edit hydrated mirror buffers locally; saves still flow through the mirror save queue |
| Git plugins | Use `:RemoteGitStatus`, `:RemoteGitDiff`, and `:RemoteGitBlame` for remote repository state |
| Terminals and command runners | Use workspace readiness API v2 for attached pipe processes or PTYs |
| DAP | Need remote debug adapter and path mapping |

## Generic Workspace Runtime

Plugins should not detect SSH targets, call `remote_health`, install an agent,
or build remote shell commands. Workspace Runtime Readiness API v2 separates
static provider support from current authority readiness. Resolve a
provider-neutral context with `require("nvim_remote_mirror").workspace()`, use
`supports()` or `capability_status()` only for UI decisions, and call
`prepare()` before execution. The returned prepared facade exposes the
narrowest runtime surface:

API v2 is the breaking WIP migration target. It has no API-v1 compatibility
layer: a plugin must require `context.api_version == 2` and must not retry a
failed v2 operation through legacy authorization or capability assumptions.

| Surface | Use |
| --- | --- |
| `context:supports(capability)` | Synchronously inspect static provider support; never infer readiness |
| `context:capability_status(capability)` | Read the latest local readiness snapshot without probing |
| `context:prepare(capability, callback)` | Asynchronously probe readiness, negotiate capability, and authorize trust |
| `prepared:job_spec(process)` | A plugin already owns the local job or terminal and accepts argv or a command string |
| `prepared:spawn(process, handlers)` | The integration needs a managed attached pipe or PTY process and exit metadata |
| `prepared:open_pty(process, handlers)` | The integration needs a managed attached PTY |
| `:RemoteTerminal [cmd...]` | A user wants a terminal split without writing an adapter |

`prepared:job_spec()` returns authoritative local bridge `argv` plus a canonical
`command` rendering for string-only APIs. Remote argv, cwd, and environment
remain structured in a private single-use ticket until the sidecar bridge; do
not append shell text to the returned command. This lets ToggleTerm and similar
plugins consume one generic contract instead of requiring core patches for
each terminal UI.

`prepare()` is read-only with respect to the authority: it may probe the agent
and may persist an explicit decision in the private local trust store, but it
never installs or updates a remote executable. Configured signed automatic
repair occurs only as part of connect. A missing or incompatible agent therefore
completes the plugin's prepare callback once with a typed readiness error; the
plugin does not implement a repair branch.

For every accepted prepare call, the callback runs exactly once. It may run
inline when readiness and trust are cached, or later after a probe or prompt;
initialize callback-visible state before invoking `prepare()`. The prepared
facade is bound to one workspace epoch, readiness revision, and capability. A
stale facade fails with `stale_preparation`; using a process facade for PTY
stdio, or a terminal facade for pipe stdio, fails with `unsupported`.

Direct `context:job_spec()`, `context:spawn()`, and `context:open_pty()` remain
as a v2 late-check path. They are allowed only while the requested capability
is `unchecked`, or `ready` with `effective = true`, and after existing trust is
verified. `checking` or an unavailable authority returns
`capability_not_ready`; disabled, unsupported, and explicitly unnegotiated
capabilities return `capability_disabled`, `unsupported`, and
`capability_unavailable`, respectively. The runtime bridge still performs the
definitive Hello. New integrations should use the prepared facade so successful
readiness, authorization, and later execution are bound to one revision.

Contexts are epoch-bound. Resolve again after `stale_context`, disconnect, or
reconnect, or invalidate cached contexts on the `NrmWorkspaceConnected`,
`NrmWorkspaceDisconnected`, and `NrmWorkspaceEpochChanged` `User` events.
`NrmWorkspaceReadinessChanged` does not change identity: retain the context if
desired, discard prepared facades, inspect `capability_status()`, and prepare
again.

Only attached processes and PTYs are available today. Detached/reconnectable
sessions and workspace watching are not advertised. See
[Workspace Runtime Readiness API v2](workspace-runtime.md), including the ToggleTerm
adapter example, trust model, path/URI mapping, handles, and failure modes.

## Formatter, Linter, And Git Policy

Formatters and linters that operate on the current buffer can run locally
against hydrated mirror files. They must not write project caches, generated
state, or temporary artifacts under the mirror files root unless those files
should be adopted into the remote workspace.

Git state belongs to the remote workspace, not the mirror directory. Local git
plugins should not assume the mirror is a checkout. Use the sidecar-backed
commands instead:

| Command | Result |
| --- | --- |
| `:RemoteGitStatus [path...]` | Remote `git status --porcelain` entries in quickfix |
| `:RemoteGitDiff [path]` | Remote diff in a `nofile` diff scratch buffer |
| `:RemoteGitBlame [path]` | Remote blame output in quickfix |

These commands invoke `git` beside the remote root through the agent with
workspace-relative pathspecs and bounded output capture. They are primitives for
daily use, not a full fugitive/gitsigns/neogit compatibility layer.

## Write Adoption Caveat

By default, saving a new file under the mirror files root does not create it
remotely. Use `:RemoteAdopt [path]` when the file should become a
workspace-relative remote path. Setting `adoption_policy = "auto"` restores the
legacy behavior where mirror-root files are adopted automatically.

After `:RemoteCd`, cwd-based plugins are more likely to write under the mirror
files root. Keep plugin caches and temporary output outside that root unless the
files should exist remotely. Good examples are `$XDG_CACHE_HOME`, `/tmp`,
plugin-specific state directories, or an explicit remote-intended generated
directory.

## Adapter Rule

Add adapters only when a plugin needs behavior that local mirror files cannot
provide. The preferred order is:

1. Let the plugin operate on mirror files unchanged.
2. Provide small path/root helpers.
3. Add a focused adapter for remote-only behavior.
4. Avoid making general UI plugins required dependencies.

The first generic adapter is `require("nvim_remote_mirror.pickers")`. It uses
sidecar-backed file and grep APIs with builtin `vim.ui.select` selection.
Plugin-specific Telescope/fzf/snacks sources are future work; non-builtin
provider names warn and use builtin selection today. Data-only integrations
should call `require("nvim_remote_mirror").grep_async()` instead of scraping
quickfix.
