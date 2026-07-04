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
| `mirror_root()` | Return the workspace mirror state root |
| `files_root()` | Return the local mirror files root |
| `remote_root()` | Return the remote workspace root |
| `is_remote_buffer(bufnr)` | Test whether a buffer belongs to a remote mirror workspace |
| `remote_path(bufnr_or_local_path)` | Convert a remote buffer or mirror-local path to a workspace-relative path |
| `local_path(remote_path)` | Convert a workspace-relative path to a mirror-local path |

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
| Formatters/linters | Need explicit local-vs-remote tool policy |
| Git plugins | Need a remote git adapter or sidecar git commands |
| Terminals | Need remote PTY/session support |
| DAP | Need remote debug adapter and path mapping |

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
