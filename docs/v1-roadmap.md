# Daily-Driver V1 Roadmap

This roadmap defines the remaining work to make `nvim-remote-mirror` usable as
a daily remote editing environment for local and SSH workspaces. V1 is not VS
Code Remote parity; it means the core open, save, search, LSP, and local-plugin
compatibility workflows are reliable enough to dogfood.

## V1 Definition Of Done

- Local and SSH workspaces support normal edit/save/reconnect workflows without
  losing local edits.
- File navigation and grep have remote-backed picker flows, not only hydrated
  mirror-local fallbacks.
- Save queue, failed saves, conflicts, and unreplayable rows are visible and
  actionable from the dashboard/UI.
- Remote LSP can be started, inspected, restarted, and stopped with predictable
  path rewriting and clear failure messages.
- Plugin compatibility has documented behavior for pickers, search, LSP,
  formatters, linters, git plugins, terminals, and DAP.
- `just check`, small perf smoke, local dogfood, and SSH dogfood all pass.

## Orchestration Model

Each sprint is a small vertical slice. The main integrator owns architecture,
review, final tests, and commits. Batch Codex and subagents are used for
bounded parallel work only.

- Use the `nvim-remote-mirror` skill before sprint implementation to preserve
  mirror, queue, path, and remote-worker invariants.
- Use `test-engineer` when adding tests or validating failure modes.
- Use `codex-mcp-server-usage` before batch Codex jobs.
- Use read-only batch Codex for fan-out analysis and end-of-sprint diff review.
- Use subagents only for disjoint implementation or exploration scopes.

Example batch-review shape:

```text
Task A: Review Lua dashboard and queue changes for stale callbacks and
disconnected behavior.
Task B: Review sidecar save queue changes for replay, conflict, and migration
edge cases.
Task C: Review docs and tests for user-visible behavior drift.
```

Keep these ownership boundaries stable while using workers:

- The integrator owns docs, command registration, final review, final tests, and
  commits.
- `crates/nrm-sidecar/src/main.rs` is single-owner per sprint because it owns
  command specs, mirror DB, queueing, scheduling, server sessions, and LSP
  proxy paths.
- `lua/nvim_remote_mirror/init.lua` is single-owner per sprint because it owns
  global client state, requests, reconnects, saves, find/grep, and LSP helpers.
- `lua/nvim_remote_mirror/ui.lua` is single-owner during Sprint 1 dashboard and
  conflict work.
- Any sidecar-agent protocol change must have one owner across
  `nrm-protocol`, `nrm-agent`, `nrm-sidecar`, Lua callers, and docs.

## Sprint 0: Source Of Truth

**Goal:** turn the v1 work into a single reviewable backlog.

**Implementation:**

- Keep this roadmap as the source of truth for v1 readiness.
- Link it from `docs/design.md` and `README.md`.
- Keep older `docs/architecture-user-stories.md` focused on completed
  architecture hardening stories.

**Acceptance:**

- Roadmap names scope, sprints, acceptance gates, test expectations, and
  orchestration rules.
- Docs-only change passes `just check`.

## Sprint 1: Dashboard, Queue, And Conflict UX

**User story:** As a remote editor user, I want queued saves and conflicts to
be obvious and actionable so I can recover without inspecting SQLite state or
raw quickfix entries.

**Implementation:**

- Add dashboard sections for remote health, queue counts, conflicts,
  unreplayable saves, reconnect/backoff, and last error.
- Add conflict actions: open local mirror file, open saved snapshot, open
  remote conflict copy, diff local vs remote, retry queued saves, and refresh.
- Diff conflicts against the durable snapshot when available, not only the live
  local mirror file.
- Add explicit resolve commands only when they preserve the save invariant that
  local saved bytes are durable before remote upload.
- Block accept-remote if the saved remote conflict copy is partial/truncated.
- Warn or refuse when resolving an older conflict while newer queued saves exist
  for the same path.
- Keep `ui.lua` focused on prompts/selectors; sidecar queue state remains in
  Rust.

**Code example:**

```vim
:RemoteWorkspace
:RemoteConflicts
:RemoteFlushQueue
```

**Acceptance:**

- Failed dashboard actions keep the dashboard visible.
- Conflict UI can show and diff local and remote copies.
- Large queues do not hide conflict rows.
- `pending`, `failed`, `conflict`, and `unreplayable` states are visible.

**Tests:**

- Lua: `tests/ui.lua`, `tests/save_queue.lua`, with new coverage for dashboard
  rendering, action selection, disconnected failure, stale callbacks, missing
  files, conflict diff actions, retry actions, and unreplayable rows.
- Rust: `cargo test -p nrm-sidecar --locked save_queue`, `conflict`, and
  `unreplayable` filters for queue counts, conflict state transitions, retry
  behavior, and replayability.

## Sprint 2: Picker And Search Compatibility

**User story:** As a user with existing picker/search plugins, I want remote
file and grep workflows that feel native while still using the sidecar for
remote truth.

**Implementation:**

- Add a small Lua adapter layer for remote file and grep picker sources.
- Add `require("nvim_remote_mirror.pickers").files(opts)` and
  `require("nvim_remote_mirror.pickers").grep(opts)` as the first public picker
  entry points.
- Add `nrm.grep_async(query, opts, callback)` so picker adapters can consume grep
  data without quickfix side effects.
- Provide generic APIs that optional integrations can call without making
  Telescope, fzf-lua, snacks, or other pickers required dependencies.
- Add `picker.provider = "auto"` configuration for builtin `vim.ui.select`
  selection; non-builtin provider names warn and fall back until plugin-specific
  adapters are implemented.
- Display workspace-relative paths; open selections through the Lua `open()` API.
- Prefer sidecar-backed `find_paths` and `grep` over scanning hydrated mirror
  files.

**Code example:**

```lua
local adapters = require("nvim_remote_mirror.adapters")

adapters.files({
  query = "src",
  on_select = function(item)
    require("nvim_remote_mirror").open(item.path)
  end,
})
```

**Acceptance:**

- Generic adapter works without optional picker plugins installed.
- Optional integrations fail softly when their plugin is absent.
- Picker results use remote-relative labels and mirror-safe open behavior.
- Search handles remote unavailable and cached fallback clearly.

**Tests:**

- Add `tests/adapters.lua` for no-plugin fallback, optional plugin absence,
  connected/disconnected states, bad paths, empty results, and stale callbacks.
- Existing Lua focus: `tests/find_generation.lua`,
  `tests/grep_cache_empty.lua`, and `tests/autohydrate_pending.lua`.
- Rust focus: `cargo test -p nrm-sidecar --locked find_paths`,
  `cargo test -p nrm-sidecar --locked grep_cache`, and
  `cargo test -p nrm-agent --locked grep`.

## Sprint 3: Remote LSP Daily-Driver Hardening

**User story:** As a user running remote language servers, I want LSP lifecycle
and path rewriting to be predictable across reconnects and common LSP features.

**Implementation:**

- Add LSP status/debug helpers for active proxy state, remote command, health,
  and last error.
- Harden start, stop, restart, reconnect, server crash, and remote unavailable
  paths.
- Track Neovim LSP client IDs by workspace identity and stop only matching
  remote-mirror clients on disconnect or workspace switch.
- Ensure sidecar LSP proxy shutdown closes child stdin, terminates or kills after
  a bounded grace period, joins pump threads, and reports clear exit reasons.
- Expand rewrite coverage for diagnostics, locations, code actions, rename,
  workspace edits, document changes, encoded file URIs, and prose strings.
- Include false-positive rewrite cases such as `file://` text inside prose,
  `file://localhost`, URI query/fragment parts, duplicate map-key collisions,
  and path-like-but-unrelated keys.
- Dogfood `rust-analyzer` first, then document server-specific caveats.

**Code example:**

```lua
require("nvim_remote_mirror").start_lsp({
  name = "rust-analyzer",
  cmd = { "rust-analyzer" },
})
```

**Acceptance:**

- LSP start skips clearly while remote is unavailable or in backoff.
- LSP restart and reconnect do not leave stale proxy state.
- URI/path rewriting does not rewrite unrelated prose or arbitrary object keys.
- Diagnostics and workspace edits resolve to mirror-local buffers.

**Tests:**

- Rust rewrite/proxy tests for LSP message shapes.
- Add `tests/lsp.lua` for start failure, status reporting, restart/reconnect
  behavior, and remote-unavailable UI where feasible.
- Focused commands: `cargo test -p nrm-sidecar --locked lsp`,
  `cargo test -p nrm-sidecar --locked rewrite`, and
  `cargo test -p nrm-sidecar --locked remote_health`.
- Manual dogfood script for `rust-analyzer` over local and SSH workspaces.

## Sprint 4: Formatters, Linters, And Git Policy

**User story:** As a user with normal development tooling, I want a clear policy
for whether tools run locally on mirror files or remotely through the sidecar.

**Implementation:**

- Document local-vs-remote policy for formatters, linters, and git plugins.
- Add remote command primitives only where required by concrete workflows.
- Start with remote git status, diff, and blame commands before attempting full
  git-plugin compatibility.
- Keep plugin caches and generated temp files outside the mirror root by
  default.

**Code example:**

```vim
:RemoteCd
:RemoteStatus
:RemoteGitStatus
:RemoteGitDiff
:RemoteGitBlame
" Local formatters may operate on hydrated mirror buffers.
" Remote git operations should go through nrm-provided commands.
```

**Acceptance:**

- Docs name supported and unsupported plugin classes.
- Git status/diff/blame can be obtained without local repo checkout semantics.
- Formatting a remote buffer does not bypass save queue safety.

**Status:** Started. Sidecar-backed `:RemoteGitStatus`, `:RemoteGitDiff`, and
`:RemoteGitBlame` are implemented as bounded remote agent commands. Full
git-plugin adapters remain future work.

**Tests:**

- Existing Lua focus: `tests/workspace_api.lua` and
  `tests/workspace_flush.lua` for path conversion, disconnected behavior, and
  bad paths.
- Rust focus: `cargo test -p nrm-sidecar --locked adopt` and
  `cargo test -p nrm-sidecar --locked flush`.
- Add protocol, sidecar, agent, and Lua command tests for any new remote
  git/tooling command.
- Manual checks with representative formatter/linter/git configurations.

## Sprint 5: Reliability, Performance, And Release Readiness

**User story:** As a daily user, I want install, health, recovery, and
performance checks that make failures diagnosable before data is at risk.

**Implementation:**

- Add explicit health and remote agent repair commands. Implemented:
  `:RemoteHealth`, `:RemoteInstallAgent[!]`, and `:RemoteUpdateAgent[!]`
  classify missing, incompatible, non-executable, and missing-root failures and
  originally uploaded the configured local agent over SSH. Signed registry mode
  later added verified native artifact selection without changing the commands.
  Connection-time repair is now automatic only for SSH clients that configure
  that trusted signed registry and leave `remote_agent_auto_install` enabled;
  default no-registry connections remain non-mutating.
- Sync configuration docs and help with Lua defaults, including prefetch,
  autohydrate, and queue replay delay options.
- Add failure-injection coverage for sidecar restart, agent kill, SSH drop,
  missing agent, missing snapshot, and remote reboot.
- Define performance budgets for scan, find, grep, open, save replay, and
  background mirror.
- Document required and optional quality gates, including Lua lint/format,
  dependency audit, and narrow Miri coverage for protocol parsing.
- Package release docs for local binary build and remote agent install.
- Decide the v1 support matrix explicitly. This was the original Ubuntu-only CI
  baseline; the current signed six-target release work supersedes it with
  native Linux, macOS, and Windows jobs.

**Code example:**

```vim
:RemoteWorkspace
:RemoteStatus
:RemoteHealth
:RemoteUpdateAgent
```

**Acceptance:**

- A new user can verify setup before connecting to a real workspace.
- Failure messages point to actionable fixes.
- Small perf smoke runs in CI; large perf smoke is documented for local runs.
- README and Vim help describe the v1 path clearly.

**Tests:**

- `just check`
- `just ci`
- `just lint-extra`
- `just audit`
- `just audit-strict`
- `just miri-protocol`
- `just fuzz-protocol`
- `scripts/perf_smoke.sh --small`
- `cargo bench --workspace --no-run --locked`
- Add `tests/health.lua` for healthcheck command behavior once implemented.
- Manual local workspace dogfood
- Manual SSH workspace dogfood

Manual local dogfood sequence:

```vim
:RemoteWorkspace
:RemoteConnect /path/to/local/repo
:RemoteScan
:RemoteFind src
:RemoteGrep needle
:RemoteOpen src/main.rs
:RemoteQueue
```

Manual SSH dogfood sequence:

```sh
ssh host 'command -v nrm-agent'
```

```vim
:RemoteConnect ssh://host/path/to/repo
:RemoteScan
:RemoteFind src
:RemoteGrep needle
:RemoteOpen src/main.rs
:RemoteFlushQueue
```

## Post-V1 Backlog

- Multi-client socket write coordination.
- Persistent remote terminal broker with detach, reattach, and replay.
- Provider-neutral workspace watch implementation.
- DAP launch and path mapping.
- Non-SSH transport factory and transport abstraction tests.
- Full plugin-specific adapters beyond the first picker/search integrations.
