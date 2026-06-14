# Design

## Goal

Build a local-first reusable remote workspace daemon for Neovim. Editing,
navigation, search, status, and basic LSP workflows should stay responsive over
slow or unstable SSH by using a durable checksum-verified local mirror.

SSH is the default transport today. The sidecar/agent boundary should stay
narrow enough to support a future QUIC or UDP-over-WireGuard transport without
changing Neovim commands.

## Architecture

| Part | Runs | Job |
| --- | --- | --- |
| Neovim plugin | local | UI, commands, buffers, quickfix, LSP client setup |
| `nrm-sidecar` | local | Mirror database, save queue, caching, scheduling |
| `nrm-agent` | remote or local | Filesystem reads, scans, hashes, grep, writes |
| Mirror directory | local | Hydrated file bytes and conflict/snapshot files |
| SQLite state | local | Metadata, indexes, queue state, scan progress |

## Core Behaviors

| Behavior | Rule |
| --- | --- |
| Open | Prefer cached mirror bytes, hydrate when missing |
| Find | Search known path metadata locally |
| Grep | Show cached results early, merge remote results when available |
| Save | Snapshot locally before upload |
| Conflict | Keep local save as truth and preserve remote copy |
| Background mirror | Scan, prefetch, and validate in small idle batches |
| Reconnect | Reuse mirror state and retry queued saves |

## Current Limits

| Limit | Direction |
| --- | --- |
| One active client per socket sidecar | Add multi-client coordination later |
| No streaming UI | Add incremental picker updates after API settles |
| Basic LSP proxy only | Harden path translation and server lifecycle |
| No terminal or DAP remoting | Keep behind the same sidecar boundary |
| SSH only | Add a transport factory after SSH behavior is stable |

## Next Milestones

1. Polish the dashboard and queue workflows.
2. Harden plugin compatibility through mirror path/root semantics.
3. Add provider adapters for file and grep pickers where mirror files are not enough.
4. Add conflict diff/resolve commands with explicit accept/retry actions.
5. Expand remote LSP dogfooding and status reporting.
6. Add transport abstraction tests before any non-SSH transport work.
