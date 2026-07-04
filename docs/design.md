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
| One active client per socket sidecar | `workspace_info` reports `client_mode = "single_writer"`; add multi-client coordination later |
| No streaming UI | Add incremental picker updates after API settles |
| Basic LSP proxy only | Harden path translation and server lifecycle |
| No terminal or DAP remoting | Keep behind the same sidecar boundary |
| SSH only | Add a transport factory after SSH behavior is stable |

## Next Milestones

The current daily-driver v1 sprint plan lives in [v1-roadmap.md](v1-roadmap.md).
In priority order, it covers dashboard and queue workflows, picker/search
compatibility, remote LSP hardening, formatter/linter/git policy, and release
readiness.

See [architecture-user-stories.md](architecture-user-stories.md) for the
reviewed user stories behind the current architecture hardening work.
