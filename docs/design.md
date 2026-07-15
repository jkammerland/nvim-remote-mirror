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
| `nrm-registry` | local library | Strict manifest/signature policy, HTTPS/file retrieval, verified cache |
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
| Agent install/update | Opt-in signed repair on SSH connect plus explicit commands; verify locally, activate transactionally, roll back failures |

## Remote Host and Agent Distribution

SSH host detection is lazy and shared across agent lanes. Linux, macOS, and
Windows hosts are normalized to x64 or ARM64 and one of six fixed Rust release
targets. POSIX launch/install uses shell scripts; Windows uses PowerShell 5.1
encoded commands and binary-safe stdio. Canonical Windows workspace targets use
`ssh://host/B:/repos/project`; UNC and drive-relative roots are outside the
supported model.

SSH agent launch has a bounded ordered stdout prelude before framed RPC. The
transport wrapper may report a narrow typed pre-exec failure or confirm
`READY`; after that point child stderr is diagnostics-only and cannot trigger
automatic replacement. Missing or invalid preludes and failures after `READY`
remain untyped, so bootstrap eligibility cannot be forged by agent output.

Agent distribution has two mutually exclusive sources:

- With no registry URL, automatic install is inactive. Explicit install/update
  streams the configured local `agent` file, and the caller owns
  OS/architecture selection.
- With a registry URL, the local sidecar verifies a detached Ed25519 signature,
  strict manifest policy, target, size, and SHA-256 before upload. Registry mode
  fails closed and cannot fall back to the local file.

Connect remains local-first and non-mutating unless SSH, a configured trusted
signed registry, and `remote_agent_auto_install` are all enabled. In that
opt-in mode it repairs only missing, non-executable, version-mismatched, or
protocol-mismatched agents; it does not mutate missing-root, unavailable, or
unclassified hosts. Failures leave a connected but degraded mirror. The
transaction holds a per-target lease across sidecar processes and reprobes
under that lease, so simultaneous connects cannot both replace the executable;
a live contender reports `install_in_progress`. POSIX per-process claims close
the lease-owner and operation-owner publication windows: a live claim prevents
ownerless state from being reaped, while malformed claim identities or file
types fail closed. Dead partial claim contents are safely ignored because the
strict token/PID filename is the liveness identity.
The
registry cache is a performance/reliability layer, not a trust anchor: current
keys, signatures, manifest policy, size, and digest are reverified on every
use. Only transient network/rate-limit/server failures may use a verified
cached manifest pair. See [agent-registry.md](agent-registry.md) for the full
trust and key-rotation model.

The remote transaction writes a stable same-directory recovery journal before
upload. The next per-target lease holder reconciles interrupted staging or
activation before probing the agent. Recovery removes or replaces files only
when the recorded paths, file types, prior state, and that journal's own
candidate/previous digests agree. A newer request's verified digest is applied
only to its subsequent transaction; malformed or file-hash-mismatched state
still fails closed and remains available for diagnosis.

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
