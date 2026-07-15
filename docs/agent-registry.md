# Signed agent registry operations

The agent registry is an optional distribution channel for native `nrm-agent`
executables. No registry URL is configured by default. When an SSH connection,
a configured trusted signed registry, and the default
`remote_agent_auto_install = true` are all in effect, connection setup can
install or repair the agent automatically. Explicit `:RemoteInstallAgent` and
`:RemoteUpdateAgent` commands remain available, and setting
`remote_agent_auto_install = false` keeps registry operations explicit.

Registry trust is configured out of band in Neovim. A registry response cannot
add or replace a trusted key. The Rust sidecar validates that every configured
key is a canonical, nonweak Ed25519 curve point before any registry retrieval.

```lua
require("nvim_remote_mirror").setup({
  remote_agent_auto_install = true,
  remote_agent_registry_url =
    "https://github.com/owner/repo/releases/download/v{version}/nrm-agent-manifest-v1.json",
  remote_agent_registry_public_keys = {
    ["release-2026-q3"] = "<standard-base64-encoded-32-byte-Ed25519-key>",
  },
  remote_agent_registry_signature_threshold = 1,
})
```

Automatic bootstrap and explicit install/update both fail closed in registry
mode: they never fall back to an unsigned local executable. Without a registry
URL, automatic bootstrap is inactive; only explicit install/update can upload
the configured local executable.

The protected six-target build, exact signer-set gate, provenance verification,
and immutable GitHub Release procedure are documented in [releasing.md](releasing.md).

## Published files

Each immutable versioned release contains one native executable for every
supported target, one manifest, and one detached-signature document:

```text
nrm-agent-0.1.0-x86_64-unknown-linux-musl
nrm-agent-0.1.0-aarch64-unknown-linux-musl
nrm-agent-0.1.0-x86_64-apple-darwin
nrm-agent-0.1.0-aarch64-apple-darwin
nrm-agent-0.1.0-x86_64-pc-windows-msvc.exe
nrm-agent-0.1.0-aarch64-pc-windows-msvc.exe
nrm-agent-manifest-v1.json
nrm-agent-manifest-v1.json.sig
```

The manifest is strict JSON. It contains exactly the published bytes' target,
filename, size, and lowercase SHA-256 digest. Artifacts are sorted by target so
release output is deterministic.

```json
{
  "schema_version": 1,
  "package": "nrm-agent",
  "version": "0.1.0",
  "protocol_version": 7,
  "source_commit": "0123456789abcdef0123456789abcdef01234567",
  "artifacts": [
    {
      "target": "aarch64-apple-darwin",
      "filename": "nrm-agent-0.1.0-aarch64-apple-darwin",
      "sha256": "<64-lowercase-hex-characters>",
      "size": 1234567
    }
  ]
}
```

Sign the manifest bytes exactly as published. Do not parse and reserialize the
manifest before signing or verification. The adjacent `.sig` file is strict
JSON with distinct key IDs and standard-base64 Ed25519 signatures:

```json
{
  "schema_version": 1,
  "signatures": [
    {
      "key_id": "release-2026-q3",
      "signature": "<standard-base64-encoded-64-byte-Ed25519-signature>"
    }
  ]
}
```

The release job must re-download and verify the complete draft release before
publishing it. Once published, the version tag and every release asset are
immutable.

## Connection-time bootstrap

After local-only `workspace_info` completes, the Lua client requests automatic
update/repair only when all of these conditions hold:

- the target uses SSH;
- `remote_agent_registry_url` and its out-of-band trust policy are configured;
- `remote_agent_auto_install` is `true`; and
- the sidecar advertises `remote_agent_automatic_bootstrap_v1` support.

The versioned capability is required because the older generic
`remote_agent_bootstrap` capability only describes explicit install/update and
does not guarantee that the sidecar enforces automatic-request restrictions.

The sidecar independently enforces signed-registry and SSH requirements. An
automatic request uses update semantics, cannot set `force = true`, and applies
this health policy:

| Agent health | Automatic action |
| --- | --- |
| `ok` | Skip without fetching an artifact |
| `missing_agent` | Install the verified candidate |
| `agent_not_executable` | Transactionally replace with the verified candidate |
| `version_mismatch` | Transactionally replace with the verified candidate |
| `protocol_mismatch` | Transactionally replace with the verified candidate |
| Any other state | Skip without mutating the host |

The last row includes `remote_root_missing`, unavailable, and unclassified
failures. These can indicate a target, transport, permission, or policy problem
that agent replacement must not try to repair.

Automatic bootstrap completes before connect-time save recovery, queue flush,
or background mirror work begins. If registry verification, download, staging,
activation, or rollback fails, Neovim still finishes the local-first
connection in a degraded state. The Bootstrap and Registry dashboard fields
retain the failure; no unsigned fallback is attempted.

Automatic bootstrap uses derived socket paths only. A configured fixed
`socket_path` cannot incorporate the current sidecar executable identity, so
the client skips automatic mutation with a stable diagnostic instead of
trusting a potentially stale daemon. Leave `socket_path` unset for automatic
bootstrap, or restart a fixed-path daemon and use the explicit install/update
commands.

Once the sidecar accepts an automatic update, the transaction is not canceled
from Neovim. An explicit disconnect immediately detaches the editor and queues
the sidecar disconnect request, but preserves a stdio sidecar until the
snapshotted bootstrap callback deadline (including its delivery grace) so
activation or rollback can finish. Socket clients may close their channel while
the detached daemon completes the bounded transaction. The sidecar's absolute
bootstrap deadline remains authoritative; this behavior does not extend its
forward-work budget.

Install and update are serialized across sidecar processes by a per-target
remote lease. The lease remains held through the post-acquisition health probe,
staging, validation, activation, rollback, and cleanup. A second automatic
request reprobes while holding the lease and skips if the first request already
installed a compatible agent; otherwise a live holder fails the contender with
`install_in_progress`. POSIX operation guards and Windows exclusive
delete-on-close markers keep an in-flight mutation protected if the long-lived
holder process exits. Stale state is removed only when ownership can be proven
dead; malformed or ambiguous state fails closed. On POSIX, adjacent
per-process claims are published before creating the fixed lease or operation
directory. A live claim protects the owner-publication window, and an
ownerless directory is reaped only after every well-formed claim identity is
proven dead. Malformed names or file types fail closed, while a dead partial
claim is recovered from its strict token/PID filename without trusting its
contents.

Each transaction publishes a stable same-directory journal before the artifact
upload starts. After a process or connection interruption, the next lease
holder reconciles that journal before its health probe. A prepared partial
upload is removed only when it is the exact derived regular file and the
original target state still matches. Later phases either restore the recorded
previous executable or finish safe cleanup of an already committed candidate.
Recovery uses the candidate and previous SHA-256 digests recorded by that
interrupted transaction. A newer request's verified digest authorizes only the
new staging/activation transaction, so a historical-digest difference is not
itself malformed. Malformed records, unexpected paths or file types, and file
hash mismatches are preserved and reported instead of guessed away. The journal
is a crash-recovery record, not an additional source of trust.

POSIX install-directory components are created individually under `umask 077`
and validated before descending. The final directory must be a non-symlink
directory owned by the login UID with no group/world write bits. Physical
ancestors must be root/login-owned and non-shared-writable, except for sticky
physical ancestors (for example Linux `/tmp` or macOS `/private/tmp`). The final
directory cannot be a symlink; root/login-owned ancestor symlinks are accepted
only when their resolved physical chain passes the same checks. Recovery
journals must be login-owned mode `0600`.

The remote login account is the installation trust boundary. POSIX activation
records the prior and candidate SHA-256 digests and rechecks them immediately
before destructive steps, so observed non-cooperating replacements are
preserved and reported. Portable shell cannot provide a kernel-atomic
compare-and-swap against a hostile process running as the same remote user in
the final check/rename window; such a process can already modify the installed
binary directly. Windows uses native replacement and exclusive file handles.

## Client verification

For an automatic bootstrap or explicit registry-backed install/update, the
sidecar:

1. Detects the remote operating system and architecture and selects one of the
   six fixed Rust targets.
2. Expands the single `{version}` placeholder in the configured URL.
3. Downloads the manifest and adjacent signature document with bounded sizes,
   time, and redirects.
4. Verifies the configured Ed25519 threshold over the unmodified manifest
   bytes.
5. Strictly validates package version, protocol version, target uniqueness,
   filenames, sizes, and digests.
6. Streams the selected artifact into a local verified cache, then rechecks its
   size and SHA-256 digest before every use.
7. Uploads the verified bytes through SSH and performs the transactional remote
   install, including staged and post-activation Hello checks.

Registry documents are limited to 1 MiB for the manifest and 64 KiB for the
signature document. Each artifact is limited to 128 MiB. HTTPS follows at most
five redirects, never downgrades to another scheme, never forwards URL
credentials, and rejects private or local literal redirect destinations.
`file://` artifacts must remain regular files inside the manifest directory.

## Cache and failure policy

Raw manifests and signatures are cached by expanded manifest URL. Artifacts are
cached by SHA-256 digest. A cache hit is not treated as permanently trusted:
the current trusted keys and threshold, signature, manifest policy, artifact
size, and artifact digest are verified again on every use.

A previously verified cached manifest/signature pair may replace a failed
current document retrieval only after a timeout, connection failure, rate
limit, or 5xx response. A content-addressed artifact may be a normal cache hit
after a freshly verified manifest. The sidecar never substitutes an older
manifest/signature pair after:

- a malformed manifest or signature document;
- an invalid or insufficient signature set;
- an unexpected package, version, protocol, target, filename, size, or digest;
- a 4xx response other than a rate limit;
- a redirect, URL, filesystem-containment, or other policy violation.

This distinction prevents a malicious current response from being hidden by a
previously valid cache entry.

Fallback is best-effort, not guaranteed. Budget enforcement can evict older
entries, and a budget that cannot retain both the selected artifact and its raw
manifest/signature pair can leave the artifact available for an online cache
hit while making a later offline manifest fallback impossible. Size the cache
for the native artifacts and release history that must remain available.

## Deadline and diagnostics

`remote_agent_registry_timeout_ms` is one absolute deadline for an automatic or
explicit registry-backed install/update, not only an HTTP timeout. It starts
when the sidecar accepts the request and also bounds host detection, cache
locking, download, staging, both validation probes, activation, rollback, and
cleanup. The sidecar clips each nested timeout to the remaining budget and
retains a bounded recovery reserve. Neovim waits that configured duration plus
one second for the final reply.
Local filesystem calls are checked immediately before and after execution and
streaming work is checked between 64 KiB chunks. A single kernel-stalled syscall
is not portably preemptible, but expiry prevents cache fallback or any later
bootstrap phase from starting.

`:RemoteWorkspace`, `:RemoteHealth`, hello/status results, and remote-health
notifications include `registry_health`. Its state is `not_checked`,
`fetching`, `verified`, or `error` when registry mode is enabled (`disabled`
otherwise). The dashboard additionally shows whether automatic bootstrap is
disabled, installing, ready, skipped, or in error, plus its result, skip reason,
or error. Registry diagnostics include the detected OS/architecture/path style
and selected Rust target, a redacted manifest URL, sorted verified signing key
IDs, artifact and manifest SHA-256 values, network/file/cache sources,
cache-hit/fallback flags, and a stable `error_code`. Registry failures do not
overwrite the health of an already working remote agent.

## Key rotation

With the default threshold of one, use an overlap period:

1. Generate the new Ed25519 signing key in the protected release environment.
   Distribute its public key and key ID to users through the same out-of-band
   channel used for the original trust bootstrap.
2. Configure clients to trust both the old and new public keys.
3. Publish every manifest with signatures from both keys during the overlap.
4. Confirm that updated clients verify the new signature.
5. Stop publishing the old signature, then remove the old public key from
   client configurations after the supported client population has migrated.

Increasing the signature threshold is a separate policy migration. Publish
enough overlapping signatures and update clients' trusted key sets before
raising the threshold. Otherwise automatic and explicit installs/updates
correctly fail closed.

If a key is compromised, remove it from client trust configuration through the
out-of-band channel, rotate release credentials, and publish with unaffected
keys. Cached manifests are reverified against the current trust set, so a cache
entry signed only by the removed key stops being usable. This model cannot
revoke a key on clients that have not received the trust update.

## Security boundaries and limitations

The registry is an immutable signed-manifest design, not TUF. It authenticates
the exact manifest and artifact digest, but it does not provide independent
freshness metadata, repository-wide rollback protection, delegated roles, or
online compromise recovery. Operators must publish immutable versioned
releases and distribute trusted public-key changes independently.

Registry authentication, custom HTTP headers, plain HTTP, server-provided trust
keys, and non-SSH installation transports are intentionally unsupported. UNC
and drive-relative Windows paths are also unsupported; use canonical targets
such as `ssh://host/B:/repos/project`.
