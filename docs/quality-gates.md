# Quality Gates

This repo has a local-first default gate and a smaller set of optional deep
checks. Keep the default gate deterministic, offline after dependencies are
cached, and practical for every code change.

## Default Gate

Run this before handing off substantial changes:

```sh
just check
```

`just check` covers:

- Rust formatting, clippy with `-D warnings` and documented unsafe-block
  enforcement, and workspace tests.
- Lua syntax for every tracked plugin, module, and test file. CI uses
  `luac5.1`; local runs prefer `luac5.1` and fall back to `luac`.
- Neovim version/capability preflight and headless Neovim tests.
- Bash syntax for scripts.
- `git diff --check`.

CI runs the same categories plus the small performance smoke. The Lua syntax
gate intentionally enumerates tracked files so new modules such as picker or
adapter helpers are checked without updating a hand-maintained file list.
Run `just ci` for the local equivalent of CI's required checks plus the small
performance smoke.

## Extra Local Checks

These checks need tools that are not required for the default developer setup:

```sh
just lint-extra
just audit
just miri-protocol
```

`just lint-extra` runs:

- `stylua --check lua plugin tests`
- `selene lua plugin tests`
- `bash -n scripts/*.sh`
- `shellcheck scripts/*.sh`

`just audit` runs `cargo audit -f Cargo.lock`. It should be used before
release, dependency bumps, and security-sensitive changes. `just audit-strict`
also denies warning-class advisories, but it is not clean today because
`bincode 1.3.x` is reported as unmaintained.

`just miri-protocol` runs only the `nrm-protocol` tests under Miri with strict
provenance enabled. That crate is the best sanitizer-like target because it owns
frame parsing and bincode round-trips without subprocess, SQLite, thread, or
filesystem dependencies.
If the recipe fails while Miri is building its sysroot, fix the local nightly
Miri/linker setup before treating the result as a repo test failure.

## Sanitizer Position

Do not add blanket sanitizer runs to `just check` yet.

- `nrm-agent` and `nrm-sidecar` rely on subprocesses, SQLite, threads, Unix file
  descriptors, and filesystem race tests. Miri is not a good whole-crate fit.
- AddressSanitizer can be useful for targeted Linux reproductions around the
  Unix `openat`/`renameat`/process-group code, but it needs nightly Rust,
  `rust-src`, a working system linker, and usually `-Zbuild-std`.
- ThreadSanitizer is unlikely to be a stable default gate until the sidecar has
  smaller isolated concurrency tests.

Prefer adding ordinary deterministic Rust tests around unsafe boundaries first:
pinned parent directory behavior, final symlink rejection, CAS recheck before
rename, subprocess shutdown, and queue hazard ordering.

## Current Follow-Ups

- Migrate the binary RPC codec off `bincode 1.3.x` or explicitly accept the
  unmaintained warning before making `audit-strict` a required gate.
- Decide whether CI should install and enforce `stylua`, `selene`, and
  `shellcheck`. The configs already exist; the tools are currently optional.
- Add protocol fuzzing if the sidecar-agent boundary becomes exposed to
  untrusted peers or if frame parsing grows more complex.
