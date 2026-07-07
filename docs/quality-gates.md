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
performance smoke. CI also installs and runs the pinned optional lint/audit
tools listed below.

## Extra Local Checks

These checks need tools that are not required for the default developer setup:

```sh
just lint-extra
just audit-strict
just miri-protocol
just fuzz-protocol
```

`just lint-extra` runs:

- `stylua --check lua plugin tests` with StyLua `2.5.2` in CI.
- `selene lua plugin tests` with Selene `0.31.0` in CI.
- `bash -n scripts/*.sh`
- `shellcheck scripts/*.sh` with ShellCheck `0.10.0` in CI.

Selene uses the repo-local `vim.yml` standard-library shim to treat the Neovim
`vim` global as an available API while still linting ordinary Lua mistakes.

`just audit` runs `cargo audit -f Cargo.lock`. `just audit-strict` also denies
warning-class advisories and is part of `just ci`; CI installs cargo-audit
`0.22.1`.

`just miri-protocol` runs only the `nrm-protocol` library tests under Miri with
strict provenance enabled. It needs nightly Rust, Miri, and `clang` for the
local nightly sysroot build. That crate is the best sanitizer-like target
because it owns frame parsing and postcard round-trips without subprocess,
SQLite, thread, or filesystem dependencies.
If the recipe fails while Miri is building its sysroot, fix the local nightly
Miri/linker setup before treating the result as a repo test failure.

`just fuzz-protocol` runs the `cargo-fuzz` target for framed sidecar-agent RPC
decoding. It needs nightly Rust, `cargo-fuzz`, and `clang` for sanitizer-backed
linking. It is bounded to 30 seconds by default so it is useful as a local smoke
check; longer fuzzing belongs in explicit release or security work.
If it fails while linking sanitizer-instrumented build scripts, verify the local
nightly sanitizer/linker setup before treating the result as a fuzz target
failure.

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

- Keep `cargo audit -D warnings` clean as dependencies change.
- Decide whether to pin/install a specific Neovim release in CI instead of
  relying on the runner's apt package.
- Add longer scheduled fuzzing if the sidecar-agent boundary becomes exposed to
  untrusted peers or if frame parsing grows more complex.
