set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

toolchain := "1.95.0"
target_dir := "target/rustup-1.95.0"
cargo := `if command -v rustup >/dev/null 2>&1; then rustup which --toolchain 1.95.0 cargo; else command -v cargo; fi`
rustc := `if command -v rustup >/dev/null 2>&1; then rustup which --toolchain 1.95.0 rustc; else command -v rustc; fi`
rustdoc := `if command -v rustup >/dev/null 2>&1; then rustup which --toolchain 1.95.0 rustdoc; else command -v rustdoc; fi`
luac := `if command -v luac5.1 >/dev/null 2>&1; then command -v luac5.1; else command -v luac; fi`

fmt-check:
    RUSTC={{rustc}} RUSTDOC={{rustdoc}} CARGO_TARGET_DIR={{target_dir}} {{cargo}} fmt --all --check

clippy:
    RUSTC={{rustc}} RUSTDOC={{rustdoc}} CARGO_TARGET_DIR={{target_dir}} {{cargo}} clippy --workspace --all-targets --locked -- -D warnings -D clippy::undocumented_unsafe_blocks

rust-test:
    RUSTC={{rustc}} RUSTDOC={{rustdoc}} CARGO_TARGET_DIR={{target_dir}} {{cargo}} test --workspace --locked

lua-syntax:
    git ls-files -z '*.lua' | xargs -0 {{luac}} -p

nvim-preflight:
    nvim --headless --clean +'lua local v = vim.version(); if v.major == 0 and v.minor < 10 then error(string.format("nvim-remote-mirror requires Neovim 0.10+, got %d.%d.%d", v.major, v.minor, v.patch or 0)) end; if vim.fn.exists("*readblob") ~= 1 then error("nvim-remote-mirror requires readblob()") end' +qa

lua-test: nvim-preflight
    find tests -maxdepth 1 -name '*.lua' -print0 | sort -z | while IFS= read -r -d '' test; do nvim --headless -u NONE -l "$test"; done

shell-syntax:
    bash -n scripts/*.sh

whitespace:
    git diff --check

lua-format-check:
    if ! command -v stylua >/dev/null 2>&1; then echo "stylua is required: cargo install stylua --locked"; exit 127; fi
    stylua --check lua plugin tests

lua-lint:
    if ! command -v selene >/dev/null 2>&1; then echo "selene is required: cargo install selene --locked"; exit 127; fi
    selene lua plugin tests

shell-lint: shell-syntax
    if ! command -v shellcheck >/dev/null 2>&1; then echo "shellcheck is required"; exit 127; fi
    shellcheck scripts/*.sh

audit:
    if ! command -v cargo-audit >/dev/null 2>&1; then echo "cargo-audit is required: cargo install cargo-audit --locked"; exit 127; fi
    cargo audit -f Cargo.lock

audit-strict:
    if ! command -v cargo-audit >/dev/null 2>&1; then echo "cargo-audit is required: cargo install cargo-audit --locked"; exit 127; fi
    cargo audit -f Cargo.lock -D warnings

miri-protocol:
    if ! rustup run nightly cargo miri --version >/dev/null 2>&1; then echo "nightly miri is required: rustup toolchain install nightly --component miri --component rust-src"; exit 127; fi
    MIRIFLAGS="-Zmiri-strict-provenance" CARGO_TARGET_DIR=target/miri rustup run nightly cargo miri test -p nrm-protocol --locked

perf-smoke-small:
    scripts/perf_smoke.sh --small

lint-extra: lua-format-check lua-lint shell-lint

quality-extra: lint-extra audit miri-protocol

check: fmt-check clippy rust-test lua-syntax lua-test shell-syntax whitespace

ci: check perf-smoke-small
