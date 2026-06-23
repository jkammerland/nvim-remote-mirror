set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

toolchain := "1.95.0"
target_dir := "target/rustup-1.95.0"
cargo := `if command -v rustup >/dev/null 2>&1; then rustup which --toolchain 1.95.0 cargo; else command -v cargo; fi`
rustc := `if command -v rustup >/dev/null 2>&1; then rustup which --toolchain 1.95.0 rustc; else command -v rustc; fi`
rustdoc := `if command -v rustup >/dev/null 2>&1; then rustup which --toolchain 1.95.0 rustdoc; else command -v rustdoc; fi`

fmt-check:
    RUSTC={{rustc}} RUSTDOC={{rustdoc}} CARGO_TARGET_DIR={{target_dir}} {{cargo}} fmt --all --check

clippy:
    RUSTC={{rustc}} RUSTDOC={{rustdoc}} CARGO_TARGET_DIR={{target_dir}} {{cargo}} clippy --workspace --all-targets --locked -- -D warnings

rust-test:
    RUSTC={{rustc}} RUSTDOC={{rustdoc}} CARGO_TARGET_DIR={{target_dir}} {{cargo}} test --workspace --locked

lua-syntax:
    luac -p lua/nvim_remote_mirror/init.lua lua/nvim_remote_mirror/ui.lua plugin/nvim_remote_mirror.lua tests/*.lua

lua-test:
    find tests -maxdepth 1 -name '*.lua' -print0 | sort -z | while IFS= read -r -d '' test; do nvim --headless -u NONE -l "$test"; done

whitespace:
    git diff --check

check: fmt-check clippy rust-test lua-syntax lua-test whitespace
