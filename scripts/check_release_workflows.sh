#!/usr/bin/env bash
set -euo pipefail

production=${NRM_RELEASE_WORKFLOW_PRODUCTION:-.github/workflows/release.yml}
dry_run=${NRM_RELEASE_WORKFLOW_DRY_RUN:-.github/workflows/release-dry-run.yml}

fail() {
  printf 'release workflow policy: %s\n' "$1" >&2
  exit 1
}

line_of_single_literal() {
  local description=$1
  local literal=$2
  local path=$3
  local count
  count=$(grep -Fc -- "$literal" "$path" || true)
  [[ "$count" -eq 1 ]] || fail "$description must occur exactly once, found $count"
  grep -nF -- "$literal" "$path" | cut -d: -f1
}

line_of_single_block_literal() {
  local description=$1
  local literal=$2
  local block=$3
  local count
  count=$(grep -Fc -- "$literal" <<< "$block" || true)
  [[ "$count" -eq 1 ]] || fail "$description must occur exactly once, found $count"
  grep -nF -- "$literal" <<< "$block" | cut -d: -f1
}

line_of_single_block_exact_literal() {
  local description=$1
  local literal=$2
  local block=$3
  local count
  count=$(grep -Fxc -- "$literal" <<< "$block" || true)
  [[ "$count" -eq 1 ]] || fail "$description must occur exactly once, found $count"
  grep -nFx -- "$literal" <<< "$block" | cut -d: -f1
}

extract_single_workflow_step() {
  local workflow=$1
  local name=$2
  local header="      - name: $name"
  local count
  count=$(grep -Fxc -- "$header" "$workflow" || true)
  [[ "$count" -eq 1 ]] \
    || fail "$workflow must contain exactly one $name step, found $count"
  awk -v header="$header" '
    $0 == header {
      active = 1
    }
    active && $0 != header && /^      - name:/ {
      exit
    }
    active {
      print
    }
  ' "$workflow"
}

extract_single_workflow_job() {
  local workflow=$1
  local name=$2
  local header="  $name:"
  local count
  count=$(grep -Fxc -- "$header" "$workflow" || true)
  [[ "$count" -eq 1 ]] \
    || fail "$workflow must contain exactly one $name job, found $count"
  awk -v header="$header" '
    $0 == header {
      active = 1
    }
    active && $0 != header && /^  [[:alnum:]_-]+:$/ {
      exit
    }
    active {
      print
    }
  ' "$workflow"
}

extract_single_block_workflow_step() {
  local block=$1
  local name=$2
  local header="      - name: $name"
  local count
  count=$(grep -Fxc -- "$header" <<< "$block" || true)
  [[ "$count" -eq 1 ]] \
    || fail "native job must contain exactly one $name step, found $count"
  awk -v header="$header" '
    $0 == header {
      active = 1
    }
    active && $0 != header && /^      - name:/ {
      exit
    }
    active {
      print
    }
  ' <<< "$block"
}

reviewed_native_job_sha256() {
  local workflow_kind=$1
  local native_job=$2
  case "$workflow_kind:$native_job" in
    production:linux) printf '%s\n' '17621b452a63043fbfaa832af082d491ce4c7fcbf96bbf23f2cbab51dca0c4a4' ;;
    production:macos) printf '%s\n' '2d85c04f513b458ee42f6b5b1b683c37be8a23fd03c9b56f1c61b0de31f42e3e' ;;
    production:windows) printf '%s\n' '17e4bdfdf8274187de11d659ac58f74924fbf7f0a4bf8d1dadd08fbbcb29f2a1' ;;
    dry-run:linux) printf '%s\n' '4ed0e21a285bde76f1cc1214edc47428f266c6f63d470ca463c5f60f74fa739f' ;;
    dry-run:macos) printf '%s\n' '6a5b5ae3b1c808d914606f10623b163af1c678de3463aa9f7b08805ec39fa53b' ;;
    dry-run:windows) printf '%s\n' 'a42bedf88fc5f6e56843d63b880331b25ba77b2791f8ccefc0f1f2a33957fbee' ;;
    *) fail "missing reviewed digest for $workflow_kind $native_job job" ;;
  esac
}

sha256_stdin() {
  python3 -c \
    'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
}

expected_musl_step="$(cat <<'EOF'
      - name: Install musl and pinned Rust target
        shell: bash
        run: |
          set -euo pipefail
          sudo sed -i \
            's|http://ports.ubuntu.com/ubuntu-ports|https://ports.ubuntu.com/ubuntu-ports|g' \
            /etc/apt/sources.list.d/ubuntu.sources
          if grep -F 'http://ports.ubuntu.com/ubuntu-ports' /etc/apt/sources.list.d/ubuntu.sources; then
            echo "Ubuntu ports source was not upgraded to HTTPS" >&2
            exit 1
          fi
          sudo apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true update
          sudo apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true install -y musl-tools
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --target "$TARGET"
          rustup default "$RUST_TOOLCHAIN"
          rustc -vV
EOF
)"

expected_bash_native_test_body="$(cat <<'EOF'
        shell: bash
        run: |
          set -euo pipefail
          cargo test -p nrm-protocol -p nrm-agent --locked --target "$TARGET"
          cargo test -p nrm-sidecar --locked --target "$TARGET" -- --test-threads=1
EOF
)"

expected_windows_native_test_body="$(cat <<'EOF'
        shell: pwsh
        run: |
          Set-StrictMode -Version Latest
          $ErrorActionPreference = "Stop"
          $PSNativeCommandUseErrorActionPreference = $true
          cargo test -p nrm-protocol -p nrm-agent --locked --target $env:TARGET
          cargo test -p nrm-sidecar --locked --target $env:TARGET -- --test-threads=1
EOF
)"

command -v python3 >/dev/null 2>&1 \
  || fail 'python3 is required to validate release workflows'

for workflow in "$production" "$dry_run"; do
  [[ -f "$workflow" ]] || fail "missing $workflow"
  if grep -En '^[[:space:]]+uses: [^#[:space:]]+@' "$workflow" \
    | grep -Ev '@[0-9a-f]{40}([[:space:]]|$)'; then
    fail "$workflow contains an action reference that is not a full commit ID"
  fi
  grep -F 'GH_CLI_VERSION: "2.96.0"' "$workflow" >/dev/null \
    || fail "$workflow does not pin the reviewed GitHub CLI version"
  grep -F 'GH_CLI_LINUX_AMD64_SHA256: 83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60' \
    "$workflow" >/dev/null \
    || fail "$workflow does not pin the reviewed GitHub CLI archive digest"

  actual_musl_step=$(extract_single_workflow_step \
    "$workflow" 'Install musl and pinned Rust target')
  [[ "$actual_musl_step" == "$expected_musl_step" ]] \
    || fail "$workflow native musl setup must match the reviewed fail-closed step exactly"

  if [[ "$workflow" == "$production" ]]; then
    workflow_kind=production
    native_test_step_name='Run native target tests'
  else
    workflow_kind=dry-run
    native_test_step_name='Run native protocol, agent, and sidecar tests'
  fi

  for native_job in linux macos windows; do
    native_job_block=$(extract_single_workflow_job "$workflow" "$native_job")
    native_timeout_key_count=$(grep -Ec -- \
      "^[[:space:]]+['\"]?timeout-minutes['\"]?[[:space:]]*:" \
      <<< "$native_job_block" || true)
    native_timeout_count=$(grep -Fxc -- '    timeout-minutes: 60' \
      <<< "$native_job_block" || true)
    [[ "$native_timeout_key_count" -eq 1 && "$native_timeout_count" -eq 1 ]] \
      || fail "$workflow $native_job job must have exactly one 60-minute timeout"
    if grep -Eq \
      "^[[:space:]]+['\"]?(if|continue-on-error)['\"]?[[:space:]]*:" \
      <<< "$native_job_block"; then
      fail "$workflow $native_job job must not conditionally skip or ignore native validation"
    fi

    actual_native_test_step=$(extract_single_block_workflow_step \
      "$native_job_block" "$native_test_step_name")
    if [[ "$native_job" == windows ]]; then
      expected_native_test_step="      - name: $native_test_step_name
$expected_windows_native_test_body"
    else
      expected_native_test_step="      - name: $native_test_step_name
$expected_bash_native_test_body"
    fi
    [[ "$actual_native_test_step" == "$expected_native_test_step" ]] \
      || fail "$workflow $native_job native test step must match the reviewed fail-closed step exactly"

    if [[ "$native_job" == linux ]]; then
      if [[ "$workflow" == "$production" ]]; then
        native_build_step_name='Build, execute, and validate static agent'
      else
        native_build_step_name='Build, execute, and reject dynamic Linux agents'
      fi
    else
      native_build_step_name='Build and execute native agent'
    fi
    if [[ "$workflow" == "$production" ]]; then
      native_attest_step_name='Attest native agent provenance'
      native_upload_step_name='Upload native agent'
    else
      native_attest_step_name='Attest dry-run agent provenance'
      native_upload_step_name='Upload dry-run native agent'
    fi
    native_test_step_line=$(line_of_single_block_exact_literal \
      "$workflow $native_job native test step" \
      "      - name: $native_test_step_name" "$native_job_block")
    native_build_step_line=$(line_of_single_block_exact_literal \
      "$workflow $native_job native build step" \
      "      - name: $native_build_step_name" "$native_job_block")
    native_attest_step_line=$(line_of_single_block_exact_literal \
      "$workflow $native_job native attestation step" \
      "      - name: $native_attest_step_name" "$native_job_block")
    native_upload_step_line=$(line_of_single_block_exact_literal \
      "$workflow $native_job native upload step" \
      "      - name: $native_upload_step_name" "$native_job_block")
    [[ "$native_test_step_line" -lt "$native_build_step_line" \
      && "$native_build_step_line" -lt "$native_attest_step_line" \
      && "$native_attest_step_line" -lt "$native_upload_step_line" ]] \
      || fail "$workflow $native_job must test before build, attestation, and upload"

    actual_native_job_sha256=$(printf '%s' "$native_job_block" | sha256_stdin)
    expected_native_job_sha256=$(reviewed_native_job_sha256 \
      "$workflow_kind" "$native_job")
    [[ "$actual_native_job_sha256" == "$expected_native_job_sha256" ]] \
      || fail "$workflow $native_job job differs from its fully reviewed block"
  done

  if grep -F -- 'cargo test -p nrm-protocol -p nrm-agent -p nrm-sidecar' "$workflow"; then
    fail "$workflow must not run the process-heavy sidecar suite at default parallelism"
  fi
done

sign_block="$(sed -n '/^  sign:/,/^  publish:/p' "$production" | sed '$d')"
[[ -n "$sign_block" ]] || fail 'production workflow is missing the isolated sign job'
grep -F 'environment: release' <<< "$sign_block" >/dev/null \
  || fail 'isolated sign job is not protected by the release environment'
grep -F 'secrets.NRM_REGISTRY_SIGNING_KEYS_JSON' <<< "$sign_block" >/dev/null \
  || fail 'isolated sign job does not receive the signing secret'
grep -F 'signing seed and trusted public key differ' <<< "$sign_block" >/dev/null \
  || fail 'isolated sign job does not bind seeds to protected public keys'
grep -F 'validate_executable(artifact_bytes, target)' <<< "$sign_block" >/dev/null \
  || fail 'isolated sign job does not validate native executable formats before signing'

heredoc_start="          python3 - <<'PY'"
heredoc_end='          PY'
[[ "$(grep -Fxc -- "$heredoc_start" "$production")" -eq 1 ]] \
  || fail 'production workflow must contain exactly one inline signer Python heredoc'
[[ "$(grep -Fxc -- "$heredoc_end" "$production")" -eq 1 ]] \
  || fail 'production workflow must contain exactly one inline signer Python terminator'

temporary=$(mktemp -d "${TMPDIR:-/tmp}/nrm-release-policy.XXXXXX")
trap 'rm -rf "$temporary"' EXIT
signer_python="$temporary/signer.py"
awk -v start="$heredoc_start" -v finish="$heredoc_end" '
  $0 == start {
    active = 1
    next
  }
  active && $0 == finish {
    complete = 1
    exit
  }
  active {
    if ($0 == "") {
      print ""
      next
    }
    if (substr($0, 1, 10) != "          ") {
      invalid_indent = 1
      exit
    }
    print substr($0, 11)
  }
  END {
    if (invalid_indent) {
      exit 42
    }
    if (!complete) {
      exit 43
    }
  }
' "$production" > "$signer_python" \
  || fail 'could not extract the indentation-safe inline signer Python'
[[ -s "$signer_python" ]] || fail 'inline signer Python is empty'
PYTHONPYCACHEPREFIX="$temporary/pycache" python3 -m py_compile "$signer_python" \
  || fail 'inline signer Python does not compile'

validation_line=$(line_of_single_literal \
  'inline signer executable-validation invocation' \
  'validate_executable(artifact_bytes, target)' "$signer_python")
signing_line=$(line_of_single_literal \
  'inline signer OpenSSL signing invocation' \
  '["openssl", "pkeyutl", "-sign"' "$signer_python")
signature_output_line=$(line_of_single_literal \
  'inline signer detached-signature output' \
  '(assets / "nrm-agent-manifest-v1.json.sig").write_bytes(' "$signer_python")
if ((validation_line >= signing_line || validation_line >= signature_output_line)); then
  fail 'inline signer must validate every executable before signing or writing signatures'
fi

if grep -Eq 'actions/checkout|cargo (build|run|test)|target/release|scripts/' <<< "$sign_block"; then
  fail 'isolated sign job executes release-tag repository content'
fi

outside_sign="$({ sed -n '1,/^  sign:/p' "$production" | sed '$d'; sed -n '/^  publish:/,$p' "$production"; })"
if grep -F 'secrets.NRM_REGISTRY_SIGNING_KEYS_JSON' <<< "$outside_sign"; then
  fail 'signing secret is referenced outside the isolated sign job'
fi
if grep -E 'vars\.NRM_' <<< "$outside_sign"; then
  fail 'release-environment NRM variables are referenced outside the isolated sign job'
fi
[[ "$(grep -Fc -- '--trusted-public-keys signed-candidate/trusted-public-keys.json' "$production")" -eq 2 ]] \
  || fail 'publish must verify signer output and downloaded release with the isolated trust file'

grep -F 'needs: [prepare, sign]' "$production" >/dev/null \
  || fail 'publish job does not depend on the isolated signer'
if sed -n '/^  publish:/,$p' "$production" | grep -F 'environment: release'; then
  fail 'publish job must not receive the release environment secrets'
fi

draft_create_line=$(line_of_single_literal \
  'draft-creation step' '      - name: Create draft release' "$production")
draft_populate_line=$(line_of_single_literal \
  'draft-population step' '      - name: Populate draft release' "$production")
draft_verify_line=$(line_of_single_literal \
  'draft-verification step' '      - name: Re-download and verify complete draft' "$production")
draft_cleanup_line=$(line_of_single_literal \
  'failed-draft cleanup step' "      - name: Remove this run's failed draft" "$production")
if ! ((draft_create_line < draft_populate_line \
    && draft_populate_line < draft_verify_line \
    && draft_verify_line < draft_cleanup_line)); then
  fail 'draft creation, population, verification, and cleanup steps are out of order'
fi

draft_create_block="$(
  sed -n '/^      - name: Create draft release$/,/^      - name: Populate draft release$/p' \
    "$production" | sed '$d'
)"
draft_populate_block="$(
  sed -n '/^      - name: Populate draft release$/,/^      - name: Re-download and verify complete draft$/p' \
    "$production" | sed '$d'
)"
# These values describe literal shell source in the workflow. Expanding them in
# this policy process would weaken the checks.
# shellcheck disable=SC1003,SC2016
readonly draft_create_endpoint='"repos/$GITHUB_REPOSITORY/releases" --input -' \
  draft_id_prefix='          draft_id="$(jq -er' \
  draft_created_output='          echo "created=true" >> "$GITHUB_OUTPUT"' \
  draft_id_output='          echo "id=$draft_id" >> "$GITHUB_OUTPUT"' \
  draft_exact_endpoint='"repos/$GITHUB_REPOSITORY/releases/$draft_id"' \
  draft_delete_prefix='if ! gh api --method DELETE \' \
  draft_upload='          gh release upload "$RELEASE_TAG" "${assets[@]}"' \
  draft_by_tag_endpoint='releases/tags/$RELEASE_TAG' \
  cleanup_exact_endpoint='"repos/$GITHUB_REPOSITORY/releases/$EXPECTED_RELEASE_ID"'
grep -F 'id: draft' <<< "$draft_create_block" >/dev/null \
  || fail 'draft creation does not expose the release identity to later cleanup'
grep -F 'generate_release_notes: true' <<< "$draft_create_block" >/dev/null \
  || fail 'draft creation does not request generated release notes'
grep -F '**Work in progress.**' <<< "$draft_create_block" >/dev/null \
  || fail 'draft creation does not mark the public release as work in progress'
grep -F "$draft_create_endpoint" <<< "$draft_create_block" >/dev/null \
  || fail 'draft creation does not capture the create-release API response'
grep -F "$draft_id_prefix" <<< "$draft_create_block" >/dev/null \
  || fail 'draft creation does not derive its cleanup ID from the create response'
grep -F 'trap cleanup_incomplete_draft_create EXIT' <<< "$draft_create_block" >/dev/null \
  || fail 'draft creation cannot clean up a post-create validation failure'
draft_id_line=$(line_of_single_block_literal 'draft response ID capture' \
  "$draft_id_prefix" "$draft_create_block")
draft_trap_line=$(line_of_single_block_literal 'draft inline cleanup trap installation' \
  '          trap cleanup_incomplete_draft_create EXIT' "$draft_create_block")
draft_validation_line=$(line_of_single_block_literal 'draft response validation' \
  "            --arg warning '**Work in progress.**' \\" "$draft_create_block")
draft_created_output_line=$(line_of_single_block_literal 'draft-created output' \
  "$draft_created_output" "$draft_create_block")
draft_id_output_line=$(line_of_single_block_literal 'draft-ID output' \
  "$draft_id_output" "$draft_create_block")
draft_trap_release_line=$(line_of_single_block_exact_literal 'draft inline cleanup trap release' \
  '          trap - EXIT' "$draft_create_block")
if ! ((draft_id_line < draft_trap_line \
    && draft_trap_line < draft_validation_line \
    && draft_validation_line < draft_created_output_line \
    && draft_created_output_line < draft_id_output_line \
    && draft_id_output_line < draft_trap_release_line)); then
  fail 'draft inline cleanup trap does not cover validation and output publication'
fi
[[ "$(grep -Fc "$draft_exact_endpoint" \
  <<< "$draft_create_block")" -eq 2 ]] \
  || fail 'draft-creation cleanup must retrieve and delete only the exact response release ID'
grep -F "$draft_delete_prefix" <<< "$draft_create_block" >/dev/null \
  || fail 'draft-creation cleanup does not delete its exact incomplete draft'
if grep -F 'gh release upload' <<< "$draft_create_block"; then
  fail 'draft creation and asset upload must be separate failure domains'
fi
line_of_single_literal 'draft asset upload' \
  "$draft_upload" "$production" >/dev/null
grep -F "$draft_upload" \
  <<< "$draft_populate_block" >/dev/null \
  || fail 'draft population does not contain the sole asset upload'
if grep -F "$draft_by_tag_endpoint" "$production"; then
  fail 'draft identity must not use the published-release-by-tag endpoint'
fi

cleanup_block="$(sed -n \
  "/^      - name: Remove this run's failed draft\$/,\$p" "$production")"
grep -F "steps.draft.outputs.created == 'true'" <<< "$cleanup_block" >/dev/null \
  || fail 'failed-draft cleanup is not gated on successful draft creation'
grep -F 'steps.draft.outputs.id' <<< "$cleanup_block" >/dev/null \
  || fail 'failed-draft cleanup does not use the captured release ID'
grep -F "$cleanup_exact_endpoint" \
  <<< "$cleanup_block" >/dev/null \
  || fail 'failed-draft cleanup does not retrieve the exact release by ID'

if grep -F 'retention-days: 1' "$dry_run"; then
  fail 'dry-run artifacts can expire before a delayed ARM64 aggregate job'
fi
[[ "$(grep -Fc 'retention-days: 7' "$dry_run")" -eq 4 ]] \
  || fail 'all dry-run native and aggregate artifacts must be retained for seven days'
