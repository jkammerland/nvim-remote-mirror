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
command -v python3 >/dev/null 2>&1 || fail 'python3 is required to compile the inline signer'
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
