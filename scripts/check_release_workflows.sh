#!/usr/bin/env bash
set -euo pipefail

production=.github/workflows/release.yml
dry_run=.github/workflows/release-dry-run.yml

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

if grep -F 'retention-days: 1' "$dry_run"; then
  fail 'dry-run artifacts can expire before a delayed ARM64 aggregate job'
fi
[[ "$(grep -Fc 'retention-days: 7' "$dry_run")" -eq 4 ]] \
  || fail 'all dry-run native and aggregate artifacts must be retained for seven days'
