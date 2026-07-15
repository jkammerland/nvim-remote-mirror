#!/usr/bin/env bash
set -euo pipefail

production=.github/workflows/release.yml
dry_run=.github/workflows/release-dry-run.yml
policy=scripts/check_release_workflows.sh

temporary=$(mktemp -d "${TMPDIR:-/tmp}/nrm-release-policy-tests.XXXXXX")
trap 'rm -rf "$temporary"' EXIT

case_production="$temporary/release.yml"
case_dry_run="$temporary/release-dry-run.yml"
mutated="$temporary/mutated.yml"
cp "$dry_run" "$case_dry_run"

run_case() {
  NRM_RELEASE_WORKFLOW_PRODUCTION="$case_production" \
    NRM_RELEASE_WORKFLOW_DRY_RUN="$case_dry_run" \
    "$policy"
}

expect_rejected() {
  local description=$1
  if run_case >"$temporary/stdout" 2>"$temporary/stderr"; then
    printf 'release workflow policy test unexpectedly accepted %s\n' "$description" >&2
    exit 1
  fi
}

apply_sed_mutation() {
  local expression=$1
  sed "$expression" "$case_production" > "$mutated"
  mv "$mutated" "$case_production"
}

apply_dry_run_sed_mutation() {
  local expression=$1
  sed "$expression" "$case_dry_run" > "$mutated"
  mv "$mutated" "$case_dry_run"
}

insert_before_line() {
  local path=$1
  local needle=$2
  local insertion=$3
  awk -v needle="$needle" -v insertion="$insertion" '
    $0 == needle {
      print insertion
      inserted = 1
    }
    {
      print
    }
    END {
      if (!inserted) {
        exit 42
      }
    }
  ' "$path" > "$mutated"
  mv "$mutated" "$path"
}

insert_after_line() {
  local path=$1
  local needle=$2
  local insertion=$3
  awk -v needle="$needle" -v insertion="$insertion" '
    {
      print
    }
    $0 == needle {
      print insertion
      inserted = 1
    }
    END {
      if (!inserted) {
        exit 42
      }
    }
  ' "$path" > "$mutated"
  mv "$mutated" "$path"
}

relocate_windows_sidecar_test_to_linux() {
  local path=$1
  # These must remain literal workflow expressions.
  # shellcheck disable=SC2016
  local linux_line='          cargo test -p nrm-sidecar --locked --target "$TARGET" -- --test-threads=1'
  # shellcheck disable=SC2016
  local windows_line='          cargo test -p nrm-sidecar --locked --target $env:TARGET -- --test-threads=1'
  awk -v linux_line="$linux_line" -v windows_line="$windows_line" '
    /^  [[:alnum:]_-]+:$/ {
      job = $0
    }
    job == "  linux:" && $0 == linux_line && !duplicated {
      print
      print
      duplicated = 1
      next
    }
    job == "  windows:" && $0 == windows_line && !removed {
      removed = 1
      next
    }
    {
      print
    }
    END {
      if (!duplicated || !removed) {
        exit 42
      }
    }
  ' "$path" > "$mutated"
  mv "$mutated" "$path"
}

insert_extra_parallel_sidecar_step() {
  local path=$1
  local next_step=$2
  insert_before_line "$path" "$next_step" \
    '      - name: Re-run sidecar tests at default parallelism'
  # This must remain a literal workflow expression.
  # shellcheck disable=SC2016
  insert_before_line "$path" "$next_step" \
    '        run: cargo test --locked --target "$TARGET" -p nrm-sidecar'
}

insert_extra_toolchain_workspace_test_step() {
  local path=$1
  local next_step=$2
  insert_before_line "$path" "$next_step" \
    '      - name: Re-run workspace tests at default parallelism'
  # This must remain a literal workflow expression.
  # shellcheck disable=SC2016
  insert_before_line "$path" "$next_step" \
    '        run: cargo +1.95.0 test --workspace --locked --target "$TARGET"'
}

insert_extra_variable_workspace_test_step() {
  local path=$1
  local next_step=$2
  insert_before_line "$path" "$next_step" \
    '      - name: Re-run workspace tests through configured Cargo'
  # These must remain literal workflow expressions.
  # shellcheck disable=SC2016
  insert_before_line "$path" "$next_step" \
    '        run: "${CARGO:-cargo}" test --workspace --locked --target "$TARGET"'
}

move_linux_test_step_to_job_end() {
  local path=$1
  local name=$2
  local header="      - name: $name"
  awk -v header="$header" '
    $0 == "  linux:" {
      in_linux = 1
    }
    in_linux && $0 == header {
      captured = $0 ORS
      capturing = 1
      next
    }
    capturing {
      if ($0 ~ /^      - name:/) {
        capturing = 0
      } else {
        captured = captured $0 ORS
        next
      }
    }
    $0 == "  macos:" {
      printf "%s", captured
      print
      inserted = 1
      in_linux = 0
      next
    }
    {
      print
    }
    END {
      if (captured == "" || !inserted) {
        exit 42
      }
    }
  ' "$path" > "$mutated"
  mv "$mutated" "$path"
}

insert_upload_into_create() {
  awk '
    /^      - name: Create draft release$/ {
      in_create = 1
    }
    {
      print
    }
    in_create && !inserted && /^          set -euo pipefail$/ {
      print "          gh release upload \"$RELEASE_TAG\" \"${assets[@]}\""
      inserted = 1
    }
  ' "$case_production" > "$mutated"
  mv "$mutated" "$case_production"
}

move_trap_after_validation() {
  awk '
    $0 == "          trap cleanup_incomplete_draft_create EXIT" {
      trap_line = $0
      next
    }
    {
      print
    }
    $0 == "            <<< \"$draft_json\" >/dev/null" {
      print trap_line
      trap_line = ""
    }
    END {
      if (trap_line != "") {
        exit 42
      }
    }
  ' "$case_production" > "$mutated"
  mv "$mutated" "$case_production"
}

cp "$production" "$case_production"
apply_sed_mutation \
  's#https://ports.ubuntu.com/ubuntu-ports#http://ports.ubuntu.com/ubuntu-ports#'
expect_rejected 'production Ubuntu ports source left on plaintext HTTP'

cp "$production" "$case_production"
apply_sed_mutation 's/Acquire::Retries=5/Acquire::Retries=0/'
expect_rejected 'production APT operations without the bounded retry policy'

cp "$production" "$case_production"
apply_sed_mutation 's/Acquire::ForceIPv4=true/Acquire::ForceIPv4=false/'
expect_rejected 'production APT operations without the IPv4 policy'

cp "$production" "$case_production"
apply_sed_mutation '/Acquire::ForceIPv4=true update/s/$/ || true/'
expect_rejected 'fail-open production APT index update'

cp "$production" "$case_production"
insert_before_line "$case_production" \
  '          sudo apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true update' \
  '          set +e'
expect_rejected 'production APT setup with errexit disabled'

cp "$production" "$case_production"
insert_before_line "$case_production" \
  '          sudo apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true update' \
  '          {'
insert_after_line "$case_production" \
  '          sudo apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true install -y musl-tools' \
  '          } || true'
expect_rejected 'production APT setup guarded by fail-open shell control flow'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
apply_dry_run_sed_mutation 's/Acquire::Retries=5/Acquire::Retries=0/'
expect_rejected 'dry-run APT operations without the bounded retry policy'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
apply_dry_run_sed_mutation '/Acquire::ForceIPv4=true install -y musl-tools/s/$/ || true/'
expect_rejected 'fail-open dry-run musl installation'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
insert_before_line "$case_dry_run" \
  '          sudo apt-get -o Acquire::Retries=5 -o Acquire::ForceIPv4=true update' \
  "          sudo sed -i 's|https://ports.ubuntu.com/ubuntu-ports|http://ports.ubuntu.com/ubuntu-ports|g' /etc/apt/sources.list.d/ubuntu.sources"
expect_rejected 'dry-run source downgrade after the HTTPS guard'
cp "$dry_run" "$case_dry_run"

cp "$production" "$case_production"
apply_sed_mutation 's/ -- --test-threads=1//g'
expect_rejected 'parallel production sidecar suites'

cp "$production" "$case_production"
# Keep the total marker count unchanged while moving serialization off the
# process-heavy sidecar command. The policy must bind both on one line.
# shellcheck disable=SC2016
apply_sed_mutation \
  's/cargo test -p nrm-protocol -p nrm-agent --locked --target "$TARGET"/cargo test -p nrm-protocol -p nrm-agent --locked --target "$TARGET" -- --test-threads=1/; s/cargo test -p nrm-sidecar --locked --target "$TARGET" -- --test-threads=1/cargo test -p nrm-sidecar --locked --target "$TARGET"/'
expect_rejected 'production serialization marker detached from the sidecar command'

cp "$production" "$case_production"
relocate_windows_sidecar_test_to_linux "$case_production"
expect_rejected 'production sidecar test relocated out of the Windows job'

cp "$production" "$case_production"
insert_extra_parallel_sidecar_step "$case_production" \
  '      - name: Build, execute, and validate static agent'
expect_rejected 'extra production sidecar test at default parallelism'

cp "$production" "$case_production"
insert_extra_toolchain_workspace_test_step "$case_production" \
  '      - name: Build, execute, and validate static agent'
expect_rejected 'extra production toolchain-qualified workspace test'

cp "$production" "$case_production"
insert_extra_variable_workspace_test_step "$case_production" \
  '      - name: Build, execute, and validate static agent'
expect_rejected 'extra production variable-expanded workspace test'

cp "$production" "$case_production"
insert_after_line "$case_production" \
  '      - name: Run native target tests' \
  '        if: false'
expect_rejected 'conditionally skipped production native test steps'

cp "$production" "$case_production"
insert_after_line "$case_production" \
  '      - name: Run native target tests' \
  '        continue-on-error : true'
expect_rejected 'whitespace-obscured production continue-on-error key'

cp "$production" "$case_production"
insert_after_line "$case_production" \
  '      - name: Build, execute, and validate static agent' \
  '        "i\u0066": false'
expect_rejected 'escaped production conditional key outside the reviewed test step'

cp "$production" "$case_production"
move_linux_test_step_to_job_end "$case_production" 'Run native target tests'
expect_rejected 'production native test moved after artifact upload'

cp "$production" "$case_production"
apply_sed_mutation 's/timeout-minutes: 60/timeout-minutes: 600/g'
expect_rejected 'production native jobs without the 60-minute bound'

cp "$production" "$case_production"
insert_after_line "$case_production" \
  '    timeout-minutes: 60' \
  '    timeout-minutes: 600'
expect_rejected 'production native jobs with an overriding timeout key'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
apply_dry_run_sed_mutation 's/ -- --test-threads=1//g'
expect_rejected 'parallel dry-run sidecar suites'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
relocate_windows_sidecar_test_to_linux "$case_dry_run"
expect_rejected 'dry-run sidecar test relocated out of the Windows job'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
insert_extra_parallel_sidecar_step "$case_dry_run" \
  '      - name: Build, execute, and reject dynamic Linux agents'
expect_rejected 'extra dry-run sidecar test at default parallelism'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
insert_extra_toolchain_workspace_test_step "$case_dry_run" \
  '      - name: Build, execute, and reject dynamic Linux agents'
expect_rejected 'extra dry-run toolchain-qualified workspace test'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
insert_extra_variable_workspace_test_step "$case_dry_run" \
  '      - name: Build, execute, and reject dynamic Linux agents'
expect_rejected 'extra dry-run variable-expanded workspace test'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
insert_after_line "$case_dry_run" \
  '      - name: Run native protocol, agent, and sidecar tests' \
  '        if: false'
expect_rejected 'conditionally skipped dry-run native test steps'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
insert_after_line "$case_dry_run" \
  '      - name: Run native protocol, agent, and sidecar tests' \
  '        continue-on-error : true'
expect_rejected 'whitespace-obscured dry-run continue-on-error key'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
insert_after_line "$case_dry_run" \
  '      - name: Build, execute, and reject dynamic Linux agents' \
  '        "i\u0066": false'
expect_rejected 'escaped dry-run conditional key outside the reviewed test step'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
move_linux_test_step_to_job_end "$case_dry_run" \
  'Run native protocol, agent, and sidecar tests'
expect_rejected 'dry-run native test moved after artifact upload'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
apply_dry_run_sed_mutation 's/timeout-minutes: 60/timeout-minutes: 600/g'
expect_rejected 'dry-run native jobs without the 60-minute bound'

cp "$production" "$case_production"
cp "$dry_run" "$case_dry_run"
insert_after_line "$case_dry_run" \
  '    timeout-minutes: 60' \
  '    timeout-minutes: 600'
expect_rejected 'dry-run native jobs with an overriding timeout key'
cp "$dry_run" "$case_dry_run"

cp "$production" "$case_production"
# This sed expression intentionally matches literal workflow variables.
# shellcheck disable=SC2016
apply_sed_mutation \
  's#"repos/$GITHUB_REPOSITORY/releases" --input -#"repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG" --input -#'
expect_rejected 'draft lookup through the published-release-by-tag endpoint'

cp "$production" "$case_production"
insert_upload_into_create
expect_rejected 'asset upload inside the draft-creation failure domain'

cp "$production" "$case_production"
apply_sed_mutation 's/\*\*Work in progress\.\*\*/Release candidate/'
expect_rejected 'a public release without the work-in-progress warning'

cp "$production" "$case_production"
apply_sed_mutation '/draft_id=.*jq -er/d'
expect_rejected 'cleanup identity not captured from the create response'

cp "$production" "$case_production"
apply_sed_mutation '/trap cleanup_incomplete_draft_create EXIT/d'
expect_rejected 'a post-create validation failure without inline cleanup'

cp "$production" "$case_production"
move_trap_after_validation
expect_rejected 'inline cleanup installed only after response validation'
