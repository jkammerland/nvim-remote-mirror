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
