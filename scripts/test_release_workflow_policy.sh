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
