//! POSIX transactional installation planning for `nrm-agent`.
//!
//! The scripts in this module are fixed literals. Remote paths and other
//! caller-controlled values are passed as positional `sh -c` arguments, never
//! interpolated into script source.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::Digest as _;

const STAGE_RECORD: &str = "NRM_INSTALL_STAGE_V1";
const ACTIVATED_RECORD: &str = "NRM_INSTALL_ACTIVATED_V1";
const RECONCILED_RECORD: &str = "NRM_INSTALL_RECONCILED_V1";
const ROLLED_BACK_RECORD: &str = "NRM_INSTALL_ROLLED_BACK_V1";
const ABSENT_RECORD: &str = "NRM_INSTALL_ABSENT_V1";
const CLEANED_RECORD: &str = "NRM_INSTALL_CLEANED_V1";
const LEASE_READY_RECORD: &str = "NRM_INSTALL_LEASE_READY_V1";
const ERROR_RECORD: &str = "NRM_INSTALL_ERROR_V1";

static POSIX_GUARD_NONCE: AtomicU64 = AtomicU64::new(0);

fn new_posix_guard_token(target: &str, command: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    hasher.update(
        POSIX_GUARD_NONCE
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    hasher.update(target.as_bytes());
    hasher.update(command.as_bytes());
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const POSIX_LEASE_SCRIPT: &str = r#"set -u
set -f
target=$1
token=$2
expected_sha256=$3

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

home=${HOME-}
case "$target" in
  "\$HOME"/*)
    if [ -z "$home" ]; then fail invalid_target 40; fi
    target="$home/${target#"\$HOME"/}"
    ;;
  "~"/*)
    if [ -z "$home" ]; then fail invalid_target 40; fi
    target="$home/${target#"~/"}"
    ;;
esac
case "$target" in /*) ;; *) fail invalid_target 40 ;; esac
case "$target" in */) fail invalid_target 40 ;; esac
case "$target" in */./*|*/../*|*/.|*/..) fail invalid_target 40 ;; esac
case "$token" in
  ????????????????????????????????) ;;
  *) fail invalid_state 40 ;;
esac
case "$token" in *[!0-9a-f]*) fail invalid_state 40 ;; esac

tab=$(printf '\t')
newline='
'
case "$target" in *"$tab"*|*"$newline"*) fail invalid_target 40 ;; esac

umask 077
dir=${target%/*}
if [ -z "$dir" ]; then dir=/; fi

current_uid=$(id -u 2>/dev/null) || fail invalid_target 40
case "$current_uid" in ''|*[!0-9]*) fail invalid_target 40 ;; esac

secure_directory() {
  secure_path=$1
  require_current_owner=$2
  [ -d "$secure_path" ] && [ ! -L "$secure_path" ] || return 1
  secure_stat_style=gnu
  if secure_metadata=$(LC_ALL=C stat -c '%u %a' "$secure_path" 2>/dev/null); then :
  elif secure_metadata=$(LC_ALL=C stat -f '%u %p' "$secure_path" 2>/dev/null); then
    secure_stat_style=bsd
  else return 1
  fi
  old_ifs=$IFS
  IFS=' '
  set -- $secure_metadata
  IFS=$old_ifs
  [ "$#" -eq 2 ] || return 1
  secure_owner=$1
  secure_mode=$2
  if [ "$secure_stat_style" = bsd ]; then
    case "$secure_mode" in
      4[0-7][0-7][0-7][0-7]) secure_mode=${secure_mode#?} ;;
      *) return 1 ;;
    esac
  fi
  case "$secure_owner" in ''|*[!0-9]*) return 1 ;; esac
  if [ "$secure_owner" != 0 ] && [ "$secure_owner" != "$current_uid" ]; then return 1; fi
  if [ "$require_current_owner" = 1 ] && [ "$secure_owner" != "$current_uid" ]; then return 1; fi
  case "$secure_mode" in
    [0-7][0-7][0-7]) secure_special=0; secure_permissions=$secure_mode ;;
    [0-7][0-7][0-7][0-7])
      secure_special=${secure_mode%???}
      secure_permissions=${secure_mode#?}
      ;;
    *) return 1 ;;
  esac
  secure_tail=${secure_permissions#?}
  secure_group=${secure_tail%?}
  secure_other=${secure_tail#?}
  secure_shared_write=0
  case "$secure_group" in 2|3|6|7) secure_shared_write=1 ;; esac
  case "$secure_other" in 2|3|6|7) secure_shared_write=1 ;; esac
  if [ "$secure_shared_write" = 1 ]; then
    [ "$require_current_owner" = 0 ] || return 1
    case "$secure_special" in 1|3|5|7) ;; *) return 1 ;; esac
  fi
}

secure_symlink_owner() {
  symlink_path=$1
  [ -L "$symlink_path" ] || return 1
  if symlink_owner=$(LC_ALL=C stat -c '%u' "$symlink_path" 2>/dev/null); then :
  elif symlink_owner=$(LC_ALL=C stat -f '%u' "$symlink_path" 2>/dev/null); then :
  else return 1
  fi
  case "$symlink_owner" in ''|*[!0-9]*) return 1 ;; esac
  [ "$symlink_owner" = 0 ] || [ "$symlink_owner" = "$current_uid" ]
}

secure_physical_chain() {
  physical_dir=$1
  physical_endpoint_required=$2
  if [ "$physical_dir" = / ]; then
    secure_directory / "$physical_endpoint_required"
    return
  fi
  secure_directory / 0 || return 1
  physical_remaining=${physical_dir#/}
  physical_prefix=
  while [ -n "$physical_remaining" ]; do
    case "$physical_remaining" in
      */*) physical_component=${physical_remaining%%/*}; physical_remaining=${physical_remaining#*/} ;;
      *) physical_component=$physical_remaining; physical_remaining= ;;
    esac
    [ -n "$physical_component" ] || return 1
    physical_prefix="$physical_prefix/$physical_component"
    if [ -n "$physical_remaining" ]; then physical_final=0
    else physical_final=$physical_endpoint_required
    fi
    secure_directory "$physical_prefix" "$physical_final" || return 1
  done
}

secure_directory_chain() {
  if [ "$dir" = / ]; then secure_directory / 1; return; fi
  secure_directory / 0 || return 1
  lexical_remaining=${dir#/}
  lexical_prefix=
  while [ -n "$lexical_remaining" ]; do
    case "$lexical_remaining" in
      */*) lexical_component=${lexical_remaining%%/*}; lexical_remaining=${lexical_remaining#*/} ;;
      *) lexical_component=$lexical_remaining; lexical_remaining= ;;
    esac
    [ -n "$lexical_component" ] || return 1
    lexical_prefix="$lexical_prefix/$lexical_component"
    if [ -n "$lexical_remaining" ]; then lexical_final=0; else lexical_final=1; fi
    if [ ! -e "$lexical_prefix" ] && [ ! -L "$lexical_prefix" ]; then
      if ! mkdir "$lexical_prefix" 2>/dev/null; then
        if [ ! -e "$lexical_prefix" ] && [ ! -L "$lexical_prefix" ]; then return 2; fi
      fi
    fi
    if [ -L "$lexical_prefix" ]; then
      [ "$lexical_final" = 0 ] || return 1
      secure_symlink_owner "$lexical_prefix" || return 1
    fi
    [ -d "$lexical_prefix" ] || return 1
    lexical_resolved=$(CDPATH= cd -P "$lexical_prefix" 2>/dev/null && pwd -P) || return 1
    case "$lexical_resolved" in /*) ;; *) return 1 ;; esac
    case "$lexical_resolved" in *"$tab"*|*"$newline"*) return 1 ;; esac
    secure_physical_chain "$lexical_resolved" "$lexical_final" || return 1
  done
}

if secure_directory_chain; then :
else
  secure_status=$?
  if [ "$secure_status" = 2 ]; then fail stage_create_failed 30; fi
  fail invalid_target 40
fi

lease="${target}.nrm-install-lease"
owner="${lease}/owner.${token}"
owner_next="${lease}/.owner-next"
claim_prefix="${lease}.claim"
claim="${claim_prefix}.${token}.$$"
journal="${target}.nrm-install-state"
journal_next="${journal}.next"
lease_owned=0
claim_owned=0
active_reaper_claim=
active_reaper_claim_owned=0

valid_hash() {
  hash_value=$1
  [ "${#hash_value}" -eq 64 ] || return 1
  case "$hash_value" in *[!0-9a-f]*) return 1 ;; esac
}

if ! valid_hash "$expected_sha256"; then fail invalid_state 40; fi

hash_file() {
  hash_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    hash_line=$(sha256sum <"$hash_path") || return 1
  elif command -v shasum >/dev/null 2>&1; then
    hash_line=$(shasum -a 256 <"$hash_path") || return 1
  else
    return 1
  fi
  hash_value=${hash_line%% *}
  valid_hash "$hash_value" || return 1
  printf '%s\n' "$hash_value"
}

matches_hash() {
  match_path=$1
  match_expected=$2
  [ -f "$match_path" ] && [ ! -L "$match_path" ] || return 1
  match_actual=$(hash_file "$match_path") || return 1
  [ "$match_actual" = "$match_expected" ]
}

valid_derived_path() {
  derived_path=$1
  derived_separator=$2
  case "$derived_path" in "$target""$derived_separator"*) ;; *) return 1 ;; esac
  derived_suffix=${derived_path#"$target""$derived_separator"}
  case "$derived_suffix" in ??????????) ;; *) return 1 ;; esac
  case "$derived_suffix" in *[!A-Za-z0-9]*) return 1 ;; esac
}

read_journal_path() {
  journal_path=$1
  [ -f "$journal_path" ] && [ ! -L "$journal_path" ] || return 1
  if journal_metadata=$(LC_ALL=C stat -c '%u %a' "$journal_path" 2>/dev/null); then :
  elif journal_metadata=$(LC_ALL=C stat -f '%u %Lp' "$journal_path" 2>/dev/null); then :
  else return 1
  fi
  old_ifs=$IFS
  IFS=' '
  set -- $journal_metadata
  IFS=$old_ifs
  [ "$#" -eq 2 ] || return 1
  [ "$1" = "$current_uid" ] || return 1
  case "$2" in 600|0600) ;; *) return 1 ;; esac
  journal_line=
  journal_extra=
  {
    IFS= read -r journal_line || return 1
    if IFS= read -r journal_extra || [ -n "$journal_extra" ]; then return 1; fi
  } <"$journal_path"
  old_ifs=$IFS
  IFS=$tab
  set -- $journal_line
  IFS=$old_ifs
  [ "$#" -eq 8 ] || return 1
  [ "$1" = NRM_INSTALL_STATE_V1 ] || return 1
  journal_target=$2
  journal_phase=$3
  journal_mode=$4
  journal_stage=$5
  journal_backup=$6
  journal_previous_hash=$7
  journal_candidate_hash=$8
  [ "$journal_target" = "$target" ] || return 1
  case "$journal_phase" in preparing|staged) ;; *) return 1 ;; esac
  valid_derived_path "$journal_stage" .nrm-stage. || return 1
  valid_derived_path "$journal_backup" .nrm-backup. || return 1
  [ "$journal_stage" != "$journal_backup" ] || return 1
  valid_hash "$journal_candidate_hash" || return 1
  case "$journal_mode" in
    present) valid_hash "$journal_previous_hash" || return 1 ;;
    missing) [ "$journal_previous_hash" = - ] || return 1 ;;
    *) return 1 ;;
  esac
  canonical_journal_line=$(printf 'NRM_INSTALL_STATE_V1\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
    "$journal_target" "$journal_phase" "$journal_mode" "$journal_stage" "$journal_backup" \
    "$journal_previous_hash" "$journal_candidate_hash") || return 1
  [ "$journal_line" = "$canonical_journal_line" ]
}

read_journal() {
  read_journal_path "$journal"
}

read_owner() {
  owner_path=$1
  expected_owner_token=$2
  [ -f "$owner_path" ] && [ ! -L "$owner_path" ] || return 1
  owner_line=
  owner_extra=
  {
    IFS= read -r owner_line || return 1
    if IFS= read -r owner_extra || [ -n "$owner_extra" ]; then return 1; fi
  } <"$owner_path"
  old_ifs=$IFS
  IFS=$tab
  set -- $owner_line
  IFS=$old_ifs
  [ "$#" -eq 3 ] || return 1
  [ "$1" = NRM_INSTALL_OWNER_V1 ] || return 1
  [ "$2" = "$expected_owner_token" ] || return 1
  owner_pid=$3
  case "$owner_pid" in ''|0|0*|*[!0-9]*) return 1 ;; esac
  canonical_owner_line=$(printf 'NRM_INSTALL_OWNER_V1\t%s\t%s' \
    "$expected_owner_token" "$owner_pid") || return 1
  [ "$owner_line" = "$canonical_owner_line" ]
}

scan_claims() {
  scan_prefix=$1
  scan_own=$2
  live_claim=0
  set +f
  for scan_claim in "$scan_prefix".*; do
    set -f
    if [ ! -e "$scan_claim" ] && [ ! -L "$scan_claim" ]; then continue; fi
    [ "$scan_claim" != "$scan_own" ] || continue
    if [ ! -f "$scan_claim" ] || [ -L "$scan_claim" ]; then fail invalid_state 40; fi
    scan_identity=${scan_claim#"$scan_prefix".}
    scan_token=${scan_identity%.*}
    scan_pid=${scan_identity##*.}
    case "$scan_token" in
      ????????????????????????????????) ;;
      *) fail invalid_state 40 ;;
    esac
    case "$scan_token" in *[!0-9a-f]*) fail invalid_state 40 ;; esac
    case "$scan_pid" in ''|0|0*|*[!0-9]*) fail invalid_state 40 ;; esac
    if kill -0 "$scan_pid" 2>/dev/null; then
      live_claim=1
    else
      rm -f "$scan_claim" || fail invalid_state 40
    fi
  done
  set -f
}

inspect_active() {
  set +f
  set -- "${lease}/active"/owner.*
  set -f
  if [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; then return 1; fi
  [ "$#" -eq 1 ] || return 2
  active_owner_path=$1
  [ -f "$active_owner_path" ] && [ ! -L "$active_owner_path" ] || return 2
  active_identity=${active_owner_path##*/owner.}
  active_token=${active_identity%.*}
  active_filename_pid=${active_identity##*.}
  case "$active_token" in
    ????????????????????????????????) ;;
    *) return 2 ;;
  esac
  case "$active_token" in *[!0-9a-f]*) return 2 ;; esac
  case "$active_filename_pid" in ''|0|0*|*[!0-9]*) return 2 ;; esac
  read_owner "$active_owner_path" "$active_token" || return 2
  [ "$owner_pid" = "$active_filename_pid" ] || return 2
  active_pid=$owner_pid
}

remove_journal_last() {
  expected_journal_line=$1
  read_journal || return 1
  [ "$journal_line" = "$expected_journal_line" ] || return 1
  [ ! -e "$journal_next" ] && [ ! -L "$journal_next" ] || return 1
  rm -f "$journal" || return 1
  [ ! -e "$journal" ] && [ ! -L "$journal" ]
}

recover_journal() {
  recovery_source=$journal
  recovery_next_line=
  if [ ! -e "$journal" ] && [ ! -L "$journal" ]; then
    if [ ! -e "$journal_next" ] && [ ! -L "$journal_next" ]; then return 0; fi
    read_journal_path "$journal_next" || return 1
    [ "$journal_phase" = preparing ] || return 1
    recovery_source=$journal_next
  else
    read_journal || return 1
    if [ -e "$journal_next" ] || [ -L "$journal_next" ]; then
      recovery_primary_line=$journal_line
      recovery_primary_phase=$journal_phase
      recovery_primary_mode=$journal_mode
      recovery_primary_stage=$journal_stage
      recovery_primary_backup=$journal_backup
      recovery_primary_previous_hash=$journal_previous_hash
      recovery_primary_candidate_hash=$journal_candidate_hash
      read_journal_path "$journal_next" || return 1
      [ "$recovery_primary_phase" = preparing ] || return 1
      [ "$journal_target" = "$target" ] || return 1
      [ "$journal_mode" = "$recovery_primary_mode" ] || return 1
      [ "$journal_stage" = "$recovery_primary_stage" ] || return 1
      [ "$journal_backup" = "$recovery_primary_backup" ] || return 1
      [ "$journal_previous_hash" = "$recovery_primary_previous_hash" ] || return 1
      [ "$journal_candidate_hash" = "$recovery_primary_candidate_hash" ] || return 1
      case "$journal_phase" in preparing|staged) ;; *) return 1 ;; esac
      recovery_next_line=$journal_line
      journal_line=$recovery_primary_line
      journal_phase=$recovery_primary_phase
      journal_mode=$recovery_primary_mode
      journal_stage=$recovery_primary_stage
      journal_backup=$recovery_primary_backup
      journal_previous_hash=$recovery_primary_previous_hash
      journal_candidate_hash=$recovery_primary_candidate_hash
    fi
  fi
  recovery_journal_line=$journal_line
  recovery_phase=$journal_phase
  recovery_mode=$journal_mode
  recovery_stage=$journal_stage
  recovery_backup=$journal_backup
  recovery_previous_hash=$journal_previous_hash
  recovery_candidate_hash=$journal_candidate_hash

  stage_exists=0
  backup_exists=0
  target_exists=0
  if [ -e "$recovery_stage" ] || [ -L "$recovery_stage" ]; then stage_exists=1; fi
  if [ -e "$recovery_backup" ] || [ -L "$recovery_backup" ]; then backup_exists=1; fi
  if [ -e "$target" ] || [ -L "$target" ]; then target_exists=1; fi

  if [ "$recovery_phase" = preparing ]; then
    [ "$backup_exists" = 0 ] || return 1
    if [ "$recovery_mode" = present ]; then
      matches_hash "$target" "$recovery_previous_hash" || return 1
    else
      [ "$target_exists" = 0 ] || return 1
    fi
    if [ "$stage_exists" = 1 ]; then
      [ -f "$recovery_stage" ] && [ ! -L "$recovery_stage" ] || return 1
      if [ "$recovery_mode" = present ]; then
        matches_hash "$target" "$recovery_previous_hash" || return 1
      else
        [ ! -e "$target" ] && [ ! -L "$target" ] || return 1
      fi
      rm -f "$recovery_stage" || return 1
    fi
  elif [ "$recovery_mode" = present ]; then
    if [ "$stage_exists" = 1 ]; then
      matches_hash "$recovery_stage" "$recovery_candidate_hash" || return 1
      matches_hash "$target" "$recovery_previous_hash" || return 1
      if [ "$backup_exists" = 1 ]; then
        matches_hash "$recovery_backup" "$recovery_previous_hash" || return 1
      fi
      matches_hash "$recovery_stage" "$recovery_candidate_hash" || return 1
      matches_hash "$target" "$recovery_previous_hash" || return 1
      rm -f "$recovery_stage" || return 1
      if [ "$backup_exists" = 1 ]; then
        matches_hash "$recovery_backup" "$recovery_previous_hash" || return 1
        matches_hash "$target" "$recovery_previous_hash" || return 1
        rm -f "$recovery_backup" || return 1
      fi
      matches_hash "$target" "$recovery_previous_hash" || return 1
    elif [ "$backup_exists" = 1 ]; then
      matches_hash "$recovery_backup" "$recovery_previous_hash" || return 1
      if matches_hash "$target" "$recovery_candidate_hash"; then
        if ! recovery_error=$(mktemp "${recovery_backup}.lease-recovery-error.XXXXXXXXXX"); then
          return 1
        fi
        if ! matches_hash "$recovery_backup" "$recovery_previous_hash" ||
           ! matches_hash "$target" "$recovery_candidate_hash"; then
          rm -f "$recovery_error"
          return 1
        fi
        if ! mv -f "$recovery_backup" "$target" 2>"$recovery_error"; then
          cat "$recovery_error" >&2
          rm -f "$recovery_error"
          return 1
        fi
        rm -f "$recovery_error"
        matches_hash "$target" "$recovery_previous_hash" || return 1
      elif matches_hash "$target" "$recovery_previous_hash"; then
        matches_hash "$recovery_backup" "$recovery_previous_hash" || return 1
        rm -f "$recovery_backup" || return 1
        matches_hash "$target" "$recovery_previous_hash" || return 1
      else
        return 1
      fi
    else
      if matches_hash "$target" "$recovery_previous_hash"; then :
      elif matches_hash "$target" "$recovery_candidate_hash"; then :
      else return 1
      fi
    fi
  else
    [ "$backup_exists" = 0 ] || return 1
    if [ "$stage_exists" = 1 ]; then
      [ "$target_exists" = 0 ] || return 1
      matches_hash "$recovery_stage" "$recovery_candidate_hash" || return 1
      rm -f "$recovery_stage" || return 1
      [ ! -e "$target" ] && [ ! -L "$target" ] || return 1
    elif [ "$target_exists" = 1 ]; then
      matches_hash "$target" "$recovery_candidate_hash" || return 1
    fi
  fi

  if [ -n "$recovery_next_line" ]; then
    read_journal_path "$journal_next" || return 1
    [ "$journal_line" = "$recovery_next_line" ] || return 1
    rm -f "$journal_next" || return 1
    [ ! -e "$journal_next" ] && [ ! -L "$journal_next" ] || return 1
  fi
  if [ "$recovery_source" = "$journal_next" ]; then
    read_journal_path "$journal_next" || return 1
    [ "$journal_line" = "$recovery_journal_line" ] || return 1
    rm -f "$journal_next" || return 1
    [ ! -e "$journal_next" ] && [ ! -L "$journal_next" ]
  else
    remove_journal_last "$recovery_journal_line"
  fi
}

cleanup_lease() {
  if [ "$active_reaper_claim_owned" = 1 ]; then
    rm -f "$active_reaper_claim" 2>/dev/null || :
  fi
  if [ "$lease_owned" = 1 ]; then
    if read_owner "$owner" "$token" && [ "$owner_pid" = "$$" ]; then
      rm -f "$owner"
    fi
    if [ -f "$owner_next" ] && [ ! -L "$owner_next" ]; then rm -f "$owner_next"; fi
    rmdir "$lease" 2>/dev/null || :
  fi
  if [ "$claim_owned" = 1 ]; then rm -f "$claim" 2>/dev/null || :; fi
}
trap cleanup_lease 0
trap 'exit 70' 1 2 15

if [ -e "$claim" ] || [ -L "$claim" ] ||
   ! (set -C; printf 'NRM_INSTALL_OWNER_V1\t%s\t%s\n' "$token" "$$" >"$claim"); then
  fail invalid_state 40
fi
claim_owned=1
if ! read_owner "$claim" "$token" || [ "$owner_pid" != "$$" ]; then fail invalid_state 40; fi

attempt=0
while [ "$attempt" -lt 4 ]; do
  attempt=$((attempt + 1))
  if mkdir "$lease" 2>/dev/null; then
    lease_owned=1
    if ! read_owner "$claim" "$token" || [ "$owner_pid" != "$$" ]; then
      fail invalid_state 40
    fi
    if ! (set -C; printf 'NRM_INSTALL_OWNER_V1\t%s\t%s\n' "$token" "$$" >"$owner_next"); then
      fail stage_create_failed 30
    fi
    if ! read_owner "$owner_next" "$token" || [ "$owner_pid" != "$$" ]; then
      fail invalid_state 40
    fi
    if [ -e "$owner" ] || [ -L "$owner" ] || ! mv "$owner_next" "$owner"; then
      fail invalid_state 40
    fi
    if ! read_owner "$owner" "$token" || [ "$owner_pid" != "$$" ]; then
      fail invalid_state 40
    fi
    set +f
    set -- "$lease"/owner.*
    set -f
    if [ "$#" -ne 1 ] || [ "$1" != "$owner" ]; then fail invalid_state 40; fi
    if ! rm -f "$claim"; then fail invalid_state 40; fi
    claim_owned=0
    if ! recover_journal; then fail invalid_state 40; fi
    printf 'NRM_INSTALL_LEASE_READY_V1\t%s\t%s\n' "$target" "$token"
    while IFS= read -r ignored; do :; done
    exit 0
  fi

  if [ -L "$lease" ] || [ ! -d "$lease" ]; then
    fail invalid_state 40
  fi
  # The adjacent lease claim elects a single stale-state reaper. A contender
  # that arrives after this scan sees this process's live claim and yields.
  scan_claims "$claim_prefix" "$claim"
  if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi

  active_claim_prefix="${lease}/active.claim"
  active_reaper_claim="${active_claim_prefix}.${token}.$$"
  if [ -e "$active_reaper_claim" ] || [ -L "$active_reaper_claim" ] ||
     ! (set -C; printf 'NRM_INSTALL_OWNER_V1\t%s\t%s\n' "$token" "$$" >"$active_reaper_claim"); then
    fail invalid_state 40
  fi
  active_reaper_claim_owned=1
  if ! read_owner "$active_reaper_claim" "$token" || [ "$owner_pid" != "$$" ]; then
    fail invalid_state 40
  fi
  scan_claims "$active_claim_prefix" "$active_reaper_claim"
  if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi

  set +f
  for active_operation in "$lease"/starting.* "$lease"/operation.*; do
    set -f
    if [ ! -e "$active_operation" ] && [ ! -L "$active_operation" ]; then continue; fi
    if [ ! -d "$active_operation" ] || [ -L "$active_operation" ]; then
      fail invalid_state 40
    fi
    operation_name=${active_operation##*/}
    operation_identity=${operation_name#*.}
    operation_token=${operation_identity%.*}
    operation_pid=${operation_identity##*.}
    case "$operation_token" in
      ????????????????????????????????) ;;
      *) fail invalid_state 40 ;;
    esac
    case "$operation_token" in *[!0-9a-f]*) fail invalid_state 40 ;; esac
    case "$operation_pid" in ''|0|0*|*[!0-9]*) fail invalid_state 40 ;; esac
    if kill -0 "$operation_pid" 2>/dev/null; then
      fail install_in_progress 24
    fi
    set +f
    for operation_entry in "$active_operation"/*; do
      set -f
      if [ ! -e "$operation_entry" ] && [ ! -L "$operation_entry" ]; then continue; fi
      case ${operation_entry##*/} in ready|go) ;; *) fail invalid_state 40 ;; esac
      if [ ! -f "$operation_entry" ] || [ -L "$operation_entry" ]; then
        fail invalid_state 40
      fi
      rm -f "$operation_entry" || fail invalid_state 40
    done
    rmdir "$active_operation" 2>/dev/null || fail install_in_progress 24
  done
  set -f
  active_guard="${lease}/active"
  if [ -e "$active_guard" ] || [ -L "$active_guard" ]; then
    if [ ! -d "$active_guard" ] || [ -L "$active_guard" ]; then fail invalid_state 40; fi
    inspect_active
    active_status=$?
    if [ "$active_status" = 0 ]; then
      if kill -0 "$active_pid" 2>/dev/null; then fail install_in_progress 24; fi
      if [ -e "$active_guard/.owner-next" ] || [ -L "$active_guard/.owner-next" ]; then
        fail invalid_state 40
      fi
      set +f
      set -- "$active_guard"/*
      set -f
      if [ "$#" -ne 1 ] || [ "$1" != "$active_owner_path" ]; then fail invalid_state 40; fi
      stale_active_owner=$active_owner_path
      stale_active_token=$active_token
      stale_active_pid=$active_pid
      scan_claims "$active_claim_prefix" "$active_reaper_claim"
      if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi
      if ! read_owner "$stale_active_owner" "$stale_active_token" ||
         [ "$owner_pid" != "$stale_active_pid" ]; then fail invalid_state 40; fi
      rm -f "$stale_active_owner" || fail invalid_state 40
      rmdir "$active_guard" 2>/dev/null || fail invalid_state 40
    elif [ "$active_status" = 1 ]; then
      active_next="$active_guard/.owner-next"
      scan_claims "$active_claim_prefix" "$active_reaper_claim"
      if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi
      if [ -e "$active_next" ] || [ -L "$active_next" ]; then
        if [ ! -f "$active_next" ] || [ -L "$active_next" ]; then fail invalid_state 40; fi
        rm -f "$active_next" || fail invalid_state 40
      fi
      rmdir "$active_guard" 2>/dev/null || fail invalid_state 40
    else
      fail invalid_state 40
    fi
  else
    scan_claims "$active_claim_prefix" "$active_reaper_claim"
    if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi
  fi
  if ! rm -f "$active_reaper_claim"; then fail invalid_state 40; fi
  active_reaper_claim_owned=0
  set +f
  set -- "$lease"/owner.*
  set -f
  if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
    scan_claims "$claim_prefix" "$claim"
    if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi
    if [ -e "$owner_next" ] || [ -L "$owner_next" ]; then
      if [ ! -f "$owner_next" ] || [ -L "$owner_next" ]; then fail invalid_state 40; fi
      rm -f "$owner_next" || fail invalid_state 40
    fi
    if rmdir "$lease" 2>/dev/null; then continue; fi
    fail invalid_state 40
  fi
  existing_owner=$1
  existing_token=${existing_owner##*/owner.}
  case "$existing_token" in
    ????????????????????????????????) ;;
    *) fail invalid_state 40 ;;
  esac
  case "$existing_token" in *[!0-9a-f]*) fail invalid_state 40 ;; esac
  if ! read_owner "$existing_owner" "$existing_token"; then fail invalid_state 40; fi
  if kill -0 "$owner_pid" 2>/dev/null; then
    fail install_in_progress 24
  fi
  existing_owner_pid=$owner_pid
  # The token is part of the owner filename, so a delayed stale reaper can
  # only remove the owner it inspected. It cannot unlink a new holder's
  # distinct owner file after another contender recreates the lease directory.
  scan_claims "$claim_prefix" "$claim"
  if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi
  if ! read_owner "$existing_owner" "$existing_token" ||
     [ "$owner_pid" != "$existing_owner_pid" ]; then fail invalid_state 40; fi
  if ! rm -f "$existing_owner"; then fail invalid_state 40; fi
  scan_claims "$claim_prefix" "$claim"
  if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi
  if rmdir "$lease" 2>/dev/null; then
    continue
  fi
  fail install_in_progress 24
done
fail install_in_progress 24
"#;

const POSIX_LEASE_GUARD_SCRIPT: &str = r#"set -u
set -f
target=$1
token=$2
guard_token=$3
action=$4

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

home=${HOME-}
case "$target" in
  "\$HOME"/*)
    if [ -z "$home" ]; then fail invalid_target 40; fi
    target="$home/${target#"\$HOME"/}"
    ;;
  "~"/*)
    if [ -z "$home" ]; then fail invalid_target 40; fi
    target="$home/${target#"~/"}"
    ;;
esac
case "$target" in /*) ;; *) fail invalid_target 40 ;; esac
case "$token" in
  ????????????????????????????????) ;;
  *) fail invalid_state 40 ;;
esac
case "$token" in *[!0-9a-f]*) fail invalid_state 40 ;; esac
case "$guard_token" in
  ????????????????????????????????) ;;
  *) fail invalid_state 40 ;;
esac
case "$guard_token" in *[!0-9a-f]*) fail invalid_state 40 ;; esac

lease="${target}.nrm-install-lease"
owner="${lease}/owner.${token}"
tab=$(printf '\t')
read_owner() {
  owner_path=$1
  expected_owner_token=$2
  [ -f "$owner_path" ] && [ ! -L "$owner_path" ] || return 1
  owner_line=
  owner_extra=
  {
    IFS= read -r owner_line || return 1
    if IFS= read -r owner_extra || [ -n "$owner_extra" ]; then return 1; fi
  } <"$owner_path"
  old_ifs=$IFS
  IFS=$tab
  set -- $owner_line
  IFS=$old_ifs
  [ "$#" -eq 3 ] || return 1
  [ "$1" = NRM_INSTALL_OWNER_V1 ] || return 1
  [ "$2" = "$expected_owner_token" ] || return 1
  owner_pid=$3
  case "$owner_pid" in ''|0|0*|*[!0-9]*) return 1 ;; esac
  canonical_owner_line=$(printf 'NRM_INSTALL_OWNER_V1\t%s\t%s' \
    "$expected_owner_token" "$owner_pid") || return 1
  [ "$owner_line" = "$canonical_owner_line" ]
}

scan_claims() {
  scan_prefix=$1
  scan_own=$2
  live_claim=0
  set +f
  for scan_claim in "$scan_prefix".*; do
    set -f
    if [ ! -e "$scan_claim" ] && [ ! -L "$scan_claim" ]; then continue; fi
    [ "$scan_claim" != "$scan_own" ] || continue
    if [ ! -f "$scan_claim" ] || [ -L "$scan_claim" ]; then fail invalid_state 40; fi
    scan_identity=${scan_claim#"$scan_prefix".}
    scan_token=${scan_identity%.*}
    scan_pid=${scan_identity##*.}
    case "$scan_token" in
      ????????????????????????????????) ;;
      *) fail invalid_state 40 ;;
    esac
    case "$scan_token" in *[!0-9a-f]*) fail invalid_state 40 ;; esac
    case "$scan_pid" in ''|0|0*|*[!0-9]*) fail invalid_state 40 ;; esac
    if kill -0 "$scan_pid" 2>/dev/null; then
      live_claim=1
    else
      rm -f "$scan_claim" || fail invalid_state 40
    fi
  done
  set -f
}

inspect_active() {
  set +f
  set -- "$active"/owner.*
  set -f
  if [ "$#" -eq 1 ] && [ ! -e "$1" ] && [ ! -L "$1" ]; then return 1; fi
  [ "$#" -eq 1 ] || return 2
  active_existing_owner=$1
  [ -f "$active_existing_owner" ] && [ ! -L "$active_existing_owner" ] || return 2
  active_identity=${active_existing_owner##*/owner.}
  active_existing_token=${active_identity%.*}
  active_filename_pid=${active_identity##*.}
  case "$active_existing_token" in
    ????????????????????????????????) ;;
    *) return 2 ;;
  esac
  case "$active_existing_token" in *[!0-9a-f]*) return 2 ;; esac
  case "$active_filename_pid" in ''|0|0*|*[!0-9]*) return 2 ;; esac
  read_owner "$active_existing_owner" "$active_existing_token" || return 2
  [ "$owner_pid" = "$active_filename_pid" ] || return 2
  active_existing_pid=$owner_pid
}

if ! read_owner "$owner" "$token"; then fail invalid_state 40; fi
if ! kill -0 "$owner_pid" 2>/dev/null; then fail invalid_state 40; fi
lease_owner_pid=$owner_pid

umask 077
active="${lease}/active"
active_owner="${active}/owner.${guard_token}.$$"
active_owner_next="${active}/.owner-next"
active_claim_prefix="${lease}/active.claim"
active_claim="${active_claim_prefix}.${guard_token}.$$"
active_owned=0
active_claim_owned=0
starting="${lease}/starting.${guard_token}.$$"
guard=
action_pid=
cleanup_guard() {
  if [ -n "$action_pid" ] && kill -0 "$action_pid" 2>/dev/null; then
    kill "$action_pid" 2>/dev/null || :
    wait "$action_pid" 2>/dev/null || :
  fi
  for operation_dir in "$starting" ${guard:+"$guard"}; do
    rm -f "$operation_dir/ready" "$operation_dir/go" 2>/dev/null || :
    rmdir "$operation_dir" 2>/dev/null || :
  done
  if [ "$active_owned" = 1 ] && read_owner "$active_owner" "$guard_token" &&
     [ "$owner_pid" = "$$" ]; then
    rm -f "$active_owner" 2>/dev/null || :
  fi
  if [ "$active_owned" = 1 ] && [ -f "$active_owner_next" ] &&
     [ ! -L "$active_owner_next" ]; then rm -f "$active_owner_next" 2>/dev/null || :; fi
  if [ "$active_owned" = 1 ]; then rmdir "$active" 2>/dev/null || :; fi
  if [ "$active_claim_owned" = 1 ]; then rm -f "$active_claim" 2>/dev/null || :; fi
  if [ ! -e "$owner" ] && [ ! -L "$owner" ]; then
    rmdir "$lease" 2>/dev/null || :
  fi
}
trap cleanup_guard 0
trap 'exit 70' 1 2 15

if [ -e "$active_claim" ] || [ -L "$active_claim" ] ||
   ! (set -C; printf 'NRM_INSTALL_OWNER_V1\t%s\t%s\n' "$guard_token" "$$" >"$active_claim"); then
  fail invalid_state 40
fi
active_claim_owned=1
if ! read_owner "$active_claim" "$guard_token" || [ "$owner_pid" != "$$" ]; then fail invalid_state 40; fi

active_attempt=0
while [ "$active_attempt" -lt 4 ]; do
  active_attempt=$((active_attempt + 1))
  if mkdir "$active" 2>/dev/null; then
    active_owned=1
    if ! read_owner "$active_claim" "$guard_token" || [ "$owner_pid" != "$$" ]; then
      fail invalid_state 40
    fi
    if ! (set -C; printf 'NRM_INSTALL_OWNER_V1\t%s\t%s\n' "$guard_token" "$$" >"$active_owner_next"); then
      fail invalid_state 40
    fi
    if ! read_owner "$active_owner_next" "$guard_token" || [ "$owner_pid" != "$$" ]; then
      fail invalid_state 40
    fi
    if [ -e "$active_owner" ] || [ -L "$active_owner" ] ||
       ! mv "$active_owner_next" "$active_owner"; then
      fail invalid_state 40
    fi
    if ! read_owner "$active_owner" "$guard_token" || [ "$owner_pid" != "$$" ]; then
      fail invalid_state 40
    fi
    set +f
    set -- "$active"/*
    set -f
    if [ "$#" -ne 1 ] || [ "$1" != "$active_owner" ]; then fail invalid_state 40; fi
    if ! rm -f "$active_claim"; then fail invalid_state 40; fi
    active_claim_owned=0
    break
  fi
  if [ -L "$active" ] || [ ! -d "$active" ]; then fail invalid_state 40; fi
  inspect_active
  active_status=$?
  if [ "$active_status" = 0 ]; then fail install_in_progress 24; fi
  if [ "$active_status" != 1 ]; then fail invalid_state 40; fi
  scan_claims "$active_claim_prefix" "$active_claim"
  if [ "$live_claim" = 1 ]; then fail install_in_progress 24; fi
  if [ -e "$active_owner_next" ] || [ -L "$active_owner_next" ]; then
    if [ ! -f "$active_owner_next" ] || [ -L "$active_owner_next" ]; then fail invalid_state 40; fi
    rm -f "$active_owner_next" || fail invalid_state 40
  fi
  rmdir "$active" 2>/dev/null || fail invalid_state 40
done
if [ "$active_owned" != 1 ]; then fail install_in_progress 24; fi
if ! mkdir "$starting" 2>/dev/null; then fail install_in_progress 24; fi
# POSIX shells may attach /dev/null to an asynchronous list's standard input.
# Preserve the upload stream before backgrounding, then make it the guarded
# action's stdin explicitly. Close the saved descriptor in both processes.
exec 3<&0
(
  cd "$starting" || exit 40
  : >ready || exit 40
  gate_attempt=0
  while [ ! -f go ]; do
    gate_attempt=$((gate_attempt + 1))
    [ "$gate_attempt" -lt 30 ] || exit 40
    sleep 1
  done
  exec sh -c "$action" <&3 3<&-
) &
action_pid=$!
exec 3<&-
while [ ! -f "$starting/ready" ]; do
  kill -0 "$action_pid" 2>/dev/null || fail invalid_state 40
  sleep 1
done
guard="${lease}/operation.${guard_token}.${action_pid}"
if ! mv "$starting" "$guard"; then fail invalid_state 40; fi

# Recheck after publishing the operation guard. If the old holder died before
# the guard was visible, a new holder may already own a recreated directory;
# the old token must never authorize work in that new lease generation.
expected_owner_pid=$lease_owner_pid
if ! read_owner "$owner" "$token"; then fail invalid_state 40; fi
if [ "$owner_pid" != "$expected_owner_pid" ] || ! kill -0 "$owner_pid" 2>/dev/null; then
  fail invalid_state 40
fi
if ! read_owner "$active_owner" "$guard_token" || [ "$owner_pid" != "$$" ]; then
  fail invalid_state 40
fi

if ! : >"$guard/go"; then fail invalid_state 40; fi
wait "$action_pid"
status=$?
action_pid=
exit "$status"
"#;

const POSIX_STAGE_SCRIPT: &str = r#"set -u
set -f
target=$1
expected_version=$2
force=$3
expected_sha256=$4

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

valid_hash() {
  hash_value=$1
  [ "${#hash_value}" -eq 64 ] || return 1
  case "$hash_value" in *[!0-9a-f]*) return 1 ;; esac
}

hash_file() {
  hash_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    hash_line=$(sha256sum <"$hash_path") || return 1
  elif command -v shasum >/dev/null 2>&1; then
    hash_line=$(shasum -a 256 <"$hash_path") || return 1
  else
    return 1
  fi
  hash_value=${hash_line%% *}
  valid_hash "$hash_value" || return 1
  printf '%s\n' "$hash_value"
}

if ! valid_hash "$expected_sha256"; then
  fail invalid_state 40
fi

home=${HOME-}
case "$target" in
  "\$HOME"/*)
    if [ -z "$home" ]; then fail invalid_target 40; fi
    target="$home/${target#"\$HOME"/}"
    ;;
  "~"/*)
    if [ -z "$home" ]; then fail invalid_target 40; fi
    target="$home/${target#"~/"}"
    ;;
esac
case "$target" in
  /*) ;;
  *) fail invalid_target 40 ;;
esac
case "$target" in
  */) fail invalid_target 40 ;;
esac

tab=$(printf '\t')
newline='
'
case "$target" in
  *"$tab"*|*"$newline"*) fail invalid_target 40 ;;
esac

umask 077
dir=${target%/*}
if [ -z "$dir" ]; then
  dir=/
fi
current_uid=$(id -u 2>/dev/null) || fail invalid_target 40
case "$current_uid" in ''|*[!0-9]*) fail invalid_target 40 ;; esac

secure_directory() {
  secure_path=$1
  require_current_owner=$2
  [ -d "$secure_path" ] && [ ! -L "$secure_path" ] || return 1
  secure_stat_style=gnu
  if secure_metadata=$(LC_ALL=C stat -c '%u %a' "$secure_path" 2>/dev/null); then :
  elif secure_metadata=$(LC_ALL=C stat -f '%u %p' "$secure_path" 2>/dev/null); then
    secure_stat_style=bsd
  else return 1
  fi
  old_ifs=$IFS
  IFS=' '
  set -- $secure_metadata
  IFS=$old_ifs
  [ "$#" -eq 2 ] || return 1
  secure_owner=$1
  secure_mode=$2
  if [ "$secure_stat_style" = bsd ]; then
    case "$secure_mode" in
      4[0-7][0-7][0-7][0-7]) secure_mode=${secure_mode#?} ;;
      *) return 1 ;;
    esac
  fi
  case "$secure_owner" in ''|*[!0-9]*) return 1 ;; esac
  if [ "$secure_owner" != 0 ] && [ "$secure_owner" != "$current_uid" ]; then return 1; fi
  if [ "$require_current_owner" = 1 ] && [ "$secure_owner" != "$current_uid" ]; then return 1; fi
  case "$secure_mode" in
    [0-7][0-7][0-7]) secure_special=0; secure_permissions=$secure_mode ;;
    [0-7][0-7][0-7][0-7])
      secure_special=${secure_mode%???}
      secure_permissions=${secure_mode#?}
      ;;
    *) return 1 ;;
  esac
  secure_tail=${secure_permissions#?}
  secure_group=${secure_tail%?}
  secure_other=${secure_tail#?}
  secure_shared_write=0
  case "$secure_group" in 2|3|6|7) secure_shared_write=1 ;; esac
  case "$secure_other" in 2|3|6|7) secure_shared_write=1 ;; esac
  if [ "$secure_shared_write" = 1 ]; then
    [ "$require_current_owner" = 0 ] || return 1
    case "$secure_special" in 1|3|5|7) ;; *) return 1 ;; esac
  fi
}

secure_symlink_owner() {
  symlink_path=$1
  [ -L "$symlink_path" ] || return 1
  if symlink_owner=$(LC_ALL=C stat -c '%u' "$symlink_path" 2>/dev/null); then :
  elif symlink_owner=$(LC_ALL=C stat -f '%u' "$symlink_path" 2>/dev/null); then :
  else return 1
  fi
  case "$symlink_owner" in ''|*[!0-9]*) return 1 ;; esac
  [ "$symlink_owner" = 0 ] || [ "$symlink_owner" = "$current_uid" ]
}

secure_physical_chain() {
  physical_dir=$1
  physical_endpoint_required=$2
  if [ "$physical_dir" = / ]; then
    secure_directory / "$physical_endpoint_required"
    return
  fi
  secure_directory / 0 || return 1
  physical_remaining=${physical_dir#/}
  physical_prefix=
  while [ -n "$physical_remaining" ]; do
    case "$physical_remaining" in
      */*) physical_component=${physical_remaining%%/*}; physical_remaining=${physical_remaining#*/} ;;
      *) physical_component=$physical_remaining; physical_remaining= ;;
    esac
    [ -n "$physical_component" ] || return 1
    physical_prefix="$physical_prefix/$physical_component"
    if [ -n "$physical_remaining" ]; then physical_final=0
    else physical_final=$physical_endpoint_required
    fi
    secure_directory "$physical_prefix" "$physical_final" || return 1
  done
}

secure_directory_chain() {
  if [ "$dir" = / ]; then secure_directory / 1; return; fi
  secure_directory / 0 || return 1
  lexical_remaining=${dir#/}
  lexical_prefix=
  while [ -n "$lexical_remaining" ]; do
    case "$lexical_remaining" in
      */*) lexical_component=${lexical_remaining%%/*}; lexical_remaining=${lexical_remaining#*/} ;;
      *) lexical_component=$lexical_remaining; lexical_remaining= ;;
    esac
    [ -n "$lexical_component" ] || return 1
    lexical_prefix="$lexical_prefix/$lexical_component"
    if [ -n "$lexical_remaining" ]; then lexical_final=0; else lexical_final=1; fi
    if [ ! -e "$lexical_prefix" ] && [ ! -L "$lexical_prefix" ]; then
      if ! mkdir "$lexical_prefix" 2>/dev/null; then
        if [ ! -e "$lexical_prefix" ] && [ ! -L "$lexical_prefix" ]; then return 2; fi
      fi
    fi
    if [ -L "$lexical_prefix" ]; then
      [ "$lexical_final" = 0 ] || return 1
      secure_symlink_owner "$lexical_prefix" || return 1
    fi
    [ -d "$lexical_prefix" ] || return 1
    lexical_resolved=$(CDPATH= cd -P "$lexical_prefix" 2>/dev/null && pwd -P) || return 1
    case "$lexical_resolved" in /*) ;; *) return 1 ;; esac
    case "$lexical_resolved" in *"$tab"*|*"$newline"*) return 1 ;; esac
    secure_physical_chain "$lexical_resolved" "$lexical_final" || return 1
  done
}

if secure_directory_chain; then :
else
  secure_status=$?
  if [ "$secure_status" = 2 ]; then fail stage_create_failed 30; fi
  fail invalid_target 40
fi
journal="${target}.nrm-install-state"
journal_next="${journal}.next"
if [ -e "$journal" ] || [ -L "$journal" ] ||
   [ -e "$journal_next" ] || [ -L "$journal_next" ]; then
  fail invalid_state 40
fi
had_previous=0
previous_hash=-
if [ -e "$target" ] || [ -L "$target" ]; then
  had_previous=1
  if [ ! -f "$target" ] || [ -L "$target" ]; then
    fail invalid_target 40
  fi
  if [ "$force" != 1 ]; then
    fail already_exists 23
  fi
  if ! previous_hash=$(hash_file "$target"); then
    fail stage_create_failed 30
  fi
fi

stage=
backup=
version_actual=
version_expected=
version_stderr=
journal_published=0
journal_next_owned=0
preparing_line=

exact_line_file() {
  exact_path=$1
  exact_expected=$2
  [ -f "$exact_path" ] && [ ! -L "$exact_path" ] || return 1
  exact_line=
  exact_extra=
  {
    IFS= read -r exact_line || return 1
    if IFS= read -r exact_extra || [ -n "$exact_extra" ]; then return 1; fi
  } <"$exact_path"
  [ "$exact_line" = "$exact_expected" ]
}

target_is_original() {
  if [ "$had_previous" = 1 ]; then
    [ -f "$target" ] && [ ! -L "$target" ] || return 1
    original_hash=$(hash_file "$target") || return 1
    [ "$original_hash" = "$previous_hash" ]
  else
    [ ! -e "$target" ] && [ ! -L "$target" ]
  fi
}

cleanup_stage() {
  if [ -n "$version_actual" ]; then rm -f "$version_actual"; fi
  if [ -n "$version_expected" ]; then rm -f "$version_expected"; fi
  if [ -n "$version_stderr" ]; then rm -f "$version_stderr"; fi
  if [ "$journal_next_owned" = 1 ] &&
     [ -f "$journal_next" ] && [ ! -L "$journal_next" ]; then
    rm -f "$journal_next"
    journal_next_owned=0
  fi
  if [ "$journal_published" = 0 ]; then
    if [ -n "$stage" ]; then rm -f "$stage"; fi
    if [ -n "$backup" ]; then rm -f "$backup"; fi
  elif [ -n "$preparing_line" ] && exact_line_file "$journal" "$preparing_line" &&
       [ ! -e "$journal_next" ] && [ ! -L "$journal_next" ] &&
       [ ! -e "$backup" ] && [ ! -L "$backup" ] && target_is_original; then
    if [ ! -e "$stage" ] && [ ! -L "$stage" ]; then :
    elif [ -f "$stage" ] && [ ! -L "$stage" ] && target_is_original; then
      rm -f "$stage"
    else
      return
    fi
    if target_is_original && exact_line_file "$journal" "$preparing_line"; then
      rm -f "$journal"
    fi
  fi
}
trap cleanup_stage 0
trap 'exit 70' 1 2 15

if ! stage=$(mktemp "${target}.nrm-stage.XXXXXXXXXX"); then
  fail stage_create_failed 30
fi
if ! backup=$(mktemp "${target}.nrm-backup.XXXXXXXXXX"); then
  fail stage_create_failed 30
fi
if ! rm -f "$backup"; then
  fail stage_create_failed 30
fi

if [ "$had_previous" = 1 ]; then journal_mode=present; else journal_mode=missing; fi
if ! preparing_line=$(printf 'NRM_INSTALL_STATE_V1\t%s\tpreparing\t%s\t%s\t%s\t%s\t%s' \
    "$target" "$journal_mode" "$stage" "$backup" "$previous_hash" "$expected_sha256"); then
  fail stage_create_failed 30
fi
if ! (set -C; printf '%s\n' "$preparing_line" >"$journal_next"); then
  fail invalid_state 40
fi
journal_next_owned=1
if ! exact_line_file "$journal_next" "$preparing_line"; then
  fail invalid_state 40
fi
if [ -e "$journal" ] || [ -L "$journal" ] || ! ln "$journal_next" "$journal"; then
  fail invalid_state 40
fi
journal_published=1
if ! exact_line_file "$journal" "$preparing_line" || ! cmp -s "$journal_next" "$journal"; then
  fail invalid_state 40
fi
if ! rm -f "$journal_next"; then fail invalid_state 40; fi
journal_next_owned=0

if ! cat > "$stage"; then
  fail upload_failed 31
fi
if ! chmod 755 "$stage"; then
  fail chmod_failed 32
fi
if [ ! -f "$stage" ] || [ -L "$stage" ]; then
  fail upload_failed 31
fi
if ! candidate_hash=$(hash_file "$stage"); then
  fail upload_failed 31
fi
if [ "$candidate_hash" != "$expected_sha256" ]; then
  fail upload_failed 31
fi
if ! version_actual=$(mktemp "${stage}.version-actual.XXXXXXXXXX"); then
  fail stage_create_failed 30
fi
if ! version_expected=$(mktemp "${stage}.version-expected.XXXXXXXXXX"); then
  fail stage_create_failed 30
fi
if ! version_stderr=$(mktemp "${stage}.version-stderr.XXXXXXXXXX"); then
  fail stage_create_failed 30
fi
if ! "$stage" --version >"$version_actual" 2>"$version_stderr"; then
  fail version_exec_failed 33
fi
if ! printf 'nrm-agent %s\n' "$expected_version" >"$version_expected"; then
  fail stage_create_failed 30
fi
if [ -s "$version_stderr" ] || ! cmp -s "$version_expected" "$version_actual"; then
  fail version_mismatch 34
fi

rm -f "$version_actual" "$version_expected" "$version_stderr"
version_actual=
version_expected=
version_stderr=
if ! staged_line=$(printf 'NRM_INSTALL_STATE_V1\t%s\tstaged\t%s\t%s\t%s\t%s\t%s' \
    "$target" "$journal_mode" "$stage" "$backup" "$previous_hash" "$candidate_hash"); then
  fail stage_create_failed 30
fi
if ! (set -C; printf '%s\n' "$staged_line" >"$journal_next"); then
  fail invalid_state 40
fi
journal_next_owned=1
if ! exact_line_file "$journal_next" "$staged_line" ||
   ! exact_line_file "$journal" "$preparing_line"; then
  fail invalid_state 40
fi
if ! mv -f "$journal_next" "$journal"; then
  fail invalid_state 40
fi
journal_next_owned=0
if ! exact_line_file "$journal" "$staged_line"; then fail invalid_state 40; fi
trap - 0 1 2 15
printf 'NRM_INSTALL_STAGE_V1\t%s\t%s\t%s\t%s\n' "$target" "$stage" "$backup" "$had_previous"
"#;

const POSIX_ACTIVATE_SCRIPT: &str = r#"set -u
set -f
LC_ALL=C
export LC_ALL
target=$1
stage=$2
backup=$3
force=$4
expected_previous=$5
expected_sha256=$6
journal="${target}.nrm-install-state"
journal_next="${journal}.next"

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

valid_hash() {
  hash_value=$1
  [ "${#hash_value}" -eq 64 ] || return 1
  case "$hash_value" in *[!0-9a-f]*) return 1 ;; esac
}

hash_file() {
  hash_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    hash_line=$(sha256sum <"$hash_path") || return 1
  elif command -v shasum >/dev/null 2>&1; then
    hash_line=$(shasum -a 256 <"$hash_path") || return 1
  else
    return 1
  fi
  hash_value=${hash_line%% *}
  valid_hash "$hash_value" || return 1
  printf '%s\n' "$hash_value"
}

read_state() {
  if [ -e "$journal_next" ] || [ -L "$journal_next" ]; then return 1; fi
  if [ ! -f "$journal" ] || [ -L "$journal" ]; then return 1; fi
  state_line=
  state_extra=
  {
    IFS= read -r state_line || return 1
    if IFS= read -r state_extra || [ -n "$state_extra" ]; then return 1; fi
  } <"$journal"
  old_ifs=$IFS
  IFS=$(printf '\t')
  set -- $state_line
  IFS=$old_ifs
  [ "$#" -eq 8 ] || return 1
  [ "$1" = NRM_INSTALL_STATE_V1 ] || return 1
  [ "$2" = "$target" ] || return 1
  [ "$3" = staged ] || return 1
  state_mode=$4
  [ "$5" = "$stage" ] || return 1
  [ "$6" = "$backup" ] || return 1
  previous_hash=$7
  candidate_hash=$8
  valid_hash "$expected_sha256" || return 1
  [ "$candidate_hash" = "$expected_sha256" ] || return 1
  valid_hash "$candidate_hash" || return 1
  case "$state_mode" in
    present) valid_hash "$previous_hash" || return 1 ;;
    missing) [ "$previous_hash" = - ] || return 1 ;;
    *) return 1 ;;
  esac
  canonical_state_line=$(printf 'NRM_INSTALL_STATE_V1\t%s\tstaged\t%s\t%s\t%s\t%s\t%s' \
    "$target" "$state_mode" "$stage" "$backup" "$previous_hash" "$candidate_hash") || return 1
  [ "$state_line" = "$canonical_state_line" ]
}

case "$target" in /*) ;; *) fail invalid_state 40 ;; esac
case "$stage" in "$target".nrm-stage.*) ;; *) fail invalid_state 40 ;; esac
case "$backup" in "$target".nrm-backup.*) ;; *) fail invalid_state 40 ;; esac
case "$expected_previous" in 0|1) ;; *) fail invalid_state 40 ;; esac
if [ "$stage" = "$backup" ] || [ ! -f "$stage" ] || [ -L "$stage" ] || [ ! -x "$stage" ]; then
  fail invalid_state 40
fi
if [ -e "$backup" ] || [ -L "$backup" ]; then
  fail invalid_state 40
fi
if ! read_state; then fail invalid_state 40; fi
if { [ "$expected_previous" = 1 ] && [ "$state_mode" != present ]; } ||
   { [ "$expected_previous" = 0 ] && [ "$state_mode" != missing ]; }; then
  fail invalid_state 40
fi
if ! actual_candidate=$(hash_file "$stage") || [ "$actual_candidate" != "$candidate_hash" ]; then
  fail invalid_state 40
fi

if [ "$expected_previous" = 1 ]; then
  if [ ! -f "$target" ] || [ -L "$target" ]; then fail invalid_state 40; fi
  if [ "$force" != 1 ]; then
    fail already_exists 23
  fi
  if ! actual_previous=$(hash_file "$target") || [ "$actual_previous" != "$previous_hash" ]; then
    fail invalid_state 40
  fi
  # The rollback copy must be a distinct inode. A hard link would let an
  # in-place writer corrupt the live target and its backup simultaneously.
  if ! cp -pP "$target" "$backup"; then
    fail activation_failed 41
  fi
else
  if [ -e "$target" ] || [ -L "$target" ]; then fail invalid_state 40; fi
fi

if [ "$expected_previous" = 1 ]; then
  if [ ! -f "$backup" ] || [ -L "$backup" ]; then fail invalid_state 40; fi
  if ! actual_backup=$(hash_file "$backup") || [ "$actual_backup" != "$previous_hash" ]; then
    fail invalid_state 40
  fi
  if [ ! -f "$target" ] || [ -L "$target" ]; then fail invalid_state 40; fi
  if ! actual_previous=$(hash_file "$target") || [ "$actual_previous" != "$previous_hash" ]; then
    fail invalid_state 40
  fi
else
  if [ -e "$backup" ] || [ -L "$backup" ] || [ -e "$target" ] || [ -L "$target" ]; then
    fail invalid_state 40
  fi
fi
if [ ! -f "$stage" ] || [ -L "$stage" ] ||
   ! actual_candidate=$(hash_file "$stage") || [ "$actual_candidate" != "$candidate_hash" ]; then
  fail invalid_state 40
fi

if ! move_error=$(mktemp "${stage}.activate-error.XXXXXXXXXX"); then
  fail activation_failed 41
fi
if ! mv -f "$stage" "$target" 2>"$move_error"; then
  lower=$(tr '[:upper:]' '[:lower:]' <"$move_error")
  cat "$move_error" >&2
  rm -f "$move_error"
  case "$lower" in
    *"text file busy"*|*"resource busy"*|*"device busy"*|*"being used"*|*"sharing violation"*|*"in use"*)
      fail process_in_use 42
      ;;
    *) fail activation_failed 41 ;;
  esac
fi
rm -f "$move_error"
if [ ! -f "$target" ] || [ -L "$target" ] ||
   ! actual_candidate=$(hash_file "$target") || [ "$actual_candidate" != "$candidate_hash" ]; then
  fail invalid_state 40
fi
if [ "$expected_previous" = 1 ]; then
  if [ ! -f "$backup" ] || [ -L "$backup" ] ||
     ! actual_backup=$(hash_file "$backup") || [ "$actual_backup" != "$previous_hash" ]; then
    fail invalid_state 40
  fi
fi
printf 'NRM_INSTALL_ACTIVATED_V1\t%s\t%s\t%s\n' "$target" "$backup" "$expected_previous"
"#;

const POSIX_RECONCILE_SCRIPT: &str = r#"set -u
set -f
target=$1
stage=$2
backup=$3
had_previous=$4
expected_sha256=$5
journal="${target}.nrm-install-state"
journal_next="${journal}.next"

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

valid_hash() {
  hash_value=$1
  [ "${#hash_value}" -eq 64 ] || return 1
  case "$hash_value" in *[!0-9a-f]*) return 1 ;; esac
}

hash_file() {
  hash_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    hash_line=$(sha256sum <"$hash_path") || return 1
  elif command -v shasum >/dev/null 2>&1; then
    hash_line=$(shasum -a 256 <"$hash_path") || return 1
  else
    return 1
  fi
  hash_value=${hash_line%% *}
  valid_hash "$hash_value" || return 1
  printf '%s\n' "$hash_value"
}

read_state() {
  if [ -e "$journal_next" ] || [ -L "$journal_next" ]; then return 1; fi
  if [ ! -f "$journal" ] || [ -L "$journal" ]; then return 1; fi
  state_line=
  state_extra=
  {
    IFS= read -r state_line || return 1
    if IFS= read -r state_extra || [ -n "$state_extra" ]; then return 1; fi
  } <"$journal"
  old_ifs=$IFS
  IFS=$(printf '\t')
  set -- $state_line
  IFS=$old_ifs
  [ "$#" -eq 8 ] || return 1
  [ "$1" = NRM_INSTALL_STATE_V1 ] || return 1
  [ "$2" = "$target" ] || return 1
  [ "$3" = staged ] || return 1
  state_mode=$4
  [ "$5" = "$stage" ] || return 1
  [ "$6" = "$backup" ] || return 1
  previous_hash=$7
  candidate_hash=$8
  valid_hash "$expected_sha256" || return 1
  [ "$candidate_hash" = "$expected_sha256" ] || return 1
  valid_hash "$candidate_hash" || return 1
  case "$state_mode" in
    present) valid_hash "$previous_hash" || return 1 ;;
    missing) [ "$previous_hash" = - ] || return 1 ;;
    *) return 1 ;;
  esac
  canonical_state_line=$(printf 'NRM_INSTALL_STATE_V1\t%s\tstaged\t%s\t%s\t%s\t%s\t%s' \
    "$target" "$state_mode" "$stage" "$backup" "$previous_hash" "$candidate_hash") || return 1
  [ "$state_line" = "$canonical_state_line" ]
}

matches_hash() {
  match_path=$1
  match_expected=$2
  [ -f "$match_path" ] && [ ! -L "$match_path" ] || return 1
  match_actual=$(hash_file "$match_path") || return 1
  [ "$match_actual" = "$match_expected" ]
}

case "$target" in /*) ;; *) fail rollback_failed 50 ;; esac
case "$stage" in "$target".nrm-stage.*) ;; *) fail rollback_failed 50 ;; esac
case "$backup" in "$target".nrm-backup.*) ;; *) fail rollback_failed 50 ;; esac
case "$had_previous" in 0|1) ;; *) fail rollback_failed 50 ;; esac
if ! read_state; then fail rollback_failed 50; fi
if { [ "$had_previous" = 1 ] && [ "$state_mode" != present ]; } ||
   { [ "$had_previous" = 0 ] && [ "$state_mode" != missing ]; }; then
  fail rollback_failed 50
fi

if [ -e "$stage" ] || [ -L "$stage" ]; then
  if ! matches_hash "$stage" "$candidate_hash"; then fail rollback_failed 50; fi
  if [ "$had_previous" = 1 ]; then
    if ! matches_hash "$target" "$previous_hash"; then fail rollback_failed 50; fi
    if [ -e "$backup" ] || [ -L "$backup" ]; then
      if ! matches_hash "$backup" "$previous_hash"; then fail rollback_failed 50; fi
    fi
    outcome=activation_unchanged_present
  else
    if [ -e "$target" ] || [ -L "$target" ]; then
      fail rollback_failed 50
    fi
    if [ -e "$backup" ] || [ -L "$backup" ]; then fail rollback_failed 50; fi
    outcome=activation_unchanged_missing
  fi
  if ! matches_hash "$stage" "$candidate_hash"; then fail rollback_failed 50; fi
  if ! rm -f "$stage"; then fail rollback_failed 50; fi
  if [ -e "$backup" ] || [ -L "$backup" ]; then
    if ! matches_hash "$backup" "$previous_hash" || ! rm -f "$backup"; then
      fail rollback_failed 50
    fi
  fi
elif [ "$had_previous" = 1 ]; then
  if [ -e "$backup" ] || [ -L "$backup" ]; then
    if ! matches_hash "$backup" "$previous_hash"; then
      fail rollback_failed 50
    fi
    if matches_hash "$target" "$candidate_hash"; then
      if ! rollback_error=$(mktemp "${backup}.reconcile-error.XXXXXXXXXX"); then
        fail rollback_failed 50
      fi
      if ! matches_hash "$backup" "$previous_hash" ||
         ! matches_hash "$target" "$candidate_hash"; then
        rm -f "$rollback_error"
        fail rollback_failed 50
      fi
      if ! mv -f "$backup" "$target" 2>"$rollback_error"; then
        cat "$rollback_error" >&2
        rm -f "$rollback_error"
        fail rollback_failed 50
      fi
      rm -f "$rollback_error"
      if ! matches_hash "$target" "$previous_hash"; then fail rollback_failed 50; fi
    elif matches_hash "$target" "$previous_hash"; then
      # A prior reconciliation may have removed the stage before dying. The
      # target is already restored; remove only the verified duplicate backup.
      if ! matches_hash "$backup" "$previous_hash" || ! rm -f "$backup"; then
        fail rollback_failed 50
      fi
    else
      fail rollback_failed 50
    fi
    outcome=restored_previous
  elif matches_hash "$target" "$previous_hash"; then
    outcome=restored_previous
  else
    fail rollback_failed 50
  fi
else
  if [ -e "$backup" ] || [ -L "$backup" ]; then
    fail rollback_failed 50
  fi
  if [ -e "$target" ] || [ -L "$target" ]; then
    if ! matches_hash "$target" "$candidate_hash"; then
      fail rollback_failed 50
    fi
    if ! matches_hash "$target" "$candidate_hash" || ! rm -f "$target"; then
      fail rollback_failed 50
    fi
    if [ -e "$target" ] || [ -L "$target" ]; then fail rollback_failed 50; fi
  fi
  outcome=removed_candidate
fi

if ! read_state; then fail rollback_failed 50; fi
if { [ "$had_previous" = 1 ] && [ "$state_mode" != present ]; } ||
   { [ "$had_previous" = 0 ] && [ "$state_mode" != missing ]; }; then
  fail rollback_failed 50
fi
if [ ! -f "$journal" ] || [ -L "$journal" ] || ! rm -f "$journal"; then
  fail rollback_failed 50
fi

printf 'NRM_INSTALL_RECONCILED_V1\t%s\t%s\n' "$target" "$outcome"
"#;

const POSIX_ROLLBACK_SCRIPT: &str = r#"set -u
set -f
target=$1
stage=$2
backup=$3
had_previous=$4
expected_sha256=$5
journal="${target}.nrm-install-state"
journal_next="${journal}.next"

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

valid_hash() {
  hash_value=$1
  [ "${#hash_value}" -eq 64 ] || return 1
  case "$hash_value" in *[!0-9a-f]*) return 1 ;; esac
}

hash_file() {
  hash_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    hash_line=$(sha256sum <"$hash_path") || return 1
  elif command -v shasum >/dev/null 2>&1; then
    hash_line=$(shasum -a 256 <"$hash_path") || return 1
  else
    return 1
  fi
  hash_value=${hash_line%% *}
  valid_hash "$hash_value" || return 1
  printf '%s\n' "$hash_value"
}

read_state() {
  if [ -e "$journal_next" ] || [ -L "$journal_next" ]; then return 1; fi
  if [ ! -f "$journal" ] || [ -L "$journal" ]; then return 1; fi
  state_line=
  state_extra=
  {
    IFS= read -r state_line || return 1
    if IFS= read -r state_extra || [ -n "$state_extra" ]; then return 1; fi
  } <"$journal"
  old_ifs=$IFS
  IFS=$(printf '\t')
  set -- $state_line
  IFS=$old_ifs
  [ "$#" -eq 8 ] || return 1
  [ "$1" = NRM_INSTALL_STATE_V1 ] || return 1
  [ "$2" = "$target" ] || return 1
  [ "$3" = staged ] || return 1
  state_mode=$4
  [ "$5" = "$stage" ] || return 1
  [ "$6" = "$backup" ] || return 1
  previous_hash=$7
  candidate_hash=$8
  valid_hash "$expected_sha256" || return 1
  [ "$candidate_hash" = "$expected_sha256" ] || return 1
  valid_hash "$candidate_hash" || return 1
  case "$state_mode" in
    present) valid_hash "$previous_hash" || return 1 ;;
    missing) [ "$previous_hash" = - ] || return 1 ;;
    *) return 1 ;;
  esac
  canonical_state_line=$(printf 'NRM_INSTALL_STATE_V1\t%s\tstaged\t%s\t%s\t%s\t%s\t%s' \
    "$target" "$state_mode" "$stage" "$backup" "$previous_hash" "$candidate_hash") || return 1
  [ "$state_line" = "$canonical_state_line" ]
}

matches_hash() {
  match_path=$1
  match_expected=$2
  [ -f "$match_path" ] && [ ! -L "$match_path" ] || return 1
  match_actual=$(hash_file "$match_path") || return 1
  [ "$match_actual" = "$match_expected" ]
}

case "$target" in /*) ;; *) fail rollback_failed 50 ;; esac
case "$stage" in "$target".nrm-stage.*) ;; *) fail rollback_failed 50 ;; esac
case "$backup" in "$target".nrm-backup.*) ;; *) fail rollback_failed 50 ;; esac
case "$had_previous" in 0|1) ;; *) fail rollback_failed 50 ;; esac
if [ -e "$stage" ] || [ -L "$stage" ]; then fail rollback_failed 50; fi
if ! read_state; then fail rollback_failed 50; fi
if { [ "$had_previous" = 1 ] && [ "$state_mode" != present ]; } ||
   { [ "$had_previous" = 0 ] && [ "$state_mode" != missing ]; }; then
  fail rollback_failed 50
fi

if [ "$had_previous" = 1 ]; then
  if [ -e "$backup" ] || [ -L "$backup" ]; then
    if ! matches_hash "$backup" "$previous_hash" ||
       ! matches_hash "$target" "$candidate_hash"; then
      fail rollback_failed 50
    fi
    if ! rollback_error=$(mktemp "${backup}.rollback-error.XXXXXXXXXX"); then
      fail rollback_failed 50
    fi
    if ! matches_hash "$backup" "$previous_hash" ||
       ! matches_hash "$target" "$candidate_hash"; then
      rm -f "$rollback_error"
      fail rollback_failed 50
    fi
    if ! mv -f "$backup" "$target" 2>"$rollback_error"; then
      cat "$rollback_error" >&2
      rm -f "$rollback_error"
      fail rollback_failed 50
    fi
    rm -f "$rollback_error"
    if ! matches_hash "$target" "$previous_hash"; then fail rollback_failed 50; fi
  elif ! matches_hash "$target" "$previous_hash"; then
    fail rollback_failed 50
  fi
elif [ "$had_previous" = 0 ]; then
  if [ -e "$backup" ] || [ -L "$backup" ]; then fail rollback_failed 50; fi
  if [ -e "$target" ] || [ -L "$target" ]; then
    if ! matches_hash "$target" "$candidate_hash"; then
      fail rollback_failed 50
    fi
    if ! matches_hash "$target" "$candidate_hash" || ! rm -f "$target"; then
      fail rollback_failed 50
    fi
    if [ -e "$target" ] || [ -L "$target" ]; then fail rollback_failed 50; fi
  fi
else
  fail rollback_failed 50
fi

if [ -e "$backup" ] || [ -L "$backup" ]; then fail rollback_failed 50; fi
if ! read_state; then fail rollback_failed 50; fi
if { [ "$had_previous" = 1 ] && [ "$state_mode" != present ]; } ||
   { [ "$had_previous" = 0 ] && [ "$state_mode" != missing ]; }; then
  fail rollback_failed 50
fi
if [ ! -f "$journal" ] || [ -L "$journal" ] || ! rm -f "$journal"; then
  fail rollback_failed 50
fi
printf 'NRM_INSTALL_ROLLED_BACK_V1\t%s\t%s\n' "$target" "$had_previous"
"#;

const POSIX_ABSENCE_CHECK_SCRIPT: &str = r#"set -u
target=$1
journal="${target}.nrm-install-state"
journal_next="${journal}.next"

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

case "$target" in /*) ;; *) fail rollback_failed 50 ;; esac
if [ -e "$journal" ] || [ -L "$journal" ] ||
   [ -e "$journal_next" ] || [ -L "$journal_next" ]; then
  fail rollback_failed 50
fi
if [ -e "$target" ] || [ -L "$target" ]; then
  fail rollback_failed 50
fi
printf 'NRM_INSTALL_ABSENT_V1\t%s\n' "$target"
"#;

const POSIX_CLEANUP_SCRIPT: &str = r#"set -u
set -f
target=$1
stage=$2
backup=$3
had_previous=$4
expected_sha256=$5
journal="${target}.nrm-install-state"
journal_next="${journal}.next"

fail() {
  printf 'NRM_INSTALL_ERROR_V1\tcleanup_failed\n' >&2
  exit 51
}

valid_hash() {
  hash_value=$1
  [ "${#hash_value}" -eq 64 ] || return 1
  case "$hash_value" in *[!0-9a-f]*) return 1 ;; esac
}

hash_file() {
  hash_path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    hash_line=$(sha256sum <"$hash_path") || return 1
  elif command -v shasum >/dev/null 2>&1; then
    hash_line=$(shasum -a 256 <"$hash_path") || return 1
  else
    return 1
  fi
  hash_value=${hash_line%% *}
  valid_hash "$hash_value" || return 1
  printf '%s\n' "$hash_value"
}

read_state() {
  if [ -e "$journal_next" ] || [ -L "$journal_next" ]; then return 1; fi
  if [ ! -f "$journal" ] || [ -L "$journal" ]; then return 1; fi
  state_line=
  state_extra=
  {
    IFS= read -r state_line || return 1
    if IFS= read -r state_extra || [ -n "$state_extra" ]; then return 1; fi
  } <"$journal"
  old_ifs=$IFS
  IFS=$(printf '\t')
  set -- $state_line
  IFS=$old_ifs
  [ "$#" -eq 8 ] || return 1
  [ "$1" = NRM_INSTALL_STATE_V1 ] || return 1
  [ "$2" = "$target" ] || return 1
  [ "$3" = staged ] || return 1
  state_mode=$4
  [ "$5" = "$stage" ] || return 1
  [ "$6" = "$backup" ] || return 1
  previous_hash=$7
  candidate_hash=$8
  valid_hash "$expected_sha256" || return 1
  [ "$candidate_hash" = "$expected_sha256" ] || return 1
  valid_hash "$candidate_hash" || return 1
  case "$state_mode" in
    present) valid_hash "$previous_hash" || return 1 ;;
    missing) [ "$previous_hash" = - ] || return 1 ;;
    *) return 1 ;;
  esac
  canonical_state_line=$(printf 'NRM_INSTALL_STATE_V1\t%s\tstaged\t%s\t%s\t%s\t%s\t%s' \
    "$target" "$state_mode" "$stage" "$backup" "$previous_hash" "$candidate_hash") || return 1
  [ "$state_line" = "$canonical_state_line" ]
}

matches_hash() {
  match_path=$1
  match_expected=$2
  [ -f "$match_path" ] && [ ! -L "$match_path" ] || return 1
  match_actual=$(hash_file "$match_path") || return 1
  [ "$match_actual" = "$match_expected" ]
}

case "$target" in /*) ;; *) fail ;; esac
case "$stage" in "$target".nrm-stage.*) ;; *) fail ;; esac
case "$backup" in "$target".nrm-backup.*) ;; *) fail ;; esac
case "$had_previous" in 0|1) ;; *) fail ;; esac
if ! read_state; then fail; fi
if { [ "$had_previous" = 1 ] && [ "$state_mode" != present ]; } ||
   { [ "$had_previous" = 0 ] && [ "$state_mode" != missing ]; }; then
  fail
fi

if [ -e "$stage" ] || [ -L "$stage" ]; then
  if ! matches_hash "$stage" "$candidate_hash"; then fail; fi
  if [ -e "$backup" ] || [ -L "$backup" ]; then fail; fi
  if [ "$had_previous" = 1 ]; then
    if ! matches_hash "$target" "$previous_hash"; then fail; fi
  elif [ -e "$target" ] || [ -L "$target" ]; then
    fail
  fi
  if ! matches_hash "$stage" "$candidate_hash" || ! rm -f "$stage"; then fail; fi
else
  if [ "$had_previous" = 1 ]; then
    if matches_hash "$target" "$candidate_hash"; then
      if [ -e "$backup" ] || [ -L "$backup" ]; then
        if ! matches_hash "$backup" "$previous_hash" ||
           ! matches_hash "$target" "$candidate_hash" ||
           ! rm -f "$backup"; then
          fail
        fi
      fi
      if ! matches_hash "$target" "$candidate_hash"; then fail; fi
    elif matches_hash "$target" "$previous_hash"; then
      # Resuming cleanup after the pre-activation stage was already removed.
      if [ -e "$backup" ] || [ -L "$backup" ]; then fail; fi
    else
      fail
    fi
  else
    if [ -e "$backup" ] || [ -L "$backup" ]; then fail; fi
    if [ -e "$target" ] || [ -L "$target" ]; then
      if ! matches_hash "$target" "$candidate_hash"; then fail; fi
    fi
  fi
fi
if ! read_state; then fail; fi
if { [ "$had_previous" = 1 ] && [ "$state_mode" != present ]; } ||
   { [ "$had_previous" = 0 ] && [ "$state_mode" != missing ]; }; then
  fail
fi
if [ ! -f "$journal" ] || [ -L "$journal" ] || ! rm -f "$journal"; then
  fail
fi
printf 'NRM_INSTALL_CLEANED_V1\t%s\n' "$target"
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PosixInstallPlan {
    target_input: String,
    expected_version: String,
    expected_sha256: Option<String>,
    expected_protocol_version: u16,
    force: bool,
    lease_token: Option<String>,
}

impl PosixInstallPlan {
    pub(crate) fn new(
        target_input: impl Into<String>,
        expected_version: impl Into<String>,
        expected_protocol_version: u16,
        force: bool,
    ) -> Result<Self, InstallPlanError> {
        let target_input = target_input.into();
        validate_target_input(&target_input)?;
        let expected_version = expected_version.into();
        validate_version(&expected_version)?;
        Ok(Self {
            target_input,
            expected_version,
            expected_sha256: None,
            expected_protocol_version,
            force,
            lease_token: None,
        })
    }

    pub(crate) fn stage_command(&self) -> String {
        self.guard_command(render_posix_script(
            "nrm-agent-stage",
            POSIX_STAGE_SCRIPT,
            &[
                self.target_input.as_str(),
                self.expected_version.as_str(),
                bool_arg(self.force),
                self.expected_sha256.as_deref().unwrap_or("-"),
            ],
        ))
    }

    pub(crate) fn lease_command(&self, token: &str) -> Result<String, InstallPlanError> {
        validate_lease_token(token)?;
        let expected_sha256 = self.expected_sha256.as_deref().ok_or_else(|| {
            InstallPlanError::Record(
                "expected artifact digest must be set before acquiring the install lease"
                    .to_owned(),
            )
        })?;
        Ok(render_posix_script(
            "nrm-agent-install-lease",
            POSIX_LEASE_SCRIPT,
            &[self.target_input.as_str(), token, expected_sha256],
        ))
    }

    pub(crate) fn parse_lease_ready_stdout(
        &self,
        token: &str,
        stdout: &str,
    ) -> Result<String, InstallPlanError> {
        validate_lease_token(token)?;
        let fields = parse_record(stdout, LEASE_READY_RECORD, 2)?;
        if fields[1] != token {
            return Err(InstallPlanError::Record(
                "lease readiness token does not match the requested lease".to_owned(),
            ));
        }
        validate_resolved_target(fields[0])?;
        if self.target_input.starts_with('/') && fields[0] != self.target_input {
            return Err(InstallPlanError::Record(
                "lease target does not match the requested absolute path".to_owned(),
            ));
        }
        Ok(fields[0].to_owned())
    }

    pub(crate) fn set_force(&mut self, force: bool) {
        self.force = force;
    }

    pub(crate) fn bind_resolved_lease_target(
        &mut self,
        target: &str,
    ) -> Result<(), InstallPlanError> {
        validate_resolved_target(target)?;
        if self.target_input.starts_with('/') && self.target_input != target {
            return Err(InstallPlanError::Record(
                "resolved lease target does not match the requested absolute path".to_owned(),
            ));
        }
        self.target_input = target.to_owned();
        Ok(())
    }

    pub(crate) fn set_expected_sha256(&mut self, digest: &str) -> Result<(), InstallPlanError> {
        if !is_lowercase_sha256(digest) {
            return Err(InstallPlanError::Record(
                "expected artifact digest must be lowercase SHA-256".to_owned(),
            ));
        }
        self.expected_sha256 = Some(digest.to_owned());
        Ok(())
    }

    pub(crate) fn set_lease_token(&mut self, token: &str) -> Result<(), InstallPlanError> {
        validate_lease_token(token)?;
        self.lease_token = Some(token.to_owned());
        Ok(())
    }

    fn guard_command(&self, command: String) -> String {
        let Some(token) = self.lease_token.as_deref() else {
            return command;
        };
        let guard_token = new_posix_guard_token(&self.target_input, &command);
        render_posix_script(
            "nrm-agent-install-operation",
            POSIX_LEASE_GUARD_SCRIPT,
            &[
                self.target_input.as_str(),
                token,
                guard_token.as_str(),
                command.as_str(),
            ],
        )
    }

    pub(crate) fn parse_stage_stdout(
        &self,
        stdout: &str,
    ) -> Result<StagedInstall, InstallPlanError> {
        let fields = parse_record(stdout, STAGE_RECORD, 4)?;
        let staged = StagedInstall {
            target_path: fields[0].to_owned(),
            stage_path: fields[1].to_owned(),
            backup_path: fields[2].to_owned(),
            had_previous: parse_bool_field(fields[3])?,
        };
        validate_staged(&staged)?;
        if self.target_input.starts_with('/') && staged.target_path != self.target_input {
            return Err(InstallPlanError::Record(
                "staged target does not match the requested absolute path".to_owned(),
            ));
        }
        Ok(staged)
    }

    pub(crate) fn staged_validation(&self, staged: &StagedInstall) -> PosixValidationHook {
        PosixValidationHook {
            executable_path: staged.stage_path.clone(),
            expected_version: Some(self.expected_version.clone()),
            expected_protocol_version: Some(self.expected_protocol_version),
            phase: ValidationPhase::Staged,
            mode: ValidationMode::FullHelloExact,
        }
    }

    pub(crate) fn activate_command(&self, staged: &StagedInstall) -> String {
        self.guard_command(render_posix_script(
            "nrm-agent-activate",
            POSIX_ACTIVATE_SCRIPT,
            &[
                staged.target_path.as_str(),
                staged.stage_path.as_str(),
                staged.backup_path.as_str(),
                bool_arg(self.force),
                bool_arg(staged.had_previous),
                self.expected_sha256.as_deref().unwrap_or("-"),
            ],
        ))
    }

    pub(crate) fn parse_activation_stdout(
        &self,
        staged: &StagedInstall,
        stdout: &str,
    ) -> Result<ActivatedInstall, InstallPlanError> {
        let fields = parse_record(stdout, ACTIVATED_RECORD, 3)?;
        if fields[0] != staged.target_path || fields[1] != staged.backup_path {
            return Err(InstallPlanError::Record(
                "activation record paths do not match the staged install".to_owned(),
            ));
        }
        let had_previous = parse_bool_field(fields[2])?;
        if had_previous != staged.had_previous {
            return Err(InstallPlanError::Record(
                "activation record does not match staged prior-target state".to_owned(),
            ));
        }
        Ok(ActivatedInstall {
            staged: staged.clone(),
            had_previous,
        })
    }

    pub(crate) fn post_activation_validation(
        &self,
        activated: &ActivatedInstall,
    ) -> PosixValidationHook {
        PosixValidationHook {
            executable_path: activated.staged.target_path.clone(),
            expected_version: Some(self.expected_version.clone()),
            expected_protocol_version: Some(self.expected_protocol_version),
            phase: ValidationPhase::Activated,
            mode: ValidationMode::FullHelloExact,
        }
    }

    pub(crate) fn reconcile_activation_command(&self, staged: &StagedInstall) -> String {
        self.guard_command(render_posix_script(
            "nrm-agent-reconcile",
            POSIX_RECONCILE_SCRIPT,
            &[
                staged.target_path.as_str(),
                staged.stage_path.as_str(),
                staged.backup_path.as_str(),
                bool_arg(staged.had_previous),
                self.expected_sha256.as_deref().unwrap_or("-"),
            ],
        ))
    }

    pub(crate) fn parse_reconciliation_stdout(
        &self,
        staged: &StagedInstall,
        stdout: &str,
    ) -> Result<ActivationRecovery, InstallPlanError> {
        let fields = parse_record(stdout, RECONCILED_RECORD, 2)?;
        if fields[0] != staged.target_path {
            return Err(InstallPlanError::Record(
                "reconciliation record target does not match the staged install".to_owned(),
            ));
        }
        let kind = match fields[1] {
            "activation_unchanged_present" => ActivationRecoveryKind::ActivationUnchangedPresent,
            "activation_unchanged_missing" => ActivationRecoveryKind::ActivationUnchangedMissing,
            "restored_previous" => ActivationRecoveryKind::RestoredPrevious,
            "removed_candidate" => ActivationRecoveryKind::RemovedCandidate,
            _ => {
                return Err(InstallPlanError::Record(
                    "reconciliation record has an unknown recovery outcome".to_owned(),
                ));
            }
        };
        Ok(ActivationRecovery {
            target_path: staged.target_path.clone(),
            kind,
        })
    }

    pub(crate) fn reconciliation_validation(
        &self,
        recovery: &ActivationRecovery,
    ) -> PosixValidationHook {
        PosixValidationHook {
            executable_path: recovery.target_path.clone(),
            expected_version: None,
            expected_protocol_version: None,
            phase: ValidationPhase::Reconciled,
            mode: match recovery.kind {
                ActivationRecoveryKind::ActivationUnchangedPresent
                | ActivationRecoveryKind::RestoredPrevious => ValidationMode::Reprobe,
                ActivationRecoveryKind::ActivationUnchangedMissing
                | ActivationRecoveryKind::RemovedCandidate => ValidationMode::ExpectMissing,
            },
        }
    }

    pub(crate) fn rollback_command(&self, activated: &ActivatedInstall) -> String {
        self.guard_command(render_posix_script(
            "nrm-agent-rollback",
            POSIX_ROLLBACK_SCRIPT,
            &[
                activated.staged.target_path.as_str(),
                activated.staged.stage_path.as_str(),
                activated.staged.backup_path.as_str(),
                bool_arg(activated.had_previous),
                self.expected_sha256.as_deref().unwrap_or("-"),
            ],
        ))
    }

    pub(crate) fn parse_rollback_stdout(
        &self,
        activated: &ActivatedInstall,
        stdout: &str,
    ) -> Result<RollbackOutcome, InstallPlanError> {
        let fields = parse_record(stdout, ROLLED_BACK_RECORD, 2)?;
        if fields[0] != activated.staged.target_path {
            return Err(InstallPlanError::Record(
                "rollback record target does not match the activated install".to_owned(),
            ));
        }
        let restored_previous = parse_bool_field(fields[1])?;
        if restored_previous != activated.had_previous {
            return Err(InstallPlanError::Record(
                "rollback record does not match prior-target state".to_owned(),
            ));
        }
        Ok(RollbackOutcome {
            target_path: activated.staged.target_path.clone(),
            restored_previous,
        })
    }

    pub(crate) fn rollback_validation(&self, outcome: &RollbackOutcome) -> PosixValidationHook {
        PosixValidationHook {
            executable_path: outcome.target_path.clone(),
            expected_version: None,
            expected_protocol_version: None,
            phase: ValidationPhase::RolledBack,
            mode: if outcome.restored_previous {
                ValidationMode::Reprobe
            } else {
                ValidationMode::ExpectMissing
            },
        }
    }

    pub(crate) fn absence_check_command(
        &self,
        hook: &PosixValidationHook,
    ) -> Result<String, InstallPlanError> {
        validate_absence_hook(hook)?;
        Ok(self.guard_command(render_posix_script(
            "nrm-agent-absence-check",
            POSIX_ABSENCE_CHECK_SCRIPT,
            &[hook.executable_path.as_str()],
        )))
    }

    pub(crate) fn parse_absence_check_stdout(
        &self,
        hook: &PosixValidationHook,
        stdout: &str,
    ) -> Result<(), InstallPlanError> {
        validate_absence_hook(hook)?;
        let fields = parse_record(stdout, ABSENT_RECORD, 1)?;
        if fields[0] != hook.executable_path {
            return Err(InstallPlanError::Record(
                "absence record target does not match the validation hook".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn cleanup_command(&self, staged: &StagedInstall) -> String {
        self.guard_command(render_posix_script(
            "nrm-agent-cleanup",
            POSIX_CLEANUP_SCRIPT,
            &[
                staged.target_path.as_str(),
                staged.stage_path.as_str(),
                staged.backup_path.as_str(),
                bool_arg(staged.had_previous),
                self.expected_sha256.as_deref().unwrap_or("-"),
            ],
        ))
    }

    pub(crate) fn parse_cleanup_stdout(
        &self,
        staged: &StagedInstall,
        stdout: &str,
    ) -> Result<(), InstallPlanError> {
        let fields = parse_record(stdout, CLEANED_RECORD, 1)?;
        if fields[0] != staged.target_path {
            return Err(InstallPlanError::Record(
                "cleanup record target does not match the staged install".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StagedInstall {
    pub(crate) target_path: String,
    pub(crate) stage_path: String,
    pub(crate) backup_path: String,
    pub(crate) had_previous: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActivatedInstall {
    pub(crate) staged: StagedInstall,
    pub(crate) had_previous: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RollbackOutcome {
    pub(crate) target_path: String,
    pub(crate) restored_previous: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActivationRecoveryKind {
    /// The stage still existed, so the atomic activation rename did not occur.
    ActivationUnchangedPresent,
    /// The stage still existed and no target was present.
    ActivationUnchangedMissing,
    /// The stage was gone and the preserved prior executable was restored.
    RestoredPrevious,
    /// The stage was gone, there was no backup, and the candidate was removed.
    RemovedCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActivationRecovery {
    pub(crate) target_path: String,
    pub(crate) kind: ActivationRecoveryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidationPhase {
    Staged,
    Activated,
    Reconciled,
    RolledBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidationMode {
    /// Run exact `--version`, then a complete protocol Hello.
    FullHelloExact,
    /// Reprobe the restored prior executable without assuming it is current.
    Reprobe,
    /// Confirm that the target is absent after rolling back a new install.
    ExpectMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PosixValidationHook {
    pub(crate) executable_path: String,
    pub(crate) expected_version: Option<String>,
    pub(crate) expected_protocol_version: Option<u16>,
    pub(crate) phase: ValidationPhase,
    pub(crate) mode: ValidationMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstallFailureKind {
    AlreadyExists,
    InstallInProgress,
    InvalidTarget,
    StageCreateFailed,
    UploadFailed,
    ChmodFailed,
    VersionExecutionFailed,
    VersionMismatch,
    InvalidState,
    ActivationFailed,
    ProcessInUse,
    RollbackFailed,
    CleanupFailed,
    CommandFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InstallFailure {
    pub(crate) kind: InstallFailureKind,
    pub(crate) exit_code: Option<i32>,
    pub(crate) detail: String,
}

impl fmt::Display for InstallFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for InstallFailure {}

pub(crate) fn classify_install_failure(exit_code: Option<i32>, stderr: &str) -> InstallFailure {
    let marker = stderr.lines().rev().find_map(|line| {
        line.strip_prefix(ERROR_RECORD)
            .and_then(|rest| rest.strip_prefix('\t'))
    });
    let lower = stderr.to_ascii_lowercase();
    let kind = marker.map(marker_failure_kind).unwrap_or_else(|| {
        if contains_process_in_use(&lower) {
            InstallFailureKind::ProcessInUse
        } else if lower.contains("rollback") {
            InstallFailureKind::RollbackFailed
        } else {
            InstallFailureKind::CommandFailed
        }
    });
    InstallFailure {
        kind,
        exit_code,
        detail: failure_detail(stderr),
    }
}

#[cfg(test)]
pub(crate) fn validate_exact_version_output(
    expected_version: &str,
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), InstallFailure> {
    let expected = format!("nrm-agent {expected_version}\n");
    if !success {
        return Err(InstallFailure {
            kind: InstallFailureKind::VersionExecutionFailed,
            exit_code: None,
            detail: "nrm-agent --version did not exit successfully".to_owned(),
        });
    }
    if stdout != expected.as_bytes() || !stderr.is_empty() {
        return Err(InstallFailure {
            kind: InstallFailureKind::VersionMismatch,
            exit_code: None,
            detail: "nrm-agent --version output did not match exactly".to_owned(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InstallPlanError {
    Target(String),
    Version(String),
    Record(String),
}

impl fmt::Display for InstallPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(message) => write!(formatter, "invalid install target: {message}"),
            Self::Version(message) => {
                write!(formatter, "invalid expected agent version: {message}")
            }
            Self::Record(message) => write!(formatter, "invalid install record: {message}"),
        }
    }
}

impl std::error::Error for InstallPlanError {}

fn validate_target_input(target: &str) -> Result<(), InstallPlanError> {
    if target.is_empty() || target.len() > 4096 {
        return Err(InstallPlanError::Target(
            "path must contain between 1 and 4096 bytes".to_owned(),
        ));
    }
    if target != target.trim()
        || target.chars().any(char::is_control)
        || target.ends_with('/')
        || target.starts_with("//")
    {
        return Err(InstallPlanError::Target(
            "path contains unsupported whitespace, controls, or trailing separators".to_owned(),
        ));
    }
    let path = target
        .strip_prefix("$HOME/")
        .or_else(|| target.strip_prefix("~/"))
        .or_else(|| target.strip_prefix('/'))
        .ok_or_else(|| {
            InstallPlanError::Target("path must be absolute or start with $HOME/ or ~/".to_owned())
        })?;
    if path.is_empty()
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(InstallPlanError::Target(
            "path must name a file and must not contain . or .. components".to_owned(),
        ));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), InstallPlanError> {
    if version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        return Err(InstallPlanError::Version(
            "version must be a short ASCII SemVer-like value".to_owned(),
        ));
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_staged(staged: &StagedInstall) -> Result<(), InstallPlanError> {
    validate_runtime_path(&staged.target_path)?;
    validate_runtime_path(&staged.stage_path)?;
    validate_runtime_path(&staged.backup_path)?;
    if staged.stage_path == staged.backup_path {
        return Err(InstallPlanError::Record(
            "stage and backup paths must be distinct".to_owned(),
        ));
    }
    validate_derived_path(&staged.target_path, &staged.stage_path, ".nrm-stage.")?;
    validate_derived_path(&staged.target_path, &staged.backup_path, ".nrm-backup.")?;
    if posix_parent(&staged.target_path) != posix_parent(&staged.stage_path)
        || posix_parent(&staged.target_path) != posix_parent(&staged.backup_path)
    {
        return Err(InstallPlanError::Record(
            "stage and backup must be in the target directory".to_owned(),
        ));
    }
    Ok(())
}

fn validate_absence_hook(hook: &PosixValidationHook) -> Result<(), InstallPlanError> {
    if hook.mode != ValidationMode::ExpectMissing {
        return Err(InstallPlanError::Record(
            "absence checks require an expect-missing validation hook".to_owned(),
        ));
    }
    validate_runtime_path(&hook.executable_path)
}

fn validate_runtime_path(path: &str) -> Result<(), InstallPlanError> {
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.ends_with('/')
        || path.chars().any(char::is_control)
    {
        return Err(InstallPlanError::Record(
            "runtime path is not a safe absolute POSIX file path".to_owned(),
        ));
    }
    Ok(())
}

fn validate_derived_path(
    target: &str,
    derived: &str,
    separator: &str,
) -> Result<(), InstallPlanError> {
    let prefix = format!("{target}{separator}");
    let suffix = derived.strip_prefix(&prefix).ok_or_else(|| {
        InstallPlanError::Record("derived path has the wrong target prefix".to_owned())
    })?;
    if !(6..=32).contains(&suffix.len()) || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(InstallPlanError::Record(
            "derived path has an invalid uniqueness suffix".to_owned(),
        ));
    }
    Ok(())
}

fn posix_parent(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) => "/",
        Some((parent, _)) => parent,
        None => "",
    }
}

fn parse_record<'a>(
    stdout: &'a str,
    expected_record: &str,
    field_count: usize,
) -> Result<Vec<&'a str>, InstallPlanError> {
    let line = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(stdout);
    if line.contains(['\r', '\n']) {
        return Err(InstallPlanError::Record(
            "command produced more than one output line".to_owned(),
        ));
    }
    let mut fields = line.split('\t');
    if fields.next() != Some(expected_record) {
        return Err(InstallPlanError::Record(format!(
            "expected {expected_record} record"
        )));
    }
    let fields: Vec<_> = fields.collect();
    if fields.len() != field_count || fields.iter().any(|field| field.is_empty()) {
        return Err(InstallPlanError::Record(format!(
            "{expected_record} has the wrong field count"
        )));
    }
    Ok(fields)
}

fn parse_bool_field(value: &str) -> Result<bool, InstallPlanError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(InstallPlanError::Record(
            "boolean field must be 0 or 1".to_owned(),
        )),
    }
}

fn render_posix_script(name: &str, script: &str, args: &[&str]) -> String {
    let mut words = vec![
        shell_quote("sh"),
        shell_quote("-c"),
        shell_quote(script),
        shell_quote(name),
    ];
    words.extend(args.iter().map(shell_quote));
    words.join(" ")
}

fn shell_quote(value: impl AsRef<str>) -> String {
    format!("'{}'", value.as_ref().replace('\'', "'\\''"))
}

fn bool_arg(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn marker_failure_kind(marker: &str) -> InstallFailureKind {
    match marker {
        "already_exists" => InstallFailureKind::AlreadyExists,
        "install_in_progress" => InstallFailureKind::InstallInProgress,
        "invalid_target" => InstallFailureKind::InvalidTarget,
        "stage_create_failed" => InstallFailureKind::StageCreateFailed,
        "upload_failed" => InstallFailureKind::UploadFailed,
        "chmod_failed" => InstallFailureKind::ChmodFailed,
        "version_exec_failed" => InstallFailureKind::VersionExecutionFailed,
        "version_mismatch" => InstallFailureKind::VersionMismatch,
        "invalid_state" => InstallFailureKind::InvalidState,
        "activation_failed" => InstallFailureKind::ActivationFailed,
        "process_in_use" => InstallFailureKind::ProcessInUse,
        "rollback_failed" => InstallFailureKind::RollbackFailed,
        "cleanup_failed" => InstallFailureKind::CleanupFailed,
        _ => InstallFailureKind::CommandFailed,
    }
}

fn validate_lease_token(token: &str) -> Result<(), InstallPlanError> {
    if token.len() != 32
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(InstallPlanError::Record(
            "lease token must be 32 lowercase hexadecimal characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_resolved_target(target: &str) -> Result<(), InstallPlanError> {
    if !target.starts_with('/')
        || target.ends_with('/')
        || target.chars().any(char::is_control)
        || target[1..]
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(InstallPlanError::Record(
            "lease readiness target is not a safe absolute path".to_owned(),
        ));
    }
    Ok(())
}

fn contains_process_in_use(lower: &str) -> bool {
    [
        "text file busy",
        "resource busy",
        "device busy",
        "being used by another process",
        "sharing violation",
        "process_in_use",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn failure_detail(stderr: &str) -> String {
    let detail: String = stderr
        .trim()
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    if detail.is_empty() {
        return "remote install command failed without diagnostics".to_owned();
    }
    const MAX_DETAIL_BYTES: usize = 4096;
    if detail.len() <= MAX_DETAIL_BYTES {
        return detail;
    }
    let mut end = MAX_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &detail[..end])
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::io::Write as _;
    #[cfg(unix)]
    use std::process::{Command, Output, Stdio};

    #[cfg(unix)]
    use tempfile::tempdir;

    use sha2::{Digest as _, Sha256};

    use super::*;

    const VERSION: &str = "0.1.0";
    const PROTOCOL: u16 = 7;

    fn plan(target: &str, force: bool) -> PosixInstallPlan {
        plan_for_candidate(target, force, &fake_agent(VERSION))
    }

    fn fake_agent(version: &str) -> Vec<u8> {
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'nrm-agent {version}\\n'; exit 0; fi\nexit 0\n"
        )
        .into_bytes()
    }

    fn candidate_sha256(candidate: &[u8]) -> String {
        Sha256::digest(candidate)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn plan_for_candidate(target: &str, force: bool, candidate: &[u8]) -> PosixInstallPlan {
        let mut plan = PosixInstallPlan::new(target, VERSION, PROTOCOL, force).unwrap();
        plan.set_expected_sha256(&candidate_sha256(candidate))
            .unwrap();
        plan
    }

    fn state_path(staged: &StagedInstall) -> String {
        format!("{}.nrm-install-state", staged.target_path)
    }

    #[cfg(unix)]
    fn run(command: &str, stdin: &[u8]) -> Output {
        run_with_env(command, stdin, None)
    }

    #[cfg(unix)]
    fn run_with_env(
        command: &str,
        stdin: &[u8],
        environment: Option<(&str, &std::path::Path)>,
    ) -> Output {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(environment)
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    #[cfg(unix)]
    fn stdout(output: &Output) -> String {
        String::from_utf8(output.stdout.clone()).unwrap()
    }

    #[cfg(unix)]
    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[cfg(unix)]
    fn acquire_lease_holder(plan: &PosixInstallPlan, token: &str) -> std::process::Child {
        use std::io::{BufRead as _, BufReader};

        let mut holder = Command::new("sh")
            .arg("-c")
            .arg(format!("exec {}", plan.lease_command(token).unwrap()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut readiness = String::new();
        BufReader::new(holder.stdout.take().unwrap())
            .read_line(&mut readiness)
            .unwrap();
        plan.parse_lease_ready_stdout(token, &readiness).unwrap();
        holder
    }

    #[cfg(unix)]
    fn recover_with_lease(plan: &PosixInstallPlan, token: &str) -> Output {
        let recovered = run(&plan.lease_command(token).unwrap(), &[]);
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        plan.parse_lease_ready_stdout(token, &stdout(&recovered))
            .unwrap();
        recovered
    }

    #[cfg(unix)]
    #[test]
    fn guarded_stage_preserves_upload_stdin_under_dash() {
        use std::os::unix::fs::symlink;

        const TOKEN: &str = "0123456789abcdef0123456789abcdef";

        let directory = tempdir().unwrap();
        let target = directory.path().join("nrm-agent");
        let candidate = fake_agent(VERSION);
        let mut plan = plan_for_candidate(target.to_str().unwrap(), true, &candidate);
        let mut holder = acquire_lease_holder(&plan, TOKEN);
        plan.set_lease_token(TOKEN).unwrap();

        let command = plan.stage_command();
        assert!(command.contains("exec 3<&0"));
        assert!(command.contains("<&3 3<&-"));

        let dash = ["/bin/dash", "/usr/bin/dash"]
            .into_iter()
            .map(std::path::Path::new)
            .find(|path| path.is_file());
        if let Some(dash) = dash {
            let fake_bin = directory.path().join("dash-bin");
            fs::create_dir(&fake_bin).unwrap();
            symlink(dash, fake_bin.join("sh")).unwrap();
            let search_path = std::path::PathBuf::from(format!(
                "{}:{}",
                fake_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ));

            let staged_output = run_with_env(&command, &candidate, Some(("PATH", &search_path)));
            assert!(staged_output.status.success(), "{}", stderr(&staged_output));
            let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
            assert_eq!(fs::read(&staged.stage_path).unwrap(), candidate);

            let cleanup = run_with_env(
                &plan.cleanup_command(&staged),
                &[],
                Some(("PATH", &search_path)),
            );
            assert!(cleanup.status.success(), "{}", stderr(&cleanup));
        }

        drop(holder.stdin.take());
        let released = holder.wait_with_output().unwrap();
        assert!(released.status.success(), "{}", stderr(&released));
    }

    #[cfg(unix)]
    #[test]
    fn install_lease_serializes_holders_and_reaps_dead_owner() {
        use std::io::{BufRead as _, BufReader};

        const TOKEN_ONE: &str = "0123456789abcdef0123456789abcdef";
        const TOKEN_TWO: &str = "fedcba9876543210fedcba9876543210";

        let dir = tempdir().unwrap();
        let injection_marker = dir.path().join("lease-injection-ran");
        let target = dir.path().join(format!(
            "agent with ' lease; $(touch {})",
            injection_marker.display()
        ));
        let target = target.to_str().unwrap();
        let plan = plan(target, true);
        let command = plan.lease_command(TOKEN_ONE).unwrap();

        let mut holder = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut readiness = String::new();
        BufReader::new(holder.stdout.take().unwrap())
            .read_line(&mut readiness)
            .unwrap();
        assert_eq!(
            plan.parse_lease_ready_stdout(TOKEN_ONE, &readiness)
                .unwrap(),
            target
        );

        let stale = format!("{target}.nrm-install-lease");
        let active = format!("{stale}/active");
        fs::create_dir(&active).unwrap();
        let empty_active = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(empty_active.status.code(), Some(24));
        assert!(!std::path::Path::new(&active).exists());

        fs::create_dir(&active).unwrap();
        fs::write(format!("{active}/.owner-next"), b"partial").unwrap();
        let partial_active = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(partial_active.status.code(), Some(24));
        assert!(!std::path::Path::new(&active).exists());

        let contender = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(contender.status.code(), Some(24));
        assert_eq!(
            classify_install_failure(contender.status.code(), &stderr(&contender)).kind,
            InstallFailureKind::InstallInProgress
        );

        drop(holder.stdin.take());
        let released = holder.wait_with_output().unwrap();
        assert!(released.status.success(), "{}", stderr(&released));
        assert!(!std::path::Path::new(&format!("{target}.nrm-install-lease")).exists());

        fs::create_dir(&stale).unwrap();
        let ownerless = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
        assert!(ownerless.status.success(), "{}", stderr(&ownerless));
        plan.parse_lease_ready_stdout(TOKEN_TWO, &stdout(&ownerless))
            .unwrap();
        assert!(!std::path::Path::new(&stale).exists());

        fs::create_dir(&stale).unwrap();
        fs::write(format!("{stale}/.owner-next"), b"partial").unwrap();
        let unpublished = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
        assert!(unpublished.status.success(), "{}", stderr(&unpublished));
        plan.parse_lease_ready_stdout(TOKEN_TWO, &stdout(&unpublished))
            .unwrap();
        assert!(!std::path::Path::new(&stale).exists());

        fs::create_dir(&stale).unwrap();
        fs::write(format!("{stale}/owner.{TOKEN_ONE}"), "not-a-pid\n").unwrap();
        let malformed = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(malformed.status.code(), Some(40));
        assert!(std::path::Path::new(&stale).exists());
        fs::remove_dir_all(&stale).unwrap();

        fs::create_dir(&stale).unwrap();
        fs::write(
            format!("{stale}/owner.{TOKEN_ONE}"),
            format!(
                "NRM_INSTALL_OWNER_V1\t{TOKEN_ONE}\t{}\n",
                std::process::id()
            ),
        )
        .unwrap();
        let unrelated_live_pid = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(unrelated_live_pid.status.code(), Some(24));
        assert_eq!(
            classify_install_failure(
                unrelated_live_pid.status.code(),
                &stderr(&unrelated_live_pid)
            )
            .kind,
            InstallFailureKind::InstallInProgress
        );
        assert!(std::path::Path::new(&stale).exists());
        fs::remove_dir_all(&stale).unwrap();

        fs::create_dir(&stale).unwrap();
        fs::write(
            format!("{stale}/owner.{TOKEN_ONE}"),
            format!("NRM_INSTALL_OWNER_V1\t{TOKEN_ONE}\t999999\n"),
        )
        .unwrap();
        let reacquired = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
        assert!(reacquired.status.success(), "{}", stderr(&reacquired));
        assert_eq!(
            plan.parse_lease_ready_stdout(TOKEN_TWO, &stdout(&reacquired))
                .unwrap(),
            target
        );
        assert!(!std::path::Path::new(&stale).exists());
        assert!(!injection_marker.exists());

        for malformed_owner in [
            format!("NRM_INSTALL_OWNER_V1\t{TOKEN_ONE}\t999999\nextra\n"),
            format!("NRM_INSTALL_OWNER_V1\t{TOKEN_ONE}\t999999"),
            format!("NRM_INSTALL_OWNER_V1\t{TOKEN_TWO}\t999999\n"),
            format!("NRM_INSTALL_OWNER_V1\t{TOKEN_ONE}\t0\n"),
        ] {
            fs::create_dir(&stale).unwrap();
            fs::write(format!("{stale}/owner.{TOKEN_ONE}"), malformed_owner).unwrap();
            let rejected = run(&plan.lease_command(TOKEN_TWO).unwrap(), &[]);
            assert_eq!(rejected.status.code(), Some(40), "{}", stderr(&rejected));
            assert!(std::path::Path::new(&stale).exists());
            fs::remove_dir_all(&stale).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn install_lease_does_not_reap_a_live_owner_publication_claim() {
        const TOKEN_ONE: &str = "0123456789abcdef0123456789abcdef";
        const TOKEN_TWO: &str = "fedcba9876543210fedcba9876543210";

        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let lease = format!("{target}.nrm-install-lease");
        let ready = dir.path().join("lease-claim-ready");
        let release = dir.path().join("lease-claim-release");
        let paused_creator = r#"set -eu
lease=$1
token=$2
ready=$3
release=$4
claim="${lease}.claim.${token}.$$"
umask 077
printf 'NRM_INSTALL_OWNER_V1\t%s\t%s\n' "$token" "$$" >"$claim"
mkdir "$lease"
: >"$ready"
while [ ! -e "$release" ]; do sleep 1; done
rmdir "$lease"
rm -f "$claim"
"#;
        let mut creator = Command::new("sh")
            .arg("-c")
            .arg(paused_creator)
            .arg("lease-claim-test")
            .arg(&lease)
            .arg(TOKEN_ONE)
            .arg(&ready)
            .arg(&release)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while !ready.exists() && started.elapsed() < std::time::Duration::from_secs(3) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "paused lease creator did not become ready");

        let contender = run(&plan(target, true).lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(contender.status.code(), Some(24), "{}", stderr(&contender));
        assert_eq!(
            classify_install_failure(contender.status.code(), &stderr(&contender)).kind,
            InstallFailureKind::InstallInProgress
        );
        assert!(std::path::Path::new(&lease).is_dir());
        assert!(
            fs::read_dir(dir.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("nrm-agent.nrm-install-lease.claim.{TOKEN_ONE}."))
            }),
            "the live publication claim was removed"
        );
        assert!(fs::read_dir(&lease).unwrap().next().is_none());

        creator.kill().unwrap();
        let killed = creator.wait_with_output().unwrap();
        assert!(!killed.status.success());
        let recovered = run(&plan(target, true).lease_command(TOKEN_TWO).unwrap(), &[]);
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        plan(target, true)
            .parse_lease_ready_stdout(TOKEN_TWO, &stdout(&recovered))
            .unwrap();
        assert!(!std::path::Path::new(&lease).exists());
        assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("nrm-agent.nrm-install-lease.claim.")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn install_lease_claim_elects_a_single_stale_state_reaper() {
        const OLD_TOKEN: &str = "0123456789abcdef0123456789abcdef";
        const REAPER_TOKEN: &str = "11111111111111111111111111111111";
        const CONTENDER_TOKEN: &str = "fedcba9876543210fedcba9876543210";

        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let lease = format!("{target}.nrm-install-lease");
        fs::create_dir(&lease).unwrap();
        fs::write(
            format!("{lease}/owner.{OLD_TOKEN}"),
            format!("NRM_INSTALL_OWNER_V1\t{OLD_TOKEN}\t999999\n"),
        )
        .unwrap();

        let ready = dir.path().join("reaper-claim-ready");
        let release = dir.path().join("reaper-claim-release");
        let paused_reaper = r#"set -eu
lease=$1
token=$2
ready=$3
release=$4
claim="${lease}.claim.${token}.$$"
umask 077
printf 'NRM_INSTALL_OWNER_V1\t%s\t%s\n' "$token" "$$" >"$claim"
: >"$ready"
while [ ! -e "$release" ]; do sleep 1; done
rm -f "$claim"
"#;
        let mut reaper = Command::new("sh")
            .arg("-c")
            .arg(paused_reaper)
            .arg("stale-owner-reaper-test")
            .arg(&lease)
            .arg(REAPER_TOKEN)
            .arg(&ready)
            .arg(&release)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while !ready.exists() && started.elapsed() < std::time::Duration::from_secs(3) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            ready.exists(),
            "paused stale-owner reaper did not become ready"
        );

        let contender = run(
            &plan(target, true).lease_command(CONTENDER_TOKEN).unwrap(),
            &[],
        );
        assert_eq!(contender.status.code(), Some(24), "{}", stderr(&contender));
        assert!(std::path::Path::new(&lease).is_dir());
        assert!(std::path::Path::new(&format!("{lease}/owner.{OLD_TOKEN}")).is_file());
        assert!(fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&format!(
                    "nrm-agent.nrm-install-lease.claim.{REAPER_TOKEN}."
                ))
        }));

        reaper.kill().unwrap();
        let killed = reaper.wait_with_output().unwrap();
        assert!(!killed.status.success());
        let recovered = run(
            &plan(target, true).lease_command(CONTENDER_TOKEN).unwrap(),
            &[],
        );
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        assert!(!std::path::Path::new(&lease).exists());
    }

    #[cfg(unix)]
    #[test]
    fn install_claims_reject_empty_pids_and_reap_dead_partial_records() {
        const TOKEN_ONE: &str = "0123456789abcdef0123456789abcdef";
        const TOKEN_TWO: &str = "fedcba9876543210fedcba9876543210";

        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let lease = format!("{target}.nrm-install-lease");
        fs::create_dir(&lease).unwrap();
        let empty_pid_claim = format!("{lease}.claim.{TOKEN_ONE}.");
        fs::write(
            &empty_pid_claim,
            format!("NRM_INSTALL_OWNER_V1\t{TOKEN_ONE}\t1\n"),
        )
        .unwrap();
        let rejected = run(&plan(target, true).lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(rejected.status.code(), Some(40), "{}", stderr(&rejected));
        assert_eq!(
            classify_install_failure(rejected.status.code(), &stderr(&rejected)).kind,
            InstallFailureKind::InvalidState
        );
        assert!(std::path::Path::new(&lease).is_dir());
        assert!(std::path::Path::new(&empty_pid_claim).is_file());
        fs::remove_file(&empty_pid_claim).unwrap();

        let malformed_claim = format!("{lease}.claim.{TOKEN_ONE}.999999");
        fs::write(&malformed_claim, b"not an owner record\n").unwrap();
        let recovered = run(&plan(target, true).lease_command(TOKEN_TWO).unwrap(), &[]);
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        assert!(!std::path::Path::new(&lease).exists());
        assert!(!std::path::Path::new(&malformed_claim).exists());

        let mut guarded_plan = plan(target, true);
        let mut holder = acquire_lease_holder(&guarded_plan, TOKEN_ONE);
        guarded_plan.set_lease_token(TOKEN_ONE).unwrap();
        let active = format!("{lease}/active");
        fs::create_dir(&active).unwrap();
        let empty_active_pid_claim = format!("{lease}/active.claim.{TOKEN_TWO}.");
        fs::write(
            &empty_active_pid_claim,
            format!("NRM_INSTALL_OWNER_V1\t{TOKEN_TWO}\t1\n"),
        )
        .unwrap();
        let marker = dir.path().join("malformed-claim-action-ran");
        let rejected = run(
            &guarded_plan.guard_command(format!(": > {}", shell_quote(marker.to_string_lossy()))),
            &[],
        );
        assert_eq!(rejected.status.code(), Some(40), "{}", stderr(&rejected));
        assert!(!marker.exists());
        assert!(std::path::Path::new(&active).is_dir());
        assert!(std::path::Path::new(&empty_active_pid_claim).is_file());
        fs::remove_file(&empty_active_pid_claim).unwrap();

        let partial_active_claim = format!("{lease}/active.claim.{TOKEN_TWO}.999999");
        fs::write(&partial_active_claim, b"").unwrap();
        let recovered = run(
            &guarded_plan.guard_command(format!(": > {}", shell_quote(marker.to_string_lossy()))),
            &[],
        );
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        assert!(marker.exists());
        assert!(!std::path::Path::new(&partial_active_claim).exists());
        assert!(!std::path::Path::new(&active).exists());

        drop(holder.stdin.take());
        let released = holder.wait_with_output().unwrap();
        assert!(released.status.success(), "{}", stderr(&released));
    }

    #[cfg(unix)]
    #[test]
    fn install_guard_does_not_reap_a_live_active_publication_claim() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef";

        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let lease = format!("{target}.nrm-install-lease");
        let mut guarded_plan = plan(target, true);
        let mut holder = acquire_lease_holder(&guarded_plan, TOKEN);
        guarded_plan.set_lease_token(TOKEN).unwrap();

        let ready = dir.path().join("active-claim-ready");
        let release = dir.path().join("active-claim-release");
        let paused_creator = r#"set -eu
lease=$1
token=$2
ready=$3
release=$4
claim="${lease}/active.claim.${token}.$$"
umask 077
printf 'NRM_INSTALL_OWNER_V1\t%s\t%s\n' "$token" "$$" >"$claim"
mkdir "$lease/active"
: >"$ready"
while [ ! -e "$release" ]; do sleep 1; done
rmdir "$lease/active"
rm -f "$claim"
"#;
        let mut creator = Command::new("sh")
            .arg("-c")
            .arg(paused_creator)
            .arg("active-claim-test")
            .arg(&lease)
            .arg(TOKEN)
            .arg(&ready)
            .arg(&release)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while !ready.exists() && started.elapsed() < std::time::Duration::from_secs(3) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "paused active creator did not become ready");

        let overlap_marker = dir.path().join("overlapping-action-ran");
        let contender = run(
            &guarded_plan.guard_command(format!(
                ": > {}",
                shell_quote(overlap_marker.to_string_lossy())
            )),
            &[],
        );
        assert_eq!(contender.status.code(), Some(24), "{}", stderr(&contender));
        assert_eq!(
            classify_install_failure(contender.status.code(), &stderr(&contender)).kind,
            InstallFailureKind::InstallInProgress
        );
        assert!(!overlap_marker.exists());
        assert!(std::path::Path::new(&format!("{lease}/active")).is_dir());
        assert!(fs::read_dir(&lease).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("active.claim.{TOKEN}."))
        }));

        creator.kill().unwrap();
        let killed = creator.wait_with_output().unwrap();
        assert!(!killed.status.success());
        let recovered_marker = dir.path().join("recovered-action-ran");
        let recovered = run(
            &guarded_plan.guard_command(format!(
                ": > {}",
                shell_quote(recovered_marker.to_string_lossy())
            )),
            &[],
        );
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        assert!(recovered_marker.exists());

        drop(holder.stdin.take());
        let released = holder.wait_with_output().unwrap();
        assert!(released.status.success(), "{}", stderr(&released));
        assert!(!std::path::Path::new(&lease).exists());
    }

    #[cfg(unix)]
    #[test]
    fn install_active_owner_generation_prevents_delayed_reaper_aba() {
        const LEASE_TOKEN: &str = "0123456789abcdef0123456789abcdef";
        const CONTENDER_TOKEN: &str = "fedcba9876543210fedcba9876543210";
        const STALE_GUARD_TOKEN: &str = "11111111111111111111111111111111";

        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let lease = format!("{target}.nrm-install-lease");
        let active = format!("{lease}/active");
        let mut guarded_plan = plan(target, true);
        let mut holder = acquire_lease_holder(&guarded_plan, LEASE_TOKEN);
        guarded_plan.set_lease_token(LEASE_TOKEN).unwrap();

        fs::create_dir(&active).unwrap();
        let stale_owner = format!("{active}/owner.{STALE_GUARD_TOKEN}.999999");
        fs::write(
            &stale_owner,
            format!("NRM_INSTALL_OWNER_V1\t{STALE_GUARD_TOKEN}\t999999\n"),
        )
        .unwrap();
        let stale_reaper = run(
            &plan(target, true).lease_command(CONTENDER_TOKEN).unwrap(),
            &[],
        );
        assert_eq!(
            stale_reaper.status.code(),
            Some(24),
            "{}",
            stderr(&stale_reaper)
        );
        assert!(!std::path::Path::new(&active).exists());

        let action_ready = dir.path().join("generation-action-ready");
        let action_release = dir.path().join("generation-action-release");
        let action = format!(
            ": > {}; while [ ! -e {} ]; do sleep 1; done",
            shell_quote(action_ready.to_string_lossy()),
            shell_quote(action_release.to_string_lossy())
        );
        let operation = Command::new("sh")
            .arg("-c")
            .arg(guarded_plan.guard_command(action))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while !action_ready.exists() && started.elapsed() < std::time::Duration::from_secs(3) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(action_ready.exists(), "guarded action did not become ready");

        let active_owners = fs::read_dir(&active)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(active_owners.len(), 1);
        let current_owner = &active_owners[0];
        assert!(current_owner
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("owner."));
        assert_ne!(current_owner, &std::path::PathBuf::from(&stale_owner));

        // A delayed stale reaper can unlink only the exact generation it
        // inspected. Its subsequent rmdir cannot remove the new non-empty
        // active directory.
        let _ = fs::remove_file(&stale_owner);
        assert!(fs::remove_dir(&active).is_err());
        assert!(current_owner.is_file());

        let overlap_marker = dir.path().join("generation-overlap-ran");
        let overlapping = run(
            &guarded_plan.guard_command(format!(
                ": > {}",
                shell_quote(overlap_marker.to_string_lossy())
            )),
            &[],
        );
        assert_eq!(
            overlapping.status.code(),
            Some(24),
            "{}",
            stderr(&overlapping)
        );
        assert!(!overlap_marker.exists());

        fs::write(&action_release, b"release").unwrap();
        let operation = operation.wait_with_output().unwrap();
        assert!(operation.status.success(), "{}", stderr(&operation));
        drop(holder.stdin.take());
        let released = holder.wait_with_output().unwrap();
        assert!(released.status.success(), "{}", stderr(&released));
        assert!(!std::path::Path::new(&lease).exists());
    }

    #[cfg(unix)]
    #[test]
    fn install_directories_are_private_and_unsafe_or_symlink_parents_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        const TOKEN: &str = "0123456789abcdef0123456789abcdef";
        let root = tempdir().unwrap();

        let lease_parent = root.path().join("lease/new/private");
        let lease_target = lease_parent.join("nrm-agent");
        let lease_plan = plan(lease_target.to_str().unwrap(), true);
        let lease = run(
            &format!("umask 000; {}", lease_plan.lease_command(TOKEN).unwrap()),
            &[],
        );
        assert!(lease.status.success(), "{}", stderr(&lease));
        for path in [
            root.path().join("lease"),
            root.path().join("lease/new"),
            lease_parent,
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                0o700,
                "lease setup inherited a permissive caller umask"
            );
        }

        let candidate = fake_agent(VERSION);
        let stage_parent = root.path().join("stage/new/private");
        let stage_target = stage_parent.join("nrm-agent");
        let stage_plan = plan_for_candidate(stage_target.to_str().unwrap(), true, &candidate);
        let stage = run(
            &format!("umask 000; {}", stage_plan.stage_command()),
            &candidate,
        );
        assert!(stage.status.success(), "{}", stderr(&stage));
        let staged = stage_plan.parse_stage_stdout(&stdout(&stage)).unwrap();
        for path in [
            root.path().join("stage"),
            root.path().join("stage/new"),
            stage_parent,
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                0o700,
                "staging inherited a permissive caller umask"
            );
        }
        let journal = state_path(&staged);
        assert_eq!(
            fs::metadata(&journal).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
        let next_stage_plan =
            plan_for_candidate(stage_target.to_str().unwrap(), true, b"next signed release");
        let exposed_journal = run(&next_stage_plan.lease_command(TOKEN).unwrap(), &[]);
        assert_eq!(
            exposed_journal.status.code(),
            Some(40),
            "{}",
            stderr(&exposed_journal)
        );
        assert!(std::path::Path::new(&staged.stage_path).exists());
        assert!(std::path::Path::new(&journal).exists());
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        let cleanup = run(&stage_plan.cleanup_command(&staged), &[]);
        assert!(cleanup.status.success(), "{}", stderr(&cleanup));

        let unsafe_parent = root.path().join("unsafe");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let unsafe_target = unsafe_parent.join("nrm-agent");
        let unsafe_plan = plan(unsafe_target.to_str().unwrap(), true);
        let rejected = run(&unsafe_plan.lease_command(TOKEN).unwrap(), &[]);
        assert_eq!(rejected.status.code(), Some(40), "{}", stderr(&rejected));
        assert_eq!(
            classify_install_failure(rejected.status.code(), &stderr(&rejected)).kind,
            InstallFailureKind::InvalidTarget
        );
        assert!(
            !std::path::Path::new(&format!("{}.nrm-install-lease", unsafe_target.display()))
                .exists()
        );

        let physical_parent = root.path().join("physical");
        fs::create_dir(&physical_parent).unwrap();
        let ancestor_link = root.path().join("ancestor-link");
        symlink(&physical_parent, &ancestor_link).unwrap();
        let linked_ancestor_target = ancestor_link.join("private/nrm-agent");
        let linked_ancestor_plan = plan(linked_ancestor_target.to_str().unwrap(), true);
        let accepted = run(&linked_ancestor_plan.lease_command(TOKEN).unwrap(), &[]);
        assert!(accepted.status.success(), "{}", stderr(&accepted));
        assert!(physical_parent.join("private").is_dir());

        let actual_parent = root.path().join("actual-final");
        fs::create_dir(&actual_parent).unwrap();
        let linked_parent = root.path().join("linked-final");
        symlink(&actual_parent, &linked_parent).unwrap();
        let linked_target = linked_parent.join("nrm-agent");
        let linked_plan = plan(linked_target.to_str().unwrap(), true);
        let rejected = run(&linked_plan.lease_command(TOKEN).unwrap(), &[]);
        assert_eq!(rejected.status.code(), Some(40), "{}", stderr(&rejected));
        assert_eq!(
            classify_install_failure(rejected.status.code(), &stderr(&rejected)).kind,
            InstallFailureKind::InvalidTarget
        );
    }

    #[cfg(unix)]
    #[test]
    fn bsd_stat_preserves_sticky_ancestor_bits_for_lease_and_stage() {
        use std::os::unix::fs::PermissionsExt as _;

        const TOKEN: &str = "0123456789abcdef0123456789abcdef";
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let fake_bin = root.path().join("fake-bin");
        fs::create_dir(&fake_bin).unwrap();
        let fake_stat = fake_bin.join("stat");
        fs::write(
            &fake_stat,
            br#"#!/bin/sh
[ "$1" = "-f" ] || exit 1
format=$2
path=$3
uid=$(id -u) || exit 1
case "$format" in
  '%u %p')
    [ -d "$path" ] && [ ! -L "$path" ] || exit 1
    case "$path" in
      /|/private) printf '0 40755\n' ;;
      /tmp|/private/tmp) printf '0 41777\n' ;;
      */bad-bsd-type) printf '%s 100700\n' "$uid" ;;
      *) printf '%s 40700\n' "$uid" ;;
    esac
    ;;
  '%u %Lp')
    if [ -d "$path" ] && [ ! -L "$path" ]; then
      case "$path" in
        /|/private) printf '0 755\n' ;;
        /tmp|/private/tmp) printf '0 777\n' ;;
        *) printf '%s 700\n' "$uid" ;;
      esac
    else
      printf '%s 600\n' "$uid"
    fi
    ;;
  '%u') printf '%s\n' "$uid" ;;
  *) exit 1 ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&fake_stat, fs::Permissions::from_mode(0o755)).unwrap();
        let search_path = std::path::PathBuf::from(format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        ));

        let lease_target = root.path().join("lease/new/nrm-agent");
        let lease_plan = plan(lease_target.to_str().unwrap(), true);
        let leased = run_with_env(
            &lease_plan.lease_command(TOKEN).unwrap(),
            &[],
            Some(("PATH", &search_path)),
        );
        assert!(leased.status.success(), "{}", stderr(&leased));
        lease_plan
            .parse_lease_ready_stdout(TOKEN, &stdout(&leased))
            .unwrap();

        let candidate = fake_agent(VERSION);
        let stage_target = root.path().join("stage/new/nrm-agent");
        let stage_plan = plan_for_candidate(stage_target.to_str().unwrap(), true, &candidate);
        let staged_output = run_with_env(
            &stage_plan.stage_command(),
            &candidate,
            Some(("PATH", &search_path)),
        );
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = stage_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        let cleanup = run_with_env(
            &stage_plan.cleanup_command(&staged),
            &[],
            Some(("PATH", &search_path)),
        );
        assert!(cleanup.status.success(), "{}", stderr(&cleanup));

        let malformed_parent = root.path().join("bad-bsd-type");
        fs::create_dir(&malformed_parent).unwrap();
        let malformed_plan = plan(malformed_parent.join("nrm-agent").to_str().unwrap(), true);
        let rejected = run_with_env(
            &malformed_plan.lease_command(TOKEN).unwrap(),
            &[],
            Some(("PATH", &search_path)),
        );
        assert_eq!(rejected.status.code(), Some(40), "{}", stderr(&rejected));
        assert_eq!(
            classify_install_failure(rejected.status.code(), &stderr(&rejected)).kind,
            InstallFailureKind::InvalidTarget
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_operation_guard_survives_holder_disconnect() {
        use std::io::{BufRead as _, BufReader};

        const TOKEN_ONE: &str = "0123456789abcdef0123456789abcdef";
        const TOKEN_TWO: &str = "fedcba9876543210fedcba9876543210";
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let mut guarded_plan = plan(target, true);
        let mut holder = Command::new("sh")
            .arg("-c")
            .arg(guarded_plan.lease_command(TOKEN_ONE).unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut readiness = String::new();
        BufReader::new(holder.stdout.take().unwrap())
            .read_line(&mut readiness)
            .unwrap();
        guarded_plan
            .parse_lease_ready_stdout(TOKEN_ONE, &readiness)
            .unwrap();
        guarded_plan.set_lease_token(TOKEN_ONE).unwrap();

        let operation_ready = dir.path().join("operation-ready");
        let operation_release = dir.path().join("operation-release");
        let action = format!(
            ": > {}; while [ ! -e {} ]; do sleep 1; done",
            shell_quote(operation_ready.to_string_lossy()),
            shell_quote(operation_release.to_string_lossy())
        );
        let operation = Command::new("sh")
            .arg("-c")
            .arg(guarded_plan.guard_command(action))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while !operation_ready.exists() && started.elapsed() < std::time::Duration::from_secs(3) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            operation_ready.exists(),
            "operation guard did not become ready"
        );

        drop(holder.stdin.take());
        let released = holder.wait_with_output().unwrap();
        assert!(released.status.success(), "{}", stderr(&released));
        let contender = run(&plan(target, true).lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(contender.status.code(), Some(24), "{}", stderr(&contender));
        assert_eq!(
            classify_install_failure(contender.status.code(), &stderr(&contender)).kind,
            InstallFailureKind::InstallInProgress
        );

        fs::write(&operation_release, b"release").unwrap();
        let operation = operation.wait_with_output().unwrap();
        assert!(operation.status.success(), "{}", stderr(&operation));
        assert!(!std::path::Path::new(&format!("{target}.nrm-install-lease")).exists());
        let reacquired = run(&plan(target, true).lease_command(TOKEN_TWO).unwrap(), &[]);
        assert!(reacquired.status.success(), "{}", stderr(&reacquired));
    }

    #[cfg(unix)]
    #[test]
    fn install_operation_journal_survives_guard_sigkill_and_is_reaped_after_action() {
        use std::io::{BufRead as _, BufReader};

        const TOKEN_ONE: &str = "0123456789abcdef0123456789abcdef";
        const TOKEN_TWO: &str = "fedcba9876543210fedcba9876543210";
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let mut guarded_plan = plan(target, true);
        let mut holder = Command::new("sh")
            .arg("-c")
            .arg(guarded_plan.lease_command(TOKEN_ONE).unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut readiness = String::new();
        BufReader::new(holder.stdout.take().unwrap())
            .read_line(&mut readiness)
            .unwrap();
        guarded_plan
            .parse_lease_ready_stdout(TOKEN_ONE, &readiness)
            .unwrap();
        guarded_plan.set_lease_token(TOKEN_ONE).unwrap();

        let action_ready = dir.path().join("sigkill-action-ready");
        let action_release = dir.path().join("sigkill-action-release");
        let action = format!(
            ": > {}; while [ ! -e {} ]; do sleep 1; done",
            shell_quote(action_ready.to_string_lossy()),
            shell_quote(action_release.to_string_lossy())
        );
        let mut operation = Command::new("sh")
            .arg("-c")
            .arg(guarded_plan.guard_command(action))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while !action_ready.exists() && started.elapsed() < std::time::Duration::from_secs(3) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(action_ready.exists(), "guarded action did not become ready");

        operation.kill().unwrap();
        let overlapping_marker = dir.path().join("overlapping-guard-ran");
        let overlapping = run(
            &guarded_plan.guard_command(format!(
                ": > {}",
                shell_quote(overlapping_marker.to_string_lossy())
            )),
            &[],
        );
        assert_eq!(
            overlapping.status.code(),
            Some(24),
            "{}",
            stderr(&overlapping)
        );
        assert_eq!(
            classify_install_failure(overlapping.status.code(), &stderr(&overlapping)).kind,
            InstallFailureKind::InstallInProgress
        );
        assert!(
            !overlapping_marker.exists(),
            "a second guarded action overlapped the transport-orphaned action"
        );
        let contender = run(&plan(target, true).lease_command(TOKEN_TWO).unwrap(), &[]);
        assert_eq!(contender.status.code(), Some(24), "{}", stderr(&contender));
        assert_eq!(
            classify_install_failure(contender.status.code(), &stderr(&contender)).kind,
            InstallFailureKind::InstallInProgress
        );

        fs::write(&action_release, b"release").unwrap();
        let killed = operation.wait_with_output().unwrap();
        assert!(!killed.status.success());
        drop(holder.stdin.take());
        let released = holder.wait_with_output().unwrap();
        assert!(released.status.success(), "{}", stderr(&released));

        let reacquired = run(&plan(target, true).lease_command(TOKEN_TWO).unwrap(), &[]);
        assert!(reacquired.status.success(), "{}", stderr(&reacquired));
        assert!(!std::path::Path::new(&format!("{target}.nrm-install-lease")).exists());
    }

    #[cfg(unix)]
    #[test]
    fn stable_journal_is_atomic_exact_and_recovers_across_candidate_upgrades() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let candidate = fake_agent(VERSION);
        let plan = plan_for_candidate(target, true, &candidate);

        let staged_output = run(&plan.stage_command(), &candidate);
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
        let expected = format!(
            "NRM_INSTALL_STATE_V1\t{}\tstaged\tmissing\t{}\t{}\t-\t{}\n",
            target,
            staged.stage_path,
            staged.backup_path,
            candidate_sha256(&candidate)
        );
        assert_eq!(fs::read_to_string(state_path(&staged)).unwrap(), expected);
        assert!(!std::path::Path::new(&format!("{}.next", state_path(&staged))).exists());
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".nrm-install-state.tmp.")
        }));

        let overlapping = run(&plan.stage_command(), &candidate);
        assert_eq!(overlapping.status.code(), Some(40));
        assert_eq!(fs::read(&staged.stage_path).unwrap(), candidate);
        assert_eq!(fs::read_to_string(state_path(&staged)).unwrap(), expected);

        let stale_trust_plan = plan_for_candidate(target, true, b"different trusted artifact");
        let stale_trust = run(
            &stale_trust_plan
                .lease_command("0123456789abcdef0123456789abcdef")
                .unwrap(),
            &[],
        );
        assert!(stale_trust.status.success(), "{}", stderr(&stale_trust));
        stale_trust_plan
            .parse_lease_ready_stdout("0123456789abcdef0123456789abcdef", &stdout(&stale_trust))
            .unwrap();
        assert!(
            !std::path::Path::new(&staged.stage_path).exists(),
            "the prior release's staged candidate was not removed"
        );
        assert!(
            !std::path::Path::new(&state_path(&staged)).exists(),
            "the prior release's recovered journal was retained"
        );
    }

    #[cfg(unix)]
    #[test]
    fn lease_recovers_sigkill_during_partial_upload() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef";

        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"previous agent";
        fs::write(&target, previous).unwrap();
        let target = target.to_str().unwrap();
        let candidate = fake_agent(VERSION);
        let plan = plan_for_candidate(target, true, &candidate);
        let state = format!("{target}.nrm-install-state");

        let mut upload = Command::new("sh")
            .arg("-c")
            .arg(format!("exec {}", plan.stage_command()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let partial = b"partial-upload";
        upload.stdin.as_mut().unwrap().write_all(partial).unwrap();
        upload.stdin.as_mut().unwrap().flush().unwrap();

        let started = std::time::Instant::now();
        while !std::path::Path::new(&state).is_file()
            && started.elapsed() < std::time::Duration::from_secs(3)
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let journal = fs::read_to_string(&state).expect("pre-upload journal was not published");
        let fields = journal
            .trim_end_matches('\n')
            .split('\t')
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 8, "{journal:?}");
        assert_eq!(fields[0], "NRM_INSTALL_STATE_V1");
        assert_eq!(fields[1], target);
        assert_eq!(fields[2], "preparing");
        assert_eq!(fields[3], "present");
        assert_eq!(fields[7], candidate_sha256(&candidate));
        let stage = fields[4].to_owned();

        let started = std::time::Instant::now();
        while fs::metadata(&stage).map_or(true, |metadata| metadata.len() < partial.len() as u64)
            && started.elapsed() < std::time::Duration::from_secs(3)
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(fs::read(&stage).unwrap(), partial);

        upload.kill().unwrap();
        drop(upload.stdin.take());
        let killed = upload.wait_with_output().unwrap();
        assert!(!killed.status.success());

        let next_plan = plan_for_candidate(target, true, b"next signed release");
        recover_with_lease(&next_plan, TOKEN);
        assert_eq!(fs::read(target).unwrap(), previous);
        assert!(!std::path::Path::new(&stage).exists());
        assert!(!std::path::Path::new(&state).exists());
        assert!(!std::path::Path::new(&format!("{state}.next")).exists());
    }

    #[cfg(unix)]
    #[test]
    fn new_release_lease_recovers_killed_staging_and_activation_before_readiness() {
        const TOKEN_ONE: &str = "0123456789abcdef0123456789abcdef";
        const TOKEN_TWO: &str = "fedcba9876543210fedcba9876543210";

        let dir = tempdir().unwrap();
        let previous = b"previous agent";

        let staged_target = dir.path().join("staged-agent");
        fs::write(&staged_target, previous).unwrap();
        let mut staged_plan = plan(staged_target.to_str().unwrap(), true);
        let mut holder = acquire_lease_holder(&staged_plan, TOKEN_ONE);
        staged_plan.set_lease_token(TOKEN_ONE).unwrap();
        let staged_output = run(&staged_plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = staged_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        holder.kill().unwrap();
        holder.wait().unwrap();

        let staged_next_plan = plan_for_candidate(
            staged_target.to_str().unwrap(),
            true,
            b"next staged release",
        );
        recover_with_lease(&staged_next_plan, TOKEN_TWO);
        assert_eq!(fs::read(&staged_target).unwrap(), previous);
        assert!(!std::path::Path::new(&staged.stage_path).exists());
        assert!(!std::path::Path::new(&staged.backup_path).exists());
        assert!(!std::path::Path::new(&state_path(&staged)).exists());

        let activated_target = dir.path().join("activated-agent");
        fs::write(&activated_target, previous).unwrap();
        let mut activated_plan = plan(activated_target.to_str().unwrap(), true);
        let mut holder = acquire_lease_holder(&activated_plan, TOKEN_ONE);
        activated_plan.set_lease_token(TOKEN_ONE).unwrap();
        let staged_output = run(&activated_plan.stage_command(), &fake_agent(VERSION));
        let staged = activated_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        let activated_output = run(&activated_plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        holder.kill().unwrap();
        holder.wait().unwrap();

        let activated_next_plan = plan_for_candidate(
            activated_target.to_str().unwrap(),
            true,
            b"next activated release",
        );
        recover_with_lease(&activated_next_plan, TOKEN_TWO);
        assert_eq!(fs::read(&activated_target).unwrap(), previous);
        assert!(!std::path::Path::new(&staged.backup_path).exists());
        assert!(!std::path::Path::new(&state_path(&staged)).exists());

        let committed_target = dir.path().join("committed-agent");
        fs::write(&committed_target, previous).unwrap();
        let mut committed_plan = plan(committed_target.to_str().unwrap(), true);
        let mut holder = acquire_lease_holder(&committed_plan, TOKEN_ONE);
        committed_plan.set_lease_token(TOKEN_ONE).unwrap();
        let staged_output = run(&committed_plan.stage_command(), &fake_agent(VERSION));
        let staged = committed_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        let activated_output = run(&committed_plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        fs::remove_file(&staged.backup_path).unwrap();
        holder.kill().unwrap();
        holder.wait().unwrap();

        let committed_next_plan = plan_for_candidate(
            committed_target.to_str().unwrap(),
            true,
            b"next committed release",
        );
        recover_with_lease(&committed_next_plan, TOKEN_TWO);
        assert_eq!(fs::read(&committed_target).unwrap(), fake_agent(VERSION));
        assert!(!std::path::Path::new(&state_path(&staged)).exists());
    }

    #[cfg(unix)]
    #[test]
    fn lease_recovery_keeps_new_candidate_or_absence_and_rejects_ambiguity() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef";
        let dir = tempdir().unwrap();

        let absent_target = dir.path().join("absent-agent");
        let absent_plan = plan(absent_target.to_str().unwrap(), true);
        let staged_output = run(&absent_plan.stage_command(), &fake_agent(VERSION));
        let staged = absent_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        recover_with_lease(&absent_plan, TOKEN);
        assert!(!absent_target.exists());
        assert!(!std::path::Path::new(&staged.stage_path).exists());
        assert!(!std::path::Path::new(&state_path(&staged)).exists());

        let candidate_target = dir.path().join("candidate-agent");
        let candidate_plan = plan(candidate_target.to_str().unwrap(), true);
        let staged_output = run(&candidate_plan.stage_command(), &fake_agent(VERSION));
        let staged = candidate_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        let activated_output = run(&candidate_plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        recover_with_lease(&candidate_plan, TOKEN);
        assert_eq!(fs::read(&candidate_target).unwrap(), fake_agent(VERSION));
        assert!(!std::path::Path::new(&state_path(&staged)).exists());

        let malformed_target = dir.path().join("malformed-agent");
        let malformed_plan = plan(malformed_target.to_str().unwrap(), true);
        let staged_output = run(&malformed_plan.stage_command(), &fake_agent(VERSION));
        let staged = malformed_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        fs::write(state_path(&staged), b"NRM_INSTALL_STATE_V1\tmalformed\n").unwrap();
        let malformed_next_plan = plan_for_candidate(
            malformed_target.to_str().unwrap(),
            true,
            b"next malformed release",
        );
        let malformed = run(&malformed_next_plan.lease_command(TOKEN).unwrap(), &[]);
        assert_eq!(malformed.status.code(), Some(40), "{}", stderr(&malformed));
        assert!(std::path::Path::new(&staged.stage_path).exists());
        assert!(std::path::Path::new(&state_path(&staged)).exists());

        let replaced_target = dir.path().join("replaced-agent");
        let replaced_plan = plan(replaced_target.to_str().unwrap(), true);
        let staged_output = run(&replaced_plan.stage_command(), &fake_agent(VERSION));
        let staged = replaced_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        let replacement = b"external replacement";
        fs::write(&staged.stage_path, replacement).unwrap();
        let replaced_next_plan = plan_for_candidate(
            replaced_target.to_str().unwrap(),
            true,
            b"next replacement release",
        );
        let replaced = run(&replaced_next_plan.lease_command(TOKEN).unwrap(), &[]);
        assert_eq!(replaced.status.code(), Some(40), "{}", stderr(&replaced));
        assert_eq!(fs::read(&staged.stage_path).unwrap(), replacement);
        assert!(std::path::Path::new(&state_path(&staged)).exists());
    }

    #[test]
    fn install_lease_readiness_records_are_exact() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef";
        let absolute_plan = plan("/tmp/nrm-agent", true);
        assert_eq!(
            absolute_plan.parse_lease_ready_stdout(
                TOKEN,
                "NRM_INSTALL_LEASE_READY_V1\t/tmp/nrm-agent\t0123456789abcdef0123456789abcdef\n"
            )
            .unwrap(),
            "/tmp/nrm-agent"
        );
        for invalid in [
            "NRM_INSTALL_LEASE_READY_V1\t/tmp/nrm-agent\tbad\n",
            "NRM_INSTALL_LEASE_READY_V1\t/tmp/other\t0123456789abcdef0123456789abcdef\n",
            "NRM_INSTALL_LEASE_READY_V1\t/tmp/nrm-agent\t0123456789abcdef0123456789abcdef\nextra\n",
        ] {
            assert!(absolute_plan
                .parse_lease_ready_stdout(TOKEN, invalid)
                .is_err());
        }
        assert!(absolute_plan.lease_command("ABCDEF").is_err());

        let mut home_plan = plan("$HOME/.local/bin/custom-agent", true);
        home_plan
            .bind_resolved_lease_target("/home/test/.local/bin/custom-agent")
            .unwrap();
        assert_eq!(home_plan.target_input, "/home/test/.local/bin/custom-agent");
        assert!(home_plan
            .bind_resolved_lease_target("/home/test/../escape")
            .is_err());
        assert!(plan("/tmp/nrm-agent", true)
            .bind_resolved_lease_target("/tmp/other-agent")
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lease_rejects_traversing_resolved_home_before_creating_directories() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef";
        let dir = tempdir().unwrap();
        let traversing_home = dir.path().join("home").join("..").join("escape");
        let output = run_with_env(
            &plan("$HOME/new/bin/nrm-agent", true)
                .lease_command(TOKEN)
                .unwrap(),
            &[],
            Some(("HOME", &traversing_home)),
        );
        assert_eq!(output.status.code(), Some(40));
        assert_eq!(
            classify_install_failure(output.status.code(), &stderr(&output)).kind,
            InstallFailureKind::InvalidTarget
        );
        assert!(!dir.path().join("escape").exists());
    }

    #[test]
    fn artifact_digest_setter_requires_lowercase_sha256() {
        let mut plan = PosixInstallPlan::new("/tmp/nrm-agent", VERSION, PROTOCOL, true).unwrap();
        for invalid in [
            "",
            "abc",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ] {
            assert!(
                plan.set_expected_sha256(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        plan.set_expected_sha256(digest).unwrap();
        assert!(plan.stage_command().contains(digest));
    }

    #[cfg(unix)]
    #[test]
    fn staging_without_expected_artifact_digest_fails_closed() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let plan =
            PosixInstallPlan::new(target.to_str().unwrap(), VERSION, PROTOCOL, true).unwrap();
        let output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert_eq!(output.status.code(), Some(40));
        assert_eq!(
            classify_install_failure(output.status.code(), &stderr(&output)).kind,
            InstallFailureKind::InvalidState
        );
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn stages_validates_activates_and_cleans_up() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let target = dir.path().join("agent with ' quote; $(true)");
        let target = target.to_str().unwrap();
        let plan = plan(target, true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();

        assert_ne!(staged.stage_path, staged.backup_path);
        assert!(!staged.had_previous);
        assert_eq!(posix_parent(&staged.stage_path), posix_parent(target));
        assert_eq!(posix_parent(&staged.backup_path), posix_parent(target));
        assert!(
            !std::path::Path::new(&staged.backup_path).exists(),
            "staging must reserve a unique backup name without leaving a placeholder"
        );
        assert!(std::path::Path::new(&state_path(&staged)).is_file());
        assert_eq!(
            fs::metadata(&staged.stage_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        let hook = plan.staged_validation(&staged);
        assert_eq!(hook.mode, ValidationMode::FullHelloExact);
        assert_eq!(hook.phase, ValidationPhase::Staged);
        assert_eq!(hook.expected_protocol_version, Some(PROTOCOL));
        let version_output = Command::new(&hook.executable_path)
            .arg("--version")
            .output()
            .unwrap();
        validate_exact_version_output(
            hook.expected_version.as_deref().unwrap(),
            version_output.status.success(),
            &version_output.stdout,
            &version_output.stderr,
        )
        .unwrap();

        let activated_output = run(&plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        let activated = plan
            .parse_activation_stdout(&staged, &stdout(&activated_output))
            .unwrap();
        assert!(!activated.had_previous);
        assert_eq!(fs::read(target).unwrap(), fake_agent(VERSION));
        let hook = plan.post_activation_validation(&activated);
        assert_eq!(hook.executable_path, target);
        assert_eq!(hook.phase, ValidationPhase::Activated);

        let cleanup_output = run(&plan.cleanup_command(&staged), &[]);
        assert!(
            cleanup_output.status.success(),
            "{}",
            stderr(&cleanup_output)
        );
        plan.parse_cleanup_stdout(&staged, &stdout(&cleanup_output))
            .unwrap();
        assert!(!std::path::Path::new(&staged.stage_path).exists());
        assert!(!std::path::Path::new(&staged.backup_path).exists());
        assert!(!std::path::Path::new(&state_path(&staged)).exists());
    }

    #[cfg(unix)]
    #[test]
    fn failed_postactivation_can_restore_and_reprobe_previous_agent() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"#!/bin/sh\nprintf 'old agent\\n'\n";
        fs::write(&target, previous).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();

        let target_text = target.to_str().unwrap();
        let plan = plan(target_text, true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
        assert!(staged.had_previous);
        let activated_output = run(&plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        let activated = plan
            .parse_activation_stdout(&staged, &stdout(&activated_output))
            .unwrap();
        assert!(activated.had_previous);
        assert_eq!(fs::read(&target).unwrap(), fake_agent(VERSION));

        let rollback_output = run(&plan.rollback_command(&activated), &[]);
        assert!(
            rollback_output.status.success(),
            "{}",
            stderr(&rollback_output)
        );
        let rollback = plan
            .parse_rollback_stdout(&activated, &stdout(&rollback_output))
            .unwrap();
        assert!(rollback.restored_previous);
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert!(!std::path::Path::new(&state_path(&staged)).exists());
        let hook = plan.rollback_validation(&rollback);
        assert_eq!(hook.mode, ValidationMode::Reprobe);
        assert_eq!(hook.phase, ValidationPhase::RolledBack);
        assert_eq!(hook.expected_version, None);
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_a_previous_symlink_target_without_mutation() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = tempdir().unwrap();
        let previous = dir.path().join("previous-agent");
        fs::write(&previous, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&previous, fs::Permissions::from_mode(0o755)).unwrap();
        let target = dir.path().join("nrm-agent");
        symlink("previous-agent", &target).unwrap();

        let symlink_plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&symlink_plan.stage_command(), &fake_agent(VERSION));
        assert_eq!(staged_output.status.code(), Some(40));
        assert_eq!(
            classify_install_failure(staged_output.status.code(), &stderr(&staged_output)).kind,
            InstallFailureKind::InvalidTarget
        );
        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(&target).unwrap(),
            std::path::Path::new("previous-agent")
        );
        let leaked: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().contains(".nrm-"))
            .collect();
        assert!(leaked.is_empty(), "leaked install files: {leaked:?}");

        let directory_target = dir.path().join("directory-agent");
        fs::create_dir(&directory_target).unwrap();
        let directory_plan = plan(directory_target.to_str().unwrap(), true);
        let directory_output = run(&directory_plan.stage_command(), &fake_agent(VERSION));
        assert_eq!(directory_output.status.code(), Some(40));
        assert!(directory_target.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn activation_and_reconciliation_preserve_an_externally_replaced_stage() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"previous agent";
        fs::write(&target, previous).unwrap();
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
        let replacement = b"#!/bin/sh\nprintf 'nrm-agent 0.1.0\\n'\n# replaced\n";
        fs::write(&staged.stage_path, replacement).unwrap();

        let activation = run(&plan.activate_command(&staged), &[]);
        assert_eq!(activation.status.code(), Some(40));
        assert_eq!(
            classify_install_failure(activation.status.code(), &stderr(&activation)).kind,
            InstallFailureKind::InvalidState
        );
        assert_eq!(fs::read(&target).unwrap(), previous);

        let reconciliation = run(&plan.reconcile_activation_command(&staged), &[]);
        assert_eq!(reconciliation.status.code(), Some(50));
        assert_eq!(
            classify_install_failure(reconciliation.status.code(), &stderr(&reconciliation)).kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert_eq!(fs::read(&staged.stage_path).unwrap(), replacement);
        assert!(std::path::Path::new(&state_path(&staged)).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn activation_and_reconciliation_preserve_an_externally_replaced_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        fs::write(&target, b"previous agent").unwrap();
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
        let replacement = b"external target replacement";
        fs::write(&target, replacement).unwrap();

        let activation = run(&plan.activate_command(&staged), &[]);
        assert_eq!(activation.status.code(), Some(40));
        assert_eq!(fs::read(&target).unwrap(), replacement);
        let reconciliation = run(&plan.reconcile_activation_command(&staged), &[]);
        assert_eq!(reconciliation.status.code(), Some(50));
        assert_eq!(fs::read(&target).unwrap(), replacement);
        assert!(std::path::Path::new(&staged.stage_path).is_file());
        assert!(std::path::Path::new(&state_path(&staged)).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn tampered_install_state_fails_closed_without_mutating_remote_files() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"previous agent";
        fs::write(&target, previous).unwrap();
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();

        let previous_hash = candidate_sha256(previous);
        fs::write(
            state_path(&staged),
            format!("present:{previous_hash}:{}\n", "0".repeat(64)),
        )
        .unwrap();

        let activation = run(&plan.activate_command(&staged), &[]);
        assert_eq!(activation.status.code(), Some(40));
        assert_eq!(
            classify_install_failure(activation.status.code(), &stderr(&activation)).kind,
            InstallFailureKind::InvalidState
        );
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert!(std::path::Path::new(&staged.stage_path).is_file());
        assert!(!std::path::Path::new(&staged.backup_path).exists());

        let reconciliation = run(&plan.reconcile_activation_command(&staged), &[]);
        assert_eq!(reconciliation.status.code(), Some(50));
        assert_eq!(
            classify_install_failure(reconciliation.status.code(), &stderr(&reconciliation)).kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert!(std::path::Path::new(&staged.stage_path).is_file());
        assert!(std::path::Path::new(&state_path(&staged)).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn install_state_rejects_an_unterminated_extra_record() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();

        fs::OpenOptions::new()
            .append(true)
            .open(state_path(&staged))
            .unwrap()
            .write_all(b"extra")
            .unwrap();

        let activation = run(&plan.activate_command(&staged), &[]);
        assert_eq!(activation.status.code(), Some(40));
        assert_eq!(
            classify_install_failure(activation.status.code(), &stderr(&activation)).kind,
            InstallFailureKind::InvalidState
        );
        assert!(!target.exists());
        assert!(std::path::Path::new(&staged.stage_path).is_file());

        let reconciliation = run(&plan.reconcile_activation_command(&staged), &[]);
        assert_eq!(reconciliation.status.code(), Some(50));
        assert_eq!(
            classify_install_failure(reconciliation.status.code(), &stderr(&reconciliation)).kind,
            InstallFailureKind::RollbackFailed
        );
        assert!(!target.exists());
        assert!(std::path::Path::new(&staged.stage_path).is_file());
        assert!(std::path::Path::new(&state_path(&staged)).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn ambiguous_new_install_reconciliation_does_not_delete_external_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
        let activated_output = run(&plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        let replacement = b"external target after ambiguous activation";
        fs::write(&target, replacement).unwrap();

        let reconciliation = run(&plan.reconcile_activation_command(&staged), &[]);
        assert_eq!(reconciliation.status.code(), Some(50));
        assert_eq!(
            classify_install_failure(reconciliation.status.code(), &stderr(&reconciliation)).kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(fs::read(&target).unwrap(), replacement);
        assert!(std::path::Path::new(&state_path(&staged)).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn rollback_does_not_overwrite_external_target_after_activation() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"previous agent";
        fs::write(&target, previous).unwrap();
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
        let activated_output = run(&plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        let activated = plan
            .parse_activation_stdout(&staged, &stdout(&activated_output))
            .unwrap();
        let replacement = b"external target before rollback";
        fs::write(&target, replacement).unwrap();

        let rollback = run(&plan.rollback_command(&activated), &[]);
        assert_eq!(rollback.status.code(), Some(50));
        assert_eq!(
            classify_install_failure(rollback.status.code(), &stderr(&rollback)).kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(fs::read(&target).unwrap(), replacement);
        assert_eq!(fs::read(&staged.backup_path).unwrap(), previous);
        assert!(std::path::Path::new(&state_path(&staged)).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn reconciliation_with_stage_present_keeps_target_and_cleans_staging() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"previous agent";
        fs::write(&target, previous).unwrap();
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();

        let recovered_output = run(&plan.reconcile_activation_command(&staged), &[]);
        assert!(
            recovered_output.status.success(),
            "{}",
            stderr(&recovered_output)
        );
        let recovery = plan
            .parse_reconciliation_stdout(&staged, &stdout(&recovered_output))
            .unwrap();
        assert_eq!(
            recovery.kind,
            ActivationRecoveryKind::ActivationUnchangedPresent
        );
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert!(!std::path::Path::new(&staged.stage_path).exists());
        assert!(!std::path::Path::new(&staged.backup_path).exists());
        assert_eq!(
            plan.reconciliation_validation(&recovery).mode,
            ValidationMode::Reprobe
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_activation_record_after_mv_restores_previous() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"previous agent";
        fs::write(&target, previous).unwrap();
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();

        let activated_output = run(&plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        assert!(plan
            .parse_activation_stdout(&staged, "malformed activation record")
            .is_err());
        let wrong_prior_state = format!(
            "NRM_INSTALL_ACTIVATED_V1\t{}\t{}\t0\n",
            staged.target_path, staged.backup_path
        );
        assert!(plan
            .parse_activation_stdout(&staged, &wrong_prior_state)
            .is_err());
        assert!(!std::path::Path::new(&staged.stage_path).exists());
        assert!(std::path::Path::new(&staged.backup_path).exists());
        assert_eq!(fs::read(&target).unwrap(), fake_agent(VERSION));

        let recovered_output = run(&plan.reconcile_activation_command(&staged), &[]);
        let recovery = plan
            .parse_reconciliation_stdout(&staged, &stdout(&recovered_output))
            .unwrap();
        assert_eq!(recovery.kind, ActivationRecoveryKind::RestoredPrevious);
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert_eq!(
            plan.reconciliation_validation(&recovery).mode,
            ValidationMode::Reprobe
        );
    }

    #[cfg(unix)]
    #[test]
    fn ambiguous_activation_without_prior_target_removes_candidate() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
        let activated_output = run(&plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        assert!(!std::path::Path::new(&staged.stage_path).exists());
        assert!(!std::path::Path::new(&staged.backup_path).exists());
        assert!(target.exists());

        // A transport error after the remote mv has the same observable
        // state as this point: no trustworthy activation record is available.
        let recovered_output = run(&plan.reconcile_activation_command(&staged), &[]);
        let recovery = plan
            .parse_reconciliation_stdout(&staged, &stdout(&recovered_output))
            .unwrap();
        assert_eq!(recovery.kind, ActivationRecoveryKind::RemovedCandidate);
        assert!(!target.exists());
        assert_eq!(
            plan.reconciliation_validation(&recovery).mode,
            ValidationMode::ExpectMissing
        );
        let hook = plan.reconciliation_validation(&recovery);
        let absence_output = run(&plan.absence_check_command(&hook).unwrap(), &[]);
        assert!(
            absence_output.status.success(),
            "{}",
            stderr(&absence_output)
        );
        plan.parse_absence_check_stdout(&hook, &stdout(&absence_output))
            .unwrap();

        fs::write(&target, b"unexpected target").unwrap();
        let unexpected_target = run(&plan.absence_check_command(&hook).unwrap(), &[]);
        assert_eq!(unexpected_target.status.code(), Some(50));
        assert_eq!(
            classify_install_failure(unexpected_target.status.code(), &stderr(&unexpected_target))
                .kind,
            InstallFailureKind::RollbackFailed
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_stage_with_exact_previous_reconciles_without_mutating_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"previous agent";
        fs::write(&target, previous).unwrap();
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();
        assert!(staged.had_previous);
        assert!(!std::path::Path::new(&staged.backup_path).exists());

        fs::remove_file(&staged.stage_path).unwrap();
        let recovered_output = run(&plan.reconcile_activation_command(&staged), &[]);
        assert!(
            recovered_output.status.success(),
            "{}",
            stderr(&recovered_output)
        );
        let recovery = plan
            .parse_reconciliation_stdout(&staged, &stdout(&recovered_output))
            .unwrap();
        assert_eq!(recovery.kind, ActivationRecoveryKind::RestoredPrevious);
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert!(!std::path::Path::new(&staged.backup_path).exists());
        assert!(!std::path::Path::new(&state_path(&staged)).exists());
    }

    #[cfg(unix)]
    #[test]
    fn reconciliation_resumes_after_stage_was_removed_before_duplicate_backup() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let previous = b"previous agent";
        fs::write(&target, previous).unwrap();
        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
        let staged = plan.parse_stage_stdout(&stdout(&staged_output)).unwrap();

        fs::copy(&target, &staged.backup_path).unwrap();
        fs::remove_file(&staged.stage_path).unwrap();
        let recovered = run(&plan.reconcile_activation_command(&staged), &[]);
        assert!(recovered.status.success(), "{}", stderr(&recovered));
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert!(!std::path::Path::new(&staged.backup_path).exists());
        assert!(!std::path::Path::new(&state_path(&staged)).exists());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_resumes_after_each_destructive_unlink() {
        let dir = tempdir().unwrap();

        let previous_target = dir.path().join("previous-agent");
        let previous = b"previous agent";
        fs::write(&previous_target, previous).unwrap();
        let previous_plan = plan(previous_target.to_str().unwrap(), true);
        let staged_output = run(&previous_plan.stage_command(), &fake_agent(VERSION));
        let staged = previous_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        fs::remove_file(&staged.stage_path).unwrap();
        let resumed = run(&previous_plan.cleanup_command(&staged), &[]);
        assert!(resumed.status.success(), "{}", stderr(&resumed));
        assert_eq!(fs::read(&previous_target).unwrap(), previous);
        assert!(!std::path::Path::new(&state_path(&staged)).exists());

        let new_target = dir.path().join("new-agent");
        let new_plan = plan(new_target.to_str().unwrap(), true);
        let staged_output = run(&new_plan.stage_command(), &fake_agent(VERSION));
        let staged = new_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        fs::remove_file(&staged.stage_path).unwrap();
        let resumed = run(&new_plan.cleanup_command(&staged), &[]);
        assert!(resumed.status.success(), "{}", stderr(&resumed));
        assert!(!new_target.exists());
        assert!(!std::path::Path::new(&state_path(&staged)).exists());

        let activated_target = dir.path().join("activated-agent");
        fs::write(&activated_target, previous).unwrap();
        let activated_plan = plan(activated_target.to_str().unwrap(), true);
        let staged_output = run(&activated_plan.stage_command(), &fake_agent(VERSION));
        let staged = activated_plan
            .parse_stage_stdout(&stdout(&staged_output))
            .unwrap();
        let activated_output = run(&activated_plan.activate_command(&staged), &[]);
        assert!(
            activated_output.status.success(),
            "{}",
            stderr(&activated_output)
        );
        fs::remove_file(&staged.backup_path).unwrap();
        let resumed = run(&activated_plan.cleanup_command(&staged), &[]);
        assert!(resumed.status.success(), "{}", stderr(&resumed));
        assert_eq!(fs::read(&activated_target).unwrap(), fake_agent(VERSION));
        assert!(!std::path::Path::new(&state_path(&staged)).exists());
    }

    #[cfg(unix)]
    #[test]
    fn stage_names_are_unique_and_version_mismatch_leaks_nothing() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let plan = plan(target, true);

        let first_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(first_output.status.success(), "{}", stderr(&first_output));
        let first = plan.parse_stage_stdout(&stdout(&first_output)).unwrap();
        let first_cleanup = run(&plan.cleanup_command(&first), &[]);
        assert!(first_cleanup.status.success(), "{}", stderr(&first_cleanup));

        let second_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(second_output.status.success(), "{}", stderr(&second_output));
        let second = plan.parse_stage_stdout(&stdout(&second_output)).unwrap();
        assert_ne!(first.stage_path, second.stage_path);
        assert_ne!(first.backup_path, second.backup_path);
        let second_cleanup = run(&plan.cleanup_command(&second), &[]);
        assert!(
            second_cleanup.status.success(),
            "{}",
            stderr(&second_cleanup)
        );

        let mut changed_upload = fake_agent(VERSION);
        changed_upload.extend_from_slice(b"# changed in transit\n");
        let digest_mismatch = run(&plan.stage_command(), &changed_upload);
        assert_eq!(digest_mismatch.status.code(), Some(31));
        assert_eq!(
            classify_install_failure(digest_mismatch.status.code(), &stderr(&digest_mismatch)).kind,
            InstallFailureKind::UploadFailed
        );

        let mismatch_candidate = fake_agent("9.9.9");
        let mismatch_plan = plan_for_candidate(target, true, &mismatch_candidate);
        let mismatch = run(&mismatch_plan.stage_command(), &mismatch_candidate);
        assert_eq!(mismatch.status.code(), Some(34));
        assert_eq!(
            classify_install_failure(mismatch.status.code(), &stderr(&mismatch)).kind,
            InstallFailureKind::VersionMismatch
        );
        let leaked: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().contains(".nrm-"))
            .collect();
        assert!(leaked.is_empty(), "leaked install files: {leaked:?}");
    }

    #[cfg(unix)]
    #[test]
    fn expands_home_before_returning_validation_paths() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home with spaces");
        fs::create_dir_all(&home).unwrap();
        let plan = plan("$HOME/.local/bin/nrm-agent", true);
        let output = run_with_env(
            &plan.stage_command(),
            &fake_agent(VERSION),
            Some(("HOME", &home)),
        );
        assert!(output.status.success(), "{}", stderr(&output));
        let staged = plan.parse_stage_stdout(&stdout(&output)).unwrap();
        assert_eq!(
            staged.target_path,
            home.join(".local/bin/nrm-agent").to_string_lossy()
        );
        assert_eq!(
            plan.staged_validation(&staged).executable_path,
            staged.stage_path
        );
        let cleanup = run(&plan.cleanup_command(&staged), &[]);
        assert!(cleanup.status.success(), "{}", stderr(&cleanup));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_existing_without_force_and_preserves_metacharacter_path() {
        let dir = tempdir().unwrap();
        let sentinel = dir.path().join("must-not-exist");
        let target = dir
            .path()
            .join("agent ' ; $(touch${IFS}${NRM_TEST_SENTINEL})");
        fs::write(&target, b"old").unwrap();
        let plan = plan(target.to_str().unwrap(), false);
        let output = run_with_env(
            &plan.stage_command(),
            &fake_agent(VERSION),
            Some(("NRM_TEST_SENTINEL", &sentinel)),
        );
        assert_eq!(output.status.code(), Some(23));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(!sentinel.exists());
        assert_eq!(
            classify_install_failure(output.status.code(), &stderr(&output)).kind,
            InstallFailureKind::AlreadyExists
        );
    }

    #[test]
    fn exact_version_parser_rejects_extra_output_stderr_and_failures() {
        validate_exact_version_output(VERSION, true, b"nrm-agent 0.1.0\n", b"").unwrap();
        for (success, stdout, stderr, expected_kind) in [
            (
                true,
                b"nrm-agent 0.1.0\n\n".as_slice(),
                b"".as_slice(),
                InstallFailureKind::VersionMismatch,
            ),
            (
                true,
                b"nrm-agent 0.1.0\n".as_slice(),
                b"warning".as_slice(),
                InstallFailureKind::VersionMismatch,
            ),
            (
                false,
                b"".as_slice(),
                b"failed".as_slice(),
                InstallFailureKind::VersionExecutionFailed,
            ),
        ] {
            assert_eq!(
                validate_exact_version_output(VERSION, success, stdout, stderr)
                    .unwrap_err()
                    .kind,
                expected_kind
            );
        }
    }

    #[test]
    fn classifies_install_in_progress_process_in_use_and_rollback_failed_distinctly() {
        assert_eq!(
            classify_install_failure(Some(24), "NRM_INSTALL_ERROR_V1\tinstall_in_progress\n").kind,
            InstallFailureKind::InstallInProgress
        );
        assert_eq!(
            classify_install_failure(
                Some(42),
                "mv: Text file busy\nNRM_INSTALL_ERROR_V1\tprocess_in_use\n"
            )
            .kind,
            InstallFailureKind::ProcessInUse
        );
        assert_eq!(
            classify_install_failure(Some(50), "NRM_INSTALL_ERROR_V1\trollback_failed\n").kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(
            classify_install_failure(None, "sharing violation while replacing agent").kind,
            InstallFailureKind::ProcessInUse
        );
        let sanitized =
            classify_install_failure(Some(40), "\u{1b}[31mremote\r\nerror\u{7}\u{1b}[0m");
        assert!(!sanitized.detail.chars().any(char::is_control));
        assert!(!sanitized.detail.contains('\u{1b}'));
    }

    #[test]
    fn rejects_unsafe_targets_and_malformed_records() {
        for target in [
            "",
            "relative/agent",
            "/tmp/../agent",
            "/tmp//agent",
            "/tmp/agent/",
            "//server/agent",
            "/tmp/agent\nother",
            " $HOME/bin/agent",
            "\\$HOME/bin/agent",
        ] {
            assert!(
                PosixInstallPlan::new(target, VERSION, PROTOCOL, false).is_err(),
                "{target:?}"
            );
        }

        let plan = plan("/tmp/nrm-agent", true);
        for record in [
            "",
            "noise\nNRM_INSTALL_STAGE_V1\t/tmp/nrm-agent\t/tmp/nrm-agent.nrm-stage.abcdef\t/tmp/nrm-agent.nrm-backup.abcdef\n",
            "NRM_INSTALL_STAGE_V1\t/tmp/nrm-agent\t/tmp/other.nrm-stage.abcdef\t/tmp/nrm-agent.nrm-backup.abcdef\n",
            "NRM_INSTALL_STAGE_V1\t/tmp/nrm-agent\t/tmp/nrm-agent.nrm-stage.abc\t/tmp/nrm-agent.nrm-backup.abcdef\n",
        ] {
            assert!(plan.parse_stage_stdout(record).is_err(), "{record:?}");
        }
    }
}
