//! POSIX transactional installation planning for `nrm-agent`.
//!
//! The scripts in this module are fixed literals. Remote paths and other
//! caller-controlled values are passed as positional `sh -c` arguments, never
//! interpolated into script source.

use std::fmt;

const STAGE_RECORD: &str = "NRM_INSTALL_STAGE_V1";
const ACTIVATED_RECORD: &str = "NRM_INSTALL_ACTIVATED_V1";
const RECONCILED_RECORD: &str = "NRM_INSTALL_RECONCILED_V1";
const ROLLED_BACK_RECORD: &str = "NRM_INSTALL_ROLLED_BACK_V1";
const ABSENT_RECORD: &str = "NRM_INSTALL_ABSENT_V1";
const CLEANED_RECORD: &str = "NRM_INSTALL_CLEANED_V1";
const ERROR_RECORD: &str = "NRM_INSTALL_ERROR_V1";

const POSIX_STAGE_SCRIPT: &str = r#"set -u
target=$1
expected_version=$2
force=$3

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

dir=${target%/*}
if [ -z "$dir" ]; then
  dir=/
fi
if ! mkdir -p "$dir"; then
  fail stage_create_failed 30
fi
had_previous=0
if [ -e "$target" ] || [ -L "$target" ]; then
  had_previous=1
  if [ "$force" != 1 ]; then
    fail already_exists 23
  fi
fi

umask 077
stage=
backup=
version_actual=
version_expected=
version_stderr=
cleanup_stage() {
  if [ -n "$version_actual" ]; then rm -f "$version_actual"; fi
  if [ -n "$version_expected" ]; then rm -f "$version_expected"; fi
  if [ -n "$version_stderr" ]; then rm -f "$version_stderr"; fi
  if [ -n "$stage" ]; then rm -f "$stage"; fi
  if [ -n "$backup" ]; then rm -f "$backup"; fi
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
if ! cat > "$stage"; then
  fail upload_failed 31
fi
if ! chmod 755 "$stage"; then
  fail chmod_failed 32
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
trap - 0 1 2 15
printf 'NRM_INSTALL_STAGE_V1\t%s\t%s\t%s\t%s\n' "$target" "$stage" "$backup" "$had_previous"
"#;

const POSIX_ACTIVATE_SCRIPT: &str = r#"set -u
LC_ALL=C
export LC_ALL
target=$1
stage=$2
backup=$3
force=$4

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

case "$target" in /*) ;; *) fail invalid_state 40 ;; esac
case "$stage" in "$target".nrm-stage.*) ;; *) fail invalid_state 40 ;; esac
case "$backup" in "$target".nrm-backup.*) ;; *) fail invalid_state 40 ;; esac
if [ "$stage" = "$backup" ] || [ ! -f "$stage" ] || [ ! -x "$stage" ]; then
  fail invalid_state 40
fi
if [ -e "$backup" ] || [ -L "$backup" ]; then
  fail invalid_state 40
fi

had_previous=0
if [ -e "$target" ] || [ -L "$target" ]; then
  if [ "$force" != 1 ]; then
    fail already_exists 23
  fi
  if ! ln -P "$target" "$backup" 2>/dev/null; then
    if ! cp -pP "$target" "$backup"; then
      fail activation_failed 41
    fi
  fi
  had_previous=1
else
  :
fi

move_error="${stage}.activate-error"
if ! : >"$move_error"; then
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
printf 'NRM_INSTALL_ACTIVATED_V1\t%s\t%s\t%s\n' "$target" "$backup" "$had_previous"
"#;

const POSIX_RECONCILE_SCRIPT: &str = r#"set -u
target=$1
stage=$2
backup=$3
had_previous=$4

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

case "$target" in /*) ;; *) fail rollback_failed 50 ;; esac
case "$stage" in "$target".nrm-stage.*) ;; *) fail rollback_failed 50 ;; esac
case "$backup" in "$target".nrm-backup.*) ;; *) fail rollback_failed 50 ;; esac
case "$had_previous" in 0|1) ;; *) fail rollback_failed 50 ;; esac

if [ -e "$stage" ] || [ -L "$stage" ]; then
  if [ "$had_previous" = 1 ]; then
    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
      fail rollback_failed 50
    fi
    outcome=activation_unchanged_present
  else
    if [ -e "$target" ] || [ -L "$target" ]; then
      fail rollback_failed 50
    fi
    outcome=activation_unchanged_missing
  fi
  if ! rm -f "$stage" "$backup"; then
    fail cleanup_failed 51
  fi
elif [ "$had_previous" = 1 ]; then
  if [ ! -e "$backup" ] && [ ! -L "$backup" ]; then
    fail rollback_failed 50
  fi
  rollback_error="${backup}.reconcile-error"
  if ! : >"$rollback_error"; then
    fail rollback_failed 50
  fi
  if ! mv -f "$backup" "$target" 2>"$rollback_error"; then
    cat "$rollback_error" >&2
    rm -f "$rollback_error"
    fail rollback_failed 50
  fi
  rm -f "$rollback_error"
  outcome=restored_previous
else
  if [ -e "$backup" ] || [ -L "$backup" ]; then
    fail rollback_failed 50
  fi
  if ! rm -f "$target"; then
    fail rollback_failed 50
  fi
  outcome=removed_candidate
fi

printf 'NRM_INSTALL_RECONCILED_V1\t%s\t%s\n' "$target" "$outcome"
"#;

const POSIX_ROLLBACK_SCRIPT: &str = r#"set -u
target=$1
stage=$2
backup=$3
had_previous=$4

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

case "$target" in /*) ;; *) fail rollback_failed 50 ;; esac
case "$stage" in "$target".nrm-stage.*) ;; *) fail rollback_failed 50 ;; esac
case "$backup" in "$target".nrm-backup.*) ;; *) fail rollback_failed 50 ;; esac

if [ "$had_previous" = 1 ]; then
  if [ ! -e "$backup" ] && [ ! -L "$backup" ]; then
    fail rollback_failed 50
  fi
  rollback_error="${backup}.rollback-error"
  if ! : >"$rollback_error"; then
    fail rollback_failed 50
  fi
  if ! mv -f "$backup" "$target" 2>"$rollback_error"; then
    cat "$rollback_error" >&2
    rm -f "$rollback_error"
    fail rollback_failed 50
  fi
  rm -f "$rollback_error"
elif [ "$had_previous" = 0 ]; then
  if ! rm -f "$target"; then
    fail rollback_failed 50
  fi
else
  fail rollback_failed 50
fi

if ! rm -f "$stage" "$backup"; then
  fail cleanup_failed 51
fi
printf 'NRM_INSTALL_ROLLED_BACK_V1\t%s\t%s\n' "$target" "$had_previous"
"#;

const POSIX_ABSENCE_CHECK_SCRIPT: &str = r#"set -u
target=$1

fail() {
  code=$1
  status=$2
  printf 'NRM_INSTALL_ERROR_V1\t%s\n' "$code" >&2
  exit "$status"
}

case "$target" in /*) ;; *) fail rollback_failed 50 ;; esac
if [ -e "$target" ] || [ -L "$target" ]; then
  fail rollback_failed 50
fi
printf 'NRM_INSTALL_ABSENT_V1\t%s\n' "$target"
"#;

const POSIX_CLEANUP_SCRIPT: &str = r#"set -u
target=$1
stage=$2
backup=$3

fail() {
  printf 'NRM_INSTALL_ERROR_V1\tcleanup_failed\n' >&2
  exit 51
}

case "$target" in /*) ;; *) fail ;; esac
case "$stage" in "$target".nrm-stage.*) ;; *) fail ;; esac
case "$backup" in "$target".nrm-backup.*) ;; *) fail ;; esac
if ! rm -f "$stage" "$backup"; then
  fail
fi
printf 'NRM_INSTALL_CLEANED_V1\t%s\n' "$target"
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PosixInstallPlan {
    target_input: String,
    expected_version: String,
    expected_protocol_version: u16,
    force: bool,
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
            expected_protocol_version,
            force,
        })
    }

    pub(crate) fn stage_command(&self) -> String {
        render_posix_script(
            "nrm-agent-stage",
            POSIX_STAGE_SCRIPT,
            &[
                self.target_input.as_str(),
                self.expected_version.as_str(),
                bool_arg(self.force),
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
        render_posix_script(
            "nrm-agent-activate",
            POSIX_ACTIVATE_SCRIPT,
            &[
                staged.target_path.as_str(),
                staged.stage_path.as_str(),
                staged.backup_path.as_str(),
                bool_arg(self.force),
            ],
        )
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
        render_posix_script(
            "nrm-agent-reconcile",
            POSIX_RECONCILE_SCRIPT,
            &[
                staged.target_path.as_str(),
                staged.stage_path.as_str(),
                staged.backup_path.as_str(),
                bool_arg(staged.had_previous),
            ],
        )
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
        render_posix_script(
            "nrm-agent-rollback",
            POSIX_ROLLBACK_SCRIPT,
            &[
                activated.staged.target_path.as_str(),
                activated.staged.stage_path.as_str(),
                activated.staged.backup_path.as_str(),
                bool_arg(activated.had_previous),
            ],
        )
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
        Ok(render_posix_script(
            "nrm-agent-absence-check",
            POSIX_ABSENCE_CHECK_SCRIPT,
            &[hook.executable_path.as_str()],
        ))
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
        render_posix_script(
            "nrm-agent-cleanup",
            POSIX_CLEANUP_SCRIPT,
            &[
                staged.target_path.as_str(),
                staged.stage_path.as_str(),
                staged.backup_path.as_str(),
            ],
        )
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
            .any(|component| matches!(component, "." | ".."))
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
    let detail = stderr.trim();
    if detail.is_empty() {
        return "remote install command failed without diagnostics".to_owned();
    }
    const MAX_DETAIL_BYTES: usize = 4096;
    if detail.len() <= MAX_DETAIL_BYTES {
        return detail.to_owned();
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

    use super::*;

    const VERSION: &str = "0.1.0";
    const PROTOCOL: u16 = 7;

    fn plan(target: &str, force: bool) -> PosixInstallPlan {
        PosixInstallPlan::new(target, VERSION, PROTOCOL, force).unwrap()
    }

    #[cfg(unix)]
    fn fake_agent(version: &str) -> Vec<u8> {
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'nrm-agent {version}\\n'; exit 0; fi\nexit 0\n"
        )
        .into_bytes()
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
        let hook = plan.rollback_validation(&rollback);
        assert_eq!(hook.mode, ValidationMode::Reprobe);
        assert_eq!(hook.phase, ValidationPhase::RolledBack);
        assert_eq!(hook.expected_version, None);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_preserves_a_previous_symlink_target() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = tempdir().unwrap();
        let previous = dir.path().join("previous-agent");
        fs::write(&previous, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&previous, fs::Permissions::from_mode(0o755)).unwrap();
        let target = dir.path().join("nrm-agent");
        symlink("previous-agent", &target).unwrap();

        let plan = plan(target.to_str().unwrap(), true);
        let staged_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(staged_output.status.success(), "{}", stderr(&staged_output));
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
        assert!(!fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());

        let rollback_output = run(&plan.rollback_command(&activated), &[]);
        assert!(
            rollback_output.status.success(),
            "{}",
            stderr(&rollback_output)
        );
        plan.parse_rollback_stdout(&activated, &stdout(&rollback_output))
            .unwrap();
        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(&target).unwrap(),
            std::path::Path::new("previous-agent")
        );
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
    fn missing_stage_and_prior_backup_fails_closed_without_deleting_target() {
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
        assert_eq!(recovered_output.status.code(), Some(50));
        assert_eq!(
            classify_install_failure(recovered_output.status.code(), &stderr(&recovered_output))
                .kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(fs::read(&target).unwrap(), previous);
        assert!(!std::path::Path::new(&staged.backup_path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn stage_names_are_unique_and_version_mismatch_leaks_nothing() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nrm-agent");
        let target = target.to_str().unwrap();
        let plan = plan(target, true);

        let first_output = run(&plan.stage_command(), &fake_agent(VERSION));
        let second_output = run(&plan.stage_command(), &fake_agent(VERSION));
        assert!(first_output.status.success(), "{}", stderr(&first_output));
        assert!(second_output.status.success(), "{}", stderr(&second_output));
        let first = plan.parse_stage_stdout(&stdout(&first_output)).unwrap();
        let second = plan.parse_stage_stdout(&stdout(&second_output)).unwrap();
        assert_ne!(first.stage_path, second.stage_path);
        assert_ne!(first.backup_path, second.backup_path);
        for staged in [&first, &second] {
            let output = run(&plan.cleanup_command(staged), &[]);
            assert!(output.status.success(), "{}", stderr(&output));
        }

        let mismatch = run(&plan.stage_command(), &fake_agent("9.9.9"));
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
    fn classifies_process_in_use_and_rollback_failed_distinctly() {
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
    }

    #[test]
    fn rejects_unsafe_targets_and_malformed_records() {
        for target in [
            "",
            "relative/agent",
            "/tmp/../agent",
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
