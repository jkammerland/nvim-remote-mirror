//! Windows PowerShell 5.1 transactional installation planning for `nrm-agent`.
//!
//! Every script is a fixed literal launched through `-EncodedCommand`. Caller
//! controlled values are serialized as JSON, base64 encoded, and decoded only
//! after PowerShell starts; they are never interpolated into script source.

use std::fmt;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::agent_install::{
    ActivatedInstall, ActivationRecovery, ActivationRecoveryKind, PosixValidationHook,
    RollbackOutcome, StagedInstall, ValidationMode, ValidationPhase,
};
use crate::remote_host::powershell_encoded_command;

const STAGE_RECORD: &str = "NRM_INSTALL_STAGE_V1";
const ACTIVATED_RECORD: &str = "NRM_INSTALL_ACTIVATED_V1";
const RECONCILED_RECORD: &str = "NRM_INSTALL_RECONCILED_V1";
const ROLLED_BACK_RECORD: &str = "NRM_INSTALL_ROLLED_BACK_V1";
const ABSENT_RECORD: &str = "NRM_INSTALL_ABSENT_V1";
const CLEANED_RECORD: &str = "NRM_INSTALL_CLEANED_V1";
const ACTION_SCRIPT_RECORD: &str = "NRM_INSTALL_ACTION_SCRIPT_V1";
const ACTION_SCRIPT_CLEANED_RECORD: &str = "NRM_INSTALL_ACTION_SCRIPT_CLEANED_V1";
const STAGE_PREPARED_RECORD: &str = "NRM_INSTALL_STAGE_PREPARED_V1";
const STAGE_ABORTED_RECORD: &str = "NRM_INSTALL_STAGE_ABORTED_V1";
const PAYLOAD_MARKER: &str = "__NRM_INSTALL_PAYLOAD_BASE64__";
// Leave room for `.nrm-backup.<guid>.exe.state` under legacy MAX_PATH
// (259 UTF-16 code units plus the terminating NUL).
const MAX_WINDOWS_TARGET_UTF16: usize = 205;
#[cfg(test)]
const MAX_OPENSSH_CMD_COMMAND_CHARS: usize = 8_191;

const POWERSHELL_UPLOAD_ACTION_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Root([Exception]$error) {
  while ($null -ne $error.InnerException) { $error = $error.InnerException }
  return $error
}
function Hex([byte[]]$bytes) {
  return [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
}

$path = $null
try {
  $path = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(),
    'nrm-agent-install.' + [Guid]::NewGuid().ToString('N') + '.ps1')
  $stream = New-Object IO.FileStream(
    $path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try {
    $copyTask = [Console]::OpenStandardInput().CopyToAsync($stream)
    while (-not $copyTask.IsCompleted) { Start-Sleep -Milliseconds 10 }
    [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($copyTask))
    $stream.Flush($true)
  } finally {
    $stream.Dispose()
  }
  $stream = [IO.File]::OpenRead($path)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $digest = Hex $sha.ComputeHash($stream) } finally {
    $sha.Dispose()
    $stream.Dispose()
  }
  $size = (New-Object IO.FileInfo($path)).Length
} catch {
  $root = Root $_.Exception
  if ($null -ne $path) { try { [IO.File]::Delete($path) } catch {} }
  [Console]::Error.WriteLine($root.Message.Replace("`r", ' ').Replace("`n", ' '))
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`tstage_create_failed")
  exit 30
}
[Console]::Out.WriteLine("NRM_INSTALL_ACTION_SCRIPT_V1`t$path`t$size`t$digest")
"#;

const POWERSHELL_RUN_ACTION_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$json = [Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $json | ConvertFrom-Json
function Fail([string]$Code, [int]$Status, [string]$Detail) {
  if (-not [string]::IsNullOrEmpty($Detail)) { [Console]::Error.WriteLine($Detail) }
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`t$Code")
  exit $Status
}
try {
  $bytes = [IO.File]::ReadAllBytes([string]$payload.path)
  if ($bytes.Length -ne [long]$payload.expected_size) {
    Fail 'invalid_state' 40 "uploaded action-script length changed before execution: actual=$($bytes.Length) expected=$([long]$payload.expected_size)"
  }
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $digest = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
  } finally { $sha.Dispose() }
  if ($digest -ne [string]$payload.expected_sha256) {
    Fail 'invalid_state' 40 "uploaded action-script digest changed before execution: actual=$digest expected=$([string]$payload.expected_sha256)"
  }
  $utf8 = New-Object Text.UTF8Encoding($false, $true)
  & ([ScriptBlock]::Create($utf8.GetString($bytes)))
  if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  exit 0
} catch {
  $error = $_.Exception
  while ($null -ne $error.InnerException) { $error = $error.InnerException }
  [Console]::Error.WriteLine($error.Message.Replace("`r", ' ').Replace("`n", ' '))
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`tcommand_failed")
  exit 52
}
"#;

const POWERSHELL_REMOVE_ACTION_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$json = [Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $json | ConvertFrom-Json
$path = [string]$payload.path
try {
  if ([IO.Directory]::Exists($path)) { throw 'action script path names a directory' }
  if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
} catch {
  $error = $_.Exception
  while ($null -ne $error.InnerException) { $error = $error.InnerException }
  [Console]::Error.WriteLine($error.Message.Replace("`r", ' ').Replace("`n", ' '))
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`tcleanup_failed")
  exit 51
}
[Console]::Out.WriteLine("NRM_INSTALL_ACTION_SCRIPT_CLEANED_V1`t$path")
"#;

const POWERSHELL_PREPARE_STAGE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-RootException([System.Exception]$Exception) {
  $current = $Exception
  while ($null -ne $current.InnerException) { $current = $current.InnerException }
  return $current
}
function Get-Win32Code([System.Exception]$Exception) {
  $root = Get-RootException $Exception
  return ($root.HResult -band 0xffff)
}
function Test-ProcessInUse([int]$Code) {
  return $Code -eq 32 -or $Code -eq 33 -or $Code -eq 1224
}
function Test-AnyPath([string]$Path) {
  try { [void][System.IO.File]::GetAttributes($Path); return $true }
  catch {
    $code = Get-Win32Code $_.Exception
    if ($code -eq 2 -or $code -eq 3) { return $false }
    throw
  }
}

function Test-RegularFile([string]$Path) {
  $attributes = [System.IO.File]::GetAttributes($Path)
  $forbidden = [System.IO.FileAttributes]::Directory -bor
    [System.IO.FileAttributes]::ReparsePoint -bor [System.IO.FileAttributes]::Device
  return ($attributes -band $forbidden) -eq 0
}
function Get-FileHashHex([string]$Path) {
  $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
  $stream = [System.IO.File]::Open(
    $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
    $stream.Dispose()
  }
}
function Fail([string]$Code, [int]$Status, [string]$Detail) {
  if (-not [string]::IsNullOrEmpty($Detail)) {
    [Console]::Error.WriteLine($Detail.Replace("`r", ' ').Replace("`n", ' '))
  }
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`t$Code")
  exit $Status
}
function Remove-InstallFile([string]$Path) {
  if (-not [string]::IsNullOrEmpty($Path) -and (Test-AnyPath $Path)) {
    [System.IO.File]::Delete($Path)
  }
}
function Fail-Prepare([string]$Code, [int]$Status, [string]$Detail) {
  try { Remove-InstallFile $script:stage } catch {}
  try { Remove-InstallFile $script:backup } catch {}
  if ($null -ne $script:backup) { try { Remove-InstallFile "$script:backup.state" } catch {} }
  Fail $Code $Status $Detail
}

$payloadJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $payloadJson | ConvertFrom-Json
$target = [string]$payload.target
$force = [bool]$payload.force
$stage = $null
$backup = $null

try {
  $fullTarget = [System.IO.Path]::GetFullPath($target)
  if (-not [string]::Equals($fullTarget, $target, [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail 'invalid_target' 40 'target path was not canonical'
  }
  if ([System.IO.Directory]::Exists($target)) {
    Fail 'invalid_target' 40 'target path names a directory'
  }
  $directory = [System.IO.Path]::GetDirectoryName($target)
  if ([string]::IsNullOrEmpty($directory)) {
    Fail 'invalid_target' 40 'target path has no parent directory'
  }
  [void][System.IO.Directory]::CreateDirectory($directory)
} catch {
  $root = Get-RootException $_.Exception
  Fail 'stage_create_failed' 30 $root.Message
}

$hadPrevious = Test-AnyPath $target
if ($hadPrevious -and -not $force) {
  Fail 'already_exists' 23 'remote agent target already exists'
}
$previousHash = $null
if ($hadPrevious) {
  try {
    if (-not (Test-RegularFile $target)) { Fail 'invalid_target' 40 'target is not a regular file' }
    $previousHash = Get-FileHashHex $target
  } catch {
    $root = Get-RootException $_.Exception
    $code = Get-Win32Code $root
    if (Test-ProcessInUse $code) { Fail 'process_in_use' 42 $root.Message }
    Fail 'stage_create_failed' 30 $root.Message
  }
}

try {
  $nonce = [System.Guid]::NewGuid().ToString('N')
  $stage = "$target.nrm-stage.$nonce.exe"
  $backup = "$target.nrm-backup.$nonce.exe"
  $stream = New-Object System.IO.FileStream(
    $stage, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try { $stream.Flush($true) } finally { $stream.Dispose() }
} catch {
  $root = Get-RootException $_.Exception
  Fail-Prepare 'stage_create_failed' 30 $root.Message
}

$previous = if ($hadPrevious) { '1' } else { '0' }
$previousDigest = if ($hadPrevious) { $previousHash } else { '-' }
[Console]::Out.WriteLine("NRM_INSTALL_STAGE_PREPARED_V1`t$target`t$stage`t$backup`t$previous`t$previousDigest")
"#;

const POWERSHELL_ABORT_STAGE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$json = [Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $json | ConvertFrom-Json
$target = [string]$payload.target
$stage = [string]$payload.stage
$backup = [string]$payload.backup
try {
  foreach ($path in @($stage, $backup, "$backup.state")) {
    if ([IO.Directory]::Exists($path)) { throw 'installer path names a directory' }
    if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
  }
} catch {
  $error = $_.Exception
  while ($null -ne $error.InnerException) { $error = $error.InnerException }
  [Console]::Error.WriteLine($error.Message.Replace("`r", ' ').Replace("`n", ' '))
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`tcleanup_failed")
  exit 51
}
[Console]::Out.WriteLine("NRM_INSTALL_STAGE_ABORTED_V1`t$target`t$stage")
"#;

const POWERSHELL_STAGE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-RootException([System.Exception]$Exception) {
  $current = $Exception
  while ($null -ne $current.InnerException) { $current = $current.InnerException }
  return $current
}

function Get-Win32Code([System.Exception]$Exception) {
  $root = Get-RootException $Exception
  return ($root.HResult -band 0xffff)
}

function Test-ProcessInUse([int]$Code) {
  return $Code -eq 32 -or $Code -eq 33 -or $Code -eq 1224
}

function Test-AnyPath([string]$Path) {
  try {
    [void][System.IO.File]::GetAttributes($Path)
    return $true
  } catch {
    $code = Get-Win32Code $_.Exception
    if ($code -eq 2 -or $code -eq 3) { return $false }
    throw
  }
}

function Test-RegularFile([string]$Path) {
  $attributes = [System.IO.File]::GetAttributes($Path)
  $forbidden = [System.IO.FileAttributes]::Directory -bor
    [System.IO.FileAttributes]::ReparsePoint -bor [System.IO.FileAttributes]::Device
  return ($attributes -band $forbidden) -eq 0
}

function Fail([string]$Code, [int]$Status, [string]$Detail) {
  if (-not [string]::IsNullOrEmpty($Detail)) {
    [Console]::Error.WriteLine($Detail.Replace("`r", ' ').Replace("`n", ' '))
  }
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`t$Code")
  exit $Status
}

function Remove-InstallFile([string]$Path) {
  if (-not [string]::IsNullOrEmpty($Path) -and (Test-AnyPath $Path)) {
    [System.IO.File]::Delete($Path)
  }
}

function Fail-Stage([string]$Code, [int]$Status, [string]$Detail) {
  try { Remove-InstallFile $script:stage } catch {}
  try { Remove-InstallFile $script:backup } catch {}
  try { Remove-InstallFile $script:state } catch {}
  Fail $Code $Status $Detail
}

function Get-FileHashHex([string]$Path) {
  $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
  $stream = [System.IO.File]::Open(
    $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
    $stream.Dispose()
  }
}

function Write-State([string]$Path, [string]$Value) {
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
  $stream = New-Object System.IO.FileStream(
    $Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
  } finally {
    $stream.Dispose()
  }
}

function Test-BytesEqual([byte[]]$Left, [byte[]]$Right) {
  if ($Left.Length -ne $Right.Length) { return $false }
  for ($index = 0; $index -lt $Left.Length; $index++) {
    if ($Left[$index] -ne $Right[$index]) { return $false }
  }
  return $true
}

$payloadJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $payloadJson | ConvertFrom-Json
$target = [string]$payload.target
$expectedVersion = [string]$payload.expected_version
$expectedSize = [long]$payload.expected_size
$expectedSha256 = [string]$payload.expected_sha256
$stage = [string]$payload.stage
$backup = [string]$payload.backup
$hadPrevious = [bool]$payload.had_previous
$previousHash = [string]$payload.previous_sha256
$state = "$backup.state"

try {
  $fullTarget = [System.IO.Path]::GetFullPath($target)
  if (-not [string]::Equals($fullTarget, $target, [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail 'invalid_target' 40 'target path was not canonical'
  }
  if ([System.IO.Directory]::Exists($target)) {
    Fail 'invalid_target' 40 'target path names a directory'
  }
  $directory = [System.IO.Path]::GetDirectoryName($target)
  if ([string]::IsNullOrEmpty($directory)) {
    Fail 'invalid_target' 40 'target path has no parent directory'
  }
  if (-not [string]::Equals([System.IO.Path]::GetDirectoryName($stage), $directory, [System.StringComparison]::OrdinalIgnoreCase) -or
      -not [string]::Equals([System.IO.Path]::GetDirectoryName($backup), $directory, [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail-Stage 'invalid_state' 40 'staging paths left the target directory'
  }
} catch {
  $root = Get-RootException $_.Exception
  Fail-Stage 'invalid_state' 40 $root.Message
}

try {
  $targetExists = Test-AnyPath $target
  if ($hadPrevious) {
    if (-not $targetExists) { Fail-Stage 'invalid_state' 40 'target disappeared after staging was prepared' }
    if (-not (Test-RegularFile $target)) { Fail-Stage 'invalid_state' 40 'target is no longer a regular file' }
    $currentHash = Get-FileHashHex $target
    if ($currentHash -ne $previousHash) {
      Fail-Stage 'invalid_state' 40 'target contents changed after staging was prepared'
    }
  } elseif ($targetExists) {
    Fail-Stage 'invalid_state' 40 'target appeared after staging was prepared'
  }
} catch {
    $root = Get-RootException $_.Exception
    $code = Get-Win32Code $root
    if (Test-ProcessInUse $code) { Fail-Stage 'process_in_use' 42 $root.Message }
    Fail-Stage 'invalid_state' 40 $root.Message
}

try {
  if (-not (Test-AnyPath $stage)) { throw 'uploaded artifact is missing' }
  if (-not (Test-RegularFile $stage)) { throw 'uploaded artifact is not a regular file' }
  $actualSize = (New-Object System.IO.FileInfo($stage)).Length
  if ($actualSize -ne $expectedSize) {
    throw "uploaded artifact length did not match local source: actual=$actualSize expected=$expectedSize"
  }
} catch {
  $root = Get-RootException $_.Exception
  Fail-Stage 'upload_failed' 31 $root.Message
}

try {
  $candidateHash = Get-FileHashHex $stage
  if ($candidateHash -ne $expectedSha256) {
    Fail-Stage 'upload_failed' 31 'uploaded artifact digest did not match local source'
  }
} catch {
  $root = Get-RootException $_.Exception
  Fail-Stage 'upload_failed' 31 $root.Message
}

try {
  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = $stage
  $start.Arguments = '--version'
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $start
  if (-not $process.Start()) { Fail-Stage 'version_exec_failed' 33 'failed to start staged agent' }
  $stdout = New-Object System.IO.MemoryStream
  $stderr = New-Object System.IO.MemoryStream
  $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
  $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
  $process.WaitForExit()
  [System.Threading.Tasks.Task]::WaitAll(
    [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
  $exitCode = $process.ExitCode
  $process.Dispose()
} catch {
  $root = Get-RootException $_.Exception
  Fail-Stage 'version_exec_failed' 33 $root.Message
}

if ($exitCode -ne 0) {
  Fail-Stage 'version_exec_failed' 33 'nrm-agent --version did not exit successfully'
}
$expectedBytes = [System.Text.Encoding]::UTF8.GetBytes("nrm-agent $expectedVersion`n")
if ($stderr.Length -ne 0 -or -not (Test-BytesEqual $stdout.ToArray() $expectedBytes)) {
  Fail-Stage 'version_mismatch' 34 'nrm-agent --version output did not match exactly'
}
$stdout.Dispose()
$stderr.Dispose()

try {
  $stateValue = if ($hadPrevious) {
    "present:${previousHash}:$candidateHash"
  } else {
    "missing:$candidateHash"
  }
  Write-State $state $stateValue
} catch {
  $root = Get-RootException $_.Exception
  Fail-Stage 'stage_create_failed' 30 $root.Message
}

$previous = if ($hadPrevious) { '1' } else { '0' }
[Console]::Out.WriteLine("NRM_INSTALL_STAGE_V1`t$target`t$stage`t$backup`t$previous")
"#;

const POWERSHELL_ACTIVATE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-RootException([System.Exception]$Exception) {
  $current = $Exception
  while ($null -ne $current.InnerException) { $current = $current.InnerException }
  return $current
}
function Get-Win32Code([System.Exception]$Exception) {
  $root = Get-RootException $Exception
  return ($root.HResult -band 0xffff)
}
function Test-ProcessInUse([int]$Code) {
  return $Code -eq 32 -or $Code -eq 33 -or $Code -eq 1224
}
function Test-AnyPath([string]$Path) {
  try { [void][System.IO.File]::GetAttributes($Path); return $true }
  catch {
    $code = Get-Win32Code $_.Exception
    if ($code -eq 2 -or $code -eq 3) { return $false }
    throw
  }
}
function Fail([string]$Code, [int]$Status, [string]$Detail) {
  if (-not [string]::IsNullOrEmpty($Detail)) {
    [Console]::Error.WriteLine($Detail.Replace("`r", ' ').Replace("`n", ' '))
  }
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`t$Code")
  exit $Status
}
function Get-FileHashHex([string]$Path) {
  $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
  $stream = [System.IO.File]::Open(
    $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
    $stream.Dispose()
  }
}
function Read-State([string]$Path, [bool]$HadPrevious) {
  if (-not [System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path)) {
    Fail 'invalid_state' 40 'install state file is missing or invalid'
  }
  $parts = ([System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::ASCII)).Split(':')
  $validHash = '^[0-9a-f]{64}$'
  if ($HadPrevious) {
    if ($parts.Length -ne 3 -or $parts[0] -ne 'present' -or
        $parts[1] -notmatch $validHash -or $parts[2] -notmatch $validHash) {
      Fail 'invalid_state' 40 'install state file is malformed'
    }
  } elseif ($parts.Length -ne 2 -or $parts[0] -ne 'missing' -or
            $parts[1] -notmatch $validHash) {
    Fail 'invalid_state' 40 'install state file is malformed'
  }
  return $parts
}

$payloadJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $payloadJson | ConvertFrom-Json
$target = [string]$payload.target
$stage = [string]$payload.stage
$backup = [string]$payload.backup
$force = [bool]$payload.force
$expectedPrevious = [bool]$payload.had_previous
$statePath = "$backup.state"

try {
  if (-not [System.IO.File]::Exists($stage) -or [System.IO.Directory]::Exists($stage)) {
    Fail 'invalid_state' 40 'staged agent is missing or is not a file'
  }
  if (Test-AnyPath $backup) { Fail 'invalid_state' 40 'backup path is not empty' }
  $state = @(Read-State $statePath $expectedPrevious)
  $candidateHash = $state[$state.Length - 1]
  if ((Get-FileHashHex $stage) -ne $candidateHash) {
    Fail 'invalid_state' 40 'staged agent changed after validation'
  }
  $currentPrevious = Test-AnyPath $target
  if ($currentPrevious -ne $expectedPrevious) {
    Fail 'invalid_state' 40 'target state changed after staging'
  }
  if ($currentPrevious -and (Get-FileHashHex $target) -ne $state[1]) {
    Fail 'invalid_state' 40 'target contents changed after staging'
  }
  if ($currentPrevious -and -not $force) {
    Fail 'already_exists' 23 'remote agent target already exists'
  }
  if ($currentPrevious) {
    [System.IO.File]::Replace($stage, $target, $backup, $true)
  } else {
    [System.IO.File]::Move($stage, $target)
  }
} catch {
  $root = Get-RootException $_.Exception
  $code = Get-Win32Code $root
  if (Test-ProcessInUse $code) { Fail 'process_in_use' 42 $root.Message }
  Fail 'activation_failed' 41 $root.Message
}

$previous = if ($currentPrevious) { '1' } else { '0' }
[Console]::Out.WriteLine("NRM_INSTALL_ACTIVATED_V1`t$target`t$backup`t$previous")
"#;

const POWERSHELL_RECONCILE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-RootException([System.Exception]$Exception) {
  $current = $Exception
  while ($null -ne $current.InnerException) { $current = $current.InnerException }
  return $current
}
function Get-Win32Code([System.Exception]$Exception) {
  $root = Get-RootException $Exception
  return ($root.HResult -band 0xffff)
}
function Test-AnyPath([string]$Path) {
  try { [void][System.IO.File]::GetAttributes($Path); return $true }
  catch {
    $code = Get-Win32Code $_.Exception
    if ($code -eq 2 -or $code -eq 3) { return $false }
    throw
  }
}
function Remove-InstallFile([string]$Path) {
  if (Test-AnyPath $Path) { [System.IO.File]::Delete($Path) }
}
function Fail([string]$Code, [int]$Status, [string]$Detail) {
  if (-not [string]::IsNullOrEmpty($Detail)) {
    [Console]::Error.WriteLine($Detail.Replace("`r", ' ').Replace("`n", ' '))
  }
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`t$Code")
  exit $Status
}
function Get-FileHashHex([string]$Path) {
  $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
  $stream = [System.IO.File]::Open(
    $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
    $stream.Dispose()
  }
}
function Read-State([string]$Path, [bool]$HadPrevious) {
  if (-not [System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path)) {
    Fail 'rollback_failed' 50 'install state file is missing or invalid'
  }
  $parts = ([System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::ASCII)).Split(':')
  $validHash = '^[0-9a-f]{64}$'
  if ($HadPrevious) {
    if ($parts.Length -ne 3 -or $parts[0] -ne 'present' -or
        $parts[1] -notmatch $validHash -or $parts[2] -notmatch $validHash) {
      Fail 'rollback_failed' 50 'install state file is malformed'
    }
  } elseif ($parts.Length -ne 2 -or $parts[0] -ne 'missing' -or
            $parts[1] -notmatch $validHash) {
    Fail 'rollback_failed' 50 'install state file is malformed'
  }
  return $parts
}

$payloadJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $payloadJson | ConvertFrom-Json
$target = [string]$payload.target
$stage = [string]$payload.stage
$backup = [string]$payload.backup
$hadPrevious = [bool]$payload.had_previous
$statePath = "$backup.state"

try {
  $state = @(Read-State $statePath $hadPrevious)
  $candidateHash = $state[$state.Length - 1]
  $stageExists = Test-AnyPath $stage
  $targetExists = Test-AnyPath $target
  $backupExists = Test-AnyPath $backup
  if ($stageExists -and (Get-FileHashHex $stage) -ne $candidateHash) {
    Fail 'rollback_failed' 50 'staged candidate changed before reconciliation'
  }

  if ($hadPrevious) {
    if ($backupExists) {
      if ((Get-FileHashHex $backup) -ne $state[1]) {
        Fail 'rollback_failed' 50 'prior-agent backup changed before reconciliation'
      }
      if ($targetExists) {
        if ((Get-FileHashHex $target) -ne $candidateHash) {
          Fail 'rollback_failed' 50 'activated target changed before reconciliation'
        }
      }

      # All surviving transaction files are hash-gated before the first
      # destructive operation. File.Replace requires an empty backup slot.
      if ($targetExists) {
        Remove-InstallFile $stage
        [System.IO.File]::Replace($backup, $target, $stage, $true)
        Remove-InstallFile $stage
      } else {
        [System.IO.File]::Move($backup, $target)
        Remove-InstallFile $stage
      }
      $outcome = 'restored_previous'
    } elseif ($stageExists) {
      if (-not $targetExists) {
        Fail 'rollback_failed' 50 'prior target disappeared before reconciliation'
      }
      if ((Get-FileHashHex $target) -ne $state[1]) {
        Fail 'rollback_failed' 50 'prior target changed before reconciliation'
      }
      Remove-InstallFile $stage
      $outcome = 'activation_unchanged_present'
    } elseif ($targetExists -and (Get-FileHashHex $target) -eq $state[1]) {
      # A previous reconciliation may have restored the prior target and then
      # lost its response before removing the state record.
      $outcome = 'restored_previous'
    } else {
      Fail 'rollback_failed' 50 'prior agent cannot be recovered from activation state'
    }
  } else {
    if ($backupExists) { Fail 'rollback_failed' 50 'unexpected backup for a new install' }
    if ($targetExists) {
      if ((Get-FileHashHex $target) -ne $candidateHash) {
        Fail 'rollback_failed' 50 'activated target changed before reconciliation'
      }
      Remove-InstallFile $target
      Remove-InstallFile $stage
      $outcome = 'removed_candidate'
    } elseif ($stageExists) {
      Remove-InstallFile $stage
      $outcome = 'activation_unchanged_missing'
    } else {
      $outcome = 'removed_candidate'
    }
  }
  Remove-InstallFile $backup
  Remove-InstallFile $statePath
} catch {
  $root = Get-RootException $_.Exception
  Fail 'rollback_failed' 50 $root.Message
}

[Console]::Out.WriteLine("NRM_INSTALL_RECONCILED_V1`t$target`t$outcome")
"#;

const POWERSHELL_ROLLBACK_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-RootException([System.Exception]$Exception) {
  $current = $Exception
  while ($null -ne $current.InnerException) { $current = $current.InnerException }
  return $current
}
function Get-Win32Code([System.Exception]$Exception) {
  $root = Get-RootException $Exception
  return ($root.HResult -band 0xffff)
}
function Test-AnyPath([string]$Path) {
  try { [void][System.IO.File]::GetAttributes($Path); return $true }
  catch {
    $code = Get-Win32Code $_.Exception
    if ($code -eq 2 -or $code -eq 3) { return $false }
    throw
  }
}
function Remove-InstallFile([string]$Path) {
  if (Test-AnyPath $Path) { [System.IO.File]::Delete($Path) }
}
function Fail([string]$Code, [int]$Status, [string]$Detail) {
  if (-not [string]::IsNullOrEmpty($Detail)) {
    [Console]::Error.WriteLine($Detail.Replace("`r", ' ').Replace("`n", ' '))
  }
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`t$Code")
  exit $Status
}
function Get-FileHashHex([string]$Path) {
  $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
  $stream = [System.IO.File]::Open(
    $Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
    $stream.Dispose()
  }
}
function Read-State([string]$Path, [bool]$HadPrevious) {
  if (-not [System.IO.File]::Exists($Path) -or [System.IO.Directory]::Exists($Path)) {
    Fail 'rollback_failed' 50 'install state file is missing or invalid'
  }
  $parts = ([System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::ASCII)).Split(':')
  $validHash = '^[0-9a-f]{64}$'
  if ($HadPrevious) {
    if ($parts.Length -ne 3 -or $parts[0] -ne 'present' -or
        $parts[1] -notmatch $validHash -or $parts[2] -notmatch $validHash) {
      Fail 'rollback_failed' 50 'install state file is malformed'
    }
  } elseif ($parts.Length -ne 2 -or $parts[0] -ne 'missing' -or
            $parts[1] -notmatch $validHash) {
    Fail 'rollback_failed' 50 'install state file is malformed'
  }
  return $parts
}

$payloadJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $payloadJson | ConvertFrom-Json
$target = [string]$payload.target
$stage = [string]$payload.stage
$backup = [string]$payload.backup
$hadPrevious = [bool]$payload.had_previous
$statePath = "$backup.state"

try {
  if (Test-AnyPath $stage) { Fail 'rollback_failed' 50 'staging path was unexpectedly recreated' }
  $state = @(Read-State $statePath $hadPrevious)
  $candidateHash = $state[$state.Length - 1]
  if ($hadPrevious) {
    if (-not (Test-AnyPath $backup)) { Fail 'rollback_failed' 50 'missing prior-agent backup' }
    if ((Get-FileHashHex $backup) -ne $state[1]) {
      Fail 'rollback_failed' 50 'prior-agent backup changed before rollback'
    }
    if (Test-AnyPath $target) {
      if ((Get-FileHashHex $target) -ne $candidateHash) {
        Fail 'rollback_failed' 50 'activated target changed before rollback'
      }
      [System.IO.File]::Replace($backup, $target, $stage, $true)
      Remove-InstallFile $stage
    } else {
      [System.IO.File]::Move($backup, $target)
    }
  } else {
    if (Test-AnyPath $target) {
      if ((Get-FileHashHex $target) -ne $candidateHash) {
        Fail 'rollback_failed' 50 'activated target changed before rollback'
      }
      Remove-InstallFile $target
    }
  }
  Remove-InstallFile $stage
  Remove-InstallFile $backup
  Remove-InstallFile $statePath
} catch {
  $root = Get-RootException $_.Exception
  Fail 'rollback_failed' 50 $root.Message
}

$previous = if ($hadPrevious) { '1' } else { '0' }
[Console]::Out.WriteLine("NRM_INSTALL_ROLLED_BACK_V1`t$target`t$previous")
"#;

const POWERSHELL_ABSENCE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-RootException([System.Exception]$Exception) {
  $current = $Exception
  while ($null -ne $current.InnerException) { $current = $current.InnerException }
  return $current
}
function Get-Win32Code([System.Exception]$Exception) {
  $root = Get-RootException $Exception
  return ($root.HResult -band 0xffff)
}
function Test-AnyPath([string]$Path) {
  try { [void][System.IO.File]::GetAttributes($Path); return $true }
  catch {
    $code = Get-Win32Code $_.Exception
    if ($code -eq 2 -or $code -eq 3) { return $false }
    throw
  }
}
function Fail([string]$Code, [int]$Status, [string]$Detail) {
  if (-not [string]::IsNullOrEmpty($Detail)) { [Console]::Error.WriteLine($Detail) }
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`t$Code")
  exit $Status
}

$payloadJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $payloadJson | ConvertFrom-Json
$target = [string]$payload.target
try {
  if (Test-AnyPath $target) { Fail 'rollback_failed' 50 'target still exists' }
} catch {
  $root = Get-RootException $_.Exception
  Fail 'rollback_failed' 50 $root.Message
}
[Console]::Out.WriteLine("NRM_INSTALL_ABSENT_V1`t$target")
"#;

const POWERSHELL_CLEANUP_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Get-RootException([System.Exception]$Exception) {
  $current = $Exception
  while ($null -ne $current.InnerException) { $current = $current.InnerException }
  return $current
}
function Get-Win32Code([System.Exception]$Exception) {
  $root = Get-RootException $Exception
  return ($root.HResult -band 0xffff)
}
function Test-AnyPath([string]$Path) {
  try { [void][System.IO.File]::GetAttributes($Path); return $true }
  catch {
    $code = Get-Win32Code $_.Exception
    if ($code -eq 2 -or $code -eq 3) { return $false }
    throw
  }
}
function Remove-InstallFile([string]$Path) {
  if (Test-AnyPath $Path) { [System.IO.File]::Delete($Path) }
}
function Fail([string]$Code, [int]$Status, [string]$Detail) {
  if (-not [string]::IsNullOrEmpty($Detail)) { [Console]::Error.WriteLine($Detail) }
  [Console]::Error.WriteLine("NRM_INSTALL_ERROR_V1`t$Code")
  exit $Status
}

$payloadJson = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String('__NRM_INSTALL_PAYLOAD_BASE64__'))
$payload = $payloadJson | ConvertFrom-Json
$target = [string]$payload.target
$stage = [string]$payload.stage
$backup = [string]$payload.backup
try {
  Remove-InstallFile $stage
  Remove-InstallFile $backup
  Remove-InstallFile "$backup.state"
} catch {
  $root = Get-RootException $_.Exception
  Fail 'cleanup_failed' 51 $root.Message
}
[Console]::Out.WriteLine("NRM_INSTALL_CLEANED_V1`t$target")
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsInstallPlan {
    target: String,
    expected_version: String,
    expected_protocol_version: u16,
    force: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedWindowsStage {
    pub(crate) staged: StagedInstall,
    previous_sha256: Option<String>,
}

impl WindowsInstallPlan {
    pub(crate) fn new(
        target: impl Into<String>,
        expected_version: impl Into<String>,
        expected_protocol_version: u16,
        force: bool,
    ) -> Result<Self, WindowsInstallPlanError> {
        let target = normalize_windows_target(&target.into())?;
        let expected_version = expected_version.into();
        validate_version(&expected_version)?;
        Ok(Self {
            target,
            expected_version,
            expected_protocol_version,
            force,
        })
    }

    #[cfg(test)]
    pub(crate) fn target_path(&self) -> &str {
        &self.target
    }

    pub(crate) fn action_script_upload_command(&self) -> String {
        powershell_encoded_command(POWERSHELL_UPLOAD_ACTION_SCRIPT)
    }

    pub(crate) fn parse_action_script_upload_stdout(
        &self,
        script: &str,
        stdout: &str,
    ) -> Result<String, WindowsInstallPlanError> {
        let fields = parse_record(stdout, ACTION_SCRIPT_RECORD, 3)?;
        let path = normalize_action_script_path(fields[0])?;
        let size = fields[1].parse::<usize>().map_err(|_| {
            WindowsInstallPlanError::Record(
                "action-script record has an invalid byte length".to_owned(),
            )
        })?;
        if size != script.len() {
            return Err(WindowsInstallPlanError::Record(
                "uploaded action-script length does not match local bytes".to_owned(),
            ));
        }
        let digest = fields[2];
        if digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || digest != sha256_hex(script.as_bytes())
        {
            return Err(WindowsInstallPlanError::Record(
                "uploaded action-script digest does not match local bytes".to_owned(),
            ));
        }
        Ok(path)
    }

    pub(crate) fn action_script_run_command(&self, path: &str, script: &str) -> String {
        let digest = sha256_hex(script.as_bytes());
        render_command_script(
            POWERSHELL_RUN_ACTION_SCRIPT,
            &ActionScriptRunPayload {
                path,
                expected_size: script.len(),
                expected_sha256: &digest,
            },
        )
    }

    pub(crate) fn action_script_cleanup_command(&self, path: &str) -> String {
        render_command_script(
            POWERSHELL_REMOVE_ACTION_SCRIPT,
            &ActionScriptPathPayload { path },
        )
    }

    pub(crate) fn parse_action_script_cleanup_stdout(
        &self,
        path: &str,
        stdout: &str,
    ) -> Result<(), WindowsInstallPlanError> {
        let fields = parse_record(stdout, ACTION_SCRIPT_CLEANED_RECORD, 1)?;
        if fields[0] != path {
            return Err(WindowsInstallPlanError::Record(
                "action-script cleanup path does not match the uploaded script".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_stage_script(&self) -> String {
        render_action_script(
            POWERSHELL_PREPARE_STAGE_SCRIPT,
            &PrepareStagePayload {
                target: &self.target,
                force: self.force,
            },
        )
    }

    pub(crate) fn parse_prepare_stage_stdout(
        &self,
        stdout: &str,
    ) -> Result<PreparedWindowsStage, WindowsInstallPlanError> {
        let fields = parse_record(stdout, STAGE_PREPARED_RECORD, 5)?;
        if fields[0] != self.target {
            return Err(WindowsInstallPlanError::Record(
                "prepared target does not match the requested path".to_owned(),
            ));
        }
        let staged = StagedInstall {
            target_path: fields[0].to_owned(),
            stage_path: fields[1].to_owned(),
            backup_path: fields[2].to_owned(),
            had_previous: parse_bool(fields[3])?,
        };
        validate_staged(&staged)?;
        if staged.had_previous && !self.force {
            return Err(WindowsInstallPlanError::Record(
                "stage preparation reported an existing target without force enabled".to_owned(),
            ));
        }
        let previous_sha256 = if staged.had_previous {
            if !is_lowercase_sha256(fields[4]) {
                return Err(WindowsInstallPlanError::Record(
                    "prepared prior-target digest is not lowercase SHA-256".to_owned(),
                ));
            }
            Some(fields[4].to_owned())
        } else {
            if fields[4] != "-" {
                return Err(WindowsInstallPlanError::Record(
                    "missing prior target must use the digest sentinel".to_owned(),
                ));
            }
            None
        };
        Ok(PreparedWindowsStage {
            staged,
            previous_sha256,
        })
    }

    pub(crate) fn finalize_stage_script(
        &self,
        prepared: &PreparedWindowsStage,
        expected_size: u64,
        expected_sha256: &str,
    ) -> String {
        render_action_script(
            POWERSHELL_STAGE_SCRIPT,
            &StagePayload {
                target: &self.target,
                stage: &prepared.staged.stage_path,
                backup: &prepared.staged.backup_path,
                had_previous: prepared.staged.had_previous,
                previous_sha256: prepared.previous_sha256.as_deref().unwrap_or("-"),
                expected_version: &self.expected_version,
                expected_size,
                expected_sha256,
            },
        )
    }

    pub(crate) fn abort_stage_script(&self, prepared: &PreparedWindowsStage) -> String {
        render_action_script(
            POWERSHELL_ABORT_STAGE_SCRIPT,
            &InstallStatePayload::from_staged(&prepared.staged, None),
        )
    }

    pub(crate) fn parse_abort_stage_stdout(
        &self,
        prepared: &PreparedWindowsStage,
        stdout: &str,
    ) -> Result<(), WindowsInstallPlanError> {
        let fields = parse_record(stdout, STAGE_ABORTED_RECORD, 2)?;
        if fields[0] != prepared.staged.target_path || fields[1] != prepared.staged.stage_path {
            return Err(WindowsInstallPlanError::Record(
                "aborted stage paths do not match the prepared upload".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn parse_finalize_stage_stdout(
        &self,
        prepared: &PreparedWindowsStage,
        stdout: &str,
    ) -> Result<StagedInstall, WindowsInstallPlanError> {
        let staged = self.parse_stage_stdout(stdout)?;
        if staged != prepared.staged {
            return Err(WindowsInstallPlanError::Record(
                "finalized stage does not match the prepared upload".to_owned(),
            ));
        }
        Ok(staged)
    }

    fn parse_stage_stdout(&self, stdout: &str) -> Result<StagedInstall, WindowsInstallPlanError> {
        let fields = parse_record(stdout, STAGE_RECORD, 4)?;
        if fields[0] != self.target {
            return Err(WindowsInstallPlanError::Record(
                "staged target does not match the requested path".to_owned(),
            ));
        }
        let staged = StagedInstall {
            target_path: fields[0].to_owned(),
            stage_path: fields[1].to_owned(),
            backup_path: fields[2].to_owned(),
            had_previous: parse_bool(fields[3])?,
        };
        validate_staged(&staged)?;
        if staged.had_previous && !self.force {
            return Err(WindowsInstallPlanError::Record(
                "staging reported an existing target without force enabled".to_owned(),
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

    pub(crate) fn activate_script(&self, staged: &StagedInstall) -> String {
        render_action_script(
            POWERSHELL_ACTIVATE_SCRIPT,
            &InstallStatePayload::from_staged(staged, Some(self.force)),
        )
    }

    pub(crate) fn parse_activation_stdout(
        &self,
        staged: &StagedInstall,
        stdout: &str,
    ) -> Result<ActivatedInstall, WindowsInstallPlanError> {
        let fields = parse_record(stdout, ACTIVATED_RECORD, 3)?;
        if fields[0] != staged.target_path || fields[1] != staged.backup_path {
            return Err(WindowsInstallPlanError::Record(
                "activation record paths do not match the staged install".to_owned(),
            ));
        }
        let had_previous = parse_bool(fields[2])?;
        if had_previous != staged.had_previous {
            return Err(WindowsInstallPlanError::Record(
                "activation record does not match prior-target state".to_owned(),
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

    pub(crate) fn reconcile_activation_script(&self, staged: &StagedInstall) -> String {
        render_action_script(
            POWERSHELL_RECONCILE_SCRIPT,
            &InstallStatePayload::from_staged(staged, None),
        )
    }

    pub(crate) fn parse_reconciliation_stdout(
        &self,
        staged: &StagedInstall,
        stdout: &str,
    ) -> Result<ActivationRecovery, WindowsInstallPlanError> {
        let fields = parse_record(stdout, RECONCILED_RECORD, 2)?;
        if fields[0] != staged.target_path {
            return Err(WindowsInstallPlanError::Record(
                "reconciliation target does not match the staged install".to_owned(),
            ));
        }
        let kind = match fields[1] {
            "activation_unchanged_present" => ActivationRecoveryKind::ActivationUnchangedPresent,
            "activation_unchanged_missing" => ActivationRecoveryKind::ActivationUnchangedMissing,
            "restored_previous" => ActivationRecoveryKind::RestoredPrevious,
            "removed_candidate" => ActivationRecoveryKind::RemovedCandidate,
            _ => {
                return Err(WindowsInstallPlanError::Record(
                    "reconciliation record has an unknown outcome".to_owned(),
                ))
            }
        };
        let state_matches = matches!(
            (staged.had_previous, kind),
            (
                true,
                ActivationRecoveryKind::ActivationUnchangedPresent
                    | ActivationRecoveryKind::ActivationUnchangedMissing
                    | ActivationRecoveryKind::RestoredPrevious
            ) | (
                false,
                ActivationRecoveryKind::ActivationUnchangedPresent
                    | ActivationRecoveryKind::ActivationUnchangedMissing
                    | ActivationRecoveryKind::RemovedCandidate
            )
        );
        if !state_matches {
            return Err(WindowsInstallPlanError::Record(
                "reconciliation outcome does not match prior-target state".to_owned(),
            ));
        }
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

    pub(crate) fn rollback_script(&self, activated: &ActivatedInstall) -> String {
        render_action_script(
            POWERSHELL_ROLLBACK_SCRIPT,
            &InstallStatePayload::from_staged(&activated.staged, None),
        )
    }

    pub(crate) fn parse_rollback_stdout(
        &self,
        activated: &ActivatedInstall,
        stdout: &str,
    ) -> Result<RollbackOutcome, WindowsInstallPlanError> {
        let fields = parse_record(stdout, ROLLED_BACK_RECORD, 2)?;
        if fields[0] != activated.staged.target_path {
            return Err(WindowsInstallPlanError::Record(
                "rollback target does not match the activated install".to_owned(),
            ));
        }
        let restored_previous = parse_bool(fields[1])?;
        if restored_previous != activated.had_previous {
            return Err(WindowsInstallPlanError::Record(
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

    pub(crate) fn absence_check_script(
        &self,
        hook: &PosixValidationHook,
    ) -> Result<String, WindowsInstallPlanError> {
        validate_absence_hook(hook)?;
        Ok(render_action_script(
            POWERSHELL_ABSENCE_SCRIPT,
            &TargetPayload {
                target: &hook.executable_path,
            },
        ))
    }

    pub(crate) fn parse_absence_check_stdout(
        &self,
        hook: &PosixValidationHook,
        stdout: &str,
    ) -> Result<(), WindowsInstallPlanError> {
        validate_absence_hook(hook)?;
        let fields = parse_record(stdout, ABSENT_RECORD, 1)?;
        if fields[0] != hook.executable_path {
            return Err(WindowsInstallPlanError::Record(
                "absence record target does not match validation hook".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn cleanup_script(&self, staged: &StagedInstall) -> String {
        render_action_script(
            POWERSHELL_CLEANUP_SCRIPT,
            &InstallStatePayload::from_staged(staged, None),
        )
    }

    pub(crate) fn parse_cleanup_stdout(
        &self,
        staged: &StagedInstall,
        stdout: &str,
    ) -> Result<(), WindowsInstallPlanError> {
        let fields = parse_record(stdout, CLEANED_RECORD, 1)?;
        if fields[0] != staged.target_path {
            return Err(WindowsInstallPlanError::Record(
                "cleanup record target does not match the staged install".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PrepareStagePayload<'a> {
    target: &'a str,
    force: bool,
}

#[derive(Serialize)]
struct StagePayload<'a> {
    target: &'a str,
    stage: &'a str,
    backup: &'a str,
    had_previous: bool,
    previous_sha256: &'a str,
    expected_version: &'a str,
    expected_size: u64,
    expected_sha256: &'a str,
}

#[derive(Serialize)]
struct InstallStatePayload<'a> {
    target: &'a str,
    stage: &'a str,
    backup: &'a str,
    had_previous: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    force: Option<bool>,
}

impl<'a> InstallStatePayload<'a> {
    fn from_staged(staged: &'a StagedInstall, force: Option<bool>) -> Self {
        Self {
            target: &staged.target_path,
            stage: &staged.stage_path,
            backup: &staged.backup_path,
            had_previous: staged.had_previous,
            force,
        }
    }
}

#[derive(Serialize)]
struct TargetPayload<'a> {
    target: &'a str,
}

#[derive(Serialize)]
struct ActionScriptPathPayload<'a> {
    path: &'a str,
}

#[derive(Serialize)]
struct ActionScriptRunPayload<'a> {
    path: &'a str,
    expected_size: usize,
    expected_sha256: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WindowsInstallPlanError {
    Target(String),
    Version(String),
    Record(String),
}

impl fmt::Display for WindowsInstallPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(message) => write!(formatter, "invalid Windows install target: {message}"),
            Self::Version(message) => {
                write!(formatter, "invalid expected agent version: {message}")
            }
            Self::Record(message) => write!(formatter, "invalid Windows install record: {message}"),
        }
    }
}

impl std::error::Error for WindowsInstallPlanError {}

fn render_action_script(payload_script: &str, payload: &impl Serialize) -> String {
    let payload = serde_json::to_vec(payload).expect("install payload serialization cannot fail");
    let payload = STANDARD.encode(payload);
    debug_assert_eq!(payload_script.matches(PAYLOAD_MARKER).count(), 1);
    payload_script.replace(PAYLOAD_MARKER, &payload)
}

fn render_command_script(payload_script: &str, payload: &impl Serialize) -> String {
    powershell_encoded_command(&render_action_script(payload_script, payload))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn normalize_windows_target(input: &str) -> Result<String, WindowsInstallPlanError> {
    normalize_windows_absolute_path(input, MAX_WINDOWS_TARGET_UTF16, ".exe", "agent target")
        .map_err(WindowsInstallPlanError::Target)
}

fn normalize_action_script_path(input: &str) -> Result<String, WindowsInstallPlanError> {
    let normalized = normalize_windows_absolute_path(input, 260, ".ps1", "action script")
        .map_err(WindowsInstallPlanError::Record)?;
    let filename = normalized.rsplit('\\').next().unwrap_or_default();
    let nonce = filename
        .strip_prefix("nrm-agent-install.")
        .and_then(|filename| filename.strip_suffix(".ps1"))
        .ok_or_else(|| {
            WindowsInstallPlanError::Record(
                "action-script filename does not use the expected prefix".to_owned(),
            )
        })?;
    if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(WindowsInstallPlanError::Record(
            "action-script filename has an invalid GUID suffix".to_owned(),
        ));
    }
    Ok(normalized)
}

fn normalize_windows_absolute_path(
    input: &str,
    max_utf16: usize,
    required_extension: &str,
    description: &str,
) -> Result<String, String> {
    if input.is_empty() || input.encode_utf16().count() > max_utf16 || input != input.trim() {
        return Err(format!(
            "{description} must contain between 1 and {max_utf16} UTF-16 code units without edge whitespace"
        ));
    }
    if input.chars().any(char::is_control) || input.starts_with(['/', '\\']) {
        return Err(format!(
            "{description} must not contain controls or use UNC/device syntax"
        ));
    }
    let mut normalized = input.replace('/', "\\");
    let bytes = normalized.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(format!(
            "{description} must be an absolute drive path such as C:\\nrm\\file"
        ));
    }
    normalized.replace_range(0..1, &normalized[0..1].to_ascii_uppercase());
    let segments: Vec<_> = normalized[3..].split('\\').collect();
    if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
        return Err(format!("{description} must not contain empty segments"));
    }
    for segment in &segments {
        if matches!(*segment, "." | "..")
            || segment.ends_with(['.', ' '])
            || segment.contains(['<', '>', ':', '"', '|', '?', '*'])
        {
            return Err(format!(
                "{description} contains a forbidden Windows segment"
            ));
        }
        let stem = segment.split('.').next().unwrap_or_default();
        if is_reserved_windows_name(stem) {
            return Err(format!(
                "{description} contains a reserved Windows device name"
            ));
        }
    }
    if !normalized
        .to_ascii_lowercase()
        .ends_with(required_extension)
    {
        return Err(format!("{description} must end with {required_extension}"));
    }
    Ok(normalized)
}

fn is_reserved_windows_name(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
        || ["COM", "LPT"].iter().any(|prefix| {
            upper
                .strip_prefix(prefix)
                .is_some_and(|suffix| matches!(suffix, "¹" | "²" | "³"))
        })
}

fn validate_version(version: &str) -> Result<(), WindowsInstallPlanError> {
    if version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        return Err(WindowsInstallPlanError::Version(
            "version must be a short ASCII SemVer-like value".to_owned(),
        ));
    }
    Ok(())
}

fn validate_staged(staged: &StagedInstall) -> Result<(), WindowsInstallPlanError> {
    let target = normalize_windows_target(&staged.target_path)?;
    if target != staged.target_path {
        return Err(WindowsInstallPlanError::Record(
            "staged target is not in canonical drive-path form".to_owned(),
        ));
    }
    validate_derived_path(&target, &staged.stage_path, ".nrm-stage.")?;
    validate_derived_path(&target, &staged.backup_path, ".nrm-backup.")?;
    if staged.stage_path == staged.backup_path {
        return Err(WindowsInstallPlanError::Record(
            "stage and backup paths must be distinct".to_owned(),
        ));
    }
    Ok(())
}

fn validate_derived_path(
    target: &str,
    derived: &str,
    separator: &str,
) -> Result<(), WindowsInstallPlanError> {
    if derived.chars().any(char::is_control) {
        return Err(WindowsInstallPlanError::Record(
            "derived path contains control characters".to_owned(),
        ));
    }
    let prefix = format!("{target}{separator}");
    if derived.len() <= prefix.len() || derived.get(..prefix.len()) != Some(prefix.as_str()) {
        return Err(WindowsInstallPlanError::Record(
            "derived path has the wrong target prefix".to_owned(),
        ));
    }
    let suffix = derived.get(prefix.len()..).ok_or_else(|| {
        WindowsInstallPlanError::Record("derived path has an invalid UTF-8 boundary".to_owned())
    })?;
    let nonce = suffix.strip_suffix(".exe").ok_or_else(|| {
        WindowsInstallPlanError::Record("derived path must end with .exe".to_owned())
    })?;
    if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(WindowsInstallPlanError::Record(
            "derived path has an invalid GUID suffix".to_owned(),
        ));
    }
    if windows_parent(target) != windows_parent(derived) {
        return Err(WindowsInstallPlanError::Record(
            "stage and backup must remain in the target directory".to_owned(),
        ));
    }
    Ok(())
}

fn windows_parent(path: &str) -> &str {
    path.rsplit_once(['\\', '/'])
        .map(|(parent, _)| parent)
        .unwrap_or("")
}

fn validate_absence_hook(hook: &PosixValidationHook) -> Result<(), WindowsInstallPlanError> {
    if hook.mode != ValidationMode::ExpectMissing {
        return Err(WindowsInstallPlanError::Record(
            "absence checks require an expect-missing hook".to_owned(),
        ));
    }
    normalize_windows_target(&hook.executable_path)?;
    Ok(())
}

fn parse_record<'a>(
    stdout: &'a str,
    expected: &str,
    field_count: usize,
) -> Result<Vec<&'a str>, WindowsInstallPlanError> {
    let line = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(stdout);
    if line.contains(['\r', '\n']) {
        return Err(WindowsInstallPlanError::Record(
            "command produced more than one output line".to_owned(),
        ));
    }
    let mut fields = line.split('\t');
    if fields.next() != Some(expected) {
        return Err(WindowsInstallPlanError::Record(format!(
            "expected {expected} record"
        )));
    }
    let fields: Vec<_> = fields.collect();
    if fields.len() != field_count || fields.iter().any(|field| field.is_empty()) {
        return Err(WindowsInstallPlanError::Record(format!(
            "{expected} has the wrong field count"
        )));
    }
    Ok(fields)
}

fn parse_bool(value: &str) -> Result<bool, WindowsInstallPlanError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(WindowsInstallPlanError::Record(
            "boolean field must be 0 or 1".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use serde_json::Value;
    #[cfg(windows)]
    use std::fs::{self, OpenOptions};
    #[cfg(windows)]
    use std::io::{BufRead as _, BufReader, Write as _};
    #[cfg(windows)]
    use std::path::{Path, PathBuf};
    #[cfg(windows)]
    use std::process::{Command, Output, Stdio};

    use super::*;

    const VERSION: &str = "0.1.0";
    const PROTOCOL: u16 = 7;
    const TEST_ARTIFACT_SHA256: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const TEST_PREVIOUS_SHA256: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn plan(target: &str, force: bool) -> WindowsInstallPlan {
        WindowsInstallPlan::new(target, VERSION, PROTOCOL, force).unwrap()
    }

    fn prepared(plan: &WindowsInstallPlan, had_previous: bool) -> PreparedWindowsStage {
        PreparedWindowsStage {
            staged: StagedInstall {
                target_path: plan.target_path().to_owned(),
                stage_path: format!(
                    "{}.nrm-stage.0123456789abcdef0123456789abcdef.exe",
                    plan.target_path()
                ),
                backup_path: format!(
                    "{}.nrm-backup.fedcba9876543210fedcba9876543210.exe",
                    plan.target_path()
                ),
                had_previous,
            },
            previous_sha256: had_previous.then(|| TEST_PREVIOUS_SHA256.to_owned()),
        }
    }

    fn test_stage_script(plan: &WindowsInstallPlan) -> String {
        plan.finalize_stage_script(&prepared(plan, true), 123, TEST_ARTIFACT_SHA256)
    }

    fn decode_command(command: &str) -> String {
        let encoded = command.split_whitespace().last().unwrap();
        let bytes = STANDARD.decode(encoded).unwrap();
        let utf16: Vec<_> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&utf16).unwrap()
    }

    fn payload(script: &str) -> Value {
        let marker = "FromBase64String('";
        let start = script.find(marker).unwrap() + marker.len();
        let end = script[start..].find("')").unwrap() + start;
        serde_json::from_slice(&STANDARD.decode(&script[start..end]).unwrap()).unwrap()
    }

    fn staged(previous: bool) -> StagedInstall {
        StagedInstall {
            target_path: r"C:\Users\me\AppData\Local\nrm\bin\nrm-agent.exe".to_owned(),
            stage_path: r"C:\Users\me\AppData\Local\nrm\bin\nrm-agent.exe.nrm-stage.0123456789abcdef0123456789abcdef.exe".to_owned(),
            backup_path: r"C:\Users\me\AppData\Local\nrm\bin\nrm-agent.exe.nrm-backup.fedcba9876543210fedcba9876543210.exe".to_owned(),
            had_previous: previous,
        }
    }

    #[test]
    fn stage_uses_hashed_scp_path_without_interpolation() {
        let target = r"C:\Users\me\Agent ' ; $(Write-Output owned)\nrm-agent.exe";
        let plan = plan(target, true);
        let script = test_stage_script(&plan);
        assert!(!script.contains(target));
        assert!(!script.contains("OpenStandardInput"));
        assert!(script.contains("uploaded artifact is not a regular file"));
        assert!(script.contains("target contents changed after staging was prepared"));
        assert!(script.contains("RedirectStandardOutput = $true"));
        assert!(script.contains("Test-BytesEqual"));
        let finalize_payload = payload(&script);
        assert_eq!(finalize_payload["target"], target);
        assert_eq!(
            finalize_payload["stage"],
            prepared(&plan, true).staged.stage_path
        );
        assert_eq!(
            finalize_payload["backup"],
            prepared(&plan, true).staged.backup_path
        );
        assert_eq!(finalize_payload["had_previous"], true);
        assert_eq!(finalize_payload["previous_sha256"], TEST_PREVIOUS_SHA256);
        assert_eq!(finalize_payload["expected_version"], VERSION);
        assert_eq!(finalize_payload["expected_size"], 123);
        assert_eq!(finalize_payload["expected_sha256"], TEST_ARTIFACT_SHA256);

        let prepare = plan.prepare_stage_script();
        assert!(!prepare.contains(target));
        assert!(prepare.contains("[System.IO.FileMode]::CreateNew"));
        assert!(prepare.contains("Test-RegularFile"));
        let prepare_payload = payload(&prepare);
        assert_eq!(prepare_payload["target"], target);
        assert_eq!(prepare_payload["force"], true);

        let upload_command = plan.action_script_upload_command();
        let upload_script = decode_command(&upload_command);
        assert!(upload_script.contains("[Console]::OpenStandardInput().CopyToAsync($stream)"));
        assert!(upload_script.contains("NRM_INSTALL_ACTION_SCRIPT_V1"));
        assert!(upload_command.len() < MAX_OPENSSH_CMD_COMMAND_CHARS);

        let digest = Sha256::digest(script.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let helper = r"C:\Users\me\AppData\Local\Temp\nrm-agent-install.0123456789abcdef0123456789abcdef.ps1";
        let record = format!(
            "{ACTION_SCRIPT_RECORD}\t{helper}\t{}\t{digest}\r\n",
            script.len()
        );
        assert_eq!(
            plan.parse_action_script_upload_stdout(&script, &record)
                .unwrap(),
            helper
        );
        let run_command = plan.action_script_run_command(helper, &script);
        assert!(!run_command.contains(target));
        assert!(run_command.len() < MAX_OPENSSH_CMD_COMMAND_CHARS);
    }

    #[test]
    fn rejects_unsafe_or_non_executable_windows_targets() {
        for target in [
            "",
            r"relative\nrm-agent.exe",
            r"C:nrm-agent.exe",
            r"\\server\share\nrm-agent.exe",
            r"\\?\C:\nrm-agent.exe",
            r"C:\repo\..\nrm-agent.exe",
            r"C:\repo.\nrm-agent.exe",
            r"C:\repo\agent:stream.exe",
            r"C:\repo\CON.exe",
            "C:\\repo\\COM¹.exe",
            "C:\\repo\\LPT³.txt.exe",
            r"C:\repo\nrm-agent",
            "C:\\repo\\nrm-agent.exe\nother",
        ] {
            assert!(
                WindowsInstallPlan::new(target, VERSION, PROTOCOL, false).is_err(),
                "accepted {target:?}"
            );
        }
    }

    #[test]
    fn normalizes_drive_and_separator_style() {
        let plan = plan("c:/Users/me/nrm-agent.exe", false);
        assert_eq!(plan.target_path(), r"C:\Users\me\nrm-agent.exe");
    }

    #[test]
    fn parses_strict_same_directory_stage_records() {
        let forced_plan = plan(r"C:\nrm\nrm-agent.exe", true);
        let prepared_record = concat!(
            "NRM_INSTALL_STAGE_PREPARED_V1\tC:\\nrm\\nrm-agent.exe\t",
            "C:\\nrm\\nrm-agent.exe.nrm-stage.0123456789abcdef0123456789abcdef.exe\t",
            "C:\\nrm\\nrm-agent.exe.nrm-backup.fedcba9876543210fedcba9876543210.exe\t1\t",
            "1111111111111111111111111111111111111111111111111111111111111111\r\n"
        );
        let prepared = forced_plan
            .parse_prepare_stage_stdout(prepared_record)
            .unwrap();
        assert!(prepared.staged.had_previous);
        assert_eq!(
            prepared.previous_sha256.as_deref(),
            Some(TEST_PREVIOUS_SHA256)
        );

        let record = concat!(
            "NRM_INSTALL_STAGE_V1\tC:\\nrm\\nrm-agent.exe\t",
            "C:\\nrm\\nrm-agent.exe.nrm-stage.0123456789abcdef0123456789abcdef.exe\t",
            "C:\\nrm\\nrm-agent.exe.nrm-backup.fedcba9876543210fedcba9876543210.exe\t1\r\n"
        );
        let staged = forced_plan.parse_stage_stdout(record).unwrap();
        assert!(staged.had_previous);
        assert_eq!(
            forced_plan
                .staged_validation(&staged)
                .expected_protocol_version,
            Some(PROTOCOL)
        );

        for invalid in [
            "",
            "noise\nNRM_INSTALL_STAGE_V1\tC:\\nrm\\nrm-agent.exe\tx\ty\t1",
            concat!(
                "NRM_INSTALL_STAGE_V1\tC:\\nrm\\nrm-agent.exe\t",
                "D:\\nrm\\nrm-agent.exe.nrm-stage.0123456789abcdef0123456789abcdef.exe\t",
                "C:\\nrm\\nrm-agent.exe.nrm-backup.fedcba9876543210fedcba9876543210.exe\t1"
            ),
        ] {
            assert!(
                forced_plan.parse_stage_stdout(invalid).is_err(),
                "{invalid:?}"
            );
        }

        let no_force = plan(r"C:\nrm\nrm-agent.exe", false);
        assert!(no_force
            .parse_prepare_stage_stdout(prepared_record)
            .is_err());
        assert!(forced_plan
            .parse_prepare_stage_stdout(&prepared_record.replace(
                TEST_PREVIOUS_SHA256,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ))
            .is_err());
        assert!(no_force.parse_stage_stdout(record).is_err());
        assert!(forced_plan
            .parse_stage_stdout(&format!("{record}\r\n"))
            .is_err());
        assert!(forced_plan
            .parse_stage_stdout(&format!("{}\t\r\n", record.trim_end()))
            .is_err());
    }

    #[test]
    fn emitted_bootstrap_commands_fit_default_windows_openssh_cmd_limit() {
        let filename = "nrm-agent.exe";
        let target = format!(
            "C:\\{}{}",
            "a".repeat(MAX_WINDOWS_TARGET_UTF16 - 3 - filename.len()),
            filename
        );
        assert_eq!(target.encode_utf16().count(), MAX_WINDOWS_TARGET_UTF16);
        let plan = plan(&target, true);
        assert_eq!(
            format!("{}.state", prepared(&plan, true).staged.backup_path)
                .encode_utf16()
                .count(),
            259
        );
        let helper_name = "nrm-agent-install.0123456789abcdef0123456789abcdef.ps1";
        let helper = format!(
            "C:\\{}\\{helper_name}",
            "h".repeat(260 - 3 - 1 - helper_name.len())
        );
        assert_eq!(helper.encode_utf16().count(), 260);

        let prepared = prepared(&plan, true);
        let scripts = [
            plan.prepare_stage_script(),
            test_stage_script(&plan),
            plan.abort_stage_script(&prepared),
        ];
        let mut commands = vec![
            plan.action_script_upload_command(),
            plan.action_script_cleanup_command(&helper),
        ];
        commands.extend(
            scripts
                .iter()
                .map(|script| plan.action_script_run_command(&helper, script)),
        );
        for command in commands {
            assert!(
                command.len() < MAX_OPENSSH_CMD_COMMAND_CHARS,
                "encoded bootstrap exceeded cmd.exe's limit: {} characters",
                command.len()
            );
        }
    }

    #[test]
    fn record_validation_is_exact_and_never_slices_untrusted_utf8() {
        let target = r"C:\Équipe\nrm-agent.exe";
        let plan = plan(target, true);
        let wrong_case = concat!(
            "NRM_INSTALL_STAGE_V1\tC:\\équipe\\nrm-agent.exe\t",
            "C:\\équipe\\nrm-agent.exe.nrm-stage.0123456789abcdef0123456789abcdef.exe\t",
            "C:\\équipe\\nrm-agent.exe.nrm-backup.fedcba9876543210fedcba9876543210.exe\t0"
        );
        assert!(plan.parse_stage_stdout(wrong_case).is_err());

        let prefix_len = format!("{target}.nrm-stage.").len();
        let mut invalid_boundary = "x".repeat(prefix_len - 1);
        invalid_boundary.push('é');
        invalid_boundary.push_str(".exe");
        assert!(validate_derived_path(target, &invalid_boundary, ".nrm-stage.").is_err());
    }

    #[test]
    fn activation_uses_windows_replacement_and_native_lock_codes() {
        let plan = plan(&staged(true).target_path, true);
        let script = plan.activate_script(&staged(true));
        assert!(script.contains("[System.IO.File]::Replace($stage, $target, $backup, $true)"));
        assert!(script.contains("[System.IO.File]::Move($stage, $target)"));
        assert!(script.contains("$Code -eq 32 -or $Code -eq 33 -or $Code -eq 1224"));
        assert!(script.contains("'process_in_use' 42"));
        assert!(script.contains("target contents changed after staging"));
        let payload = payload(&script);
        assert_eq!(payload["had_previous"], true);
        assert_eq!(payload["force"], true);
    }

    #[test]
    fn reconciliation_rollback_and_absence_hooks_are_strict() {
        let staged = staged(true);
        let plan = plan(&staged.target_path, true);
        let reconcile = plan.reconcile_activation_script(&staged);
        assert!(reconcile.contains("File]::Replace($backup, $target, $stage, $true)"));
        assert!(reconcile.contains("Remove-InstallFile $stage"));
        assert!(reconcile.contains("'rollback_failed' 50"));
        assert!(reconcile.contains("prior-agent backup changed before reconciliation"));
        assert!(reconcile.contains("activated target changed before reconciliation"));
        assert!(reconcile.contains("prior target disappeared before reconciliation"));
        assert!(reconcile.contains("prior target changed before reconciliation"));
        assert!(reconcile.contains(
            "if (-not $targetExists) {\n        Fail 'rollback_failed' 50 'prior target disappeared before reconciliation'\n      }\n      if ((Get-FileHashHex $target) -ne $state[1])"
        ));
        assert!(
            reconcile.find("Get-FileHashHex $backup").unwrap()
                < reconcile.find("Remove-InstallFile $stage").unwrap()
        );
        assert!(
            reconcile
                .find("activated target changed before reconciliation")
                .unwrap()
                < reconcile
                    .find("File]::Replace($backup, $target, $stage, $true)")
                    .unwrap()
        );

        let activated = ActivatedInstall {
            staged: staged.clone(),
            had_previous: true,
        };
        let rollback = plan.rollback_script(&activated);
        assert!(rollback.contains("File]::Replace($backup, $target, $stage, $true)"));
        assert!(rollback.contains("staging path was unexpectedly recreated"));
        let outcome = plan
            .parse_rollback_stdout(
                &activated,
                &format!("NRM_INSTALL_ROLLED_BACK_V1\t{}\t1", staged.target_path),
            )
            .unwrap();
        assert_eq!(
            plan.rollback_validation(&outcome).mode,
            ValidationMode::Reprobe
        );

        let missing = RollbackOutcome {
            target_path: staged.target_path.clone(),
            restored_previous: false,
        };
        let hook = plan.rollback_validation(&missing);
        assert_eq!(hook.mode, ValidationMode::ExpectMissing);
        let absence = plan.absence_check_script(&hook).unwrap();
        assert!(absence.contains("NRM_INSTALL_ABSENT_V1"));
        plan.parse_absence_check_stdout(
            &hook,
            &format!("NRM_INSTALL_ABSENT_V1\t{}", staged.target_path),
        )
        .unwrap();

        let impossible = format!(
            "NRM_INSTALL_RECONCILED_V1\t{}\tremoved_candidate",
            staged.target_path
        );
        assert!(plan
            .parse_reconciliation_stdout(&staged, &impossible)
            .is_err());
    }

    #[test]
    fn rejects_activation_records_that_change_prior_state() {
        let staged = staged(true);
        let plan = plan(&staged.target_path, true);
        let record = format!(
            "NRM_INSTALL_ACTIVATED_V1\t{}\t{}\t0",
            staged.target_path, staged.backup_path
        );
        assert!(plan.parse_activation_stdout(&staged, &record).is_err());
    }

    #[cfg(windows)]
    fn encoded_process(command: &str) -> Command {
        let encoded = command
            .split_whitespace()
            .last()
            .expect("encoded PowerShell command");
        let mut process = Command::new("powershell.exe");
        process.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ]);
        process
    }

    #[cfg(windows)]
    fn run_script(command: &str, input: Option<&[u8]>) -> Output {
        let mut process = encoded_process(command);
        if let Some(input) = input {
            let mut child = process
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            return child.wait_with_output().unwrap();
        } else {
            process.stdin(Stdio::null());
        }
        process.output().unwrap()
    }

    #[cfg(windows)]
    fn run_streamed_action(
        plan: &WindowsInstallPlan,
        script: &str,
        input: Option<&[u8]>,
    ) -> Output {
        let upload = run_script(
            &plan.action_script_upload_command(),
            Some(script.as_bytes()),
        );
        let (stdout, stderr) = output_text(&upload);
        assert!(upload.status.success(), "script upload failed: {stderr}");
        let helper = plan
            .parse_action_script_upload_stdout(script, stdout)
            .unwrap();
        let output = run_script(&plan.action_script_run_command(&helper, script), input);
        let cleanup = run_script(&plan.action_script_cleanup_command(&helper), None);
        let (stdout, stderr) = output_text(&cleanup);
        assert!(cleanup.status.success(), "script cleanup failed: {stderr}");
        plan.parse_action_script_cleanup_stdout(&helper, stdout)
            .unwrap();
        output
    }

    #[cfg(windows)]
    fn run_candidate_stage(plan: &WindowsInstallPlan, candidate: &[u8]) -> Output {
        let prepare = run_streamed_action(plan, &plan.prepare_stage_script(), None);
        let (stdout, stderr) = output_text(&prepare);
        assert!(
            prepare.status.success(),
            "stage preparation failed: {stderr}"
        );
        let prepared = plan.parse_prepare_stage_stdout(stdout).unwrap();
        fs::write(&prepared.staged.stage_path, candidate).unwrap();
        run_streamed_action(
            plan,
            &plan.finalize_stage_script(&prepared, candidate.len() as u64, &sha256_hex(candidate)),
            None,
        )
    }

    #[cfg(windows)]
    fn output_text(output: &Output) -> (&str, &str) {
        (
            std::str::from_utf8(&output.stdout).unwrap(),
            std::str::from_utf8(&output.stderr).unwrap(),
        )
    }

    #[cfg(windows)]
    fn build_version_candidate(directory: &Path) -> PathBuf {
        let source = directory.join("candidate.rs");
        let executable = directory.join("candidate.exe");
        fs::write(
            &source,
            format!(
                "fn main() {{ if std::env::args().nth(1).as_deref() == Some(\"--version\") {{ print!(\"nrm-agent {}\\n\"); }} else {{ std::process::exit(2); }} }}",
                env!("CARGO_PKG_VERSION")
            ),
        )
        .unwrap();
        let output = Command::new("rustc")
            .args(["--edition=2021", "-o"])
            .arg(&executable)
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "rustc failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        OpenOptions::new()
            .append(true)
            .open(&executable)
            .unwrap()
            .write_all(&[0, b'\r', b'\n', 0x1a, 0xff, 0])
            .unwrap();
        executable
    }

    #[cfg(windows)]
    fn lock_file_exclusively(path: &Path) -> std::process::Child {
        let path = STANDARD.encode(path.to_str().unwrap().as_bytes());
        let script = format!(
            r#"$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{path}'))
$stream = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
try {{ [Console]::Out.WriteLine('READY'); [Console]::Out.Flush(); [void][Console]::In.ReadLine() }} finally {{ $stream.Dispose() }}"#
        );
        let command = powershell_encoded_command(&script);
        let mut process = encoded_process(&command);
        let mut child = process
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready, "READY\r\n");
        child
    }

    #[cfg(windows)]
    #[test]
    fn native_powershell_transaction_handles_locking_rollback_and_new_install() {
        use crate::agent_install::{classify_install_failure, InstallFailureKind};

        let directory = tempfile::tempdir().unwrap();
        let candidate = build_version_candidate(directory.path());
        let candidate_bytes = fs::read(&candidate).unwrap();
        let target = directory.path().join("nrm-agent.exe");
        let previous_bytes = b"previous remote agent";
        fs::write(&target, previous_bytes).unwrap();
        let target = target.to_str().unwrap();
        let plan =
            WindowsInstallPlan::new(target, env!("CARGO_PKG_VERSION"), PROTOCOL, true).unwrap();

        let staged_output = run_candidate_stage(&plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let staged = plan.parse_stage_stdout(stdout).unwrap();
        assert!(staged.had_previous);

        let mut locker = lock_file_exclusively(Path::new(target));
        let activation_output = run_streamed_action(&plan, &plan.activate_script(&staged), None);
        let (_, stderr) = output_text(&activation_output);
        assert!(!activation_output.status.success());
        assert_eq!(
            classify_install_failure(activation_output.status.code(), stderr).kind,
            InstallFailureKind::ProcessInUse
        );
        drop(locker.stdin.take());
        assert!(locker.wait().unwrap().success());

        let reconciliation_output =
            run_streamed_action(&plan, &plan.reconcile_activation_script(&staged), None);
        let (stdout, stderr) = output_text(&reconciliation_output);
        assert!(
            reconciliation_output.status.success(),
            "reconciliation failed: {stderr}"
        );
        let recovery = plan.parse_reconciliation_stdout(&staged, stdout).unwrap();
        assert_eq!(
            recovery.kind,
            ActivationRecoveryKind::ActivationUnchangedPresent
        );
        assert_eq!(fs::read(target).unwrap(), previous_bytes);

        let staged_output = run_candidate_stage(&plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let concurrent = plan.parse_stage_stdout(stdout).unwrap();
        let external_bytes = b"concurrent external replacement";
        fs::write(target, external_bytes).unwrap();
        let activation_output =
            run_streamed_action(&plan, &plan.activate_script(&concurrent), None);
        let (_, stderr) = output_text(&activation_output);
        assert!(!activation_output.status.success());
        assert_eq!(
            classify_install_failure(activation_output.status.code(), stderr).kind,
            InstallFailureKind::InvalidState
        );
        let reconciliation_output =
            run_streamed_action(&plan, &plan.reconcile_activation_script(&concurrent), None);
        let (_, stderr) = output_text(&reconciliation_output);
        assert!(!reconciliation_output.status.success());
        assert_eq!(
            classify_install_failure(reconciliation_output.status.code(), stderr).kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(fs::read(target).unwrap(), external_bytes);
        assert_eq!(fs::read(&concurrent.stage_path).unwrap(), candidate_bytes);
        assert!(!Path::new(&concurrent.backup_path).exists());
        let concurrent_state = format!("{}.state", concurrent.backup_path);
        assert!(Path::new(&concurrent_state).exists());
        fs::remove_file(&concurrent.stage_path).unwrap();
        fs::remove_file(concurrent_state).unwrap();
        fs::write(target, previous_bytes).unwrap();

        let staged_output = run_candidate_stage(&plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let partial = plan.parse_stage_stdout(stdout).unwrap();
        fs::rename(target, &partial.backup_path).unwrap();
        let reconciliation_output =
            run_streamed_action(&plan, &plan.reconcile_activation_script(&partial), None);
        let (stdout, stderr) = output_text(&reconciliation_output);
        assert!(
            reconciliation_output.status.success(),
            "partial-state reconciliation failed: {stderr}"
        );
        let recovery = plan.parse_reconciliation_stdout(&partial, stdout).unwrap();
        assert_eq!(recovery.kind, ActivationRecoveryKind::RestoredPrevious);
        assert_eq!(fs::read(target).unwrap(), previous_bytes);
        assert!(!Path::new(&partial.stage_path).exists());
        assert!(!Path::new(&partial.backup_path).exists());

        let staged_output = run_candidate_stage(&plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let staged = plan.parse_stage_stdout(stdout).unwrap();
        let activation_output = run_streamed_action(&plan, &plan.activate_script(&staged), None);
        let (stdout, stderr) = output_text(&activation_output);
        assert!(
            activation_output.status.success(),
            "activation failed: {stderr}"
        );
        let activated = plan.parse_activation_stdout(&staged, stdout).unwrap();
        assert_eq!(fs::read(target).unwrap(), candidate_bytes);
        let rollback_output = run_streamed_action(&plan, &plan.rollback_script(&activated), None);
        let (stdout, stderr) = output_text(&rollback_output);
        assert!(
            rollback_output.status.success(),
            "rollback failed: {stderr}"
        );
        plan.parse_rollback_stdout(&activated, stdout).unwrap();
        assert_eq!(fs::read(target).unwrap(), previous_bytes);
        assert!(!Path::new(&staged.stage_path).exists());
        assert!(!Path::new(&staged.backup_path).exists());

        let new_target = directory.path().join("new-agent.exe");
        let new_plan = WindowsInstallPlan::new(
            new_target.to_str().unwrap(),
            env!("CARGO_PKG_VERSION"),
            PROTOCOL,
            false,
        )
        .unwrap();
        let staged_output = run_candidate_stage(&new_plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let staged = new_plan.parse_stage_stdout(stdout).unwrap();
        assert!(!staged.had_previous);
        let activation_output =
            run_streamed_action(&new_plan, &new_plan.activate_script(&staged), None);
        let (stdout, stderr) = output_text(&activation_output);
        assert!(
            activation_output.status.success(),
            "activation failed: {stderr}"
        );
        let activated = new_plan.parse_activation_stdout(&staged, stdout).unwrap();
        let cleanup_output =
            run_streamed_action(&new_plan, &new_plan.cleanup_script(&staged), None);
        let (stdout, stderr) = output_text(&cleanup_output);
        assert!(cleanup_output.status.success(), "cleanup failed: {stderr}");
        new_plan.parse_cleanup_stdout(&staged, stdout).unwrap();
        assert_eq!(fs::read(&new_target).unwrap(), candidate_bytes);
        assert!(!activated.had_previous);

        let broken_target = directory.path().join("broken-rollback-agent.exe");
        fs::write(&broken_target, previous_bytes).unwrap();
        let broken_plan = WindowsInstallPlan::new(
            broken_target.to_str().unwrap(),
            env!("CARGO_PKG_VERSION"),
            PROTOCOL,
            true,
        )
        .unwrap();
        let staged_output = run_candidate_stage(&broken_plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let staged = broken_plan.parse_stage_stdout(stdout).unwrap();
        let activation_output =
            run_streamed_action(&broken_plan, &broken_plan.activate_script(&staged), None);
        let (stdout, stderr) = output_text(&activation_output);
        assert!(
            activation_output.status.success(),
            "activation failed: {stderr}"
        );
        let activated = broken_plan
            .parse_activation_stdout(&staged, stdout)
            .unwrap();
        fs::remove_file(&activated.staged.backup_path).unwrap();
        let rollback_output =
            run_streamed_action(&broken_plan, &broken_plan.rollback_script(&activated), None);
        let (_, stderr) = output_text(&rollback_output);
        assert!(!rollback_output.status.success());
        assert_eq!(
            classify_install_failure(rollback_output.status.code(), stderr).kind,
            InstallFailureKind::RollbackFailed
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_reconciliation_preserves_changed_backup_and_target_artifacts() {
        use crate::agent_install::{classify_install_failure, InstallFailureKind};

        let directory = tempfile::tempdir().unwrap();
        let candidate = build_version_candidate(directory.path());
        let candidate_bytes = fs::read(&candidate).unwrap();
        let previous_bytes = b"previous remote agent";
        let target = directory.path().join("integrity-agent.exe");
        fs::write(&target, previous_bytes).unwrap();
        let target = target.to_str().unwrap();
        let plan =
            WindowsInstallPlan::new(target, env!("CARGO_PKG_VERSION"), PROTOCOL, true).unwrap();

        let staged_output = run_candidate_stage(&plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let corrupt_backup = plan.parse_stage_stdout(stdout).unwrap();
        let activation_output =
            run_streamed_action(&plan, &plan.activate_script(&corrupt_backup), None);
        let (stdout, stderr) = output_text(&activation_output);
        assert!(
            activation_output.status.success(),
            "activation failed: {stderr}"
        );
        plan.parse_activation_stdout(&corrupt_backup, stdout)
            .unwrap();

        let corrupt_backup_bytes = b"corrupt prior-agent backup";
        fs::write(&corrupt_backup.backup_path, corrupt_backup_bytes).unwrap();
        let reconciliation_output = run_streamed_action(
            &plan,
            &plan.reconcile_activation_script(&corrupt_backup),
            None,
        );
        let (_, stderr) = output_text(&reconciliation_output);
        assert!(!reconciliation_output.status.success());
        assert_eq!(
            classify_install_failure(reconciliation_output.status.code(), stderr).kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(fs::read(target).unwrap(), candidate_bytes);
        assert_eq!(
            fs::read(&corrupt_backup.backup_path).unwrap(),
            corrupt_backup_bytes
        );
        let corrupt_backup_state = format!("{}.state", corrupt_backup.backup_path);
        assert!(Path::new(&corrupt_backup_state).exists());
        assert!(!Path::new(&corrupt_backup.stage_path).exists());

        fs::remove_file(target).unwrap();
        fs::remove_file(&corrupt_backup.backup_path).unwrap();
        fs::remove_file(corrupt_backup_state).unwrap();
        fs::write(target, previous_bytes).unwrap();

        let staged_output = run_candidate_stage(&plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let changed_target = plan.parse_stage_stdout(stdout).unwrap();
        let activation_output =
            run_streamed_action(&plan, &plan.activate_script(&changed_target), None);
        let (stdout, stderr) = output_text(&activation_output);
        assert!(
            activation_output.status.success(),
            "activation failed: {stderr}"
        );
        plan.parse_activation_stdout(&changed_target, stdout)
            .unwrap();

        let external_target_bytes = b"concurrent external replacement";
        fs::write(target, external_target_bytes).unwrap();
        let reconciliation_output = run_streamed_action(
            &plan,
            &plan.reconcile_activation_script(&changed_target),
            None,
        );
        let (_, stderr) = output_text(&reconciliation_output);
        assert!(!reconciliation_output.status.success());
        assert_eq!(
            classify_install_failure(reconciliation_output.status.code(), stderr).kind,
            InstallFailureKind::RollbackFailed
        );
        assert_eq!(fs::read(target).unwrap(), external_target_bytes);
        assert_eq!(
            fs::read(&changed_target.backup_path).unwrap(),
            previous_bytes
        );
        let changed_target_state = format!("{}.state", changed_target.backup_path);
        assert!(Path::new(&changed_target_state).exists());
        assert!(!Path::new(&changed_target.stage_path).exists());
    }

    #[cfg(windows)]
    #[test]
    fn native_reconciliation_preserves_stage_when_prior_target_disappears() {
        use crate::agent_install::{classify_install_failure, InstallFailureKind};

        let directory = tempfile::tempdir().unwrap();
        let candidate = build_version_candidate(directory.path());
        let candidate_bytes = fs::read(&candidate).unwrap();
        let target = directory.path().join("missing-prior-agent.exe");
        fs::write(&target, b"previous remote agent").unwrap();
        let target = target.to_str().unwrap();
        let plan =
            WindowsInstallPlan::new(target, env!("CARGO_PKG_VERSION"), PROTOCOL, true).unwrap();

        let staged_output = run_candidate_stage(&plan, &candidate_bytes);
        let (stdout, stderr) = output_text(&staged_output);
        assert!(staged_output.status.success(), "stage failed: {stderr}");
        let staged = plan.parse_stage_stdout(stdout).unwrap();
        let state_path = format!("{}.state", staged.backup_path);
        fs::remove_file(target).unwrap();

        let reconciliation_output =
            run_streamed_action(&plan, &plan.reconcile_activation_script(&staged), None);
        let (_, stderr) = output_text(&reconciliation_output);
        assert!(!reconciliation_output.status.success());
        assert_eq!(
            classify_install_failure(reconciliation_output.status.code(), stderr).kind,
            InstallFailureKind::RollbackFailed
        );
        assert!(stderr.contains("prior target disappeared before reconciliation"));
        assert!(!Path::new(target).exists());
        assert_eq!(fs::read(&staged.stage_path).unwrap(), candidate_bytes);
        assert!(!Path::new(&staged.backup_path).exists());
        assert!(Path::new(&state_path).exists());
    }
}
