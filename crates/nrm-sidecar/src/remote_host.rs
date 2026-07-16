use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::Path;

const PROBE_SCHEMA_VERSION: u8 = 1;
const WINDOWS_REMOTE_COMMAND_MAX_CHARS: usize = 8_191;
const POWERSHELL_BOOTSTRAP_MAGIC: [u8; 4] = *b"NRM1";
const POWERSHELL_BOOTSTRAP_MAX_BYTES: usize = 64 * 1024;
const REMOTE_HOST_PATH_MAX_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RemotePathStyle {
    Posix,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteHostInfo {
    pub(crate) os: String,
    pub(crate) arch: String,
    pub(crate) shell: String,
    pub(crate) home: String,
    pub(crate) local_app_data: Option<String>,
    pub(crate) path_style: RemotePathStyle,
    pub(crate) target: String,
}

pub(crate) fn validate_remote_host_info(info: &RemoteHostInfo) -> Result<()> {
    let expected_style = if info.os == "windows" {
        RemotePathStyle::Windows
    } else {
        RemotePathStyle::Posix
    };
    if info.path_style != expected_style {
        bail!("remote host path style does not match its operating system");
    }
    if (info.path_style == RemotePathStyle::Windows) != info.local_app_data.is_some() {
        bail!("remote host local app-data metadata does not match its platform");
    }
    if info.shell.is_empty() || info.shell.chars().any(char::is_control) {
        bail!("remote host shell must not be empty or contain control characters");
    }
    if info.path_style == RemotePathStyle::Windows && info.shell != "powershell" {
        bail!("Windows remote host must use the PowerShell planner");
    }
    match info.path_style {
        RemotePathStyle::Posix => {
            validate_canonical_posix_path("remote host home", &info.home)?;
            validate_canonical_posix_executable("remote host shell", &info.shell)?;
        }
        RemotePathStyle::Windows => {
            validate_canonical_windows_path("remote host home", &info.home)?;
            validate_canonical_windows_path(
                "remote host local app-data",
                info.local_app_data
                    .as_deref()
                    .ok_or_else(|| anyhow!("Windows remote host has no local app-data path"))?,
            )?;
        }
    }
    let rebuilt = build_host_info(
        &info.os,
        &info.arch,
        &info.shell,
        info.home.clone(),
        info.local_app_data.clone(),
        info.path_style,
    )?;
    if rebuilt != *info {
        bail!("remote host metadata is not canonical");
    }
    Ok(())
}

fn validate_canonical_posix_path(name: &str, value: &str) -> Result<()> {
    reject_field_controls(name, value)?;
    if value.len() > REMOTE_HOST_PATH_MAX_BYTES || !value.starts_with('/') {
        bail!("{name} must be a bounded absolute POSIX path");
    }
    if value != "/" && value.ends_with('/') {
        bail!("{name} must not have a trailing separator");
    }
    if value.len() > 1
        && value[1..]
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("{name} must be a canonical POSIX path");
    }
    Ok(())
}

pub(crate) fn validate_canonical_posix_executable(name: &str, value: &str) -> Result<()> {
    validate_canonical_posix_path(name, value)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'-')
    }) {
        bail!("{name} contains characters outside the safe executable-path set");
    }
    Ok(())
}

pub(crate) fn validate_canonical_windows_path(name: &str, value: &str) -> Result<()> {
    reject_field_controls(name, value)?;
    if value.len() > REMOTE_HOST_PATH_MAX_BYTES || value.len() < 3 {
        bail!("{name} must be a bounded absolute Windows path");
    }
    let bytes = value.as_bytes();
    let separator = bytes[2];
    if !bytes[0].is_ascii_uppercase()
        || bytes[1] != b':'
        || !matches!(separator, b'/' | b'\\')
        || value.starts_with("//")
        || value.starts_with("\\\\")
    {
        bail!("{name} must use an absolute local drive root");
    }
    let other_separator = if separator == b'/' { '\\' } else { '/' };
    if value.contains(other_separator) {
        bail!("{name} must use one canonical separator style");
    }
    if value.len() > 3 && value.ends_with(separator as char) {
        bail!("{name} must not have a trailing separator");
    }
    if value.len() > 3
        && value[3..]
            .split(separator as char)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("{name} must be a canonical Windows path");
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerShellProbe {
    schema_version: u8,
    os: String,
    arch: String,
    shell: String,
    home: String,
    local_app_data: String,
    path_style: String,
}

#[derive(Serialize)]
struct ProcessPayload<'a> {
    program: &'a str,
    arguments: &'a [String],
    command_line: String,
    cwd: Option<&'a str>,
    path_prepend: Option<&'a str>,
    agent_launch_diagnostics: bool,
    agent_root: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PowerShellProcessCommand {
    pub(crate) command: String,
    pub(crate) stdin_prefix: Vec<u8>,
}

// Keep this source synchronized with `POWERSHELL_PROCESS_SCRIPT_GZIP_BASE64`. The
// compressed form keeps the UTF-16LE `-EncodedCommand` below Windows' command-line
// limit while retaining an auditable, fixed script with no user interpolation.
#[cfg(test)]
pub(crate) const POWERSHELL_PROCESS_SCRIPT_SOURCE: &str = r#"param([byte[]]$payloadBytes)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$jobMethods = @'
private const uint CREATE_SUSPENDED = 4;
private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
private const uint CREATE_NO_WINDOW = 0x08000000;
private const uint STARTF_USESTDHANDLES = 0x100;
private const uint HANDLE_FLAG_INHERIT = 1;
private const uint WAIT_OBJECT_0 = 0;
private const uint WAIT_TIMEOUT = 0x102;
private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
private static readonly IntPtr PROC_THREAD_ATTRIBUTE_JOB_LIST = new IntPtr(0x0002000D);

[StructLayout(LayoutKind.Sequential)]
private struct PROCESS_INFORMATION
{
    public IntPtr Process;
    public IntPtr Thread;
    public uint ProcessId;
    public uint ThreadId;
}

[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern IntPtr CreateJobObject(IntPtr attributes, string name);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetInformationJobObject(IntPtr job, int informationClass, byte[] information, uint informationLength);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr handle);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);
[DllImport("kernel32.dll")]
private static extern void DeleteProcThreadAttributeList(IntPtr list);
[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
private static extern bool CreateProcess(
    string applicationName,
    System.Text.StringBuilder commandLine,
    IntPtr processAttributes,
    IntPtr threadAttributes,
    bool inheritHandles,
    uint creationFlags,
    IntPtr environment,
    string currentDirectory,
    IntPtr startupInfo,
    out PROCESS_INFORMATION information);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern uint ResumeThread(IntPtr thread);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool TerminateProcess(IntPtr process, uint exitCode);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern IntPtr GetStdHandle(int standardHandle);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool ReadFile(IntPtr file, byte[] buffer, uint requested, out uint read, IntPtr overlapped);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool WriteFile(IntPtr file, byte[] buffer, uint requested, out uint written, IntPtr overlapped);
[DllImport("kernel32.dll", SetLastError=true)]
private static extern bool FlushFileBuffers(IntPtr file);

private static Exception Error(string operation)
{
    return new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), operation);
}

private static void Close(ref IntPtr handle)
{
    if (handle != IntPtr.Zero)
    {
        CloseHandle(handle);
        handle = IntPtr.Zero;
    }
}

private sealed class RelayState
{
    public IntPtr Process;
    public readonly object Gate = new object();
    public Exception Failure;
    public bool Exited;

    public void Fail(Exception error)
    {
        bool terminate = false;
        lock (Gate)
        {
            if (Failure == null)
                Failure = error;
            if (!Exited)
                terminate = true;
        }
        if (terminate)
            TerminateProcess(Process, 1);
    }

    public void FailInput(Exception error)
    {
        bool terminate = false;
        lock (Gate)
        {
            if (Exited)
                return;
            if (Failure == null)
                Failure = error;
            terminate = true;
        }
        if (terminate)
            TerminateProcess(Process, 1);
    }
}

private static void WriteStandard(IntPtr destination, byte[] buffer, uint count)
{
    uint written;
    if (!WriteFile(destination, buffer, count, out written, IntPtr.Zero))
        throw Error("standard stream write failed");
    if (written != count)
        throw new System.IO.IOException("standard stream write was incomplete");
    if (!FlushFileBuffers(destination))
        throw Error("standard stream flush failed");
}

private static void WriteLaunchReady()
{
    byte[] record = System.Text.Encoding.ASCII.GetBytes(
        "NRM_AGENT_LAUNCH_V1\tREADY\n");
    WriteStandard(GetStdHandle(-11), record, (uint)record.Length);
}

private static void WriteLaunchFailure(string kind)
{
    byte[] record = System.Text.Encoding.ASCII.GetBytes(
        "NRM_AGENT_LAUNCH_V1\tFAILURE\t" + kind + "\n");
    WriteStandard(GetStdHandle(-11), record, (uint)record.Length);
}

private static void PumpInput(
    System.IO.Pipes.AnonymousPipeServerStream destination,
    RelayState state)
{
    byte[] buffer = new byte[16384];
    try
    {
        IntPtr input = GetStdHandle(-10);
        while (true)
        {
            uint count;
            if (!ReadFile(input, buffer, (uint)buffer.Length, out count, IntPtr.Zero))
            {
                if (Marshal.GetLastWin32Error() == 109)
                    break;
                throw Error("standard input read failed");
            }
            if (count == 0)
                break;
            destination.Write(buffer, 0, (int)count);
            destination.Flush();
        }
    }
    catch (Exception error) { state.FailInput(error); }
    finally { destination.Dispose(); }
}

private static void PumpOutput(
    System.IO.Pipes.AnonymousPipeServerStream source,
    int standardHandle,
    RelayState state)
{
    byte[] buffer = new byte[16384];
    try
    {
        IntPtr output = GetStdHandle(standardHandle);
        int count;
        while ((count = source.Read(buffer, 0, buffer.Length)) != 0)
            WriteStandard(output, buffer, (uint)count);
    }
    catch (Exception error) { state.Fail(error); }
    finally { source.Dispose(); }
}

private static void Zero(IntPtr memory, int length)
{
    for (int offset = 0; offset < length; offset++)
        Marshal.WriteByte(memory, offset, 0);
}

private static void MakeParentHandlePrivate(
    System.IO.Pipes.AnonymousPipeServerStream pipe)
{
    if (!SetHandleInformation(
            pipe.SafePipeHandle.DangerousGetHandle(),
            HANDLE_FLAG_INHERIT,
            0))
        throw Error("parent pipe inheritance clear failed");
}

public static int Run(
    IntPtr job,
    string applicationName,
    string commandLine,
    string directory,
    bool agentLaunchDiagnostics)
{
    System.IO.Pipes.AnonymousPipeServerStream input = null;
    System.IO.Pipes.AnonymousPipeServerStream output = null;
    System.IO.Pipes.AnonymousPipeServerStream error = null;
    IntPtr attributes = IntPtr.Zero;
    IntPtr handles = IntPtr.Zero;
    IntPtr jobValue = IntPtr.Zero;
    IntPtr startup = IntPtr.Zero;
    IntPtr process = IntPtr.Zero;
    IntPtr thread = IntPtr.Zero;
    System.Threading.Thread inputPump = null;
    System.Threading.Thread outputPump = null;
    System.Threading.Thread errorPump = null;
    RelayState state = null;
    try
    {
        input = new System.IO.Pipes.AnonymousPipeServerStream(
            System.IO.Pipes.PipeDirection.Out,
            System.IO.HandleInheritability.Inheritable);
        output = new System.IO.Pipes.AnonymousPipeServerStream(
            System.IO.Pipes.PipeDirection.In,
            System.IO.HandleInheritability.Inheritable);
        error = new System.IO.Pipes.AnonymousPipeServerStream(
            System.IO.Pipes.PipeDirection.In,
            System.IO.HandleInheritability.Inheritable);
        MakeParentHandlePrivate(input);
        MakeParentHandlePrivate(output);
        MakeParentHandlePrivate(error);
        IntPtr childInput = input.ClientSafePipeHandle.DangerousGetHandle();
        IntPtr childOutput = output.ClientSafePipeHandle.DangerousGetHandle();
        IntPtr childError = error.ClientSafePipeHandle.DangerousGetHandle();

        IntPtr attributeSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref attributeSize);
        if (attributeSize == IntPtr.Zero)
            throw Error("attribute-list sizing failed");
        attributes = Marshal.AllocHGlobal(attributeSize);
        if (!InitializeProcThreadAttributeList(attributes, 2, 0, ref attributeSize))
            throw Error("attribute-list initialization failed");

        handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
        Marshal.WriteIntPtr(handles, 0, childInput);
        Marshal.WriteIntPtr(handles, IntPtr.Size, childOutput);
        Marshal.WriteIntPtr(handles, IntPtr.Size * 2, childError);
        if (!UpdateProcThreadAttribute(
                attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, new IntPtr(IntPtr.Size * 3),
                IntPtr.Zero, IntPtr.Zero))
            throw Error("handle-list attribute failed");
        jobValue = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(jobValue, job);
        if (!UpdateProcThreadAttribute(
                attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobValue, new IntPtr(IntPtr.Size),
                IntPtr.Zero, IntPtr.Zero))
            throw Error("job-list attribute failed");

        // STARTUPINFOEX is 112 bytes on x64/ARM64. STARTUPINFO.dwFlags and
        // its three standard handles are at offsets 60, 80, 88, and 96.
        startup = Marshal.AllocHGlobal(112);
        Zero(startup, 112);
        Marshal.WriteInt32(startup, 0, 112);
        Marshal.WriteInt32(startup, 60, (int)STARTF_USESTDHANDLES);
        Marshal.WriteIntPtr(startup, 80, childInput);
        Marshal.WriteIntPtr(startup, 88, childOutput);
        Marshal.WriteIntPtr(startup, 96, childError);
        Marshal.WriteIntPtr(startup, 104, attributes);

        PROCESS_INFORMATION information;
        if (!CreateProcess(
                applicationName,
                new System.Text.StringBuilder(commandLine),
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                IntPtr.Zero,
                String.IsNullOrEmpty(directory) ? null : directory,
                startup,
                out information))
        {
            int launchError = Marshal.GetLastWin32Error();
            if (agentLaunchDiagnostics && (launchError == 2 || launchError == 3))
            {
                WriteLaunchFailure("missing");
                return 127;
            }
            if (agentLaunchDiagnostics &&
                (launchError == 5 || launchError == 193 || launchError == 216))
            {
                WriteLaunchFailure("not_executable");
                return 126;
            }
            throw new System.ComponentModel.Win32Exception(
                launchError, "CreateProcessW failed");
        }
        process = information.Process;
        thread = information.Thread;
        input.DisposeLocalCopyOfClientHandle();
        output.DisposeLocalCopyOfClientHandle();
        error.DisposeLocalCopyOfClientHandle();

        // The child is real but still suspended, and no child output pump has
        // started. This ordered record therefore cannot be forged by the
        // executable that follows it on stdout.
        if (agentLaunchDiagnostics)
            WriteLaunchReady();

        state = new RelayState();
        state.Process = process;
        inputPump = new System.Threading.Thread(
            delegate() { PumpInput(input, state); });
        outputPump = new System.Threading.Thread(
            delegate() { PumpOutput(output, -11, state); });
        errorPump = new System.Threading.Thread(
            delegate() { PumpOutput(error, -12, state); });
        inputPump.IsBackground = true;
        outputPump.IsBackground = true;
        errorPump.IsBackground = true;
        outputPump.Start();
        errorPump.Start();
        inputPump.Start();

        if (ResumeThread(thread) == UInt32.MaxValue)
            throw Error("ResumeThread failed");
        Close(ref thread);
        if (WaitForSingleObject(process, UInt32.MaxValue) != WAIT_OBJECT_0)
            throw Error("process wait failed");
        uint exitCode;
        if (!GetExitCodeProcess(process, out exitCode))
            throw Error("exit-code read failed");
        lock (state.Gate)
            state.Exited = true;

        // The primary process has exited, but descendants can still retain
        // inherited output handles. Preserve its status first, then terminate
        // the complete job before waiting for EOF from the pump threads.
        if (!TerminateJobObject(job, 1))
            throw Error("terminate remaining process job failed");
        outputPump.Join();
        errorPump.Join();
        lock (state.Gate)
        {
            if (state.Failure != null)
                throw new System.IO.IOException("standard stream relay failed", state.Failure);
        }
        return unchecked((int)exitCode);
    }
    finally
    {
        // Exceptions can occur before the primary process is reaped. Kill the
        // complete job before joining pumps so descendants cannot retain the
        // anonymous pipe handles and deadlock relay teardown.
        if (job != IntPtr.Zero)
            TerminateJobObject(job, 1);
        if (process != IntPtr.Zero &&
            WaitForSingleObject(process, 0) == WAIT_TIMEOUT)
        {
            TerminateProcess(process, 1);
            WaitForSingleObject(process, UInt32.MaxValue);
        }
        if (outputPump != null && outputPump.IsAlive)
            outputPump.Join();
        if (errorPump != null && errorPump.IsAlive)
            errorPump.Join();
        Close(ref thread);
        Close(ref process);
        if (input != null) input.Dispose();
        if (output != null) output.Dispose();
        if (error != null) error.Dispose();
        if (attributes != IntPtr.Zero)
            DeleteProcThreadAttributeList(attributes);
        if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
        if (jobValue != IntPtr.Zero) Marshal.FreeHGlobal(jobValue);
        if (startup != IntPtr.Zero) Marshal.FreeHGlobal(startup);
        if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
    }
}
'@
Add-Type -MemberDefinition $jobMethods -Name Job -Namespace Nrm *> $null
$payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
$payload = $payloadJson | ConvertFrom-Json
if ([IntPtr]::Size -ne 8) { throw 'nrm-agent requires 64-bit Windows' }
$job = [IntPtr]::Zero
$exitCode = 1
$oldPath = $env:PATH
try {
  $job = [Nrm.Job]::CreateJobObject([IntPtr]::Zero, $null)
  if ($job -eq [IntPtr]::Zero) {
    throw "CreateJobObject failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
  }
  # On x64 and ARM64, JOBOBJECT_EXTENDED_LIMIT_INFORMATION is 144 bytes and
  # BasicLimitInformation.LimitFlags is the uint32 at byte offset 16.
  $limits = New-Object byte[] 144
  [BitConverter]::GetBytes([uint32]0x2000).CopyTo($limits, 16)
  if (-not [Nrm.Job]::SetInformationJobObject($job, 9, $limits, $limits.Length)) {
    throw "SetInformationJobObject failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
  }
  if ($null -ne $payload.path_prepend -and [string]$payload.path_prepend -ne '') {
    $env:PATH = ([string]$payload.path_prepend) + ';' + $env:PATH
  }
  $program = [string]$payload.program
  $directory = [string]$payload.cwd
  $isDriveAbsolute = $program -match '^[A-Za-z]:[\\/]'
  $isUncAbsolute = $program.StartsWith('\\') -or $program.StartsWith('//')
  if ($isDriveAbsolute -or $isUncAbsolute) {
    $applicationName = $program
  } elseif ($program.StartsWith('\') -or $program.StartsWith('/')) {
    throw 'root-relative executable paths are unsupported'
  } elseif ($program -match '^[A-Za-z]:') {
    throw 'drive-relative executable paths are unsupported'
  } elseif ($program.Contains('\') -or $program.Contains('/')) {
    if ([String]::IsNullOrEmpty($directory)) {
      throw 'relative executable paths require a working directory'
    }
    $applicationName = [IO.Path]::GetFullPath([IO.Path]::Combine($directory, $program))
  } else {
    $resolved = Get-Command -Name $program -CommandType Application -ErrorAction Stop |
      Select-Object -First 1
    $applicationName = [string]$resolved.Source
    if ([String]::IsNullOrEmpty($applicationName) -or
        -not [IO.Path]::IsPathRooted($applicationName)) {
      throw "Get-Command returned a non-absolute application path for $program"
    }
  }
  $commandLine = [string]$payload.command_line
  $agentLaunchDiagnostics = $payload.agent_launch_diagnostics -eq $true
  $extension = [IO.Path]::GetExtension($applicationName)
  $isBatch = [string]::Equals($extension, '.cmd', [StringComparison]::OrdinalIgnoreCase) -or
    [string]::Equals($extension, '.bat', [StringComparison]::OrdinalIgnoreCase)
  if ($isBatch) {
    # CreateProcessW cannot execute a batch file directly. Keep the resolved
    # batch path and argv as data, quote every value, and reject cmd.exe
    # expansion characters and controls that cannot be represented safely in
    # this fixed trampoline. Other metacharacters remain inert in their quotes.
    $batchValues = @([string]$applicationName) + @($payload.arguments)
    foreach ($value in $batchValues) {
      $text = [string]$value
      foreach ($character in $text.ToCharArray()) {
        $code = [int][char]$character
        if ($code -le 0x1f -or ($code -ge 0x7f -and $code -le 0x9f)) {
          throw 'batch application paths and arguments must not contain control characters'
        }
      }
      if ($text.IndexOf([char]34) -ge 0 -or $text.IndexOf('%') -ge 0) {
        throw 'batch application paths and arguments must not contain double quotes or percent signs'
      }
    }
    $cmdApplication = [IO.Path]::Combine([Environment]::SystemDirectory, 'cmd.exe')
    if ([String]::IsNullOrEmpty($cmdApplication) -or
        -not [IO.Path]::IsPathRooted($cmdApplication) -or
        -not [IO.File]::Exists($cmdApplication)) {
      throw 'could not resolve the absolute system cmd.exe path'
    }
    # Batch files commonly forward `%*` into a native executable. Apply the
    # Windows argv rule for backslashes before the closing quote so that a
    # trailing backslash survives that second parse, while force-quoting every
    # value keeps cmd.exe metacharacters inert.
    $batchCommand = '"' + ($applicationName -replace '(\\+)$', '$1$1') + '"'
    foreach ($argument in @($payload.arguments)) {
      $batchArgument = [string]$argument
      $batchCommand += ' "' + ($batchArgument -replace '(\\+)$', '$1$1') + '"'
    }
    $commandLine = '"' + $cmdApplication + '" /d /s /v:off /c "' + $batchCommand + '"'
    $applicationName = $cmdApplication
  }
  $exitCode = [Nrm.Job]::Run(
    $job,
    $applicationName,
    $commandLine,
    [string]$payload.cwd,
    $agentLaunchDiagnostics)
} finally {
  $env:PATH = $oldPath
  if ($job -ne [IntPtr]::Zero) { [void][Nrm.Job]::CloseHandle($job) }
}
exit $exitCode"#;

// Deterministic gzip (`mtime = 0`) of `POWERSHELL_PROCESS_SCRIPT_SOURCE`.
const POWERSHELL_PROCESS_SCRIPT_GZIP_BASE64: &str = "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";

pub(crate) fn local_host_info() -> Result<RemoteHostInfo> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let windows = os == "windows";
    let home = if windows {
        std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME"))
    } else {
        std::env::var("HOME")
    }
    .context("local home directory is not available")?;
    let local_app_data = windows
        .then(|| std::env::var("LOCALAPPDATA"))
        .transpose()
        .context("LOCALAPPDATA is not available")?;
    let shell = if windows {
        "powershell".to_owned()
    } else {
        std::env::var("SHELL")
            .ok()
            .filter(|shell| validate_canonical_posix_executable("local shell", shell).is_ok())
            .unwrap_or_else(|| "/bin/sh".to_owned())
    };
    build_host_info(
        os,
        arch,
        &shell,
        home,
        local_app_data,
        if windows {
            RemotePathStyle::Windows
        } else {
            RemotePathStyle::Posix
        },
    )
}

pub(crate) fn parse_posix_probe(stdout: &str) -> Result<RemoteHostInfo> {
    reject_probe_controls(stdout, true)?;
    let normalized = stdout.strip_suffix('\n').unwrap_or(stdout);
    let fields: Vec<_> = normalized.split('\n').collect();
    if fields.len() != 4 || fields[0] != "NRM_HOST_INFO_V1" {
        bail!("POSIX host probe returned an invalid response");
    }
    if fields[3].is_empty() || !fields[3].starts_with('/') {
        bail!("POSIX host probe returned an invalid home directory");
    }
    build_host_info(
        fields[1],
        fields[2],
        "sh",
        fields[3].to_string(),
        None,
        RemotePathStyle::Posix,
    )
}

pub(crate) fn parse_powershell_probe(stdout: &str) -> Result<RemoteHostInfo> {
    let probe: PowerShellProbe = serde_json::from_str(stdout.trim())
        .context("PowerShell host probe returned invalid JSON")?;
    if probe.schema_version != PROBE_SCHEMA_VERSION
        || !probe.os.eq_ignore_ascii_case("windows")
        || !probe.shell.eq_ignore_ascii_case("powershell")
        || !probe.path_style.eq_ignore_ascii_case("windows")
    {
        bail!("PowerShell host probe returned incompatible platform metadata");
    }
    if probe.home.is_empty() || probe.local_app_data.is_empty() {
        bail!("PowerShell host probe returned an empty required directory");
    }
    reject_field_controls("home", &probe.home)?;
    reject_field_controls("local_app_data", &probe.local_app_data)?;
    build_host_info(
        "windows",
        &probe.arch,
        "powershell",
        probe.home,
        Some(probe.local_app_data),
        RemotePathStyle::Windows,
    )
}

pub(crate) fn posix_probe_command() -> String {
    let script = r#"set -eu
os=$(uname -s)
arch=$(uname -m)
printf "NRM_HOST_INFO_V1\n%s\n%s\n%s\n" "$os" "$arch" "$HOME""#;
    format!("'sh' '-lc' '{}'", script.replace('\'', "'\\''"))
}

pub(crate) fn powershell_probe_command() -> String {
    let script = r#"$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { exit 86 }
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$result = [ordered]@{
  schema_version = 1
  os = 'windows'
  arch = [string]$arch
  shell = 'powershell'
  home = [string]$HOME
  local_app_data = [string]$env:LOCALAPPDATA
  path_style = 'windows'
}
$result | ConvertTo-Json -Compress"#;
    powershell_encoded_command(script)
}

pub(crate) fn validate_remote_root(host: &RemoteHostInfo, root: &Path) -> Result<()> {
    let root = root
        .to_str()
        .ok_or_else(|| anyhow!("SSH remote root must be valid UTF-8"))?;
    reject_field_controls("remote root", root)?;
    if root.starts_with("//") || root.starts_with("\\\\") || root.starts_with("/\\") {
        bail!("remote root must not use a UNC path");
    }
    match host.path_style {
        RemotePathStyle::Posix => {
            if !root.starts_with('/') {
                bail!("POSIX remote root must be absolute");
            }
            if root[1..].contains("//") {
                bail!("POSIX remote root must not contain empty segments");
            }
            if root.split('/').any(|segment| matches!(segment, "." | "..")) {
                bail!("POSIX remote root must not contain dot segments");
            }
        }
        RemotePathStyle::Windows => {
            let bytes = root.as_bytes();
            if bytes.len() < 3
                || !bytes[0].is_ascii_uppercase()
                || bytes[1] != b':'
                || bytes[2] != b'/'
            {
                bail!("Windows remote root must use an absolute drive path such as B:/repo");
            }
            if root.contains('\\') {
                bail!("Windows remote root must use forward slashes");
            }
            let remainder = &root[3..];
            if remainder.starts_with('/') || remainder.contains("//") {
                bail!("Windows remote root must not contain empty segments");
            }
            for segment in remainder.split('/').filter(|segment| !segment.is_empty()) {
                if matches!(segment, "." | "..") {
                    bail!("Windows remote root must not contain dot segments");
                }
                if segment.contains(':') {
                    bail!("Windows remote root must not contain alternate data streams");
                }
                if segment.ends_with(['.', ' ']) {
                    bail!("Windows remote root segments must not end in a dot or space");
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn powershell_process_command(
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    path_prepend: Option<&str>,
) -> Result<PowerShellProcessCommand> {
    powershell_process_command_inner(program, args, cwd, path_prepend, false)
}

pub(crate) fn powershell_agent_process_command(
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    path_prepend: Option<&str>,
) -> Result<PowerShellProcessCommand> {
    powershell_process_command_inner(program, args, cwd, path_prepend, true)
}

fn powershell_process_command_inner(
    program: &str,
    args: &[String],
    cwd: Option<&str>,
    path_prepend: Option<&str>,
    agent_launch_diagnostics: bool,
) -> Result<PowerShellProcessCommand> {
    reject_process_field("program", program)?;
    for arg in args {
        reject_process_argument(arg)?;
    }
    if let Some(cwd) = cwd {
        reject_process_field("working directory", cwd)?;
    }
    if let Some(path_prepend) = path_prepend {
        reject_process_field("PATH prefix", path_prepend)?;
    }

    let mut command_arguments = Vec::with_capacity(args.len() + 1);
    command_arguments.push(program.to_string());
    command_arguments.extend(args.iter().cloned());
    let agent_root = if agent_launch_diagnostics {
        Some(
            args.windows(2)
                .find_map(|pair| (pair[0] == "--root").then_some(pair[1].as_str()))
                .ok_or_else(|| anyhow!("agent launch diagnostics require a --root argument"))?,
        )
    } else {
        None
    };
    let payload = ProcessPayload {
        program,
        arguments: args,
        command_line: windows_join_arguments(&command_arguments),
        cwd,
        path_prepend,
        agent_launch_diagnostics,
        agent_root,
    };
    let payload = serde_json::to_vec(&payload)?;
    let compressed_script = STANDARD
        .decode(POWERSHELL_PROCESS_SCRIPT_GZIP_BASE64)
        .expect("embedded PowerShell process script must be valid base64");
    if compressed_script.len() > POWERSHELL_BOOTSTRAP_MAX_BYTES
        || payload.len() > POWERSHELL_BOOTSTRAP_MAX_BYTES
    {
        bail!(
            "PowerShell process bootstrap exceeds the {POWERSHELL_BOOTSTRAP_MAX_BYTES}-byte document limit"
        );
    }
    let bootstrap = r#"$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::SetOut([IO.TextWriter]::Null)
$stream=[Console]::OpenStandardInput(1)
function Read-NrmBytes([int]$length) {
  $bytes=New-Object byte[] $length
  $offset=0
  while($offset -lt $length) {
    $count=$stream.Read($bytes,$offset,$length-$offset)
    if($count -eq 0) { throw 'truncated nrm process bootstrap' }
    $offset+=$count
  }
  return ,$bytes
}
function Fail-Nrm($kind,$status) {
  $record=[Text.Encoding]::ASCII.GetBytes("NRM_AGENT_LAUNCH_V1`tFAILURE`t$kind`n")
  $output=[Console]::OpenStandardOutput()
  $output.Write($record,0,$record.Length);$output.Flush();exit $status
}
[byte[]]$header=Read-NrmBytes 12
if($header[0]-ne 78 -or $header[1]-ne 82 -or $header[2]-ne 77 -or $header[3]-ne 49) { throw 'invalid nrm process bootstrap' }
$scriptLength=[BitConverter]::ToUInt32($header,4)
$payloadLength=[BitConverter]::ToUInt32($header,8)
if($scriptLength -gt 65536 -or $payloadLength -gt 65536) { throw 'oversized nrm process bootstrap' }
[byte[]]$compressed=Read-NrmBytes ([int]$scriptLength)
[byte[]]$payload=Read-NrmBytes ([int]$payloadLength)
$document=[Text.Encoding]::UTF8.GetString($payload)|ConvertFrom-Json
$diagnose=$document.agent_launch_diagnostics -eq $true
if($diagnose) {
  $pathPrepend=[string]$document.path_prepend
  if(-not [string]::IsNullOrEmpty($pathPrepend)) {
    $env:PATH=$pathPrepend+[IO.Path]::PathSeparator+$env:PATH
  }
  $root=[string]$document.agent_root
  if([string]::IsNullOrEmpty($root) -or -not [IO.Directory]::Exists($root)) {
    Fail-Nrm root_missing 66
  }
  $program=[string]$document.program
  $isPath=[IO.Path]::IsPathRooted($program) -or $program.Contains('\') -or $program.Contains('/')
  if($isPath) {
    if([IO.Directory]::Exists($program)) { Fail-Nrm not_executable 126 }
    if(-not [IO.File]::Exists($program)) { Fail-Nrm missing 127 }
  } else {
    try {
      $resolved=Get-Command -Name $program -CommandType Application -ErrorAction Stop|Select-Object -First 1
      if($null -eq $resolved) { Fail-Nrm missing 127 }
    } catch { Fail-Nrm missing 127 }
  }
}
$memory=New-Object IO.MemoryStream(,$compressed)
$gzip=New-Object IO.Compression.GZipStream($memory,[IO.Compression.CompressionMode]::Decompress)
$reader=New-Object IO.StreamReader($gzip,[Text.Encoding]::UTF8)
& ([ScriptBlock]::Create($reader.ReadToEnd())) $payload"#;
    let command = powershell_encoded_command(bootstrap);
    if command.len() > WINDOWS_REMOTE_COMMAND_MAX_CHARS {
        bail!(
            "PowerShell process command exceeds the {WINDOWS_REMOTE_COMMAND_MAX_CHARS}-character Windows command-line limit"
        );
    }
    let mut stdin_prefix = Vec::with_capacity(12 + compressed_script.len() + payload.len());
    stdin_prefix.extend_from_slice(&POWERSHELL_BOOTSTRAP_MAGIC);
    stdin_prefix.extend_from_slice(&(compressed_script.len() as u32).to_le_bytes());
    stdin_prefix.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    stdin_prefix.extend_from_slice(&compressed_script);
    stdin_prefix.extend_from_slice(&payload);
    Ok(PowerShellProcessCommand {
        command,
        stdin_prefix,
    })
}

fn build_host_info(
    os: &str,
    arch: &str,
    shell: &str,
    home: String,
    local_app_data: Option<String>,
    path_style: RemotePathStyle,
) -> Result<RemoteHostInfo> {
    let os = match os.to_ascii_lowercase().as_str() {
        "linux" => "linux",
        "darwin" | "macos" => "macos",
        "windows" | "windows_nt" => "windows",
        other => bail!("unsupported remote operating system `{other}`"),
    };
    let arch = match arch.to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        other => bail!("unsupported remote architecture `{other}`"),
    };
    let target = match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        _ => unreachable!("validated OS and architecture pair"),
    };
    reject_field_controls("shell", shell)?;
    reject_field_controls("home", &home)?;
    if let Some(local_app_data) = &local_app_data {
        reject_field_controls("local_app_data", local_app_data)?;
    }
    match path_style {
        RemotePathStyle::Posix => validate_canonical_posix_path("home", &home)?,
        RemotePathStyle::Windows => {
            validate_canonical_windows_path("home", &home)?;
            if let Some(local_app_data) = &local_app_data {
                validate_canonical_windows_path("local_app_data", local_app_data)?;
            }
        }
    }
    Ok(RemoteHostInfo {
        os: os.to_string(),
        arch: arch.to_string(),
        shell: shell.to_string(),
        home,
        local_app_data,
        path_style,
        target: target.to_string(),
    })
}

fn reject_probe_controls(value: &str, allow_newline: bool) -> Result<()> {
    if value
        .chars()
        .any(|character| character.is_control() && !(allow_newline && character == '\n'))
    {
        bail!("host probe response contains control characters");
    }
    Ok(())
}

fn reject_field_controls(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("{name} must not be empty or contain control characters");
    }
    Ok(())
}

fn reject_process_field(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("PowerShell process {name} must not be empty or contain control characters");
    }
    Ok(())
}

fn reject_process_argument(value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        bail!("PowerShell process argument must not contain control characters");
    }
    Ok(())
}

pub(crate) fn powershell_encoded_command(script: &str) -> String {
    let mut utf16le = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        utf16le.extend_from_slice(&unit.to_le_bytes());
    }
    format!(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
        STANDARD.encode(utf16le)
    )
}

fn windows_join_arguments(args: &[String]) -> String {
    args.iter()
        .map(|argument| windows_quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

fn windows_quote_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character == ' ' || character == '\t' || character == '"')
    {
        return argument.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2).saturating_add(1)));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                quoted.push(character);
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2)));
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_encoded_command(command: &str) -> String {
        let encoded = command.split_whitespace().last().unwrap();
        let bytes = STANDARD.decode(encoded).unwrap();
        let units: Vec<_> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&units).unwrap()
    }

    fn bootstrap_documents(prefix: &[u8]) -> (&[u8], &[u8]) {
        assert!(prefix.len() >= 12);
        assert_eq!(&prefix[..4], &POWERSHELL_BOOTSTRAP_MAGIC);
        let script_len = u32::from_le_bytes(prefix[4..8].try_into().unwrap()) as usize;
        let payload_len = u32::from_le_bytes(prefix[8..12].try_into().unwrap()) as usize;
        assert_eq!(prefix.len(), 12 + script_len + payload_len);
        let script_end = 12 + script_len;
        (&prefix[12..script_end], &prefix[script_end..])
    }

    #[test]
    fn maps_supported_platforms_to_release_targets() {
        for (os, arch, target) in [
            ("Linux", "x86_64", "x86_64-unknown-linux-musl"),
            ("linux", "aarch64", "aarch64-unknown-linux-musl"),
            ("Darwin", "x86_64", "x86_64-apple-darwin"),
            ("macos", "arm64", "aarch64-apple-darwin"),
            ("windows", "AMD64", "x86_64-pc-windows-msvc"),
            ("windows", "ARM64", "aarch64-pc-windows-msvc"),
        ] {
            let style = if os.eq_ignore_ascii_case("windows") {
                RemotePathStyle::Windows
            } else {
                RemotePathStyle::Posix
            };
            let (home, local_app_data) = if style == RemotePathStyle::Windows {
                (
                    r"C:\Users\test".to_owned(),
                    Some(r"C:\Users\test\AppData\Local".to_owned()),
                )
            } else {
                ("/home".to_owned(), None)
            };
            let info = build_host_info(os, arch, "test", home, local_app_data, style).unwrap();
            assert_eq!(info.target, target);
        }
        assert!(build_host_info(
            "freebsd",
            "x86_64",
            "sh",
            "/home".to_string(),
            None,
            RemotePathStyle::Posix
        )
        .is_err());
        assert!(build_host_info(
            "linux",
            "riscv64",
            "sh",
            "/home".to_string(),
            None,
            RemotePathStyle::Posix
        )
        .is_err());
    }

    #[test]
    fn validates_canonical_cached_remote_host_metadata() {
        let posix = build_host_info(
            "linux",
            "x86_64",
            "/bin/zsh",
            "/home/test".to_owned(),
            None,
            RemotePathStyle::Posix,
        )
        .unwrap();
        validate_remote_host_info(&posix).unwrap();
        let mut posix_root = posix.clone();
        posix_root.home = "/".to_owned();
        validate_remote_host_info(&posix_root).unwrap();

        let windows = build_host_info(
            "windows",
            "aarch64",
            "powershell",
            r"C:\Users\test".to_owned(),
            Some(r"C:\Users\test\AppData\Local".to_owned()),
            RemotePathStyle::Windows,
        )
        .unwrap();
        validate_remote_host_info(&windows).unwrap();
        let mut windows_root = windows.clone();
        windows_root.home = r"C:\".to_owned();
        windows_root.local_app_data = Some(r"D:\".to_owned());
        validate_remote_host_info(&windows_root).unwrap();

        let mut invalid = windows.clone();
        invalid.target = "x86_64-pc-windows-msvc".to_owned();
        assert!(validate_remote_host_info(&invalid).is_err());
        invalid = windows.clone();
        invalid.path_style = RemotePathStyle::Posix;
        assert!(validate_remote_host_info(&invalid).is_err());
        invalid = windows.clone();
        invalid.local_app_data = None;
        assert!(validate_remote_host_info(&invalid).is_err());
        invalid = windows.clone();
        invalid.shell = "cmd".to_owned();
        assert!(validate_remote_host_info(&invalid).is_err());

        for invalid_home in [
            "relative/home",
            "/home/test/",
            "/home//test",
            "/home/../test",
        ] {
            let mut invalid = posix.clone();
            invalid.home = invalid_home.to_owned();
            assert!(validate_remote_host_info(&invalid).is_err());
        }
        let mut invalid = posix;
        invalid.shell = "/bin/sh -c id".to_owned();
        assert!(validate_remote_host_info(&invalid).is_err());

        for invalid_home in [
            r"relative\home",
            r"\\server\share",
            r"c:\Users\test",
            r"C:/Users\test",
            r"C:\Users\..\test",
        ] {
            let mut invalid = windows.clone();
            invalid.home = invalid_home.to_owned();
            assert!(validate_remote_host_info(&invalid).is_err());
        }
    }

    #[test]
    fn locally_detected_host_metadata_is_valid_as_a_cached_hint() {
        let local = local_host_info().unwrap();
        validate_remote_host_info(&local).unwrap();
    }

    #[test]
    fn parses_strict_posix_probe_output() {
        let linux = parse_posix_probe("NRM_HOST_INFO_V1\nLinux\nx86_64\n/home/me\n").unwrap();
        assert_eq!(linux.os, "linux");
        assert_eq!(linux.target, "x86_64-unknown-linux-musl");
        let mac = parse_posix_probe("NRM_HOST_INFO_V1\nDarwin\narm64\n/Users/me\n").unwrap();
        assert_eq!(mac.target, "aarch64-apple-darwin");

        for invalid in [
            "",
            "NRM_HOST_INFO_V2\nLinux\nx86_64\n/home/me\n",
            "NRM_HOST_INFO_V1\nLinux\nx86_64\nrelative\n",
            "NRM_HOST_INFO_V1\nLinux\nx86_64\n/home\nextra\n",
            "NRM_HOST_INFO_V1\r\nLinux\r\nx86_64\r\n/home\r\n",
        ] {
            assert!(parse_posix_probe(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn posix_probe_command_runs_through_a_login_shell() {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(posix_probe_command())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let info = parse_posix_probe(&String::from_utf8(output.stdout).unwrap()).unwrap();
        assert!(matches!(info.os.as_str(), "linux" | "macos"));
        assert!(matches!(info.arch.as_str(), "x86_64" | "aarch64"));
    }

    #[test]
    fn parses_strict_powershell_probe_json() {
        let info = parse_powershell_probe(
            r#"{"schema_version":1,"os":"windows","arch":"AMD64","shell":"powershell","home":"C:\\Users\\me","local_app_data":"C:\\Users\\me\\AppData\\Local","path_style":"windows"}"#,
        )
        .unwrap();
        assert_eq!(info.target, "x86_64-pc-windows-msvc");
        assert_eq!(info.path_style, RemotePathStyle::Windows);

        for invalid in [
            r#"{"schema_version":2,"os":"windows","arch":"AMD64","shell":"powershell","home":"C:\\Users\\me","local_app_data":"C:\\Local","path_style":"windows"}"#,
            r#"{"schema_version":1,"os":"windows","arch":"AMD64","shell":"powershell","home":"C:\\Users\\me","local_app_data":"C:\\Local","path_style":"windows","extra":true}"#,
            r#"{"schema_version":1,"os":"linux","arch":"AMD64","shell":"powershell","home":"C:\\Users\\me","local_app_data":"C:\\Local","path_style":"windows"}"#,
        ] {
            assert!(parse_powershell_probe(invalid).is_err());
        }
    }

    #[test]
    fn validates_platform_specific_remote_roots() {
        let posix = build_host_info(
            "linux",
            "x86_64",
            "sh",
            "/home/me".to_string(),
            None,
            RemotePathStyle::Posix,
        )
        .unwrap();
        let windows = build_host_info(
            "windows",
            "arm64",
            "powershell",
            r"C:\Users\me".to_string(),
            Some(r"C:\Users\me\AppData\Local".to_string()),
            RemotePathStyle::Windows,
        )
        .unwrap();
        validate_remote_root(&posix, Path::new("/home/me/repo")).unwrap();
        validate_remote_root(&windows, Path::new("B:/repos/project")).unwrap();

        for invalid in [
            "relative",
            "//server/share",
            "/\\server/share",
            "/tmp\nrepo",
            "/repo//nested",
            "/repo/../other",
        ] {
            assert!(validate_remote_root(&posix, Path::new(invalid)).is_err());
        }
        for invalid in [
            "B:relative",
            "/B:/repos",
            "B:\\repos",
            "//server/share",
            "\\\\server\\share",
            "1:/repos",
            "b:/repos",
            "B://repos",
            "B:/repo/../other",
            "B:/repo./other",
            "B:/repo /other",
            "B:/repo:stream/other",
        ] {
            assert!(validate_remote_root(&windows, Path::new(invalid)).is_err());
        }
    }

    #[test]
    fn powershell_probe_uses_utf16le_encoded_command() {
        let command = powershell_probe_command();
        assert!(command.starts_with("powershell.exe -NoLogo -NoProfile"));
        let script = decode_encoded_command(&command);
        assert!(script.contains("PROCESSOR_ARCHITEW6432"));
        assert!(script.contains("LOCALAPPDATA"));
        assert!(script.contains("ConvertTo-Json -Compress"));
    }

    #[test]
    fn embedded_powershell_process_script_matches_audited_source() {
        use std::io::Read as _;

        let compressed = STANDARD
            .decode(POWERSHELL_PROCESS_SCRIPT_GZIP_BASE64)
            .unwrap();
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, POWERSHELL_PROCESS_SCRIPT_SOURCE.as_bytes());
    }

    #[test]
    fn powershell_process_payload_does_not_interpolate_user_input() {
        let program = r#"C:\Program Files\Agent ' ; Write-Output owned.exe"#;
        let args = vec![
            "serve".to_string(),
            String::new(),
            "--root".to_string(),
            r#"B:/repo ' ; $(owned) &|<>^()!% \"quoted\""#.to_string(),
        ];
        let launch = powershell_process_command(
            program,
            &args,
            Some("B:/repo with space"),
            Some(r"C:\Users\me\AppData\Local\nrm\bin"),
        )
        .unwrap();
        assert!(!launch.command.contains("owned"));
        assert!(
            launch.command.encode_utf16().count() <= WINDOWS_REMOTE_COMMAND_MAX_CHARS,
            "PowerShell process command exceeds the Windows command-line limit: {} UTF-16 code units",
            launch.command.encode_utf16().count()
        );
        let bootstrap = decode_encoded_command(&launch.command);
        assert!(!bootstrap.contains("Write-Output owned"));
        assert!(!bootstrap.contains("$(owned)"));
        assert!(bootstrap.contains("GZipStream"));
        assert!(bootstrap.contains("$ProgressPreference='SilentlyContinue'"));
        assert!(bootstrap.contains("OpenStandardInput(1)"));
        assert!(bootstrap.contains("Read-NrmBytes"));
        assert!(bootstrap.contains("ScriptBlock"));

        let script = POWERSHELL_PROCESS_SCRIPT_SOURCE;
        assert!(!script.contains("CopyToAsync"));
        assert!(!script.contains("System.Diagnostics.Process"));
        assert!(!script.contains("ReadAsync"));
        assert!(!script.contains("WriteAsync"));
        assert!(script.contains("CreateProcess("));
        assert!(script.contains("AnonymousPipeServerStream"));
        assert!(script.contains("PROC_THREAD_ATTRIBUTE_HANDLE_LIST"));
        assert!(script.contains("PROC_THREAD_ATTRIBUTE_JOB_LIST"));
        assert!(script.contains("EXTENDED_STARTUPINFO_PRESENT"));
        assert!(script.contains("SetHandleInformation"));
        assert!(script.contains("MakeParentHandlePrivate"));
        assert!(script.contains("DisposeLocalCopyOfClientHandle"));
        assert!(script.contains("ReadFile(input"));
        assert!(script.contains("WriteFile(destination"));
        assert!(script.contains("FlushFileBuffers(destination)"));
        assert!(script.contains("private static extern bool TerminateJobObject"));
        assert!(script.contains("if (!TerminateJobObject(job, 1))"));
        assert!(script.contains("if (job != IntPtr.Zero)\n            TerminateJobObject(job, 1);"));
        assert!(script.contains("GetStdHandle(-10)"));
        assert!(script.contains("PumpOutput(output, -11"));
        assert!(script.contains("PumpOutput(error, -12"));
        assert!(script.contains("bool agentLaunchDiagnostics)"));
        assert!(script
            .contains("if (agentLaunchDiagnostics && (launchError == 2 || launchError == 3))"));
        assert!(script.contains("if (agentLaunchDiagnostics)\n            WriteLaunchReady();"));
        assert!(script.contains("WriteLaunchReady();"));
        assert!(script.contains("WriteLaunchFailure(\"missing\");"));
        assert!(script.contains("WriteLaunchFailure(\"not_executable\");"));
        assert!(script.contains("NRM_AGENT_LAUNCH_V1\\tREADY\\n"));
        assert!(script.contains("System.Threading.Thread"));
        assert!(script.contains("STARTUPINFOEX is 112 bytes"));
        assert!(script.contains("JOBOBJECT_EXTENDED_LIMIT_INFORMATION is 144 bytes"));
        assert!(script.contains("CopyTo($limits, 16)"));
        assert!(script.contains("CloseHandle($job)"));
        assert!(script.contains("if (Failure == null)"));
        assert!(script.contains("if (!Exited)"));
        assert!(script.contains("CreateProcess(\n                applicationName,"));
        assert!(script.contains("Get-Command -Name $program -CommandType Application"));
        assert!(script.contains("[IO.Path]::GetFullPath([IO.Path]::Combine($directory, $program))"));
        assert!(script.contains("[IO.Path]::GetExtension($applicationName)"));
        assert!(script.contains("[string]::Equals($extension, '.cmd'"));
        assert!(script.contains("[string]::Equals($extension, '.bat'"));
        assert!(script.contains("[Environment]::SystemDirectory"));
        assert!(script.contains("'cmd.exe'"));
        assert!(script.contains(" /d /s /v:off /c "));
        assert!(script.contains("$applicationName = $cmdApplication"));
        assert!(script
            .contains("$agentLaunchDiagnostics = $payload.agent_launch_diagnostics -eq $true"));
        assert!(script.contains("[string]$payload.cwd,\n    $agentLaunchDiagnostics)"));
        assert!(script.contains("-replace '(\\\\+)$', '$1$1'"));
        assert!(script.contains(
            "batch application paths and arguments must not contain double quotes or percent signs"
        ));
        assert!(script
            .contains("batch application paths and arguments must not contain control characters"));

        let (compressed, payload_bytes) = bootstrap_documents(&launch.stdin_prefix);
        assert_eq!(
            compressed,
            STANDARD
                .decode(POWERSHELL_PROCESS_SCRIPT_GZIP_BASE64)
                .unwrap()
        );
        let payload: serde_json::Value = serde_json::from_slice(payload_bytes).unwrap();
        assert_eq!(payload["program"], program);
        assert_eq!(payload["arguments"], serde_json::json!(args));
        assert!(payload["command_line"]
            .as_str()
            .unwrap()
            .contains("$(owned)"));
        assert!(payload["command_line"].as_str().unwrap().contains(program));
        assert_eq!(payload["cwd"], "B:/repo with space");
        assert_eq!(payload["agent_launch_diagnostics"], false);
        assert!(payload["agent_root"].is_null());
    }

    #[test]
    fn powershell_agent_process_uses_ordered_launch_prelude_and_preflight_path() {
        let root = r#"B:/repo ' ; Write-Output owned"#;
        let path_prepend = r#"C:\nrm-test\bin"#;
        let args = vec!["serve".to_owned(), "--root".to_owned(), root.to_owned()];
        let launch =
            powershell_agent_process_command("custom-agent.exe", &args, None, Some(path_prepend))
                .unwrap();

        assert!(!launch.command.contains("custom-agent"));
        assert!(!launch.command.contains("Write-Output owned"));
        assert!(!launch.command.contains(path_prepend));
        assert!(
            launch.command.encode_utf16().count() <= WINDOWS_REMOTE_COMMAND_MAX_CHARS,
            "PowerShell agent command exceeds the Windows command-line limit"
        );
        let bootstrap = decode_encoded_command(&launch.command);
        assert!(bootstrap.contains("NRM_AGENT_LAUNCH_V1`tFAILURE"));
        assert!(bootstrap.contains("$env:PATH=$pathPrepend+[IO.Path]::PathSeparator+$env:PATH"));
        assert!(bootstrap.contains("Fail-Nrm root_missing 66"));
        assert!(bootstrap.contains("Fail-Nrm not_executable 126"));
        assert!(bootstrap.contains("Fail-Nrm missing 127"));

        let (_, payload_bytes) = bootstrap_documents(&launch.stdin_prefix);
        let payload: serde_json::Value = serde_json::from_slice(payload_bytes).unwrap();
        assert_eq!(payload["agent_launch_diagnostics"], true);
        assert_eq!(payload["agent_root"], root);
        assert_eq!(payload["path_prepend"], path_prepend);
        assert_eq!(payload["program"], "custom-agent.exe");
    }

    #[test]
    fn powershell_process_allows_empty_arguments_but_rejects_argument_controls() {
        let launch = powershell_process_command(
            "native.exe",
            &[String::new(), "after-empty".to_string()],
            None,
            None,
        )
        .unwrap();
        let (_, payload_bytes) = bootstrap_documents(&launch.stdin_prefix);
        let payload: serde_json::Value = serde_json::from_slice(payload_bytes).unwrap();
        assert_eq!(payload["arguments"], serde_json::json!(["", "after-empty"]));
        assert_eq!(payload["command_line"], r#"native.exe "" after-empty"#);

        for invalid in ["line\nbreak", "tab\tbreak", "nul\0break"] {
            let error =
                powershell_process_command("native.exe", &[invalid.to_string()], None, None)
                    .unwrap_err()
                    .to_string();
            assert_eq!(
                error,
                "PowerShell process argument must not contain control characters"
            );
        }
    }

    #[test]
    fn powershell_process_rejects_the_first_oversized_bootstrap_payload() {
        let plan = |root_len: usize| {
            let root = format!("B:/{}", "x".repeat(root_len));
            powershell_process_command(
                "nrm-agent.exe",
                &["serve".to_string(), "--root".to_string(), root.clone()],
                Some(&root),
                None,
            )
        };

        let mut passing = 0usize;
        let mut failing = 100_000usize;
        assert!(plan(passing).is_ok());
        assert!(plan(failing).is_err());
        while passing + 1 < failing {
            let candidate = passing + (failing - passing) / 2;
            if plan(candidate).is_ok() {
                passing = candidate;
            } else {
                failing = candidate;
            }
        }

        let launch = plan(passing).unwrap();
        let code_units = launch.command.encode_utf16().count();
        assert!(code_units <= WINDOWS_REMOTE_COMMAND_MAX_CHARS);
        let (_, payload) = bootstrap_documents(&launch.stdin_prefix);
        assert!(payload.len() <= POWERSHELL_BOOTSTRAP_MAX_BYTES);
        assert!(payload.len() + 4 > POWERSHELL_BOOTSTRAP_MAX_BYTES);
        let error = plan(failing).unwrap_err().to_string();
        assert_eq!(failing, passing + 1);
        assert_eq!(
            error,
            "PowerShell process bootstrap exceeds the 65536-byte document limit"
        );
    }

    #[cfg(windows)]
    fn run_native_powershell_process(
        launch: &PowerShellProcessCommand,
    ) -> (std::process::ExitStatus, Vec<u8>, Vec<u8>) {
        use std::io::{Read as _, Write as _};
        use std::process::{Command, Stdio};

        let encoded = launch.command.split_whitespace().last().unwrap();
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&launch.stdin_prefix)
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let stdout_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let mut stderr = child.stderr.take().unwrap();
        let stderr_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        let status = child.wait().unwrap();
        (
            status,
            stdout_reader.join().unwrap().unwrap(),
            stderr_reader.join().unwrap().unwrap(),
        )
    }

    #[cfg(windows)]
    #[test]
    fn powershell_agent_process_reports_exact_missing_launch_record() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().to_string_lossy().into_owned();
        let missing = format!(r#"{}\definitely-missing-nrm-agent.exe"#, root);
        let launch = powershell_agent_process_command(
            &missing,
            &["serve".to_owned(), "--root".to_owned(), root],
            None,
            None,
        )
        .unwrap();

        let (status, stdout, stderr) = run_native_powershell_process(&launch);

        assert_eq!(status.code(), Some(127));
        assert_eq!(stdout, b"NRM_AGENT_LAUNCH_V1\tFAILURE\tmissing\n");
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    }

    #[cfg(windows)]
    #[test]
    fn powershell_agent_preflight_resolves_bare_program_from_path_prepend() {
        use std::process::Command;

        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().join("managed-bin");
        let root = directory.path().join("repo");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let source = bin.join("managed-agent.rs");
        let executable = bin.join("managed-agent.exe");
        std::fs::write(&source, "fn main() { std::process::exit(41); }").unwrap();
        let compile = Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let root = root.to_string_lossy().into_owned();
        let launch = powershell_agent_process_command(
            "managed-agent.exe",
            &["serve".to_owned(), "--root".to_owned(), root],
            None,
            Some(&bin.to_string_lossy()),
        )
        .unwrap();

        let (status, stdout, stderr) = run_native_powershell_process(&launch);

        assert_eq!(status.code(), Some(41));
        assert_eq!(stdout, b"NRM_AGENT_LAUNCH_V1\tREADY\n");
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    }

    #[cfg(windows)]
    #[test]
    fn powershell_process_resolves_path_and_flushes_binary_output_before_stdin_eof() {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        use std::sync::mpsc;
        use std::thread;
        use std::time::{Duration, Instant};

        let child_dir = tempfile::tempdir().unwrap();
        let trusted_dir = child_dir.path().join("trusted");
        let untrusted_cwd = child_dir.path().join("untrusted");
        std::fs::create_dir_all(&trusted_dir).unwrap();
        std::fs::create_dir_all(&untrusted_cwd).unwrap();
        let child_source_path = trusted_dir.join("nrm-pump-child.rs");
        let child_path = trusted_dir.join("nrm-pump-child.exe");
        std::fs::write(
            &child_source_path,
            r#"use std::io::{Read, Write};
fn main() {
    let mut request = [0u8; 5];
    std::io::stdin().read_exact(&mut request).unwrap();
    std::io::stdout().write_all(&request).unwrap();
    std::io::stdout().flush().unwrap();
    std::io::stderr().write_all(&[255, 0, 13, 10]).unwrap();
    std::io::stderr().flush().unwrap();
    let mut rest = Vec::new();
    std::io::stdin().read_to_end(&mut rest).unwrap();
    std::process::exit(37);
}"#,
        )
        .unwrap();
        let compile = Command::new("rustc")
            .arg(&child_source_path)
            .arg("-o")
            .arg(&child_path)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let shadow_source_path = untrusted_cwd.join("nrm-pump-child.rs");
        let shadow_path = untrusted_cwd.join("nrm-pump-child.exe");
        std::fs::write(
            &shadow_source_path,
            r#"fn main() {
    std::io::Write::write_all(&mut std::io::stdout(), b"shadow").unwrap();
    std::process::exit(91);
}"#,
        )
        .unwrap();
        let compile_shadow = Command::new("rustc")
            .arg(&shadow_source_path)
            .arg("-o")
            .arg(&shadow_path)
            .output()
            .unwrap();
        assert!(
            compile_shadow.status.success(),
            "{}",
            String::from_utf8_lossy(&compile_shadow.stderr)
        );
        let wrapper_launch = powershell_process_command(
            "nrm-pump-child",
            &[],
            Some(&untrusted_cwd.to_string_lossy()),
            Some(&trusted_dir.to_string_lossy()),
        )
        .unwrap();
        let (_, payload) = bootstrap_documents(&wrapper_launch.stdin_prefix);
        let payload: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert_eq!(payload["command_line"], "nrm-pump-child");
        assert!(!payload["command_line"]
            .as_str()
            .unwrap()
            .contains(trusted_dir.to_string_lossy().as_ref()));
        let wrapper_encoded = wrapper_launch.command.split_whitespace().last().unwrap();
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                wrapper_encoded,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let (stdout_tx, stdout_rx) = mpsc::channel();
        let mut stdout = crate::bom_reader::LeadingBomReader::new(child.stdout.take().unwrap());
        let stdout_reader = thread::spawn(move || {
            let mut bytes = [0u8; 5];
            let result = stdout.read_exact(&mut bytes).map(|()| bytes);
            let _ = stdout_tx.send(result);
        });
        let (stderr_tx, stderr_rx) = mpsc::channel::<std::io::Result<()>>();
        let mut stderr = child.stderr.take().unwrap();
        let stderr_reader = thread::spawn(move || {
            let marker = [255, 0, 13, 10];
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            let mut reported = false;
            loop {
                match stderr.read(&mut buffer) {
                    Ok(0) => {
                        if !reported {
                            let _ = stderr_tx.send(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "child stderr marker was not observed",
                            )));
                        }
                        break;
                    }
                    Ok(count) => {
                        received.extend_from_slice(&buffer[..count]);
                        if !reported && received.windows(marker.len()).any(|item| item == marker) {
                            reported = true;
                            let _ = stderr_tx.send(Ok(()));
                        }
                        if received.len() > 4096 {
                            received.drain(..received.len() - 4096);
                        }
                    }
                    Err(error) => {
                        if !reported {
                            let _ = stderr_tx.send(Err(error));
                        }
                        break;
                    }
                }
            }
        });

        let mut stdin = child.stdin.take().unwrap();
        let request = [0, 1, 2, 255, 10];
        stdin.write_all(&wrapper_launch.stdin_prefix).unwrap();
        stdin.write_all(&request).unwrap();
        stdin.flush().unwrap();

        // This is a deadlock watchdog, not a process-startup performance
        // contract. Native ARM64 hosted runners can spend several seconds in
        // PowerShell startup and Add-Type before the child is created.
        let deadline = Instant::now() + Duration::from_secs(30);
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let received_stdout = stdout_rx.recv_timeout(remaining()).unwrap_or_else(|error| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("stdout was not flushed before stdin EOF: {error}");
        });
        assert_eq!(received_stdout.unwrap(), request);
        let received_stderr = stderr_rx.recv_timeout(remaining()).unwrap_or_else(|error| {
            let _ = child.kill();
            let _ = child.wait();
            panic!("stderr was not flushed before stdin EOF: {error}");
        });
        received_stderr.unwrap();

        drop(stdin);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("PowerShell process pump did not exit after stdin EOF");
            }
            thread::sleep(Duration::from_millis(10));
        };
        stdout_reader.join().unwrap();
        stderr_reader.join().unwrap();
        assert_eq!(status.code(), Some(37));
    }

    #[cfg(windows)]
    #[test]
    fn powershell_process_resolves_relative_program_against_working_directory_without_noise() {
        use std::io::{Read as _, Write as _};
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, Instant};

        let child_dir = tempfile::tempdir().unwrap();
        let child_source_path = child_dir.path().join("nrm-relative-child.rs");
        let child_path = child_dir.path().join("nrm-relative-child.exe");
        std::fs::write(
            &child_source_path,
            r#"use std::io::Write;
fn main() {
    std::io::stdout().write_all(&[0, 255, 1, 10]).unwrap();
    std::io::stdout().flush().unwrap();
    std::process::exit(29);
}"#,
        )
        .unwrap();
        let compile = Command::new("rustc")
            .arg(&child_source_path)
            .arg("-o")
            .arg(&child_path)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let launch = powershell_process_command(
            r".\nrm-relative-child.exe",
            &[],
            Some(&child_dir.path().to_string_lossy()),
            None,
        )
        .unwrap();
        let encoded = launch.command.split_whitespace().last().unwrap();
        let mut wrapper = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = crate::bom_reader::LeadingBomReader::new(wrapper.stdout.take().unwrap());
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let mut stderr = wrapper.stderr.take().unwrap();
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        let mut stdin = wrapper.stdin.take().unwrap();
        stdin.write_all(&launch.stdin_prefix).unwrap();
        stdin.flush().unwrap();
        drop(stdin);

        let timeout = Duration::from_secs(10);
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = wrapper.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = wrapper.kill();
                let _ = wrapper.wait();
                panic!("relative-path PowerShell process did not exit");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = stdout_reader.join().unwrap().unwrap();
        let stderr = stderr_reader.join().unwrap().unwrap();
        assert_eq!(stdout, [0, 255, 1, 10]);
        assert!(
            stderr.is_empty(),
            "unexpected PowerShell stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(status.code(), Some(29));
    }

    #[cfg(windows)]
    #[test]
    fn powershell_process_job_kills_child_when_wrapper_is_terminated() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, Instant};

        let child_dir = tempfile::tempdir().unwrap();
        let child_source_path = child_dir.path().join("nrm-job-child.rs");
        let child_path = child_dir.path().join("nrm-job-child.exe");
        let lock_path = child_dir.path().join("held.lock");
        let ready_path = child_dir.path().join("ready.pid");
        std::fs::write(
            &child_source_path,
            r#"use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::time::Duration;
fn main() {
    let mut args = std::env::args_os().skip(1);
    let lock_path = args.next().unwrap();
    let ready_path = args.next().unwrap();
    let _lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .share_mode(0)
        .open(lock_path)
        .unwrap();
    std::fs::write(ready_path, std::process::id().to_string()).unwrap();
    loop { std::thread::sleep(Duration::from_secs(60)); }
}"#,
        )
        .unwrap();
        let compile = Command::new("rustc")
            .arg(&child_source_path)
            .arg("-o")
            .arg(&child_path)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let launch = powershell_process_command(
            &child_path.to_string_lossy(),
            &[
                lock_path.to_string_lossy().into_owned(),
                ready_path.to_string_lossy().into_owned(),
            ],
            None,
            None,
        )
        .unwrap();
        let encoded = launch.command.split_whitespace().last().unwrap();
        let mut wrapper = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = wrapper.stdin.take().unwrap();
        stdin.write_all(&launch.stdin_prefix).unwrap();
        stdin.flush().unwrap();

        let timeout = Duration::from_secs(15);
        let ready_deadline = Instant::now() + timeout;
        while !ready_path.exists() {
            if let Some(status) = wrapper.try_wait().unwrap() {
                panic!("PowerShell wrapper exited before child readiness: {status}");
            }
            assert!(
                Instant::now() < ready_deadline,
                "timed out waiting for child readiness"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let child_pid = std::fs::read_to_string(&ready_path).unwrap();

        wrapper.kill().unwrap();
        wrapper.wait().unwrap();
        drop(stdin);

        let cleanup_deadline = Instant::now() + timeout;
        loop {
            match std::fs::remove_file(&lock_path) {
                Ok(()) => break,
                Err(error) if Instant::now() < cleanup_deadline => {
                    thread::sleep(Duration::from_millis(10));
                    let _ = error;
                }
                Err(error) => {
                    let _ = Command::new("taskkill")
                        .args(["/PID", child_pid.trim(), "/T", "/F"])
                        .output();
                    panic!("job child still held its lock after wrapper exit: {error}");
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn powershell_process_reaps_pipe_holding_descendants_after_exit_or_relay_failure() {
        use std::io::{Read as _, Write as _};
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, Instant};

        const DESCENDANTS: usize = 6;
        const ITERATIONS: usize = 3;
        let directory = tempfile::tempdir().unwrap();
        let fixture_source = directory.path().join("nrm-descendant-fixture.rs");
        let fixture = directory.path().join("nrm-descendant-fixture.exe");
        std::fs::write(
            &fixture_source,
            r#"use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::process::Command;
use std::time::{Duration, Instant};

const DESCENDANTS: usize = 6;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("child")) {
        let lock_path = arguments.next().unwrap();
        let ready_path = arguments.next().unwrap();
        let _lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(lock_path)
            .unwrap();
        fs::write(ready_path, std::process::id().to_string()).unwrap();
        loop { std::thread::sleep(Duration::from_secs(60)); }
    }

    let root = arguments.next().unwrap();
    let executable = std::env::current_exe().unwrap();
    for index in 0..DESCENDANTS {
        let lock = std::path::Path::new(&root).join(format!("child-{index}.lock"));
        let ready = std::path::Path::new(&root).join(format!("child-{index}.ready"));
        Command::new(&executable)
            .args([std::ffi::OsStr::new("child"), lock.as_os_str(), ready.as_os_str()])
            .spawn()
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if (0..DESCENDANTS).all(|index| {
            std::path::Path::new(&root)
                .join(format!("child-{index}.ready"))
                .exists()
        }) {
            break;
        }
        if Instant::now() >= deadline { std::process::exit(90); }
        std::thread::sleep(Duration::from_millis(10));
    }
    println!("primary-output");
    eprintln!("primary-error");
    std::process::exit(37);
}"#,
        )
        .unwrap();
        let compile = Command::new("rustc")
            .arg(&fixture_source)
            .arg("-o")
            .arg(&fixture)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        for iteration in 0..ITERATIONS {
            let run_directory = directory.path().join(format!("run-{iteration}"));
            std::fs::create_dir(&run_directory).unwrap();
            let launch = powershell_process_command(
                &fixture.to_string_lossy(),
                &[
                    "parent".to_string(),
                    run_directory.to_string_lossy().into_owned(),
                ],
                None,
                None,
            )
            .unwrap();
            let encoded = launch.command.split_whitespace().last().unwrap();
            let mut wrapper = Command::new("powershell.exe")
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    encoded,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = wrapper.stdin.take().unwrap();
            stdin.write_all(&launch.stdin_prefix).unwrap();
            stdin.flush().unwrap();
            drop(stdin);
            let force_relay_failure = iteration == ITERATIONS - 1;
            let stdout_reader = if force_relay_failure {
                drop(wrapper.stdout.take().unwrap());
                None
            } else {
                let mut stdout = wrapper.stdout.take().unwrap();
                Some(thread::spawn(move || {
                    let mut bytes = Vec::new();
                    stdout.read_to_end(&mut bytes).map(|_| bytes)
                }))
            };
            let mut stderr = wrapper.stderr.take().unwrap();
            let stderr_reader = thread::spawn(move || {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).map(|_| bytes)
            });

            let timeout = Duration::from_secs(15);
            let deadline = Instant::now() + timeout;
            let status = loop {
                if let Some(status) = wrapper.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    let _ = wrapper.kill();
                    let _ = wrapper.wait();
                    for index in 0..DESCENDANTS {
                        let ready = run_directory.join(format!("child-{index}.ready"));
                        if let Ok(pid) = std::fs::read_to_string(ready) {
                            let _ = Command::new("taskkill")
                                .args(["/PID", pid.trim(), "/T", "/F"])
                                .output();
                        }
                    }
                    panic!(
                        "PowerShell relay retained descendant pipes after primary exit or relay failure in iteration {iteration}"
                    );
                }
                thread::sleep(Duration::from_millis(10));
            };
            let stdout = stdout_reader
                .map(|reader| reader.join().unwrap().unwrap())
                .unwrap_or_default();
            let stderr = stderr_reader.join().unwrap().unwrap();
            if force_relay_failure {
                assert!(!status.success(), "iteration {iteration}");
                assert!(stdout.is_empty(), "iteration {iteration}");
                assert!(
                    String::from_utf8_lossy(&stderr).contains("standard stream relay failed"),
                    "iteration {iteration}: {}",
                    String::from_utf8_lossy(&stderr)
                );
            } else {
                assert_eq!(status.code(), Some(37), "iteration {iteration}");
                assert_eq!(stdout, b"primary-output\n", "iteration {iteration}");
                assert_eq!(stderr, b"primary-error\n", "iteration {iteration}");
            }

            for index in 0..DESCENDANTS {
                let ready = run_directory.join(format!("child-{index}.ready"));
                assert!(ready.exists(), "descendant {index} never became ready");
                let lock = run_directory.join(format!("child-{index}.lock"));
                let cleanup_deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match std::fs::remove_file(&lock) {
                        Ok(()) => break,
                        Err(error) if Instant::now() < cleanup_deadline => {
                            let _ = error;
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!(
                            "descendant {index} still held its lock after relay exit: {error}"
                        ),
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn powershell_process_runs_batch_applications_without_cmd_injection() {
        use std::io::{Read as _, Write as _};
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let capture_source = directory.path().join("nrm-batch-capture.rs");
        let capture = directory.path().join("nrm-batch-capture.exe");
        std::fs::write(
            &capture_source,
            r#"use std::io::Write as _;
fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&(arguments.len() as u32).to_le_bytes()).unwrap();
    for argument in arguments {
        let bytes = argument.as_bytes();
        stdout.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
        stdout.write_all(bytes).unwrap();
    }
    stdout.flush().unwrap();
}"#,
        )
        .unwrap();
        let compile = Command::new("rustc")
            .arg(&capture_source)
            .arg("-o")
            .arg(&capture)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let batch = directory.path().join("nrm-batch-shim.CmD");
        let capture_text = capture.to_string_lossy();
        assert!(!capture_text.contains(['"', '%']));
        std::fs::write(
            &batch,
            format!("@echo off\r\n\"{capture_text}\" %*\r\nexit /b %ERRORLEVEL%\r\n"),
        )
        .unwrap();

        let run = |launch: &PowerShellProcessCommand| {
            let encoded = launch.command.split_whitespace().last().unwrap();
            let mut wrapper = Command::new("powershell.exe")
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    encoded,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = wrapper.stdin.take().unwrap();
            stdin.write_all(&launch.stdin_prefix).unwrap();
            stdin.flush().unwrap();
            drop(stdin);
            let mut stdout = wrapper.stdout.take().unwrap();
            let stdout_reader = thread::spawn(move || {
                let mut bytes = Vec::new();
                stdout.read_to_end(&mut bytes).map(|_| bytes)
            });
            let mut stderr = wrapper.stderr.take().unwrap();
            let stderr_reader = thread::spawn(move || {
                let mut bytes = Vec::new();
                stderr.read_to_end(&mut bytes).map(|_| bytes)
            });

            let timeout = Duration::from_secs(15);
            let deadline = Instant::now() + timeout;
            let status = loop {
                if let Some(status) = wrapper.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    let _ = wrapper.kill();
                    let _ = wrapper.wait();
                    let stdout = stdout_reader.join().unwrap().unwrap();
                    let stderr = stderr_reader.join().unwrap().unwrap();
                    panic!(
                        "batch PowerShell process did not exit within {timeout:?}; stdout: {}; stderr: {}",
                        String::from_utf8_lossy(&stdout),
                        String::from_utf8_lossy(&stderr)
                    );
                }
                thread::sleep(Duration::from_millis(10));
            };
            let stdout = stdout_reader.join().unwrap().unwrap();
            let stderr = stderr_reader.join().unwrap().unwrap();
            (status, stdout, stderr)
        };

        let arguments = vec![
            String::new(),
            "two words".to_string(),
            "amp&pipe|less<than>parens()caret^bang!".to_string(),
            "single'quote".to_string(),
            r"trailing\".to_string(),
        ];
        let launch = powershell_process_command(
            &batch.to_string_lossy(),
            &arguments,
            Some(&directory.path().to_string_lossy()),
            None,
        )
        .unwrap();
        let (status, stdout, stderr) = run(&launch);
        assert!(
            status.success(),
            "batch trampoline failed with {status}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            stderr.is_empty(),
            "unexpected batch trampoline stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        let mut expected = (arguments.len() as u32).to_le_bytes().to_vec();
        for argument in &arguments {
            expected.extend_from_slice(&(argument.len() as u32).to_le_bytes());
            expected.extend_from_slice(argument.as_bytes());
        }
        assert_eq!(stdout, expected);

        let bare_launch = powershell_process_command(
            "nrm-batch-shim",
            &arguments,
            Some(&directory.path().to_string_lossy()),
            Some(&directory.path().to_string_lossy()),
        )
        .unwrap();
        let (bare_status, bare_stdout, bare_stderr) = run(&bare_launch);
        assert!(
            bare_status.success(),
            "bare batch shim failed with {bare_status}: {}",
            String::from_utf8_lossy(&bare_stderr)
        );
        assert!(
            bare_stderr.is_empty(),
            "unexpected bare batch shim stderr: {}",
            String::from_utf8_lossy(&bare_stderr)
        );
        assert_eq!(bare_stdout, expected);

        let sentinel = directory.path().join("nrm-batch-injection-sentinel");
        let sentinel_text = sentinel.to_string_lossy();
        assert!(!sentinel_text
            .chars()
            .any(|character| { character.is_whitespace() || matches!(character, '"' | '%') }));
        let hostile = [
            (
                r#"quote" & whoami"#.to_string(),
                "double quotes or percent signs",
            ),
            (
                "%PATH% & whoami".to_string(),
                "double quotes or percent signs",
            ),
            (
                format!("line\r\n&echo injected>{sentinel_text}"),
                "control characters",
            ),
            (
                format!("c1\u{0085}&echo injected>{sentinel_text}"),
                "control characters",
            ),
        ];
        for (hostile, expected_error) in hostile {
            let batch_text = batch.to_string_lossy();
            let directory_text = directory.path().to_string_lossy();
            let arguments = vec![hostile];
            let launch = if arguments[0].chars().any(char::is_control) {
                assert!(
                    powershell_process_command(
                        &batch_text,
                        &arguments,
                        Some(&directory_text),
                        None,
                    )
                    .is_err(),
                    "the Rust planner must reject control characters before transport"
                );

                // Exercise the embedded relay independently of the Rust-side
                // preflight. A malformed or non-Rust peer must not be able to
                // turn JSON controls followed by cmd metacharacters into code.
                let template =
                    powershell_process_command(&batch_text, &[], Some(&directory_text), None)
                        .unwrap();
                let command_arguments = [vec![batch_text.into_owned()], arguments.clone()].concat();
                let payload = serde_json::to_vec(&ProcessPayload {
                    program: &command_arguments[0],
                    arguments: &arguments,
                    command_line: windows_join_arguments(&command_arguments),
                    cwd: Some(&directory_text),
                    path_prepend: None,
                    agent_launch_diagnostics: false,
                    agent_root: None,
                })
                .unwrap();
                let compressed = STANDARD
                    .decode(POWERSHELL_PROCESS_SCRIPT_GZIP_BASE64)
                    .unwrap();
                let mut stdin_prefix = Vec::with_capacity(12 + compressed.len() + payload.len());
                stdin_prefix.extend_from_slice(&POWERSHELL_BOOTSTRAP_MAGIC);
                stdin_prefix.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
                stdin_prefix.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                stdin_prefix.extend_from_slice(&compressed);
                stdin_prefix.extend_from_slice(&payload);
                PowerShellProcessCommand {
                    command: template.command,
                    stdin_prefix,
                }
            } else {
                powershell_process_command(&batch_text, &arguments, Some(&directory_text), None)
                    .unwrap()
            };
            let (status, stdout, stderr) = run(&launch);
            assert!(!status.success(), "hostile batch argument was accepted");
            assert!(stdout.is_empty(), "rejected batch command unexpectedly ran");
            assert!(String::from_utf8_lossy(&stderr).contains(expected_error));
            assert!(!sentinel.exists(), "hostile batch argument executed");
        }
    }

    #[test]
    fn windows_argument_quoting_handles_empty_spaces_quotes_and_trailing_slashes() {
        assert_eq!(windows_quote_argument("plain"), "plain");
        assert_eq!(windows_quote_argument(""), "\"\"");
        assert_eq!(windows_quote_argument("two words"), "\"two words\"");
        assert_eq!(windows_quote_argument("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(
            windows_quote_argument("path with slash\\"),
            "\"path with slash\\\\\""
        );
    }
}
