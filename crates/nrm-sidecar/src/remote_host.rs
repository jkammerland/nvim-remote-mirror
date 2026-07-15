use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::Path;

const PROBE_SCHEMA_VERSION: u8 = 1;
const WINDOWS_REMOTE_COMMAND_MAX_CHARS: usize = 8_191;
const POWERSHELL_BOOTSTRAP_MAGIC: [u8; 4] = *b"NRM1";
const POWERSHELL_BOOTSTRAP_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RemotePathStyle {
    Posix,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RemoteHostInfo {
    pub(crate) os: String,
    pub(crate) arch: String,
    pub(crate) shell: String,
    pub(crate) home: String,
    pub(crate) local_app_data: Option<String>,
    pub(crate) path_style: RemotePathStyle,
    pub(crate) target: String,
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
        lock (state.Gate)
            state.Exited = true;
        outputPump.Join();
        errorPump.Join();
        lock (state.Gate)
        {
            if (state.Failure != null)
                throw new System.IO.IOException("standard stream relay failed", state.Failure);
        }
        uint exitCode;
        if (!GetExitCodeProcess(process, out exitCode))
            throw Error("exit-code read failed");
        return unchecked((int)exitCode);
    }
    finally
    {
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
    # batch path and argv as data, quote every value, and reject the two cmd.exe
    # expansion characters that cannot be represented safely in this fixed
    # trampoline. Other metacharacters remain inert inside their own quotes.
    $batchValues = @([string]$applicationName) + @($payload.arguments)
    foreach ($value in $batchValues) {
      $text = [string]$value
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
    build_host_info(
        os,
        arch,
        if windows { "powershell" } else { "sh" },
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
    reject_field_controls("home", &home)?;
    if let Some(local_app_data) = &local_app_data {
        reject_field_controls("local_app_data", local_app_data)?;
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
            let info = build_host_info(os, arch, "test", "/home".to_string(), None, style).unwrap();
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

        for hostile in [r#"quote" & whoami"#, "%PATH% & whoami"] {
            let launch = powershell_process_command(
                &batch.to_string_lossy(),
                &[hostile.to_string()],
                Some(&directory.path().to_string_lossy()),
                None,
            )
            .unwrap();
            let (status, stdout, stderr) = run(&launch);
            assert!(!status.success(), "hostile batch argument was accepted");
            assert!(stdout.is_empty(), "rejected batch command unexpectedly ran");
            assert!(String::from_utf8_lossy(&stderr).contains(
                "batch application paths and arguments must not contain double quotes or percent signs"
            ));
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
