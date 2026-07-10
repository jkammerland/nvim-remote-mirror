use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::Path;

const PROBE_SCHEMA_VERSION: u8 = 1;

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
    arguments: String,
    cwd: Option<&'a str>,
    path_prepend: Option<&'a str>,
}

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
) -> Result<String> {
    reject_process_field("program", program)?;
    for arg in args {
        reject_process_field("argument", arg)?;
    }
    if let Some(cwd) = cwd {
        reject_process_field("working directory", cwd)?;
    }
    if let Some(path_prepend) = path_prepend {
        reject_process_field("PATH prefix", path_prepend)?;
    }

    let payload = ProcessPayload {
        program,
        arguments: windows_join_arguments(args),
        cwd,
        path_prepend,
    };
    let payload = STANDARD.encode(serde_json::to_vec(&payload)?);
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$payloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{payload}'))
$payload = $payloadJson | ConvertFrom-Json
$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = [string]$payload.program
$start.Arguments = [string]$payload.arguments
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
if ($null -ne $payload.cwd -and [string]$payload.cwd -ne '') {{ $start.WorkingDirectory = [string]$payload.cwd }}
if ($null -ne $payload.path_prepend -and [string]$payload.path_prepend -ne '') {{
  $start.EnvironmentVariables['PATH'] = ([string]$payload.path_prepend) + ';' + $start.EnvironmentVariables['PATH']
}}
$process = New-Object System.Diagnostics.Process
$process.StartInfo = $start
if (-not $process.Start()) {{ throw 'failed to start remote process' }}
$stdinTask = [Console]::OpenStandardInput().CopyToAsync($process.StandardInput.BaseStream)
$stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync([Console]::OpenStandardOutput())
$stderrTask = $process.StandardError.BaseStream.CopyToAsync([Console]::OpenStandardError())
$stdinClosed = $false
while (-not $process.HasExited) {{
  if (-not $stdinClosed -and $stdinTask.IsCompleted) {{
    $process.StandardInput.Close()
    $stdinClosed = $true
  }}
  if (-not $process.HasExited) {{ Start-Sleep -Milliseconds 10 }}
}}
$process.WaitForExit()
if (-not $stdinClosed) {{ $process.StandardInput.Close() }}
[System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
exit $process.ExitCode"#
    );
    Ok(powershell_encoded_command(&script))
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

fn powershell_encoded_command(script: &str) -> String {
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
    fn powershell_process_payload_does_not_interpolate_user_input() {
        let program = r#"C:\Program Files\Agent ' ; Write-Output owned.exe"#;
        let args = vec![
            "serve".to_string(),
            "--root".to_string(),
            r#"B:/repo ' ; $(owned) \"quoted\""#.to_string(),
        ];
        let command = powershell_process_command(
            program,
            &args,
            Some("B:/repo with space"),
            Some(r"C:\Users\me\AppData\Local\nrm\bin"),
        )
        .unwrap();
        assert!(!command.contains("owned"));
        let script = decode_encoded_command(&command);
        assert!(!script.contains("Write-Output owned"));
        assert!(!script.contains("$(owned)"));
        assert!(script.contains("CopyToAsync"));
        assert!(script.contains("RedirectStandardInput"));
        assert!(script.contains("$stdinTask.IsCompleted"));
        assert!(
            script.find("$stdinTask.IsCompleted").unwrap()
                < script.find("$process.WaitForExit()").unwrap()
        );

        let marker = "FromBase64String('";
        let start = script.find(marker).unwrap() + marker.len();
        let end = script[start..].find("')").unwrap() + start;
        let payload: serde_json::Value =
            serde_json::from_slice(&STANDARD.decode(&script[start..end]).unwrap()).unwrap();
        assert_eq!(payload["program"], program);
        assert!(payload["arguments"].as_str().unwrap().contains("$(owned)"));
        assert_eq!(payload["cwd"], "B:/repo with space");
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
