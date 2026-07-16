//! Cross-platform pseudoterminal processes for the remote runtime.
//!
//! The public API deliberately exposes byte streams rather than text. Terminal
//! encodings and escape sequences belong to the frontend, and must not be
//! interpreted by this crate.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

/// Maximum number of arguments accepted by one process request.
pub const MAX_ARGUMENTS: usize = 1_024;
/// Maximum number of explicit environment edits accepted by one request.
pub const MAX_ENVIRONMENT_EDITS: usize = 2_048;
/// Maximum aggregate size of the program, arguments, cwd, and environment.
pub const MAX_COMMAND_BYTES: usize = 256 * 1024;

/// Initial or updated pseudoterminal dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl PtySize {
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        }
    }

    fn validate(self) -> Result<Self, PtyError> {
        if self.rows == 0
            || self.cols == 0
            || self.rows > i16::MAX as u16
            || self.cols > i16::MAX as u16
        {
            return Err(PtyError::InvalidSize {
                rows: self.rows,
                cols: self.cols,
            });
        }
        Ok(self)
    }
}

impl Default for PtySize {
    fn default() -> Self {
        Self::new(24, 80)
    }
}

/// A process command with explicit argument and environment boundaries.
#[derive(Clone, Debug)]
pub struct PtyCommand {
    program: OsString,
    args: Vec<OsString>,
    cwd: Option<PathBuf>,
    clear_environment: bool,
    environment: Vec<(OsString, Option<OsString>)>,
}

impl PtyCommand {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            clear_environment: false,
            environment: Vec::new(),
        }
    }

    pub fn arg(&mut self, argument: impl Into<OsString>) -> &mut Self {
        self.args.push(argument.into());
        self
    }

    pub fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn current_dir(&mut self, directory: impl Into<PathBuf>) -> &mut Self {
        self.cwd = Some(directory.into());
        self
    }

    pub fn env(&mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> &mut Self {
        self.environment.push((key.into(), Some(value.into())));
        self
    }

    pub fn env_remove(&mut self, key: impl Into<OsString>) -> &mut Self {
        self.environment.push((key.into(), None));
        self
    }

    pub fn env_clear(&mut self) -> &mut Self {
        self.clear_environment = true;
        self.environment.clear();
        self
    }

    pub fn program(&self) -> &OsStr {
        &self.program
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }

    pub fn cwd(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    pub fn clears_environment(&self) -> bool {
        self.clear_environment
    }

    pub fn environment(&self) -> &[(OsString, Option<OsString>)] {
        &self.environment
    }

    fn validate(&self) -> Result<(), PtyError> {
        if self.program.is_empty() {
            return Err(PtyError::EmptyProgram);
        }
        reject_nul("program", &self.program)?;
        if self.args.len() > MAX_ARGUMENTS {
            return Err(PtyError::TooManyArguments {
                actual: self.args.len(),
                maximum: MAX_ARGUMENTS,
            });
        }
        if self.environment.len() > MAX_ENVIRONMENT_EDITS {
            return Err(PtyError::TooManyEnvironmentEdits {
                actual: self.environment.len(),
                maximum: MAX_ENVIRONMENT_EDITS,
            });
        }
        for argument in &self.args {
            reject_nul("argument", argument)?;
        }
        if let Some(cwd) = &self.cwd {
            reject_nul("cwd", cwd.as_os_str())?;
        }
        for (index, (key, value)) in self.environment.iter().enumerate() {
            if key.is_empty() || os_contains_byte(key, b'=') || os_contains_nul(key) {
                return Err(PtyError::InvalidEnvironmentName);
            }
            if self.environment[..index]
                .iter()
                .any(|(existing, _)| platform::environment_names_equal(existing, key))
            {
                return Err(PtyError::DuplicateEnvironmentName);
            }
            if let Some(value) = value {
                reject_nul("environment value", value)?;
            }
        }

        let mut bytes = os_len(&self.program);
        bytes = checked_add(bytes, self.args.iter().map(|value| os_len(value)))?;
        bytes = checked_add(
            bytes,
            self.cwd.iter().map(|value| os_len(value.as_os_str())),
        )?;
        bytes = checked_add(
            bytes,
            self.environment.iter().flat_map(|(key, value)| {
                std::iter::once(os_len(key)).chain(value.iter().map(|value| os_len(value)))
            }),
        )?;
        if bytes > MAX_COMMAND_BYTES {
            return Err(PtyError::CommandTooLarge {
                actual: bytes,
                maximum: MAX_COMMAND_BYTES,
            });
        }
        platform::validate_command(self)
    }
}

fn checked_add(start: usize, values: impl IntoIterator<Item = usize>) -> Result<usize, PtyError> {
    values.into_iter().try_fold(start, |total, value| {
        total.checked_add(value).ok_or(PtyError::CommandTooLarge {
            actual: usize::MAX,
            maximum: MAX_COMMAND_BYTES,
        })
    })
}

fn reject_nul(field: &'static str, value: &OsStr) -> Result<(), PtyError> {
    if os_contains_nul(value) {
        Err(PtyError::EmbeddedNul { field })
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn os_len(value: &OsStr) -> usize {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_bytes().len()
}

#[cfg(unix)]
fn os_contains_nul(value: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_bytes().contains(&0)
}

#[cfg(unix)]
fn os_contains_byte(value: &OsStr, byte: u8) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_bytes().contains(&byte)
}

#[cfg(windows)]
fn os_len(value: &OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt as _;
    value.encode_wide().count().saturating_mul(2)
}

#[cfg(windows)]
fn os_contains_nul(value: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt as _;
    value.encode_wide().any(|unit| unit == 0)
}

#[cfg(windows)]
fn os_contains_byte(value: &OsStr, byte: u8) -> bool {
    use std::os::windows::ffi::OsStrExt as _;
    value.encode_wide().any(|unit| unit == u16::from(byte))
}

/// Signals supported by the portable process handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtySignal {
    Interrupt,
    Hangup,
    Terminate,
    Kill,
    Continue,
}

/// Cross-platform exit information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtyExitStatus {
    pub code: Option<u32>,
    /// POSIX signal number. Always `None` on Windows.
    pub signal: Option<i32>,
}

impl PtyExitStatus {
    pub fn success(self) -> bool {
        self.code == Some(0) && self.signal.is_none()
    }
}

/// The terminal input stream. Bytes are forwarded without transcoding.
pub struct PtyInput(platform::Input);

impl Write for PtyInput {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl PtyInput {
    /// Prepare writes for cancellation-aware retry by a runtime worker.
    pub fn prepare_cancellable_write(&self) -> std::io::Result<()> {
        platform::prepare_input_cancellation(&self.0)
    }
}

/// The terminal output stream. PTYs merge stdout and stderr by design.
pub struct PtyOutput(platform::Output);

impl Read for PtyOutput {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

impl PtyOutput {
    /// Prepare this stream for a reader that must be able to stop after the
    /// owned process has exited even if an intentionally detached descendant
    /// retains a copy of the terminal descriptor.
    pub fn prepare_cancellable_read(&self) -> std::io::Result<()> {
        platform::prepare_output_cancellation(&self.0)
    }
}

/// A process attached to a native pseudoterminal.
pub struct PtyProcess {
    inner: platform::Process,
    input: Option<PtyInput>,
    output: Option<PtyOutput>,
}

/// The stdin stream for a non-PTY process.
pub struct PipeInput(platform::PipeInput);

impl Write for PipeInput {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl PipeInput {
    /// Prepare writes for cancellation-aware retry by a runtime worker.
    pub fn prepare_cancellable_write(&self) -> std::io::Result<()> {
        platform::prepare_pipe_input_cancellation(&self.0)
    }
}

/// One raw output stream from a non-PTY process.
pub struct PipeOutput(platform::PipeOutput);

impl Read for PipeOutput {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

impl PipeOutput {
    /// Prepare this stream for bounded post-exit draining.
    pub fn prepare_cancellable_read(&self) -> std::io::Result<()> {
        platform::prepare_pipe_output_cancellation(&self.0)
    }
}

/// A process with separate binary stdin, stdout, and stderr pipes.
pub struct PipeProcess {
    inner: platform::PipeProcess,
    input: Option<PipeInput>,
    stdout: Option<PipeOutput>,
    stderr: Option<PipeOutput>,
}

impl PipeProcess {
    pub fn spawn(command: &PtyCommand) -> Result<Self, PtyError> {
        command.validate()?;
        let spawned = platform::spawn_pipe(command)?;
        Ok(Self {
            inner: spawned.process,
            input: Some(PipeInput(spawned.input)),
            stdout: Some(PipeOutput(spawned.stdout)),
            stderr: Some(PipeOutput(spawned.stderr)),
        })
    }

    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    pub fn take_input(&mut self) -> Option<PipeInput> {
        self.input.take()
    }

    pub fn take_stdout(&mut self) -> Option<PipeOutput> {
        self.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<PipeOutput> {
        self.stderr.take()
    }

    pub fn signal(&mut self, signal: PtySignal) -> Result<(), PtyError> {
        self.inner.signal(signal)
    }

    pub fn try_wait(&mut self) -> Result<Option<PtyExitStatus>, PtyError> {
        self.inner.try_wait()
    }

    pub fn wait(&mut self) -> Result<PtyExitStatus, PtyError> {
        self.inner.wait()
    }
}

impl PtyProcess {
    pub fn spawn(command: &PtyCommand, size: PtySize) -> Result<Self, PtyError> {
        command.validate()?;
        let size = size.validate()?;
        let spawned = platform::spawn(command, size)?;
        Ok(Self {
            inner: spawned.process,
            input: Some(PtyInput(spawned.input)),
            output: Some(PtyOutput(spawned.output)),
        })
    }

    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    pub fn take_input(&mut self) -> Option<PtyInput> {
        self.input.take()
    }

    pub fn take_output(&mut self) -> Option<PtyOutput> {
        let output = self.output.take();
        #[cfg(windows)]
        if let Some(output) = &output {
            output.0.mark_taken();
        }
        output
    }

    pub fn resize(&self, size: PtySize) -> Result<(), PtyError> {
        self.inner.resize(size.validate()?)
    }

    pub fn signal(&mut self, signal: PtySignal) -> Result<(), PtyError> {
        self.inner.signal(signal)
    }

    pub fn try_wait(&mut self) -> Result<Option<PtyExitStatus>, PtyError> {
        self.inner.try_wait()
    }

    pub fn wait(&mut self) -> Result<PtyExitStatus, PtyError> {
        self.inner.wait()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("PTY program must not be empty")]
    EmptyProgram,
    #[error("invalid PTY size {rows}x{cols}; rows and columns must be between 1 and 32767")]
    InvalidSize { rows: u16, cols: u16 },
    #[error("too many process arguments: {actual} exceeds {maximum}")]
    TooManyArguments { actual: usize, maximum: usize },
    #[error("too many environment edits: {actual} exceeds {maximum}")]
    TooManyEnvironmentEdits { actual: usize, maximum: usize },
    #[error("process command is too large: {actual} bytes exceeds {maximum}")]
    CommandTooLarge { actual: usize, maximum: usize },
    #[error("Windows process command line is too large: {actual} UTF-16 units exceeds {maximum}")]
    CommandLineTooLarge { actual: usize, maximum: usize },
    #[error("process value {field} contains a NUL character")]
    EmbeddedNul { field: &'static str },
    #[error("invalid environment variable name")]
    InvalidEnvironmentName,
    #[error("duplicate environment variable name")]
    DuplicateEnvironmentName,
    #[error("PTY operation {operation} is unsupported on this platform")]
    Unsupported { operation: &'static str },
    #[error("PTY {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

impl PtyError {
    pub(crate) fn io(operation: &'static str, source: std::io::Error) -> Self {
        Self::Io { operation, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_rejects_empty_dimensions() {
        assert!(matches!(
            PtySize::new(0, 80).validate(),
            Err(PtyError::InvalidSize { rows: 0, cols: 80 })
        ));
        assert!(matches!(
            PtySize::new(24, 0).validate(),
            Err(PtyError::InvalidSize { rows: 24, cols: 0 })
        ));
        assert!(matches!(
            PtySize::new(24, u16::MAX).validate(),
            Err(PtyError::InvalidSize { .. })
        ));
    }

    #[test]
    fn command_limits_argument_count() {
        let mut boundary = PtyCommand::new("ignored");
        boundary.args(std::iter::repeat_n("x", MAX_ARGUMENTS));
        boundary.validate().expect("maximum argument count");

        let mut command = PtyCommand::new("ignored");
        command.args(std::iter::repeat_n("x", MAX_ARGUMENTS + 1));
        assert!(matches!(
            command.validate(),
            Err(PtyError::TooManyArguments { .. })
        ));
    }

    #[test]
    fn command_limits_aggregate_size() {
        let command = PtyCommand::new("x".repeat(MAX_COMMAND_BYTES + 1));
        assert!(matches!(
            command.validate(),
            Err(PtyError::CommandTooLarge { .. })
        ));
    }

    #[test]
    fn command_rejects_nul_and_invalid_environment_names() {
        let command = PtyCommand::new("bad\0program");
        assert!(matches!(
            command.validate(),
            Err(PtyError::EmbeddedNul { field: "program" })
        ));

        let mut command = PtyCommand::new("valid");
        command.env("BAD=NAME", "value");
        assert!(matches!(
            command.validate(),
            Err(PtyError::InvalidEnvironmentName)
        ));

        let mut command = PtyCommand::new("valid");
        command.env("NAME", "one").env_remove("NAME");
        assert!(matches!(
            command.validate(),
            Err(PtyError::DuplicateEnvironmentName)
        ));

        let mut command = PtyCommand::new("valid");
        command.env("NAME", "bad\0value");
        assert!(matches!(
            command.validate(),
            Err(PtyError::EmbeddedNul {
                field: "environment value"
            })
        ));
    }

    #[test]
    fn command_limits_environment_edit_count() {
        let mut boundary = PtyCommand::new("ignored");
        for index in 0..MAX_ENVIRONMENT_EDITS {
            boundary.env(format!("NRM_{index}"), "x");
        }
        boundary.validate().expect("maximum environment edits");

        boundary.env("NRM_OVERFLOW", "x");
        assert!(matches!(
            boundary.validate(),
            Err(PtyError::TooManyEnvironmentEdits { .. })
        ));
    }
}
