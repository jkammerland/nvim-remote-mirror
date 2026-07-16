use crate::{CapabilitySet, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Read, Write};

pub const RUNTIME_MAX_FRAME_LEN: usize = 256 * 1024;
pub const RUNTIME_MAX_DATA_CHUNK_LEN: usize = 64 * 1024;
pub const RUNTIME_MAX_WATCH_EVENTS: usize = 4_096;
pub const RUNTIME_MAX_ARGV: usize = 1_024;
pub const RUNTIME_MAX_ENV_CHANGES: usize = 2_048;
pub const RUNTIME_MAX_PATH_BYTES: usize = 16 * 1024;
pub const RUNTIME_MAX_ERROR_MESSAGE_BYTES: usize = 8 * 1024;
pub const RUNTIME_MAX_PACKAGE_VERSION_BYTES: usize = 128;

pub type RuntimeRequestId = u64;
pub type RuntimeProcessId = u64;
pub type RuntimeWatchId = u64;
pub type PtySessionId = [u8; 16];
pub type PtyAttachmentToken = [u8; 32];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeCapability {
    ProcessPipeV1,
    ProcessPtyV1,
    WorkspaceWatchV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimePeerRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeOutputStream {
    Stdout,
    Stderr,
    Pty,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeSignal {
    Interrupt,
    Terminate,
    Kill,
    Hangup,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimePersistence {
    Attached,
    Detachable { ttl_ms: u64 },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerminalSize {
    pub columns: u16,
    pub rows: u16,
    pub pixel_width: Option<u32>,
    pub pixel_height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEnvironment {
    pub clear: bool,
    pub set: Vec<RuntimeEnvVar>,
    pub unset: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeCwd {
    WorkspaceRoot,
    WorkspaceRelative(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeProcessSpec {
    pub argv: Vec<String>,
    pub cwd: RuntimeCwd,
    pub env: RuntimeEnvironment,
    pub persistence: RuntimePersistence,
    pub terminal_size: Option<TerminalSize>,
    pub timeout_ms: Option<u64>,
    pub max_output_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PtySessionCredentials {
    pub session_id: PtySessionId,
    pub attachment_token: PtyAttachmentToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeExitStatus {
    Code(i32),
    Signal(u32),
    TimedOut,
    OutputLimit,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkspaceWatchEventKind {
    Created,
    Modified,
    Removed,
    Renamed { to: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceWatchEvent {
    pub path: String,
    pub kind: WorkspaceWatchEventKind,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeErrorCode {
    Protocol,
    Unsupported,
    InvalidRequest,
    SpawnFailed,
    SessionNotFound,
    SessionInUse,
    Unauthorized,
    WrongWorkspace,
    HistoryLost,
    ResourceLimit,
    PersistenceUnavailable,
    PermissionDenied,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeError {
    pub code: RuntimeErrorCode,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuntimeMessage {
    ClientHello {
        package_version: String,
        protocol_version: u16,
        capability: RuntimeCapability,
    },
    ServerHello {
        package_version: String,
        protocol_version: u16,
        capability: RuntimeCapability,
    },
    Error(RuntimeError),
    StartProcess {
        request_id: RuntimeRequestId,
        spec: RuntimeProcessSpec,
    },
    ProcessStarted {
        request_id: RuntimeRequestId,
        process_id: RuntimeProcessId,
        session: Option<PtySessionCredentials>,
        output_offset: u64,
    },
    AttachPty {
        request_id: RuntimeRequestId,
        credentials: PtySessionCredentials,
        replay_from: Option<u64>,
    },
    PtyAttached {
        request_id: RuntimeRequestId,
        process_id: RuntimeProcessId,
        session_id: PtySessionId,
        output_offset: u64,
    },
    Input {
        process_id: RuntimeProcessId,
        offset: u64,
        data: Vec<u8>,
    },
    InputAck {
        process_id: RuntimeProcessId,
        next_offset: u64,
    },
    CloseInput {
        process_id: RuntimeProcessId,
        next_offset: u64,
    },
    Output {
        process_id: RuntimeProcessId,
        stream: RuntimeOutputStream,
        offset: u64,
        data: Vec<u8>,
    },
    OutputAck {
        process_id: RuntimeProcessId,
        stream: RuntimeOutputStream,
        next_offset: u64,
    },
    OutputGap {
        process_id: RuntimeProcessId,
        requested_offset: u64,
        available_offset: u64,
        screen_snapshot: Vec<u8>,
    },
    Resize {
        process_id: RuntimeProcessId,
        size: TerminalSize,
    },
    Signal {
        process_id: RuntimeProcessId,
        signal: RuntimeSignal,
    },
    Detach {
        process_id: RuntimeProcessId,
    },
    Detached {
        process_id: RuntimeProcessId,
        session_id: PtySessionId,
    },
    Exited {
        process_id: RuntimeProcessId,
        status: RuntimeExitStatus,
        output_truncated: bool,
    },
    WatchStart {
        request_id: RuntimeRequestId,
        resume_from: Option<u64>,
    },
    WatchStarted {
        request_id: RuntimeRequestId,
        watch_id: RuntimeWatchId,
        next_sequence: u64,
    },
    WatchEvents {
        watch_id: RuntimeWatchId,
        sequence: u64,
        events: Vec<WorkspaceWatchEvent>,
    },
    WatchAck {
        watch_id: RuntimeWatchId,
        next_sequence: u64,
    },
    WatchOverflow {
        watch_id: RuntimeWatchId,
        sequence: u64,
        next_sequence: u64,
    },
    WatchStop {
        watch_id: RuntimeWatchId,
    },
    WatchStopped {
        watch_id: RuntimeWatchId,
    },
}

impl RuntimeMessage {
    pub fn validate(&self) -> Result<(), RuntimeValidationError> {
        match self {
            Self::ClientHello {
                package_version, ..
            }
            | Self::ServerHello {
                package_version, ..
            } => validate_package_version(package_version),
            Self::Error(error) => {
                if error.message.len() > RUNTIME_MAX_ERROR_MESSAGE_BYTES {
                    return Err(RuntimeValidationError::ErrorMessageTooLarge(
                        error.message.len(),
                    ));
                }
                reject_nul("error message", &error.message)
            }
            Self::StartProcess { spec, .. } => validate_process_spec(spec),
            Self::ProcessStarted { session, .. } => {
                if let Some(session) = session {
                    validate_credentials(session)?;
                }
                Ok(())
            }
            Self::AttachPty { credentials, .. } => validate_credentials(credentials),
            Self::PtyAttached { session_id, .. } | Self::Detached { session_id, .. } => {
                validate_nonzero_id("PTY session ID", session_id)
            }
            Self::Input { offset, data, .. } | Self::Output { offset, data, .. } => {
                validate_data_chunk(*offset, data)
            }
            Self::OutputGap {
                requested_offset,
                available_offset,
                screen_snapshot,
                ..
            } => {
                if available_offset <= requested_offset {
                    return Err(RuntimeValidationError::InvalidOutputGap);
                }
                validate_optional_data_chunk(screen_snapshot)
            }
            Self::Resize { size, .. } => validate_terminal_size(size),
            Self::WatchEvents { events, .. } => {
                if events.is_empty() {
                    return Err(RuntimeValidationError::EmptyWatchBatch);
                }
                if events.len() > RUNTIME_MAX_WATCH_EVENTS {
                    return Err(RuntimeValidationError::TooManyWatchEvents(events.len()));
                }
                for event in events {
                    validate_workspace_path(&event.path)?;
                    if let WorkspaceWatchEventKind::Renamed { to } = &event.kind {
                        validate_workspace_path(to)?;
                    }
                }
                Ok(())
            }
            Self::WatchOverflow {
                sequence,
                next_sequence,
                ..
            } if next_sequence <= sequence => Err(RuntimeValidationError::InvalidWatchOverflow),
            Self::InputAck { .. }
            | Self::CloseInput { .. }
            | Self::OutputAck { .. }
            | Self::Signal { .. }
            | Self::Detach { .. }
            | Self::Exited { .. }
            | Self::WatchStart { .. }
            | Self::WatchStarted { .. }
            | Self::WatchAck { .. }
            | Self::WatchOverflow { .. }
            | Self::WatchStop { .. }
            | Self::WatchStopped { .. } => Ok(()),
        }
    }

    fn sender(&self) -> RuntimePeerRole {
        match self {
            Self::ClientHello { .. }
            | Self::StartProcess { .. }
            | Self::AttachPty { .. }
            | Self::Input { .. }
            | Self::CloseInput { .. }
            | Self::OutputAck { .. }
            | Self::Resize { .. }
            | Self::Signal { .. }
            | Self::Detach { .. }
            | Self::WatchStart { .. }
            | Self::WatchAck { .. }
            | Self::WatchStop { .. } => RuntimePeerRole::Client,
            Self::ServerHello { .. }
            | Self::Error(_)
            | Self::ProcessStarted { .. }
            | Self::PtyAttached { .. }
            | Self::InputAck { .. }
            | Self::Output { .. }
            | Self::OutputGap { .. }
            | Self::Detached { .. }
            | Self::Exited { .. }
            | Self::WatchStarted { .. }
            | Self::WatchEvents { .. }
            | Self::WatchOverflow { .. }
            | Self::WatchStopped { .. } => RuntimePeerRole::Server,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::ClientHello { .. } => "client_hello",
            Self::ServerHello { .. } => "server_hello",
            Self::Error(_) => "error",
            Self::StartProcess { .. } => "start_process",
            Self::ProcessStarted { .. } => "process_started",
            Self::AttachPty { .. } => "attach_pty",
            Self::PtyAttached { .. } => "pty_attached",
            Self::Input { .. } => "input",
            Self::InputAck { .. } => "input_ack",
            Self::CloseInput { .. } => "close_input",
            Self::Output { .. } => "output",
            Self::OutputAck { .. } => "output_ack",
            Self::OutputGap { .. } => "output_gap",
            Self::Resize { .. } => "resize",
            Self::Signal { .. } => "signal",
            Self::Detach { .. } => "detach",
            Self::Detached { .. } => "detached",
            Self::Exited { .. } => "exited",
            Self::WatchStart { .. } => "watch_start",
            Self::WatchStarted { .. } => "watch_started",
            Self::WatchEvents { .. } => "watch_events",
            Self::WatchAck { .. } => "watch_ack",
            Self::WatchOverflow { .. } => "watch_overflow",
            Self::WatchStop { .. } => "watch_stop",
            Self::WatchStopped { .. } => "watch_stopped",
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RuntimeValidationError {
    #[error("runtime data chunk is empty")]
    EmptyDataChunk,
    #[error("runtime data chunk length {0} exceeds maximum {RUNTIME_MAX_DATA_CHUNK_LEN}")]
    DataChunkTooLarge(usize),
    #[error("runtime data offset overflows u64")]
    DataOffsetOverflow,
    #[error("runtime package version is empty")]
    EmptyPackageVersion,
    #[error(
        "runtime package version length {0} exceeds maximum {RUNTIME_MAX_PACKAGE_VERSION_BYTES}"
    )]
    PackageVersionTooLarge(usize),
    #[error("runtime command must contain at least one argument")]
    EmptyArgv,
    #[error("runtime command has {0} arguments, maximum is {RUNTIME_MAX_ARGV}")]
    TooManyArguments(usize),
    #[error("runtime environment has {0} changes, maximum is {RUNTIME_MAX_ENV_CHANGES}")]
    TooManyEnvironmentChanges(usize),
    #[error("runtime environment name is empty")]
    EmptyEnvironmentName,
    #[error("runtime environment name contains '='")]
    InvalidEnvironmentName,
    #[error("runtime environment name {0:?} is duplicated")]
    DuplicateEnvironmentName(String),
    #[error("{0} contains a NUL byte")]
    ContainsNul(&'static str),
    #[error("{0} contains a control character")]
    ContainsControl(&'static str),
    #[error("workspace path is empty")]
    EmptyWorkspacePath,
    #[error("workspace path length {0} exceeds maximum {RUNTIME_MAX_PATH_BYTES}")]
    WorkspacePathTooLarge(usize),
    #[error("workspace path must be canonical and relative")]
    InvalidWorkspacePath,
    #[error("terminal size must have nonzero rows and columns")]
    InvalidTerminalSize,
    #[error("terminal pixel dimensions must either both be present or both be absent")]
    IncompleteTerminalPixelSize,
    #[error("detachable runtime process must have a nonzero TTL")]
    ZeroDetachTtl,
    #[error("PTY session credential {0} must not be all zero")]
    ZeroSessionCredential(&'static str),
    #[error("runtime error message length {0} exceeds maximum {RUNTIME_MAX_ERROR_MESSAGE_BYTES}")]
    ErrorMessageTooLarge(usize),
    #[error("watch event batch is empty")]
    EmptyWatchBatch,
    #[error("watch event batch has {0} events, maximum is {RUNTIME_MAX_WATCH_EVENTS}")]
    TooManyWatchEvents(usize),
    #[error("watch overflow must advance the sequence")]
    InvalidWatchOverflow,
    #[error("output gap must advance from the requested offset")]
    InvalidOutputGap,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeFrameError {
    #[error("runtime frame length {0} exceeds maximum {RUNTIME_MAX_FRAME_LEN}")]
    TooLarge(usize),
    #[error("invalid runtime message: {0}")]
    Invalid(#[from] RuntimeValidationError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec error: {0}")]
    Codec(#[from] postcard::Error),
}

pub fn write_runtime_frame<W>(
    writer: &mut W,
    message: &RuntimeMessage,
) -> Result<(), RuntimeFrameError>
where
    W: Write,
{
    message.validate()?;
    let bytes = postcard::to_allocvec(message)?;
    if bytes.len() > RUNTIME_MAX_FRAME_LEN {
        return Err(RuntimeFrameError::TooLarge(bytes.len()));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn read_runtime_frame<R>(reader: &mut R) -> Result<RuntimeMessage, RuntimeFrameError>
where
    R: Read,
{
    let mut len_buf = [0_u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > RUNTIME_MAX_FRAME_LEN {
        return Err(RuntimeFrameError::TooLarge(len));
    }

    let mut bytes = Vec::new();
    let bytes_read = reader.by_ref().take(len as u64).read_to_end(&mut bytes)?;
    if bytes_read != len {
        return Err(RuntimeFrameError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "runtime frame body ended before advertised length",
        )));
    }
    let message: RuntimeMessage = postcard::from_bytes(&bytes)?;
    message.validate()?;
    Ok(message)
}

#[derive(Debug, Clone)]
pub struct RuntimeStateMachine {
    role: RuntimePeerRole,
    supported: CapabilitySet,
    phase: RuntimePhase,
}

impl RuntimeStateMachine {
    pub fn new(role: RuntimePeerRole, supported: CapabilitySet) -> Self {
        Self {
            role,
            supported,
            phase: RuntimePhase::AwaitClientHello,
        }
    }

    pub fn observe_inbound(&mut self, message: &RuntimeMessage) -> Result<(), RuntimeStateError> {
        self.observe(RuntimeDirection::Inbound, message)
    }

    pub fn observe_outbound(&mut self, message: &RuntimeMessage) -> Result<(), RuntimeStateError> {
        self.observe(RuntimeDirection::Outbound, message)
    }

    pub fn negotiated_capability(&self) -> Option<RuntimeCapability> {
        self.phase.capability()
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.phase, RuntimePhase::Closed)
    }

    fn observe(
        &mut self,
        direction: RuntimeDirection,
        message: &RuntimeMessage,
    ) -> Result<(), RuntimeStateError> {
        message.validate()?;
        let actual_sender = match (self.role, direction) {
            (RuntimePeerRole::Client, RuntimeDirection::Outbound)
            | (RuntimePeerRole::Server, RuntimeDirection::Inbound) => RuntimePeerRole::Client,
            (RuntimePeerRole::Client, RuntimeDirection::Inbound)
            | (RuntimePeerRole::Server, RuntimeDirection::Outbound) => RuntimePeerRole::Server,
        };
        if message.sender() != actual_sender {
            return Err(RuntimeStateError::WrongSender {
                message: message.name(),
                expected: message.sender(),
                actual: actual_sender,
            });
        }

        let mut next = self.phase.clone();
        apply_message(&mut next, &self.supported, message)?;
        self.phase = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum RuntimeDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone)]
enum RuntimePhase {
    AwaitClientHello,
    AwaitServerHello(RuntimeCapability),
    Ready(RuntimeCapability),
    AwaitProcessStarted {
        capability: RuntimeCapability,
        request_id: RuntimeRequestId,
        persistence: RuntimePersistence,
    },
    AwaitPtyAttached {
        request_id: RuntimeRequestId,
        session_id: PtySessionId,
        replay_from: Option<u64>,
    },
    Running(RuntimeProcessState),
    AwaitDetached(RuntimeProcessState),
    AwaitWatchStarted {
        request_id: RuntimeRequestId,
        resume_from: Option<u64>,
    },
    Watching(RuntimeWatchState),
    AwaitWatchStopped(RuntimeWatchState),
    Closed,
}

impl RuntimePhase {
    fn capability(&self) -> Option<RuntimeCapability> {
        match self {
            Self::AwaitClientHello | Self::Closed => None,
            Self::AwaitServerHello(capability)
            | Self::Ready(capability)
            | Self::AwaitProcessStarted { capability, .. } => Some(*capability),
            Self::AwaitPtyAttached { .. }
            | Self::Running(RuntimeProcessState { pty: true, .. })
            | Self::AwaitDetached(RuntimeProcessState { pty: true, .. }) => {
                Some(RuntimeCapability::ProcessPtyV1)
            }
            Self::Running(RuntimeProcessState { pty: false, .. })
            | Self::AwaitDetached(RuntimeProcessState { pty: false, .. }) => {
                Some(RuntimeCapability::ProcessPipeV1)
            }
            Self::AwaitWatchStarted { .. } | Self::Watching(_) | Self::AwaitWatchStopped(_) => {
                Some(RuntimeCapability::WorkspaceWatchV1)
            }
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::AwaitClientHello => "await_client_hello",
            Self::AwaitServerHello(_) => "await_server_hello",
            Self::Ready(_) => "ready",
            Self::AwaitProcessStarted { .. } => "await_process_started",
            Self::AwaitPtyAttached { .. } => "await_pty_attached",
            Self::Running(_) => "running",
            Self::AwaitDetached(_) => "await_detached",
            Self::AwaitWatchStarted { .. } => "await_watch_started",
            Self::Watching(_) => "watching",
            Self::AwaitWatchStopped(_) => "await_watch_stopped",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeProcessState {
    process_id: RuntimeProcessId,
    pty: bool,
    session_id: Option<PtySessionId>,
    input_sent: u64,
    input_acked: u64,
    input_closed: bool,
    stdout: StreamOffsets,
    stderr: StreamOffsets,
    pty_output: StreamOffsets,
    gap_pending: Option<(u64, u64)>,
}

impl RuntimeProcessState {
    fn new_pipe(process_id: RuntimeProcessId) -> Self {
        Self {
            process_id,
            pty: false,
            session_id: None,
            input_sent: 0,
            input_acked: 0,
            input_closed: false,
            stdout: StreamOffsets::default(),
            stderr: StreamOffsets::default(),
            pty_output: StreamOffsets::default(),
            gap_pending: None,
        }
    }

    fn new_pty(
        process_id: RuntimeProcessId,
        session_id: Option<PtySessionId>,
        output_offset: u64,
        gap_pending: Option<(u64, u64)>,
    ) -> Self {
        Self {
            process_id,
            pty: true,
            session_id,
            input_sent: 0,
            input_acked: 0,
            input_closed: false,
            stdout: StreamOffsets::default(),
            stderr: StreamOffsets::default(),
            pty_output: StreamOffsets {
                next: output_offset,
                acked: output_offset,
            },
            gap_pending,
        }
    }

    fn stream_mut(
        &mut self,
        stream: RuntimeOutputStream,
    ) -> Result<&mut StreamOffsets, RuntimeStateError> {
        match (self.pty, stream) {
            (true, RuntimeOutputStream::Pty) => Ok(&mut self.pty_output),
            (false, RuntimeOutputStream::Stdout) => Ok(&mut self.stdout),
            (false, RuntimeOutputStream::Stderr) => Ok(&mut self.stderr),
            _ => Err(RuntimeStateError::WrongOutputStream { stream }),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct StreamOffsets {
    next: u64,
    acked: u64,
}

#[derive(Debug, Clone)]
struct RuntimeWatchState {
    watch_id: RuntimeWatchId,
    next_sequence: u64,
    acked_sequence: u64,
    gap_pending: Option<(u64, u64)>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RuntimeStateError {
    #[error(transparent)]
    InvalidMessage(#[from] RuntimeValidationError),
    #[error("{message} must be sent by {expected:?}, not {actual:?}")]
    WrongSender {
        message: &'static str,
        expected: RuntimePeerRole,
        actual: RuntimePeerRole,
    },
    #[error("unexpected {message} while runtime stream is in {state}")]
    UnexpectedMessage {
        state: &'static str,
        message: &'static str,
    },
    #[error("runtime protocol version {actual} does not match required version {expected}")]
    ProtocolVersionMismatch { expected: u16, actual: u16 },
    #[error("runtime package version {actual:?} does not match required version {expected:?}")]
    PackageVersionMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("runtime capability {0:?} is not supported")]
    UnsupportedCapability(RuntimeCapability),
    #[error("runtime server selected {actual:?}, but the client requested {expected:?}")]
    CapabilityMismatch {
        expected: RuntimeCapability,
        actual: RuntimeCapability,
    },
    #[error("runtime request ID mismatch: expected {expected}, got {actual}")]
    RequestIdMismatch {
        expected: RuntimeRequestId,
        actual: RuntimeRequestId,
    },
    #[error("runtime process ID mismatch: expected {expected}, got {actual}")]
    ProcessIdMismatch {
        expected: RuntimeProcessId,
        actual: RuntimeProcessId,
    },
    #[error("runtime watch ID mismatch: expected {expected}, got {actual}")]
    WatchIdMismatch {
        expected: RuntimeWatchId,
        actual: RuntimeWatchId,
    },
    #[error("PTY session ID mismatch")]
    SessionIdMismatch,
    #[error("{capability:?} cannot use this process specification: {reason}")]
    InvalidProcessSpec {
        capability: RuntimeCapability,
        reason: &'static str,
    },
    #[error("runtime input is closed")]
    InputClosed,
    #[error("runtime {channel} offset mismatch: expected {expected}, got {actual}")]
    OffsetMismatch {
        channel: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("runtime {channel} acknowledgement regressed from {previous} to {actual}")]
    AckRegressed {
        channel: &'static str,
        previous: u64,
        actual: u64,
    },
    #[error("runtime {channel} acknowledgement {actual} exceeds sent offset {sent}")]
    AckBeyondSent {
        channel: &'static str,
        sent: u64,
        actual: u64,
    },
    #[error("output stream {stream:?} is invalid for this runtime capability")]
    WrongOutputStream { stream: RuntimeOutputStream },
    #[error("PTY output gap does not match the pending replay gap")]
    OutputGapMismatch,
    #[error("PTY replay output cannot arrive before its gap marker")]
    OutputBeforeGap,
    #[error("watch sequence overflow")]
    WatchSequenceOverflow,
    #[error("watch events cannot arrive before the pending overflow marker")]
    WatchEventBeforeOverflow,
    #[error("watch overflow does not match the pending resume gap")]
    WatchOverflowMismatch,
}

fn apply_message(
    phase: &mut RuntimePhase,
    supported: &CapabilitySet,
    message: &RuntimeMessage,
) -> Result<(), RuntimeStateError> {
    if matches!(message, RuntimeMessage::Error(_)) && !matches!(phase, RuntimePhase::Closed) {
        *phase = RuntimePhase::Closed;
        return Ok(());
    }

    let state_name = phase.name();
    match (&mut *phase, message) {
        (
            RuntimePhase::AwaitClientHello,
            RuntimeMessage::ClientHello {
                package_version,
                protocol_version,
                capability,
            },
        ) => {
            validate_protocol_and_capability(
                supported,
                package_version,
                *protocol_version,
                *capability,
            )?;
            *phase = RuntimePhase::AwaitServerHello(*capability);
        }
        (
            RuntimePhase::AwaitServerHello(expected),
            RuntimeMessage::ServerHello {
                package_version,
                protocol_version,
                capability,
            },
        ) => {
            validate_protocol_and_capability(
                supported,
                package_version,
                *protocol_version,
                *capability,
            )?;
            if capability != expected {
                return Err(RuntimeStateError::CapabilityMismatch {
                    expected: *expected,
                    actual: *capability,
                });
            }
            *phase = RuntimePhase::Ready(*capability);
        }
        (RuntimePhase::Ready(capability), RuntimeMessage::StartProcess { request_id, spec })
            if matches!(
                capability,
                RuntimeCapability::ProcessPipeV1 | RuntimeCapability::ProcessPtyV1
            ) =>
        {
            validate_spec_for_capability(*capability, spec)?;
            *phase = RuntimePhase::AwaitProcessStarted {
                capability: *capability,
                request_id: *request_id,
                persistence: spec.persistence,
            };
        }
        (
            RuntimePhase::Ready(RuntimeCapability::ProcessPtyV1),
            RuntimeMessage::AttachPty {
                request_id,
                credentials,
                replay_from,
            },
        ) => {
            *phase = RuntimePhase::AwaitPtyAttached {
                request_id: *request_id,
                session_id: credentials.session_id,
                replay_from: *replay_from,
            };
        }
        (
            RuntimePhase::AwaitProcessStarted {
                capability,
                request_id: expected_request_id,
                persistence,
            },
            RuntimeMessage::ProcessStarted {
                request_id,
                process_id,
                session,
                output_offset,
            },
        ) => {
            expect_request_id(*expected_request_id, *request_id)?;
            match (*capability, *persistence, session) {
                (RuntimeCapability::ProcessPipeV1, RuntimePersistence::Attached, None)
                    if *output_offset == 0 =>
                {
                    *phase = RuntimePhase::Running(RuntimeProcessState::new_pipe(*process_id));
                }
                (RuntimeCapability::ProcessPtyV1, RuntimePersistence::Attached, None)
                    if *output_offset == 0 =>
                {
                    *phase = RuntimePhase::Running(RuntimeProcessState::new_pty(
                        *process_id,
                        None,
                        *output_offset,
                        None,
                    ));
                }
                (
                    RuntimeCapability::ProcessPtyV1,
                    RuntimePersistence::Detachable { .. },
                    Some(credentials),
                ) if *output_offset == 0 => {
                    *phase = RuntimePhase::Running(RuntimeProcessState::new_pty(
                        *process_id,
                        Some(credentials.session_id),
                        *output_offset,
                        None,
                    ));
                }
                (RuntimeCapability::ProcessPipeV1, _, _) => {
                    return Err(RuntimeStateError::InvalidProcessSpec {
                        capability: *capability,
                        reason:
                            "pipe startup must not return a PTY session or nonzero output offset",
                    });
                }
                (RuntimeCapability::ProcessPtyV1, RuntimePersistence::Attached, _) => {
                    return Err(RuntimeStateError::InvalidProcessSpec {
                        capability: *capability,
                        reason:
                            "attached PTY startup must not return session credentials or a nonzero output offset",
                    });
                }
                (RuntimeCapability::ProcessPtyV1, RuntimePersistence::Detachable { .. }, None) => {
                    return Err(RuntimeStateError::InvalidProcessSpec {
                        capability: *capability,
                        reason: "detachable PTY startup must return session credentials",
                    });
                }
                (
                    RuntimeCapability::ProcessPtyV1,
                    RuntimePersistence::Detachable { .. },
                    Some(_),
                ) => {
                    return Err(RuntimeStateError::InvalidProcessSpec {
                        capability: *capability,
                        reason: "new detachable PTY startup must begin at output offset zero",
                    });
                }
                (RuntimeCapability::WorkspaceWatchV1, _, _) => unreachable!(),
            }
        }
        (
            RuntimePhase::AwaitPtyAttached {
                request_id: expected_request_id,
                session_id: expected_session_id,
                replay_from,
            },
            RuntimeMessage::PtyAttached {
                request_id,
                process_id,
                session_id,
                output_offset,
            },
        ) => {
            expect_request_id(*expected_request_id, *request_id)?;
            if session_id != expected_session_id {
                return Err(RuntimeStateError::SessionIdMismatch);
            }
            let gap_pending = match replay_from {
                Some(requested) if *output_offset < *requested => {
                    return Err(RuntimeStateError::OffsetMismatch {
                        channel: "PTY replay",
                        expected: *requested,
                        actual: *output_offset,
                    });
                }
                Some(requested) if *output_offset > *requested => {
                    Some((*requested, *output_offset))
                }
                _ => None,
            };
            *phase = RuntimePhase::Running(RuntimeProcessState::new_pty(
                *process_id,
                Some(*session_id),
                *output_offset,
                gap_pending,
            ));
        }
        (RuntimePhase::Running(process), message) => {
            if apply_running_message(process, message)? {
                *phase = RuntimePhase::Closed;
            } else if matches!(message, RuntimeMessage::Detach { .. }) {
                *phase = RuntimePhase::AwaitDetached(process.clone());
            }
        }
        (
            RuntimePhase::AwaitDetached(process),
            RuntimeMessage::Detached {
                process_id,
                session_id,
            },
        ) => {
            expect_process_id(process.process_id, *process_id)?;
            if process.session_id.as_ref() != Some(session_id) {
                return Err(RuntimeStateError::SessionIdMismatch);
            }
            *phase = RuntimePhase::Closed;
        }
        (RuntimePhase::AwaitDetached(process), message) => {
            if apply_running_server_message(process, message)? {
                *phase = RuntimePhase::Closed;
            }
        }
        (
            RuntimePhase::Ready(RuntimeCapability::WorkspaceWatchV1),
            RuntimeMessage::WatchStart {
                request_id,
                resume_from,
            },
        ) => {
            *phase = RuntimePhase::AwaitWatchStarted {
                request_id: *request_id,
                resume_from: *resume_from,
            };
        }
        (
            RuntimePhase::AwaitWatchStarted {
                request_id: expected_request_id,
                resume_from,
            },
            RuntimeMessage::WatchStarted {
                request_id,
                watch_id,
                next_sequence,
            },
        ) => {
            expect_request_id(*expected_request_id, *request_id)?;
            if let Some(resume_from) = resume_from {
                if next_sequence < resume_from {
                    return Err(RuntimeStateError::OffsetMismatch {
                        channel: "watch resume",
                        expected: *resume_from,
                        actual: *next_sequence,
                    });
                }
            }
            *phase = RuntimePhase::Watching(RuntimeWatchState {
                watch_id: *watch_id,
                next_sequence: *next_sequence,
                acked_sequence: *next_sequence,
                gap_pending: (*resume_from)
                    .filter(|resume_from| *resume_from < *next_sequence)
                    .map(|resume_from| (resume_from, *next_sequence)),
            });
        }
        (RuntimePhase::Watching(watch), RuntimeMessage::WatchStop { watch_id }) => {
            expect_watch_id(watch.watch_id, *watch_id)?;
            *phase = RuntimePhase::AwaitWatchStopped(watch.clone());
        }
        (RuntimePhase::Watching(watch), message) => apply_watch_message(watch, message)?,
        (RuntimePhase::AwaitWatchStopped(watch), RuntimeMessage::WatchStopped { watch_id }) => {
            expect_watch_id(watch.watch_id, *watch_id)?;
            *phase = RuntimePhase::Closed;
        }
        (RuntimePhase::AwaitWatchStopped(watch), message) => {
            apply_watch_server_message(watch, message)?;
        }
        _ => {
            return Err(RuntimeStateError::UnexpectedMessage {
                state: state_name,
                message: message.name(),
            });
        }
    }
    Ok(())
}

fn apply_running_message(
    process: &mut RuntimeProcessState,
    message: &RuntimeMessage,
) -> Result<bool, RuntimeStateError> {
    match message {
        RuntimeMessage::Input {
            process_id,
            offset,
            data,
        } => {
            expect_process_id(process.process_id, *process_id)?;
            if process.input_closed {
                return Err(RuntimeStateError::InputClosed);
            }
            expect_offset("input", process.input_sent, *offset)?;
            process.input_sent = offset
                .checked_add(data.len() as u64)
                .ok_or(RuntimeValidationError::DataOffsetOverflow)?;
            Ok(false)
        }
        RuntimeMessage::CloseInput {
            process_id,
            next_offset,
        } => {
            expect_process_id(process.process_id, *process_id)?;
            if process.input_closed {
                return Err(RuntimeStateError::InputClosed);
            }
            expect_offset("input close", process.input_sent, *next_offset)?;
            process.input_closed = true;
            Ok(false)
        }
        RuntimeMessage::OutputAck {
            process_id,
            stream,
            next_offset,
        } => {
            expect_process_id(process.process_id, *process_id)?;
            if process.gap_pending.is_some() {
                return Err(RuntimeStateError::OutputBeforeGap);
            }
            let offsets = process.stream_mut(*stream)?;
            apply_ack("output", offsets, *next_offset)?;
            Ok(false)
        }
        RuntimeMessage::Resize { process_id, .. } => {
            expect_process_id(process.process_id, *process_id)?;
            if !process.pty {
                return Err(RuntimeStateError::UnexpectedMessage {
                    state: "running_pipe",
                    message: "resize",
                });
            }
            Ok(false)
        }
        RuntimeMessage::Signal { process_id, .. } => {
            expect_process_id(process.process_id, *process_id)?;
            Ok(false)
        }
        RuntimeMessage::Detach { process_id } => {
            expect_process_id(process.process_id, *process_id)?;
            if !process.pty || process.session_id.is_none() {
                return Err(RuntimeStateError::UnexpectedMessage {
                    state: "running_pipe",
                    message: "detach",
                });
            }
            Ok(false)
        }
        _ => apply_running_server_message(process, message),
    }
}

fn apply_running_server_message(
    process: &mut RuntimeProcessState,
    message: &RuntimeMessage,
) -> Result<bool, RuntimeStateError> {
    match message {
        RuntimeMessage::InputAck {
            process_id,
            next_offset,
        } => {
            expect_process_id(process.process_id, *process_id)?;
            apply_scalar_ack(
                "input",
                process.input_sent,
                &mut process.input_acked,
                *next_offset,
            )?;
            Ok(false)
        }
        RuntimeMessage::Output {
            process_id,
            stream,
            offset,
            data,
        } => {
            expect_process_id(process.process_id, *process_id)?;
            if process.gap_pending.is_some() {
                return Err(RuntimeStateError::OutputBeforeGap);
            }
            let offsets = process.stream_mut(*stream)?;
            expect_offset("output", offsets.next, *offset)?;
            offsets.next = offset
                .checked_add(data.len() as u64)
                .ok_or(RuntimeValidationError::DataOffsetOverflow)?;
            Ok(false)
        }
        RuntimeMessage::OutputGap {
            process_id,
            requested_offset,
            available_offset,
            ..
        } => {
            expect_process_id(process.process_id, *process_id)?;
            if !process.pty || process.gap_pending != Some((*requested_offset, *available_offset)) {
                return Err(RuntimeStateError::OutputGapMismatch);
            }
            process.gap_pending = None;
            Ok(false)
        }
        RuntimeMessage::Exited { process_id, .. } => {
            expect_process_id(process.process_id, *process_id)?;
            Ok(true)
        }
        _ => Err(RuntimeStateError::UnexpectedMessage {
            state: if process.pty {
                "running_pty"
            } else {
                "running_pipe"
            },
            message: message.name(),
        }),
    }
}

fn apply_watch_message(
    watch: &mut RuntimeWatchState,
    message: &RuntimeMessage,
) -> Result<(), RuntimeStateError> {
    match message {
        RuntimeMessage::WatchAck {
            watch_id,
            next_sequence,
        } => {
            expect_watch_id(watch.watch_id, *watch_id)?;
            apply_scalar_ack(
                "watch",
                watch.next_sequence,
                &mut watch.acked_sequence,
                *next_sequence,
            )
        }
        _ => apply_watch_server_message(watch, message),
    }
}

fn apply_watch_server_message(
    watch: &mut RuntimeWatchState,
    message: &RuntimeMessage,
) -> Result<(), RuntimeStateError> {
    match message {
        RuntimeMessage::WatchEvents {
            watch_id,
            sequence,
            events,
        } => {
            expect_watch_id(watch.watch_id, *watch_id)?;
            if watch.gap_pending.is_some() {
                return Err(RuntimeStateError::WatchEventBeforeOverflow);
            }
            expect_offset("watch", watch.next_sequence, *sequence)?;
            watch.next_sequence = sequence
                .checked_add(events.len() as u64)
                .ok_or(RuntimeStateError::WatchSequenceOverflow)?;
            Ok(())
        }
        RuntimeMessage::WatchOverflow {
            watch_id,
            sequence,
            next_sequence,
        } => {
            expect_watch_id(watch.watch_id, *watch_id)?;
            if let Some(expected) = watch.gap_pending {
                if expected != (*sequence, *next_sequence) {
                    return Err(RuntimeStateError::WatchOverflowMismatch);
                }
                watch.gap_pending = None;
                return Ok(());
            }
            expect_offset("watch overflow", watch.next_sequence, *sequence)?;
            watch.next_sequence = *next_sequence;
            Ok(())
        }
        _ => Err(RuntimeStateError::UnexpectedMessage {
            state: "watching",
            message: message.name(),
        }),
    }
}

fn validate_protocol_and_capability(
    supported: &CapabilitySet,
    package_version: &str,
    protocol_version: u16,
    capability: RuntimeCapability,
) -> Result<(), RuntimeStateError> {
    if package_version != env!("CARGO_PKG_VERSION") {
        return Err(RuntimeStateError::PackageVersionMismatch {
            expected: env!("CARGO_PKG_VERSION"),
            actual: package_version.to_owned(),
        });
    }
    if protocol_version != PROTOCOL_VERSION {
        return Err(RuntimeStateError::ProtocolVersionMismatch {
            expected: PROTOCOL_VERSION,
            actual: protocol_version,
        });
    }
    if !supported.supports_runtime(capability) {
        return Err(RuntimeStateError::UnsupportedCapability(capability));
    }
    Ok(())
}

fn validate_package_version(package_version: &str) -> Result<(), RuntimeValidationError> {
    if package_version.is_empty() {
        return Err(RuntimeValidationError::EmptyPackageVersion);
    }
    if package_version.len() > RUNTIME_MAX_PACKAGE_VERSION_BYTES {
        return Err(RuntimeValidationError::PackageVersionTooLarge(
            package_version.len(),
        ));
    }
    reject_nul("runtime package version", package_version)
}

fn validate_process_spec(spec: &RuntimeProcessSpec) -> Result<(), RuntimeValidationError> {
    if spec.argv.is_empty() {
        return Err(RuntimeValidationError::EmptyArgv);
    }
    if spec.argv.len() > RUNTIME_MAX_ARGV {
        return Err(RuntimeValidationError::TooManyArguments(spec.argv.len()));
    }
    for arg in &spec.argv {
        reject_nul("runtime argument", arg)?;
        reject_control("runtime argument", arg)?;
    }
    if let RuntimeCwd::WorkspaceRelative(path) = &spec.cwd {
        validate_workspace_path(path)?;
    }
    validate_environment(&spec.env)?;
    if let RuntimePersistence::Detachable { ttl_ms: 0 } = spec.persistence {
        return Err(RuntimeValidationError::ZeroDetachTtl);
    }
    if let Some(size) = &spec.terminal_size {
        validate_terminal_size(size)?;
    }
    Ok(())
}

fn validate_spec_for_capability(
    capability: RuntimeCapability,
    spec: &RuntimeProcessSpec,
) -> Result<(), RuntimeStateError> {
    match capability {
        RuntimeCapability::ProcessPipeV1 => {
            if spec.terminal_size.is_some() {
                return Err(RuntimeStateError::InvalidProcessSpec {
                    capability,
                    reason: "pipe processes must not include a terminal size",
                });
            }
            if !matches!(spec.persistence, RuntimePersistence::Attached) {
                return Err(RuntimeStateError::InvalidProcessSpec {
                    capability,
                    reason: "pipe processes cannot be detachable",
                });
            }
        }
        RuntimeCapability::ProcessPtyV1 => {
            if spec.terminal_size.is_none() {
                return Err(RuntimeStateError::InvalidProcessSpec {
                    capability,
                    reason: "PTY processes require a terminal size",
                });
            }
            if spec.max_output_bytes.is_some() {
                return Err(RuntimeStateError::InvalidProcessSpec {
                    capability,
                    reason: "PTY live streams must not include a pipe output limit",
                });
            }
        }
        RuntimeCapability::WorkspaceWatchV1 => {
            return Err(RuntimeStateError::InvalidProcessSpec {
                capability,
                reason: "watch streams cannot start processes",
            });
        }
    }
    Ok(())
}

fn validate_environment(env: &RuntimeEnvironment) -> Result<(), RuntimeValidationError> {
    let changes = env.set.len().saturating_add(env.unset.len());
    if changes > RUNTIME_MAX_ENV_CHANGES {
        return Err(RuntimeValidationError::TooManyEnvironmentChanges(changes));
    }
    let mut names = HashSet::with_capacity(changes);
    for variable in &env.set {
        validate_env_name(&variable.name)?;
        reject_nul("environment value", &variable.value)?;
        if !names.insert(variable.name.as_str()) {
            return Err(RuntimeValidationError::DuplicateEnvironmentName(
                variable.name.clone(),
            ));
        }
    }
    for name in &env.unset {
        validate_env_name(name)?;
        if !names.insert(name.as_str()) {
            return Err(RuntimeValidationError::DuplicateEnvironmentName(
                name.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_env_name(name: &str) -> Result<(), RuntimeValidationError> {
    if name.is_empty() {
        return Err(RuntimeValidationError::EmptyEnvironmentName);
    }
    reject_nul("environment name", name)?;
    if name.contains('=') {
        return Err(RuntimeValidationError::InvalidEnvironmentName);
    }
    Ok(())
}

fn validate_workspace_path(path: &str) -> Result<(), RuntimeValidationError> {
    if path.is_empty() {
        return Err(RuntimeValidationError::EmptyWorkspacePath);
    }
    if path.len() > RUNTIME_MAX_PATH_BYTES {
        return Err(RuntimeValidationError::WorkspacePathTooLarge(path.len()));
    }
    if path.contains('\0')
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(RuntimeValidationError::InvalidWorkspacePath);
    }
    Ok(())
}

fn validate_terminal_size(size: &TerminalSize) -> Result<(), RuntimeValidationError> {
    if size.columns == 0 || size.rows == 0 {
        return Err(RuntimeValidationError::InvalidTerminalSize);
    }
    if size.pixel_width.is_some() != size.pixel_height.is_some() {
        return Err(RuntimeValidationError::IncompleteTerminalPixelSize);
    }
    Ok(())
}

fn validate_credentials(credentials: &PtySessionCredentials) -> Result<(), RuntimeValidationError> {
    validate_nonzero_id("session ID", &credentials.session_id)?;
    validate_nonzero_id("attachment token", &credentials.attachment_token)
}

fn validate_nonzero_id<const N: usize>(
    name: &'static str,
    value: &[u8; N],
) -> Result<(), RuntimeValidationError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(RuntimeValidationError::ZeroSessionCredential(name));
    }
    Ok(())
}

fn validate_data_chunk(offset: u64, data: &[u8]) -> Result<(), RuntimeValidationError> {
    if data.is_empty() {
        return Err(RuntimeValidationError::EmptyDataChunk);
    }
    validate_optional_data_chunk(data)?;
    offset
        .checked_add(data.len() as u64)
        .ok_or(RuntimeValidationError::DataOffsetOverflow)?;
    Ok(())
}

fn validate_optional_data_chunk(data: &[u8]) -> Result<(), RuntimeValidationError> {
    if data.len() > RUNTIME_MAX_DATA_CHUNK_LEN {
        return Err(RuntimeValidationError::DataChunkTooLarge(data.len()));
    }
    Ok(())
}

fn reject_nul(name: &'static str, value: &str) -> Result<(), RuntimeValidationError> {
    if value.contains('\0') {
        return Err(RuntimeValidationError::ContainsNul(name));
    }
    Ok(())
}

fn reject_control(name: &'static str, value: &str) -> Result<(), RuntimeValidationError> {
    if value.chars().any(char::is_control) {
        return Err(RuntimeValidationError::ContainsControl(name));
    }
    Ok(())
}

fn expect_request_id(
    expected: RuntimeRequestId,
    actual: RuntimeRequestId,
) -> Result<(), RuntimeStateError> {
    if expected != actual {
        return Err(RuntimeStateError::RequestIdMismatch { expected, actual });
    }
    Ok(())
}

fn expect_process_id(
    expected: RuntimeProcessId,
    actual: RuntimeProcessId,
) -> Result<(), RuntimeStateError> {
    if expected != actual {
        return Err(RuntimeStateError::ProcessIdMismatch { expected, actual });
    }
    Ok(())
}

fn expect_watch_id(
    expected: RuntimeWatchId,
    actual: RuntimeWatchId,
) -> Result<(), RuntimeStateError> {
    if expected != actual {
        return Err(RuntimeStateError::WatchIdMismatch { expected, actual });
    }
    Ok(())
}

fn expect_offset(
    channel: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), RuntimeStateError> {
    if expected != actual {
        return Err(RuntimeStateError::OffsetMismatch {
            channel,
            expected,
            actual,
        });
    }
    Ok(())
}

fn apply_ack(
    channel: &'static str,
    offsets: &mut StreamOffsets,
    actual: u64,
) -> Result<(), RuntimeStateError> {
    apply_scalar_ack(channel, offsets.next, &mut offsets.acked, actual)
}

fn apply_scalar_ack(
    channel: &'static str,
    sent: u64,
    previous: &mut u64,
    actual: u64,
) -> Result<(), RuntimeStateError> {
    if actual < *previous {
        return Err(RuntimeStateError::AckRegressed {
            channel,
            previous: *previous,
            actual,
        });
    }
    if actual > sent {
        return Err(RuntimeStateError::AckBeyondSent {
            channel,
            sent,
            actual,
        });
    }
    *previous = actual;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const PROCESS_ID: RuntimeProcessId = 23;
    const WATCH_ID: RuntimeWatchId = 41;

    fn capabilities() -> CapabilitySet {
        let mut capabilities = CapabilitySet::v1_agent();
        capabilities.runtime_process_v1 = true;
        capabilities.runtime_pty_v1 = true;
        capabilities.workspace_watch_v1 = true;
        capabilities
    }

    fn package_version() -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    fn credentials() -> PtySessionCredentials {
        PtySessionCredentials {
            session_id: [7; 16],
            attachment_token: [9; 32],
        }
    }

    fn size() -> TerminalSize {
        TerminalSize {
            columns: 120,
            rows: 40,
            pixel_width: Some(960),
            pixel_height: Some(800),
        }
    }

    fn pipe_spec() -> RuntimeProcessSpec {
        RuntimeProcessSpec {
            argv: vec![
                "git".to_string(),
                "status".to_string(),
                "--short".to_string(),
            ],
            cwd: RuntimeCwd::WorkspaceRelative("src/tools".to_string()),
            env: RuntimeEnvironment {
                clear: false,
                set: vec![RuntimeEnvVar {
                    name: "NO_COLOR".to_string(),
                    value: "1".to_string(),
                }],
                unset: vec!["PAGER".to_string()],
            },
            persistence: RuntimePersistence::Attached,
            terminal_size: None,
            timeout_ms: Some(30_000),
            max_output_bytes: Some(1024 * 1024),
        }
    }

    fn pty_spec() -> RuntimeProcessSpec {
        RuntimeProcessSpec {
            argv: vec!["/bin/sh".to_string(), "-l".to_string()],
            cwd: RuntimeCwd::WorkspaceRoot,
            env: RuntimeEnvironment::default(),
            persistence: RuntimePersistence::Detachable { ttl_ms: 86_400_000 },
            terminal_size: Some(size()),
            timeout_ms: None,
            max_output_bytes: None,
        }
    }

    fn attached_pty_spec() -> RuntimeProcessSpec {
        RuntimeProcessSpec {
            persistence: RuntimePersistence::Attached,
            ..pty_spec()
        }
    }

    fn watch_event() -> WorkspaceWatchEvent {
        WorkspaceWatchEvent {
            path: "src/old.rs".to_string(),
            kind: WorkspaceWatchEventKind::Renamed {
                to: "src/new.rs".to_string(),
            },
            is_dir: false,
        }
    }

    fn client(capability: RuntimeCapability) -> RuntimeStateMachine {
        let mut machine = RuntimeStateMachine::new(RuntimePeerRole::Client, capabilities());
        machine
            .observe_outbound(&RuntimeMessage::ClientHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability,
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::ServerHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability,
            })
            .unwrap();
        machine
    }

    fn running_pipe() -> RuntimeStateMachine {
        let mut machine = client(RuntimeCapability::ProcessPipeV1);
        machine
            .observe_outbound(&RuntimeMessage::StartProcess {
                request_id: 1,
                spec: pipe_spec(),
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::ProcessStarted {
                request_id: 1,
                process_id: PROCESS_ID,
                session: None,
                output_offset: 0,
            })
            .unwrap();
        machine
    }

    #[test]
    fn protocol_v8_does_not_advertise_unimplemented_runtime_by_default() {
        assert_eq!(PROTOCOL_VERSION, 8);
        let capabilities = CapabilitySet::v1_agent();
        assert!(!capabilities.runtime_process_v1);
        assert!(!capabilities.runtime_pty_v1);
        assert!(!capabilities.workspace_watch_v1);
        assert!(!capabilities.supports_runtime(RuntimeCapability::ProcessPipeV1));
    }

    #[test]
    fn round_trips_every_runtime_message_variant() {
        let messages = vec![
            RuntimeMessage::ClientHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            },
            RuntimeMessage::ServerHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            },
            RuntimeMessage::Error(RuntimeError {
                code: RuntimeErrorCode::SpawnFailed,
                message: "executable not found".to_string(),
                retryable: false,
            }),
            RuntimeMessage::StartProcess {
                request_id: 1,
                spec: pipe_spec(),
            },
            RuntimeMessage::ProcessStarted {
                request_id: 1,
                process_id: PROCESS_ID,
                session: Some(credentials()),
                output_offset: 3,
            },
            RuntimeMessage::AttachPty {
                request_id: 2,
                credentials: credentials(),
                replay_from: Some(4),
            },
            RuntimeMessage::PtyAttached {
                request_id: 2,
                process_id: PROCESS_ID,
                session_id: credentials().session_id,
                output_offset: 8,
            },
            RuntimeMessage::Input {
                process_id: PROCESS_ID,
                offset: 0,
                data: vec![0, 1, 0xff],
            },
            RuntimeMessage::InputAck {
                process_id: PROCESS_ID,
                next_offset: 3,
            },
            RuntimeMessage::CloseInput {
                process_id: PROCESS_ID,
                next_offset: 3,
            },
            RuntimeMessage::Output {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Stdout,
                offset: 0,
                data: vec![0, 0xfe],
            },
            RuntimeMessage::OutputAck {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Stdout,
                next_offset: 2,
            },
            RuntimeMessage::OutputGap {
                process_id: PROCESS_ID,
                requested_offset: 2,
                available_offset: 7,
                screen_snapshot: b"current screen\r\n".to_vec(),
            },
            RuntimeMessage::Resize {
                process_id: PROCESS_ID,
                size: size(),
            },
            RuntimeMessage::Signal {
                process_id: PROCESS_ID,
                signal: RuntimeSignal::Interrupt,
            },
            RuntimeMessage::Detach {
                process_id: PROCESS_ID,
            },
            RuntimeMessage::Detached {
                process_id: PROCESS_ID,
                session_id: credentials().session_id,
            },
            RuntimeMessage::Exited {
                process_id: PROCESS_ID,
                status: RuntimeExitStatus::Signal(15),
                output_truncated: true,
            },
            RuntimeMessage::WatchStart {
                request_id: 3,
                resume_from: Some(10),
            },
            RuntimeMessage::WatchStarted {
                request_id: 3,
                watch_id: WATCH_ID,
                next_sequence: 10,
            },
            RuntimeMessage::WatchEvents {
                watch_id: WATCH_ID,
                sequence: 10,
                events: vec![watch_event()],
            },
            RuntimeMessage::WatchAck {
                watch_id: WATCH_ID,
                next_sequence: 11,
            },
            RuntimeMessage::WatchOverflow {
                watch_id: WATCH_ID,
                sequence: 11,
                next_sequence: 20,
            },
            RuntimeMessage::WatchStop { watch_id: WATCH_ID },
            RuntimeMessage::WatchStopped { watch_id: WATCH_ID },
        ];

        for message in messages {
            let mut bytes = Vec::new();
            write_runtime_frame(&mut bytes, &message).unwrap();
            assert!(bytes.len() <= RUNTIME_MAX_FRAME_LEN + 4);
            let decoded = read_runtime_frame(&mut Cursor::new(bytes)).unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    fn rejects_runtime_frame_length_before_allocating() {
        let advertised = RUNTIME_MAX_FRAME_LEN + 1;
        let result = read_runtime_frame(&mut Cursor::new((advertised as u32).to_be_bytes()));
        assert!(matches!(
            result,
            Err(RuntimeFrameError::TooLarge(actual)) if actual == advertised
        ));
    }

    #[test]
    fn rejects_truncated_and_malformed_runtime_frames() {
        let mut truncated = 4_u32.to_be_bytes().to_vec();
        truncated.extend_from_slice(&[1, 2]);
        let truncated_result = read_runtime_frame(&mut Cursor::new(truncated));
        assert!(matches!(
            truncated_result,
            Err(RuntimeFrameError::Io(error))
                if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));

        let mut malformed = 4_u32.to_be_bytes().to_vec();
        malformed.extend_from_slice(&[0xff; 4]);
        assert!(matches!(
            read_runtime_frame(&mut Cursor::new(malformed)),
            Err(RuntimeFrameError::Codec(_))
        ));
    }

    #[test]
    fn rejects_serialized_message_larger_than_runtime_frame_limit() {
        let mut spec = pipe_spec();
        spec.argv = vec!["x".repeat(140 * 1024), "y".repeat(140 * 1024)];
        let result = write_runtime_frame(
            &mut Vec::new(),
            &RuntimeMessage::StartProcess {
                request_id: 1,
                spec,
            },
        );
        assert!(matches!(result, Err(RuntimeFrameError::TooLarge(_))));
    }

    #[test]
    fn enforces_binary_chunk_limit_and_offset_overflow_on_write_and_read() {
        let oversized = RuntimeMessage::Input {
            process_id: PROCESS_ID,
            offset: 0,
            data: vec![0; RUNTIME_MAX_DATA_CHUNK_LEN + 1],
        };
        assert!(matches!(
            write_runtime_frame(&mut Vec::new(), &oversized),
            Err(RuntimeFrameError::Invalid(
                RuntimeValidationError::DataChunkTooLarge(_)
            ))
        ));

        let invalid = RuntimeMessage::Output {
            process_id: PROCESS_ID,
            stream: RuntimeOutputStream::Stdout,
            offset: u64::MAX,
            data: vec![1],
        };
        let payload = postcard::to_allocvec(&invalid).unwrap();
        let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&payload);
        assert!(matches!(
            read_runtime_frame(&mut Cursor::new(framed)),
            Err(RuntimeFrameError::Invalid(
                RuntimeValidationError::DataOffsetOverflow
            ))
        ));
    }

    #[test]
    fn rejects_invalid_process_watch_and_credential_fields() {
        assert_eq!(
            RuntimeMessage::ClientHello {
                package_version: String::new(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            }
            .validate(),
            Err(RuntimeValidationError::EmptyPackageVersion)
        );
        assert!(matches!(
            RuntimeMessage::ServerHello {
                package_version: "x".repeat(RUNTIME_MAX_PACKAGE_VERSION_BYTES + 1),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            }
            .validate(),
            Err(RuntimeValidationError::PackageVersionTooLarge(_))
        ));

        let mut spec = pipe_spec();
        spec.argv.clear();
        assert_eq!(
            RuntimeMessage::StartProcess {
                request_id: 1,
                spec
            }
            .validate(),
            Err(RuntimeValidationError::EmptyArgv)
        );

        let mut spec = pipe_spec();
        spec.env.unset.push("NO_COLOR".to_string());
        assert!(matches!(
            RuntimeMessage::StartProcess {
                request_id: 1,
                spec
            }
            .validate(),
            Err(RuntimeValidationError::DuplicateEnvironmentName(name)) if name == "NO_COLOR"
        ));

        let mut spec = pipe_spec();
        spec.cwd = RuntimeCwd::WorkspaceRelative("../outside".to_string());
        assert_eq!(
            RuntimeMessage::StartProcess {
                request_id: 1,
                spec
            }
            .validate(),
            Err(RuntimeValidationError::InvalidWorkspacePath)
        );

        assert_eq!(
            RuntimeMessage::AttachPty {
                request_id: 1,
                credentials: PtySessionCredentials {
                    session_id: [0; 16],
                    attachment_token: [1; 32],
                },
                replay_from: None,
            }
            .validate(),
            Err(RuntimeValidationError::ZeroSessionCredential("session ID"))
        );

        assert_eq!(
            RuntimeMessage::WatchEvents {
                watch_id: WATCH_ID,
                sequence: 0,
                events: Vec::new(),
            }
            .validate(),
            Err(RuntimeValidationError::EmptyWatchBatch)
        );
    }

    #[test]
    fn handshake_enforces_sender_version_capability_and_order() {
        let mut machine = RuntimeStateMachine::new(RuntimePeerRole::Client, capabilities());
        assert!(matches!(
            machine.observe_inbound(&RuntimeMessage::ClientHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            }),
            Err(RuntimeStateError::WrongSender { .. })
        ));
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::StartProcess {
                request_id: 1,
                spec: pipe_spec(),
            }),
            Err(RuntimeStateError::UnexpectedMessage { .. })
        ));
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::ClientHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION - 1,
                capability: RuntimeCapability::ProcessPipeV1,
            }),
            Err(RuntimeStateError::ProtocolVersionMismatch { .. })
        ));
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::ClientHello {
                package_version: "0.0.0-mismatch".to_owned(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            }),
            Err(RuntimeStateError::PackageVersionMismatch { .. })
        ));

        machine
            .observe_outbound(&RuntimeMessage::ClientHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            })
            .unwrap();
        assert!(matches!(
            machine.observe_inbound(&RuntimeMessage::ServerHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPtyV1,
            }),
            Err(RuntimeStateError::CapabilityMismatch { .. })
        ));
        machine
            .observe_inbound(&RuntimeMessage::ServerHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            })
            .unwrap();
        assert_eq!(
            machine.negotiated_capability(),
            Some(RuntimeCapability::ProcessPipeV1)
        );

        let mut unsupported =
            RuntimeStateMachine::new(RuntimePeerRole::Server, CapabilitySet::v1_agent());
        assert!(matches!(
            unsupported.observe_inbound(&RuntimeMessage::ClientHello {
                package_version: package_version(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPtyV1,
            }),
            Err(RuntimeStateError::UnsupportedCapability(
                RuntimeCapability::ProcessPtyV1
            ))
        ));
        unsupported
            .observe_outbound(&RuntimeMessage::Error(RuntimeError {
                code: RuntimeErrorCode::Unsupported,
                message: "PTY unsupported".to_string(),
                retryable: false,
            }))
            .unwrap();
        assert!(unsupported.is_closed());
    }

    #[test]
    fn pipe_state_enforces_ids_offsets_acks_and_close_ordering() {
        let mut machine = running_pipe();
        machine
            .observe_outbound(&RuntimeMessage::Input {
                process_id: PROCESS_ID,
                offset: 0,
                data: vec![1, 2, 3],
            })
            .unwrap();
        assert!(matches!(
            machine.observe_inbound(&RuntimeMessage::InputAck {
                process_id: PROCESS_ID,
                next_offset: 4,
            }),
            Err(RuntimeStateError::AckBeyondSent { .. })
        ));
        machine
            .observe_inbound(&RuntimeMessage::InputAck {
                process_id: PROCESS_ID,
                next_offset: 3,
            })
            .unwrap();
        machine
            .observe_outbound(&RuntimeMessage::CloseInput {
                process_id: PROCESS_ID,
                next_offset: 3,
            })
            .unwrap();
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::Input {
                process_id: PROCESS_ID,
                offset: 3,
                data: vec![4],
            }),
            Err(RuntimeStateError::InputClosed)
        ));

        assert!(matches!(
            machine.observe_inbound(&RuntimeMessage::Output {
                process_id: PROCESS_ID + 1,
                stream: RuntimeOutputStream::Stdout,
                offset: 0,
                data: vec![7],
            }),
            Err(RuntimeStateError::ProcessIdMismatch { .. })
        ));
        machine
            .observe_inbound(&RuntimeMessage::Output {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Stdout,
                offset: 0,
                data: vec![7, 8],
            })
            .unwrap();
        assert!(matches!(
            machine.observe_inbound(&RuntimeMessage::Output {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Stdout,
                offset: 1,
                data: vec![9],
            }),
            Err(RuntimeStateError::OffsetMismatch { .. })
        ));
        machine
            .observe_outbound(&RuntimeMessage::OutputAck {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Stdout,
                next_offset: 2,
            })
            .unwrap();
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::OutputAck {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Stdout,
                next_offset: 1,
            }),
            Err(RuntimeStateError::AckRegressed { .. })
        ));
        machine
            .observe_inbound(&RuntimeMessage::Exited {
                process_id: PROCESS_ID,
                status: RuntimeExitStatus::Code(0),
                output_truncated: false,
            })
            .unwrap();
        assert!(machine.is_closed());
    }

    #[test]
    fn pipe_rejects_pty_only_spec_and_messages() {
        let mut machine = client(RuntimeCapability::ProcessPipeV1);
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::StartProcess {
                request_id: 1,
                spec: pty_spec(),
            }),
            Err(RuntimeStateError::InvalidProcessSpec { .. })
        ));

        machine
            .observe_outbound(&RuntimeMessage::StartProcess {
                request_id: 1,
                spec: pipe_spec(),
            })
            .unwrap();
        assert!(matches!(
            machine.observe_inbound(&RuntimeMessage::ProcessStarted {
                request_id: 2,
                process_id: PROCESS_ID,
                session: None,
                output_offset: 0,
            }),
            Err(RuntimeStateError::RequestIdMismatch { .. })
        ));
        machine
            .observe_inbound(&RuntimeMessage::ProcessStarted {
                request_id: 1,
                process_id: PROCESS_ID,
                session: None,
                output_offset: 0,
            })
            .unwrap();
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::Resize {
                process_id: PROCESS_ID,
                size: size(),
            }),
            Err(RuntimeStateError::UnexpectedMessage { .. })
        ));
        assert!(matches!(
            machine.observe_inbound(&RuntimeMessage::Output {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Pty,
                offset: 0,
                data: vec![1],
            }),
            Err(RuntimeStateError::WrongOutputStream { .. })
        ));
    }

    #[test]
    fn runtime_argv_is_control_free_and_pty_limits_are_explicitly_unsupported() {
        for argument in ["line\nfeed", "tab\tvalue", "c1\u{0085}value"] {
            let mut spec = pipe_spec();
            spec.argv.push(argument.to_string());
            assert!(matches!(
                RuntimeMessage::StartProcess {
                    request_id: 1,
                    spec,
                }
                .validate(),
                Err(RuntimeValidationError::ContainsControl("runtime argument"))
            ));
        }

        let mut machine = client(RuntimeCapability::ProcessPtyV1);
        let mut spec = attached_pty_spec();
        spec.max_output_bytes = Some(1024);
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::StartProcess {
                request_id: 1,
                spec,
            }),
            Err(RuntimeStateError::InvalidProcessSpec { .. })
        ));
    }

    #[test]
    fn pty_start_resize_detach_and_exit_race_are_validated() {
        let mut machine = client(RuntimeCapability::ProcessPtyV1);
        machine
            .observe_outbound(&RuntimeMessage::StartProcess {
                request_id: 5,
                spec: pty_spec(),
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::ProcessStarted {
                request_id: 5,
                process_id: PROCESS_ID,
                session: Some(credentials()),
                output_offset: 0,
            })
            .unwrap();
        machine
            .observe_outbound(&RuntimeMessage::Resize {
                process_id: PROCESS_ID,
                size: size(),
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::Output {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Pty,
                offset: 0,
                data: b"prompt".to_vec(),
            })
            .unwrap();
        machine
            .observe_outbound(&RuntimeMessage::Detach {
                process_id: PROCESS_ID,
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::Exited {
                process_id: PROCESS_ID,
                status: RuntimeExitStatus::Code(0),
                output_truncated: false,
            })
            .unwrap();
        assert!(machine.is_closed());
    }

    #[test]
    fn attached_pty_has_no_reattachment_credentials() {
        let mut machine = client(RuntimeCapability::ProcessPtyV1);
        machine
            .observe_outbound(&RuntimeMessage::StartProcess {
                request_id: 6,
                spec: attached_pty_spec(),
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::ProcessStarted {
                request_id: 6,
                process_id: PROCESS_ID,
                session: None,
                output_offset: 0,
            })
            .unwrap();
        machine
            .observe_outbound(&RuntimeMessage::Resize {
                process_id: PROCESS_ID,
                size: size(),
            })
            .unwrap();
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::Detach {
                process_id: PROCESS_ID,
            }),
            Err(RuntimeStateError::UnexpectedMessage { .. })
        ));

        let mut mismatched = client(RuntimeCapability::ProcessPtyV1);
        mismatched
            .observe_outbound(&RuntimeMessage::StartProcess {
                request_id: 7,
                spec: attached_pty_spec(),
            })
            .unwrap();
        assert!(matches!(
            mismatched.observe_inbound(&RuntimeMessage::ProcessStarted {
                request_id: 7,
                process_id: PROCESS_ID,
                session: Some(credentials()),
                output_offset: 0,
            }),
            Err(RuntimeStateError::InvalidProcessSpec { .. })
        ));
    }

    #[test]
    fn pty_attach_requires_explicit_history_gap_before_replay() {
        let credentials = credentials();
        let mut machine = client(RuntimeCapability::ProcessPtyV1);
        machine
            .observe_outbound(&RuntimeMessage::AttachPty {
                request_id: 7,
                credentials: credentials.clone(),
                replay_from: Some(4),
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::PtyAttached {
                request_id: 7,
                process_id: PROCESS_ID,
                session_id: credentials.session_id,
                output_offset: 9,
            })
            .unwrap();
        assert!(matches!(
            machine.observe_inbound(&RuntimeMessage::Output {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Pty,
                offset: 9,
                data: vec![1],
            }),
            Err(RuntimeStateError::OutputBeforeGap)
        ));
        machine
            .observe_inbound(&RuntimeMessage::OutputGap {
                process_id: PROCESS_ID,
                requested_offset: 4,
                available_offset: 9,
                screen_snapshot: b"screen".to_vec(),
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::Output {
                process_id: PROCESS_ID,
                stream: RuntimeOutputStream::Pty,
                offset: 9,
                data: vec![1],
            })
            .unwrap();
    }

    #[test]
    fn watch_state_enforces_sequence_ack_overflow_and_stop_ordering() {
        let mut machine = client(RuntimeCapability::WorkspaceWatchV1);
        machine
            .observe_outbound(&RuntimeMessage::WatchStart {
                request_id: 8,
                resume_from: Some(10),
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::WatchStarted {
                request_id: 8,
                watch_id: WATCH_ID,
                next_sequence: 10,
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::WatchEvents {
                watch_id: WATCH_ID,
                sequence: 10,
                events: vec![watch_event(), watch_event()],
            })
            .unwrap();
        assert!(matches!(
            machine.observe_outbound(&RuntimeMessage::WatchAck {
                watch_id: WATCH_ID,
                next_sequence: 13,
            }),
            Err(RuntimeStateError::AckBeyondSent { .. })
        ));
        machine
            .observe_outbound(&RuntimeMessage::WatchAck {
                watch_id: WATCH_ID,
                next_sequence: 12,
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::WatchOverflow {
                watch_id: WATCH_ID,
                sequence: 12,
                next_sequence: 20,
            })
            .unwrap();
        machine
            .observe_outbound(&RuntimeMessage::WatchStop { watch_id: WATCH_ID })
            .unwrap();

        // A server batch already in flight may cross the stop request.
        machine
            .observe_inbound(&RuntimeMessage::WatchEvents {
                watch_id: WATCH_ID,
                sequence: 20,
                events: vec![watch_event()],
            })
            .unwrap();
        machine
            .observe_inbound(&RuntimeMessage::WatchStopped { watch_id: WATCH_ID })
            .unwrap();
        assert!(machine.is_closed());
    }
}
