use anyhow::{anyhow, bail, Context, Result};
use nrm_protocol::{
    read_runtime_frame, write_runtime_frame, CapabilitySet, RuntimeCapability, RuntimeCwd,
    RuntimeError, RuntimeErrorCode, RuntimeExitStatus, RuntimeMessage, RuntimeOutputStream,
    RuntimePeerRole, RuntimePersistence, RuntimeProcessSpec, RuntimeSignal, RuntimeStateMachine,
    TerminalSize, PROTOCOL_VERSION, RUNTIME_MAX_DATA_CHUNK_LEN,
};
use nrm_pty::{
    PipeInput, PipeOutput, PipeProcess, PtyCommand, PtyError, PtyExitStatus, PtyInput, PtyOutput,
    PtyProcess, PtySignal, PtySize,
};
use std::io::{self, Read, Write};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_FOUND, HANDLE},
    System::IO::CancelSynchronousIo,
};

const INPUT_QUEUE_DEPTH: usize = 16;
const FRAME_QUEUE_DEPTH: usize = 16;
const SERVER_QUEUE_DEPTH: usize = 64;
const OUTPUT_FLOW_WINDOW_BYTES: u64 = 1024 * 1024;
const OUTPUT_HARD_MAX_BYTES: u64 = 128 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const OUTPUT_CANCEL_TIMEOUT: Duration = Duration::from_millis(250);
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const OUTPUT_WORKER_READING: u8 = 0;
const OUTPUT_WORKER_PUBLISHING: u8 = 1;
const TERMINATION_NONE: u8 = 0;
const TERMINATION_TIMEOUT: u8 = 1;
const TERMINATION_OUTPUT_LIMIT: u8 = 2;
const TERMINATION_CANCELLED: u8 = 3;

pub(crate) fn capabilities() -> CapabilitySet {
    let mut capabilities = CapabilitySet::v1_agent();
    capabilities.runtime_process_v1 = true;
    capabilities.runtime_pty_v1 = true;
    capabilities
}

pub(crate) fn serve(root: PathBuf) -> Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize root {}", root.display()))?;
    if !root.is_dir() {
        bail!("runtime root is not a directory");
    }
    run(root, io::stdin(), Box::new(io::stdout()))
}

fn run<R>(root: PathBuf, mut reader: R, writer: Box<dyn Write + Send>) -> Result<()>
where
    R: Read + Send + 'static,
{
    let server = RuntimeServer::new(writer)?;
    let hello = match read_runtime_frame(&mut reader) {
        Ok(message) => message,
        Err(error) => return Err(error).context("read runtime client hello"),
    };
    let capability = match &hello {
        RuntimeMessage::ClientHello { capability, .. } => *capability,
        _ => {
            server.send_error(
                RuntimeErrorCode::Protocol,
                "the first runtime message must be client_hello",
                false,
            )?;
            return Ok(());
        }
    };
    if let Err(error) = server.observe_inbound(&hello) {
        server.send_error(RuntimeErrorCode::Unsupported, &error.to_string(), false)?;
        return Ok(());
    }
    server.send(RuntimeMessage::ServerHello {
        package_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: PROTOCOL_VERSION,
        capability,
    })?;

    let start = match read_runtime_frame(&mut reader) {
        Ok(message) => message,
        Err(error) => return Err(error).context("read runtime process request"),
    };
    if matches!(start, RuntimeMessage::AttachPty { .. })
        || matches!(
            start,
            RuntimeMessage::StartProcess {
                spec: RuntimeProcessSpec {
                    persistence: RuntimePersistence::Detachable { .. },
                    ..
                },
                ..
            }
        )
    {
        if let Err(error) = start.validate() {
            server.send_error(RuntimeErrorCode::Protocol, &error.to_string(), false)?;
        } else {
            server.send_error(
                RuntimeErrorCode::PersistenceUnavailable,
                "persistent PTY broker is not available",
                false,
            )?;
        }
        return Ok(());
    }
    if let Err(error) = server.observe_inbound(&start) {
        server.send_error(RuntimeErrorCode::Protocol, &error.to_string(), false)?;
        return Ok(());
    }
    let (request_id, spec) = match start {
        RuntimeMessage::StartProcess { request_id, spec } => (request_id, spec),
        _ => {
            server.send_error(
                RuntimeErrorCode::Protocol,
                "expected start_process after runtime handshake",
                false,
            )?;
            return Ok(());
        }
    };

    if !matches!(spec.persistence, RuntimePersistence::Attached) {
        server.send_error(
            RuntimeErrorCode::PersistenceUnavailable,
            "detachable processes require the persistent runtime broker",
            false,
        )?;
        return Ok(());
    }

    let command = match build_command(&root, &spec) {
        Ok(command) => command,
        Err(error) => {
            server.send_error(RuntimeErrorCode::InvalidRequest, &error.to_string(), false)?;
            return Ok(());
        }
    };
    let spawned = match spawn_runtime_process(capability, &command, &spec) {
        Ok(process) => process,
        Err(error) => {
            server.send_error(RuntimeErrorCode::SpawnFailed, &error.to_string(), false)?;
            return Ok(());
        }
    };
    let process_id = u64::from(spawned.process.id());
    let process = Arc::new(Mutex::new(spawned.process));
    server.send(RuntimeMessage::ProcessStarted {
        request_id,
        process_id,
        session: None,
        output_offset: 0,
    })?;

    let control = ProcessControl {
        process_id,
        process,
        output_total: Arc::new(AtomicU64::new(0)),
        output_truncated: Arc::new(AtomicBool::new(false)),
        io_stop: Arc::new(AtomicBool::new(false)),
        termination: Arc::new(AtomicU8::new(TERMINATION_NONE)),
        output_flows: OutputFlows::default(),
        server: server.clone(),
    };
    let output_limit = (capability == RuntimeCapability::ProcessPipeV1).then(|| {
        spec.max_output_bytes
            .unwrap_or(OUTPUT_HARD_MAX_BYTES)
            .min(OUTPUT_HARD_MAX_BYTES)
    });
    let output_workers = spawned
        .outputs
        .into_iter()
        .map(|output| spawn_output_worker(output, output_limit, control.clone()))
        .collect();
    let done = Arc::new(AtomicBool::new(false));
    let waiter = spawn_waiter(
        control.clone(),
        output_workers,
        spec.timeout_ms.map(Duration::from_millis),
        Arc::clone(&done),
    );
    let (input_sender, input_worker) = spawn_input_worker(spawned.input, control.clone());

    let loop_result = runtime_loop(reader, &control, &input_sender, &done);
    drop(input_sender);
    if !done.load(Ordering::Acquire) {
        mark_termination(&control.termination, TERMINATION_CANCELLED);
    }
    kill_process(&control.process);
    let input_result = join_worker(input_worker, "runtime input worker");
    let waiter_result = join_worker(waiter, "runtime process waiter");
    let writer_result = server.finish();
    loop_result?;
    input_result?;
    waiter_result?;
    writer_result
}

enum ManagedProcess {
    Pipe(PipeProcess),
    Pty(PtyProcess),
}

impl ManagedProcess {
    fn id(&self) -> u32 {
        match self {
            Self::Pipe(process) => process.id(),
            Self::Pty(process) => process.id(),
        }
    }

    fn resize(&self, size: PtySize) -> Result<(), PtyError> {
        match self {
            Self::Pty(process) => process.resize(size),
            Self::Pipe(_) => Err(PtyError::Unsupported {
                operation: "resize piped process",
            }),
        }
    }

    fn signal(&mut self, signal: PtySignal) -> Result<(), PtyError> {
        match self {
            Self::Pipe(process) => process.signal(signal),
            Self::Pty(process) => process.signal(signal),
        }
    }

    fn try_wait(&mut self) -> Result<Option<PtyExitStatus>, PtyError> {
        match self {
            Self::Pipe(process) => process.try_wait(),
            Self::Pty(process) => process.try_wait(),
        }
    }
}

struct RuntimeOutput {
    stream: RuntimeOutputStream,
    reader: Box<dyn CancellableRuntimeRead>,
}

trait CancellableRuntimeRead: Read + Send {
    fn prepare_cancellable_read(&self) -> io::Result<()>;
}

impl CancellableRuntimeRead for PipeOutput {
    fn prepare_cancellable_read(&self) -> io::Result<()> {
        PipeOutput::prepare_cancellable_read(self)
    }
}

impl CancellableRuntimeRead for PtyOutput {
    fn prepare_cancellable_read(&self) -> io::Result<()> {
        PtyOutput::prepare_cancellable_read(self)
    }
}

struct SpawnedRuntimeProcess {
    process: ManagedProcess,
    input: Box<dyn CancellableRuntimeWrite>,
    outputs: Vec<RuntimeOutput>,
}

trait CancellableRuntimeWrite: Write + Send {
    fn prepare_cancellable_write(&self) -> io::Result<()>;
}

impl CancellableRuntimeWrite for PipeInput {
    fn prepare_cancellable_write(&self) -> io::Result<()> {
        PipeInput::prepare_cancellable_write(self)
    }
}

impl CancellableRuntimeWrite for PtyInput {
    fn prepare_cancellable_write(&self) -> io::Result<()> {
        PtyInput::prepare_cancellable_write(self)
    }
}

#[derive(Clone)]
struct ProcessControl {
    process_id: u64,
    process: Arc<Mutex<ManagedProcess>>,
    output_total: Arc<AtomicU64>,
    output_truncated: Arc<AtomicBool>,
    io_stop: Arc<AtomicBool>,
    termination: Arc<AtomicU8>,
    output_flows: OutputFlows,
    server: RuntimeServer,
}

#[derive(Default)]
struct OutputFlowState {
    sent: u64,
    acknowledged: u64,
    stopped: bool,
}

#[derive(Clone, Default)]
struct OutputFlow(Arc<(Mutex<OutputFlowState>, std::sync::Condvar)>);

impl OutputFlow {
    fn reserve(&self, requested: usize) -> Result<Option<(u64, usize)>> {
        let (state, ready) = &*self.0;
        let mut state = state
            .lock()
            .map_err(|_| anyhow!("runtime output flow lock poisoned"))?;
        while !state.stopped
            && state.sent.saturating_sub(state.acknowledged) >= OUTPUT_FLOW_WINDOW_BYTES
        {
            state = ready
                .wait_timeout(state, POLL_INTERVAL)
                .map_err(|_| anyhow!("runtime output flow lock poisoned"))?
                .0;
        }
        if state.stopped {
            return Ok(None);
        }
        let available =
            OUTPUT_FLOW_WINDOW_BYTES.saturating_sub(state.sent.saturating_sub(state.acknowledged));
        let length = requested.min(available as usize);
        if length == 0 {
            bail!("runtime output flow window has no reservable bytes");
        }
        let offset = state.sent;
        state.sent = state
            .sent
            .checked_add(length as u64)
            .ok_or_else(|| anyhow!("runtime output offset overflow"))?;
        Ok(Some((offset, length)))
    }

    fn acknowledge(&self, next_offset: u64) -> Result<()> {
        let (state, ready) = &*self.0;
        let mut state = state
            .lock()
            .map_err(|_| anyhow!("runtime output flow lock poisoned"))?;
        if next_offset < state.acknowledged || next_offset > state.sent {
            bail!("runtime output acknowledgement is outside the in-flight window");
        }
        state.acknowledged = next_offset;
        ready.notify_all();
        Ok(())
    }

    fn wait_drained_until(&self, deadline: Instant) -> Result<bool> {
        let (state, ready) = &*self.0;
        let mut state = state
            .lock()
            .map_err(|_| anyhow!("runtime output flow lock poisoned"))?;
        while !state.stopped && state.acknowledged != state.sent {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let (next, timeout) = ready
                .wait_timeout(state, remaining)
                .map_err(|_| anyhow!("runtime output flow lock poisoned"))?;
            state = next;
            if timeout.timed_out() && state.acknowledged != state.sent {
                return Ok(false);
            }
        }
        Ok(!state.stopped && state.acknowledged == state.sent)
    }

    fn stop(&self) {
        let (state, ready) = &*self.0;
        if let Ok(mut state) = state.lock() {
            state.stopped = true;
            ready.notify_all();
        }
    }
}

#[derive(Clone, Default)]
struct OutputFlows {
    stdout: OutputFlow,
    stderr: OutputFlow,
    pty: OutputFlow,
}

impl OutputFlows {
    fn for_stream(&self, stream: RuntimeOutputStream) -> &OutputFlow {
        match stream {
            RuntimeOutputStream::Stdout => &self.stdout,
            RuntimeOutputStream::Stderr => &self.stderr,
            RuntimeOutputStream::Pty => &self.pty,
        }
    }

    fn acknowledge(&self, stream: RuntimeOutputStream, next_offset: u64) -> Result<()> {
        self.for_stream(stream).acknowledge(next_offset)
    }

    fn wait_drained_until(&self, deadline: Instant) -> Result<bool> {
        for flow in [&self.stdout, &self.stderr, &self.pty] {
            if !flow.wait_drained_until(deadline)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn stop(&self) {
        self.stdout.stop();
        self.stderr.stop();
        self.pty.stop();
    }
}

fn spawn_runtime_process(
    capability: RuntimeCapability,
    command: &PtyCommand,
    spec: &RuntimeProcessSpec,
) -> Result<SpawnedRuntimeProcess> {
    match capability {
        RuntimeCapability::ProcessPipeV1 => {
            let mut process = PipeProcess::spawn(command)?;
            let input = process
                .take_input()
                .ok_or_else(|| anyhow!("piped process input is missing"))?;
            let stdout = process
                .take_stdout()
                .ok_or_else(|| anyhow!("piped process stdout is missing"))?;
            let stderr = process
                .take_stderr()
                .ok_or_else(|| anyhow!("piped process stderr is missing"))?;
            Ok(SpawnedRuntimeProcess {
                process: ManagedProcess::Pipe(process),
                input: Box::new(input),
                outputs: vec![
                    RuntimeOutput {
                        stream: RuntimeOutputStream::Stdout,
                        reader: Box::new(stdout),
                    },
                    RuntimeOutput {
                        stream: RuntimeOutputStream::Stderr,
                        reader: Box::new(stderr),
                    },
                ],
            })
        }
        RuntimeCapability::ProcessPtyV1 => {
            let size = pty_size(
                spec.terminal_size
                    .as_ref()
                    .ok_or_else(|| anyhow!("PTY process requires terminal dimensions"))?,
            )?;
            let mut process = PtyProcess::spawn(command, size)?;
            let input = process
                .take_input()
                .ok_or_else(|| anyhow!("PTY input is missing"))?;
            let output = process
                .take_output()
                .ok_or_else(|| anyhow!("PTY output is missing"))?;
            Ok(SpawnedRuntimeProcess {
                process: ManagedProcess::Pty(process),
                input: Box::new(input),
                outputs: vec![RuntimeOutput {
                    stream: RuntimeOutputStream::Pty,
                    reader: Box::new(output),
                }],
            })
        }
        RuntimeCapability::WorkspaceWatchV1 => bail!("workspace watch cannot spawn a process"),
    }
}

#[derive(Clone)]
struct RuntimeServer {
    state: Arc<Mutex<RuntimeStateMachine>>,
    writer: Arc<RuntimeWriter>,
}

impl RuntimeServer {
    fn new(writer: Box<dyn Write + Send>) -> Result<Self> {
        Ok(Self {
            state: Arc::new(Mutex::new(RuntimeStateMachine::new(
                RuntimePeerRole::Server,
                capabilities(),
            ))),
            writer: Arc::new(RuntimeWriter::new(writer)?),
        })
    }

    fn observe_inbound(&self, message: &RuntimeMessage) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow!("runtime state lock poisoned"))?
            .observe_inbound(message)
            .map_err(Into::into)
    }

    fn send(&self, message: RuntimeMessage) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("runtime state lock poisoned"))?;
        state.observe_outbound(&message)?;
        self.writer.enqueue(message)
    }

    fn send_error(&self, code: RuntimeErrorCode, message: &str, retryable: bool) -> Result<()> {
        self.send(RuntimeMessage::Error(RuntimeError {
            code,
            message: bounded_error_message(message),
            retryable,
        }))
    }

    fn has_failed(&self) -> bool {
        self.writer.has_failed()
    }

    fn finish(&self) -> Result<()> {
        self.writer.finish()
    }
}

enum RuntimeWriteCommand {
    Message(RuntimeMessage),
    Finish(SyncSender<()>),
}

struct RuntimeWriter {
    sender: SyncSender<RuntimeWriteCommand>,
    worker: Mutex<Option<JoinHandle<()>>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl RuntimeWriter {
    fn new(mut writer: Box<dyn Write + Send>) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(SERVER_QUEUE_DEPTH);
        let failure = Arc::new(Mutex::new(None));
        let writer_failure = Arc::clone(&failure);
        let worker = thread::Builder::new()
            .name("nrm-runtime-writer".to_string())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    match command {
                        RuntimeWriteCommand::Message(message) => {
                            if let Err(error) = write_runtime_frame(&mut writer, &message) {
                                record_writer_failure(
                                    &writer_failure,
                                    format!("write runtime frame failed: {error}"),
                                );
                                break;
                            }
                        }
                        RuntimeWriteCommand::Finish(done) => {
                            let _ = done.send(());
                            break;
                        }
                    }
                }
            })
            .context("spawn runtime frame writer")?;
        Ok(Self {
            sender,
            worker: Mutex::new(Some(worker)),
            failure,
        })
    }

    fn enqueue(&self, message: RuntimeMessage) -> Result<()> {
        match self.sender.try_send(RuntimeWriteCommand::Message(message)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                let message = "runtime output queue is full; peer is not draining output";
                record_writer_failure(&self.failure, message.to_string());
                bail!(message)
            }
            Err(TrySendError::Disconnected(_)) => {
                let message = "runtime output stream is closed";
                record_writer_failure(&self.failure, message.to_string());
                bail!(message)
            }
        }
    }

    fn has_failed(&self) -> bool {
        self.failure
            .lock()
            .map_or(true, |failure| failure.is_some())
    }

    fn finish(&self) -> Result<()> {
        let worker = self
            .worker
            .lock()
            .map_err(|_| anyhow!("runtime writer worker lock poisoned"))?
            .take();
        let Some(worker) = worker else {
            return writer_failure_result(&self.failure);
        };

        let (done_sender, done_receiver) = mpsc::sync_channel(1);
        let mut finish = RuntimeWriteCommand::Finish(done_sender);
        let deadline = Instant::now() + SERVER_SHUTDOWN_TIMEOUT;
        let should_join = loop {
            match self.sender.try_send(finish) {
                Ok(()) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if !remaining.is_zero() && done_receiver.recv_timeout(remaining).is_ok() {
                        break true;
                    }
                    record_writer_failure(
                        &self.failure,
                        "runtime output writer did not stop before its deadline".to_string(),
                    );
                    break false;
                }
                Err(TrySendError::Full(command)) if Instant::now() < deadline => {
                    finish = command;
                    thread::sleep(POLL_INTERVAL);
                }
                Err(TrySendError::Full(_)) => {
                    record_writer_failure(
                        &self.failure,
                        "runtime output queue did not drain before its deadline".to_string(),
                    );
                    break false;
                }
                Err(TrySendError::Disconnected(_)) => break true,
            }
        };
        if should_join && worker.join().is_err() {
            record_writer_failure(&self.failure, "runtime output writer panicked".to_string());
        }
        writer_failure_result(&self.failure)
    }
}

impl Drop for RuntimeWriter {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn record_writer_failure(failure: &Mutex<Option<String>>, message: String) {
    if let Ok(mut failure) = failure.lock() {
        if failure.is_none() {
            *failure = Some(message);
        }
    }
}

fn writer_failure_result(failure: &Mutex<Option<String>>) -> Result<()> {
    match failure.lock() {
        Ok(failure) => match failure.as_deref() {
            Some(message) => bail!("runtime transport failed: {message}"),
            None => Ok(()),
        },
        Err(_) => bail!("runtime writer failure lock poisoned"),
    }
}

fn runtime_loop<R>(
    mut reader: R,
    control: &ProcessControl,
    input: &SyncSender<InputCommand>,
    done: &AtomicBool,
) -> Result<()>
where
    R: Read + Send + 'static,
{
    let (frame_sender, frame_receiver) = mpsc::sync_channel(FRAME_QUEUE_DEPTH);
    let _reader_worker = thread::Builder::new()
        .name("nrm-runtime-reader".to_string())
        .spawn(move || loop {
            let frame = read_runtime_frame(&mut reader);
            let finished = frame.is_err();
            if frame_sender.send(frame).is_err() || finished {
                break;
            }
        })
        .context("spawn runtime frame reader")?;

    loop {
        if done.load(Ordering::Acquire) {
            return Ok(());
        }
        let message = match frame_receiver.recv_timeout(POLL_INTERVAL) {
            Ok(Ok(message)) => message,
            Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => continue,
        };
        if done.load(Ordering::Acquire) {
            return Ok(());
        }
        if matches!(
            message,
            RuntimeMessage::Detach { process_id } if process_id == control.process_id
        ) {
            send_error_then_kill(
                &control.server,
                &control.process,
                RuntimeErrorCode::PersistenceUnavailable,
                "attached process cannot be detached without the persistent runtime broker",
                false,
            )?;
            return Ok(());
        }
        if let Err(error) = control.server.observe_inbound(&message) {
            if done.load(Ordering::Acquire) {
                return Ok(());
            }
            send_error_then_kill(
                &control.server,
                &control.process,
                RuntimeErrorCode::Protocol,
                &error.to_string(),
                false,
            )?;
            return Ok(());
        }
        match message {
            RuntimeMessage::Input { offset, data, .. } => {
                let next_offset = offset + data.len() as u64;
                queue_input(
                    input,
                    InputCommand::Data { data, next_offset },
                    &control.server,
                    &control.process,
                )?;
            }
            RuntimeMessage::CloseInput { .. } => {
                queue_input(
                    input,
                    InputCommand::Close,
                    &control.server,
                    &control.process,
                )?;
            }
            RuntimeMessage::OutputAck {
                stream,
                next_offset,
                ..
            } => {
                control.output_flows.acknowledge(stream, next_offset)?;
            }
            RuntimeMessage::Resize { size, .. } => {
                let size = match pty_size(&size) {
                    Ok(size) => size,
                    Err(error) => {
                        send_error_then_kill(
                            &control.server,
                            &control.process,
                            RuntimeErrorCode::InvalidRequest,
                            &error.to_string(),
                            false,
                        )?;
                        return Ok(());
                    }
                };
                let result = control
                    .process
                    .lock()
                    .map_err(|_| anyhow!("runtime process lock poisoned"))?
                    .resize(size);
                if let Err(error) = result {
                    send_error_then_kill(
                        &control.server,
                        &control.process,
                        runtime_error_code(&error),
                        &error.to_string(),
                        false,
                    )?;
                    return Ok(());
                }
            }
            RuntimeMessage::Signal { signal, .. } => {
                let result = control
                    .process
                    .lock()
                    .map_err(|_| anyhow!("runtime process lock poisoned"))?
                    .signal(convert_signal(signal));
                if let Err(error) = result {
                    send_error_then_kill(
                        &control.server,
                        &control.process,
                        runtime_error_code(&error),
                        &error.to_string(),
                        false,
                    )?;
                    return Ok(());
                }
            }
            _ => {
                // The protocol state machine rejects all other messages while
                // running before this match is reached.
                unreachable!("validated runtime message was not handled")
            }
        }
        if done.load(Ordering::Acquire) {
            return Ok(());
        }
    }
}

fn queue_input(
    sender: &SyncSender<InputCommand>,
    command: InputCommand,
    server: &RuntimeServer,
    process: &Arc<Mutex<ManagedProcess>>,
) -> Result<()> {
    match sender.try_send(command) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => send_error_then_kill(
            server,
            process,
            RuntimeErrorCode::ResourceLimit,
            "runtime input queue is full",
            true,
        ),
        Err(TrySendError::Disconnected(_)) => send_error_then_kill(
            server,
            process,
            RuntimeErrorCode::Internal,
            "runtime input stream is closed",
            false,
        ),
    }
}

enum InputCommand {
    Data { data: Vec<u8>, next_offset: u64 },
    Close,
}

fn spawn_input_worker(
    mut input: Box<dyn CancellableRuntimeWrite>,
    control: ProcessControl,
) -> (SyncSender<InputCommand>, JoinHandle<()>) {
    let (sender, receiver) = mpsc::sync_channel(INPUT_QUEUE_DEPTH);
    let worker = thread::spawn(move || {
        if let Err(error) = input.prepare_cancellable_write() {
            let _ = send_error_then_kill(
                &control.server,
                &control.process,
                RuntimeErrorCode::Internal,
                &format!("prepare process input cancellation failed: {error}"),
                false,
            );
            return;
        }
        while let Ok(command) = receiver.recv() {
            match command {
                InputCommand::Data { data, next_offset } => {
                    if let Err(error) = write_runtime_input(&mut input, &data, &control.io_stop) {
                        let _ = send_error_then_kill(
                            &control.server,
                            &control.process,
                            RuntimeErrorCode::Internal,
                            &format!("write process input failed: {error}"),
                            false,
                        );
                        break;
                    }
                    if control.io_stop.load(Ordering::Acquire) {
                        break;
                    }
                    if control
                        .server
                        .send(RuntimeMessage::InputAck {
                            process_id: control.process_id,
                            next_offset,
                        })
                        .is_err()
                    {
                        kill_process(&control.process);
                        break;
                    }
                }
                InputCommand::Close => break,
            }
        }
    });
    (sender, worker)
}

fn write_runtime_input(input: &mut dyn Write, data: &[u8], stop: &AtomicBool) -> io::Result<()> {
    let mut written = 0;
    while written < data.len() {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        match input.write(&data[written..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        match input.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn spawn_output_worker(
    mut output: RuntimeOutput,
    limit: Option<u64>,
    control: ProcessControl,
) -> OutputWorker {
    let flow = control.output_flows.for_stream(output.stream).clone();
    let (done_sender, done_receiver) = mpsc::sync_channel(1);
    let force_stop = Arc::new(AtomicBool::new(false));
    let worker_force_stop = Arc::clone(&force_stop);
    let phase = Arc::new(AtomicU8::new(OUTPUT_WORKER_READING));
    let worker_phase = Arc::clone(&phase);
    let join = thread::spawn(move || {
        let _done = OutputWorkerDone(done_sender);
        if worker_force_stop.load(Ordering::Acquire) {
            return;
        }
        if let Err(error) = output.reader.prepare_cancellable_read() {
            let _ = send_error_then_kill(
                &control.server,
                &control.process,
                RuntimeErrorCode::Internal,
                &format!("prepare process output cancellation failed: {error}"),
                false,
            );
            return;
        }
        let mut buffer = vec![0_u8; RUNTIME_MAX_DATA_CHUNK_LEN];
        'output: loop {
            if worker_force_stop.load(Ordering::Acquire) {
                break;
            }
            worker_phase.store(OUTPUT_WORKER_READING, Ordering::Release);
            let read = match read_output_chunk(
                output.reader.as_mut(),
                &mut buffer,
                &control.io_stop,
                &worker_force_stop,
            ) {
                Ok(Some(read)) => read,
                Ok(None) => break,
                Err(_) if worker_force_stop.load(Ordering::Acquire) => break,
                Err(error) => {
                    let _ = send_error_then_kill(
                        &control.server,
                        &control.process,
                        RuntimeErrorCode::Internal,
                        &format!("read process output failed: {error}"),
                        false,
                    );
                    break;
                }
            };
            if worker_force_stop.load(Ordering::Acquire) {
                break;
            }
            worker_phase.store(OUTPUT_WORKER_PUBLISHING, Ordering::Release);
            let send_len = limit.map_or(read, |limit| {
                reserve_output(&control.output_total, read, limit)
            });
            if send_len < read {
                control.output_truncated.store(true, Ordering::Release);
                mark_termination(&control.termination, TERMINATION_OUTPUT_LIMIT);
                kill_process(&control.process);
            }
            if send_len == 0 {
                break;
            }
            let mut sent = 0;
            while sent < send_len {
                if worker_force_stop.load(Ordering::Acquire) {
                    break 'output;
                }
                let (offset, chunk_len) = match flow.reserve(send_len - sent) {
                    Ok(Some(reservation)) => reservation,
                    Ok(None) => break 'output,
                    Err(error) => {
                        let _ = send_error_then_kill(
                            &control.server,
                            &control.process,
                            RuntimeErrorCode::Internal,
                            &error.to_string(),
                            false,
                        );
                        break 'output;
                    }
                };
                let data = buffer[sent..sent + chunk_len].to_vec();
                if control
                    .server
                    .send(RuntimeMessage::Output {
                        process_id: control.process_id,
                        stream: output.stream,
                        offset,
                        data,
                    })
                    .is_err()
                {
                    kill_process(&control.process);
                    break 'output;
                }
                sent += chunk_len;
            }
        }
    });
    OutputWorker {
        join,
        done: done_receiver,
        force_stop,
        phase,
    }
}

fn read_output_chunk(
    output: &mut dyn Read,
    buffer: &mut [u8],
    io_stop: &AtomicBool,
    force_stop: &AtomicBool,
) -> io::Result<Option<usize>> {
    let mut read = 0;
    loop {
        if force_stop.load(Ordering::Acquire) {
            return Ok(None);
        }
        match output.read(&mut buffer[read..]) {
            Ok(0) => return Ok((read != 0).then_some(read)),
            Ok(count) => {
                read += count;
                // Windows runtime pipe and ConPTY outputs are synchronous
                // pipes. Reading again can block after a partial prompt and
                // prevent its delivery.
                #[cfg(windows)]
                return Ok(Some(read));
                #[cfg(not(windows))]
                if read == buffer.len() {
                    return Ok(Some(read));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && read != 0 => {
                return Ok(Some(read));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if io_stop.load(Ordering::Acquire) {
                    return Ok(None);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                if force_stop.load(Ordering::Acquire) {
                    return Ok(None);
                }
            }
            Err(_error) if read != 0 => return Ok(Some(read)),
            Err(error) => return Err(error),
        }
    }
}

struct OutputWorker {
    join: JoinHandle<()>,
    done: mpsc::Receiver<()>,
    force_stop: Arc<AtomicBool>,
    phase: Arc<AtomicU8>,
}

struct OutputWorkerDone(SyncSender<()>);

impl Drop for OutputWorkerDone {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

#[derive(Default)]
struct OutputWorkerShutdown {
    panicked: bool,
    abandoned: bool,
    cancellation_error: Option<String>,
}

fn wait_for_output_workers(output_workers: &[OutputWorker], deadline: Instant) -> bool {
    for worker in output_workers {
        while !worker.join.is_finished() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match worker.done.recv_timeout(remaining.min(POLL_INTERVAL)) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
    true
}

fn finish_output_workers(output_workers: Vec<OutputWorker>) -> OutputWorkerShutdown {
    let mut shutdown = OutputWorkerShutdown::default();
    let mut requested_stop = false;
    for worker in &output_workers {
        if worker.join.is_finished() {
            continue;
        }
        requested_stop = true;
        worker.force_stop.store(true, Ordering::Release);
    }
    if requested_stop {
        let cancel_deadline = Instant::now() + OUTPUT_CANCEL_TIMEOUT;
        loop {
            for worker in &output_workers {
                if !worker.join.is_finished() {
                    if let Err(error) = cancel_output_worker_read(&worker.join) {
                        shutdown
                            .cancellation_error
                            .get_or_insert_with(|| error.to_string());
                    }
                }
            }
            if wait_for_output_workers(
                &output_workers,
                (Instant::now() + POLL_INTERVAL).min(cancel_deadline),
            ) || Instant::now() >= cancel_deadline
            {
                break;
            }
        }
    }
    for worker in output_workers {
        if worker.join.is_finished() {
            shutdown.panicked |= worker.join.join().is_err();
        } else {
            // Dropping a JoinHandle detaches the thread. The worker owns its
            // reader and only shared Arc state; force_stop plus stopped output
            // flows prevent a late read from publishing another frame.
            shutdown.abandoned = true;
            drop(worker.join);
        }
    }
    shutdown
}

#[cfg(windows)]
fn cancel_output_worker_read(worker: &JoinHandle<()>) -> io::Result<()> {
    // SAFETY: Rust keeps the worker thread HANDLE valid for the JoinHandle's
    // lifetime. CancelSynchronousIo does not close it or transfer ownership.
    if unsafe { CancelSynchronousIo(worker.as_raw_handle() as HANDLE) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
        // The worker completed or was between synchronous reads. force_stop
        // requests exit, and the bounded grace loop retries cancellation to
        // close the race before a just-starting read becomes pending.
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(windows))]
fn cancel_output_worker_read(_worker: &JoinHandle<()>) -> io::Result<()> {
    Ok(())
}

fn spawn_waiter(
    control: ProcessControl,
    output_workers: Vec<OutputWorker>,
    timeout: Option<Duration>,
    done: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let started = Instant::now();
        let status = loop {
            let poll = control
                .process
                .lock()
                .map_err(|_| anyhow!("runtime process lock poisoned"))
                .and_then(|mut process| process.try_wait().map_err(Into::into));
            match poll {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(error) => break Err(error),
            }
            if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                mark_termination(&control.termination, TERMINATION_TIMEOUT);
                kill_process(&control.process);
            }
            thread::sleep(POLL_INTERVAL);
        };
        // On POSIX, a deliberately daemonized descendant can retain a PTY or
        // pipe descriptor after the owned process group has exited. Output
        // streams use nonblocking reads, so this flag drains already-buffered
        // bytes through the first empty poll and then bounds worker teardown.
        control.io_stop.store(true, Ordering::Release);
        let drain_deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
        let output_workers_timed_out = !wait_for_output_workers(&output_workers, drain_deadline);
        let output_reader_timed_out = output_workers_timed_out
            && output_workers.iter().any(|worker| {
                !worker.join.is_finished()
                    && worker.phase.load(Ordering::Acquire) == OUTPUT_WORKER_READING
            });
        if output_workers_timed_out {
            control.output_flows.stop();
        }
        let acknowledgement_timed_out = (output_workers_timed_out && !output_reader_timed_out)
            || (!output_workers_timed_out
                && !control.server.has_failed()
                && !control
                    .output_flows
                    .wait_drained_until(drain_deadline)
                    .unwrap_or(false));
        control.output_flows.stop();
        let worker_shutdown = finish_output_workers(output_workers);
        // Mark completion before publishing the terminal frame. A client may
        // already have an acknowledgement in flight for the final output
        // chunk; the reader thread must treat that late frame as harmless
        // instead of racing the state machine after `Exited` closes it.
        done.store(true, Ordering::Release);
        if control.server.has_failed() {
            return;
        }
        if output_reader_timed_out
            || worker_shutdown.abandoned
            || worker_shutdown.cancellation_error.is_some()
        {
            control.output_truncated.store(true, Ordering::Release);
            let _ = control.server.send_error(
                RuntimeErrorCode::Internal,
                "runtime output worker did not stop before its deadline",
                false,
            );
            return;
        }
        if acknowledgement_timed_out {
            control.output_truncated.store(true, Ordering::Release);
            let _ = control.server.send_error(
                RuntimeErrorCode::Internal,
                "runtime output acknowledgement did not drain before its deadline",
                false,
            );
            return;
        }
        if worker_shutdown.panicked {
            let _ = control.server.send_error(
                RuntimeErrorCode::Internal,
                "runtime output worker panicked",
                false,
            );
            return;
        }
        match status {
            Ok(status) => {
                let _ = control.server.send(RuntimeMessage::Exited {
                    process_id: control.process_id,
                    status: runtime_exit_status(
                        status,
                        control.termination.load(Ordering::Acquire),
                    ),
                    output_truncated: control.output_truncated.load(Ordering::Acquire),
                });
            }
            Err(error) => {
                let _ = control.server.send_error(
                    RuntimeErrorCode::Internal,
                    &format!("wait for runtime process failed: {error}"),
                    false,
                );
            }
        }
    })
}

fn reserve_output(total: &AtomicU64, requested: usize, limit: u64) -> usize {
    let mut current = total.load(Ordering::Acquire);
    loop {
        let reserved = (limit.saturating_sub(current) as usize).min(requested);
        let next = current.saturating_add(reserved as u64);
        match total.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return reserved,
            Err(actual) => current = actual,
        }
    }
}

fn mark_termination(reason: &AtomicU8, value: u8) {
    let _ = reason.compare_exchange(TERMINATION_NONE, value, Ordering::AcqRel, Ordering::Acquire);
}

fn runtime_exit_status(status: PtyExitStatus, termination: u8) -> RuntimeExitStatus {
    match termination {
        TERMINATION_TIMEOUT => RuntimeExitStatus::TimedOut,
        TERMINATION_OUTPUT_LIMIT => RuntimeExitStatus::OutputLimit,
        TERMINATION_CANCELLED => RuntimeExitStatus::Cancelled,
        _ => {
            if let Some(signal) = status.signal {
                RuntimeExitStatus::Signal(signal as u32)
            } else {
                RuntimeExitStatus::Code(status.code.unwrap_or(1) as i32)
            }
        }
    }
}

fn runtime_error_code(error: &PtyError) -> RuntimeErrorCode {
    match error {
        PtyError::Unsupported { .. } => RuntimeErrorCode::Unsupported,
        _ => RuntimeErrorCode::Internal,
    }
}

fn build_command(root: &Path, spec: &RuntimeProcessSpec) -> Result<PtyCommand> {
    let (program, arguments) = spec
        .argv
        .split_first()
        .ok_or_else(|| anyhow!("runtime argv must not be empty"))?;
    let cwd = resolve_cwd(root, &spec.cwd)?;
    let mut command = PtyCommand::new(program);
    command.args(arguments);
    command.current_dir(cwd);
    if spec.env.clear {
        command.env_clear();
    }
    for name in &spec.env.unset {
        command.env_remove(name);
    }
    for variable in &spec.env.set {
        command.env(&variable.name, &variable.value);
    }
    Ok(command)
}

fn resolve_cwd(root: &Path, cwd: &RuntimeCwd) -> Result<PathBuf> {
    let requested = match cwd {
        RuntimeCwd::WorkspaceRoot => root.to_path_buf(),
        RuntimeCwd::WorkspaceRelative(path) => super::resolve_remote_path(root, path)?,
    };
    let canonical = requested
        .canonicalize()
        .context("runtime working directory does not exist")?;
    super::ensure_path_within_root(root, &canonical)
        .context("runtime working directory escapes the workspace")?;
    if !canonical.is_dir() {
        bail!("runtime working directory is not a directory");
    }
    Ok(canonical)
}

fn pty_size(size: &TerminalSize) -> Result<PtySize> {
    if size.rows > i16::MAX as u16 || size.columns > i16::MAX as u16 {
        bail!("terminal rows and columns must not exceed 32767");
    }
    let pixel_width = u16::try_from(size.pixel_width.unwrap_or(0))
        .context("terminal pixel width exceeds 65535")?;
    let pixel_height = u16::try_from(size.pixel_height.unwrap_or(0))
        .context("terminal pixel height exceeds 65535")?;
    Ok(PtySize {
        rows: size.rows,
        cols: size.columns,
        pixel_width,
        pixel_height,
    })
}

fn convert_signal(signal: RuntimeSignal) -> PtySignal {
    match signal {
        RuntimeSignal::Interrupt => PtySignal::Interrupt,
        RuntimeSignal::Terminate => PtySignal::Terminate,
        RuntimeSignal::Kill => PtySignal::Kill,
        RuntimeSignal::Hangup => PtySignal::Hangup,
    }
}

fn kill_process(process: &Arc<Mutex<ManagedProcess>>) {
    if let Ok(mut process) = process.lock() {
        let _ = process.signal(PtySignal::Kill);
    }
}

fn send_error_then_kill(
    server: &RuntimeServer,
    process: &Arc<Mutex<ManagedProcess>>,
    code: RuntimeErrorCode,
    message: &str,
    retryable: bool,
) -> Result<()> {
    let result = server.send_error(code, message, retryable);
    kill_process(process);
    result
}

fn join_worker(worker: JoinHandle<()>, name: &'static str) -> Result<()> {
    worker.join().map_err(|_| anyhow!("{name} panicked"))
}

fn bounded_error_message(message: &str) -> String {
    const MAX: usize = nrm_protocol::RUNTIME_MAX_ERROR_MESSAGE_BYTES;
    if message.len() <= MAX {
        return message.to_string();
    }
    let mut end = MAX;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrm_protocol::{PtySessionCredentials, RuntimeEnvVar, RuntimeEnvironment};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::Condvar;

    const REQUEST_ID: u64 = 41;

    #[cfg(windows)]
    #[test]
    fn windows_output_chunk_returns_after_the_first_successful_read() {
        struct PromptThenBlock {
            prompt: &'static [u8],
            read: bool,
        }

        impl Read for PromptThenBlock {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                assert!(!self.read, "output chunk attempted a second blocking read");
                self.read = true;
                let read = self.prompt.len().min(buffer.len());
                buffer[..read].copy_from_slice(&self.prompt[..read]);
                Ok(read)
            }
        }

        const PROMPT: &[u8] = b"interactive prompt>";
        let mut output = PromptThenBlock {
            prompt: PROMPT,
            read: false,
        };
        let mut buffer = [0_u8; 64];
        let stopped = AtomicBool::new(false);
        let force_stopped = AtomicBool::new(false);

        let read = read_output_chunk(&mut output, &mut buffer, &stopped, &force_stopped).unwrap();

        assert_eq!(read, Some(PROMPT.len()));
        assert_eq!(&buffer[..PROMPT.len()], PROMPT);
    }

    #[cfg(windows)]
    #[test]
    fn cancelled_interrupted_output_read_does_not_start_another_read() {
        struct CancelledRead {
            force_stop: Arc<AtomicBool>,
            reads: usize,
        }

        impl Read for CancelledRead {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                assert_eq!(self.reads, 1, "cancelled output attempted another read");
                self.force_stop.store(true, Ordering::Release);
                Err(io::ErrorKind::Interrupted.into())
            }
        }

        let force_stop = Arc::new(AtomicBool::new(false));
        let mut output = CancelledRead {
            force_stop: Arc::clone(&force_stop),
            reads: 0,
        };
        let mut buffer = [0_u8; 1];

        assert_eq!(
            read_output_chunk(
                &mut output,
                &mut buffer,
                &AtomicBool::new(false),
                &force_stop,
            )
            .unwrap(),
            None
        );
        assert_eq!(output.reads, 1);
    }

    #[derive(Default)]
    struct GateState {
        started: bool,
        released: bool,
    }

    struct GatedWriter {
        gate: Arc<(Mutex<GateState>, Condvar)>,
    }

    impl Write for GatedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let (lock, ready) = &*self.gate;
            let mut state = lock.lock().unwrap();
            state.started = true;
            ready.notify_all();
            while !state.released {
                state = ready.wait(state).unwrap();
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn wait_for_gated_writer(gate: &Arc<(Mutex<GateState>, Condvar)>) {
        let (lock, ready) = &**gate;
        let state = lock.lock().unwrap();
        let (_state, wait) = ready
            .wait_timeout_while(state, Duration::from_secs(2), |state| !state.started)
            .unwrap();
        assert!(!wait.timed_out(), "writer did not enter the blocking write");
    }

    fn release_gated_writer(gate: &Arc<(Mutex<GateState>, Condvar)>) {
        let (lock, ready) = &**gate;
        let mut state = lock.lock().unwrap();
        state.released = true;
        ready.notify_all();
    }

    struct RuntimeHarness {
        client: TcpStream,
        server: Option<JoinHandle<Result<()>>>,
        _root: tempfile::TempDir,
    }

    impl RuntimeHarness {
        fn new(capability: RuntimeCapability) -> Self {
            let root = tempfile::tempdir().unwrap();
            let root_path = root.path().canonicalize().unwrap();
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server_stream, _) = listener.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let server_reader = server_stream.try_clone().unwrap();
            let server =
                thread::spawn(move || run(root_path, server_reader, Box::new(server_stream)));

            write_runtime_frame(
                &mut client,
                &RuntimeMessage::ClientHello {
                    package_version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    capability,
                },
            )
            .unwrap();
            assert_eq!(
                read_runtime_frame(&mut client).unwrap(),
                RuntimeMessage::ServerHello {
                    package_version: env!("CARGO_PKG_VERSION").to_string(),
                    protocol_version: PROTOCOL_VERSION,
                    capability,
                }
            );

            Self {
                client,
                server: Some(server),
                _root: root,
            }
        }

        fn start(&mut self, spec: RuntimeProcessSpec) -> u64 {
            write_runtime_frame(
                &mut self.client,
                &RuntimeMessage::StartProcess {
                    request_id: REQUEST_ID,
                    spec,
                },
            )
            .unwrap();
            match read_runtime_frame(&mut self.client).unwrap() {
                RuntimeMessage::ProcessStarted {
                    request_id,
                    process_id,
                    session,
                    output_offset,
                } => {
                    assert_eq!(request_id, REQUEST_ID);
                    assert_ne!(process_id, 0);
                    assert_eq!(
                        session, None,
                        "attached processes must not mint credentials"
                    );
                    assert_eq!(output_offset, 0);
                    process_id
                }
                message => panic!("expected process_started, got {message:?}"),
            }
        }

        fn finish(mut self) {
            let _ = self.client.shutdown(Shutdown::Write);
            let result = self.server.take().unwrap().join().unwrap();
            result.unwrap();
        }

        fn finish_while_input_is_open(mut self) {
            let server = self.server.take().unwrap();
            let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
            thread::spawn(move || {
                let _ = result_sender.send(server.join());
            });
            let result = result_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("runtime server waited for client input EOF after process exit")
                .unwrap();
            result.unwrap();
        }
    }

    impl Drop for RuntimeHarness {
        fn drop(&mut self) {
            let _ = self.client.shutdown(Shutdown::Both);
            if let Some(server) = self.server.take() {
                let _ = server.join();
            }
        }
    }

    #[derive(Default)]
    struct CollectedProcess {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        pty: Vec<u8>,
        input_ack: u64,
        status: Option<RuntimeExitStatus>,
        output_truncated: bool,
    }

    fn collect_process(client: &mut TcpStream, process_id: u64) -> CollectedProcess {
        collect_process_from(client, process_id, CollectedProcess::default())
    }

    fn collect_process_from(
        client: &mut TcpStream,
        process_id: u64,
        mut collected: CollectedProcess,
    ) -> CollectedProcess {
        loop {
            match read_runtime_frame(client).unwrap() {
                RuntimeMessage::InputAck {
                    process_id: actual,
                    next_offset,
                } => {
                    assert_eq!(actual, process_id);
                    assert!(next_offset >= collected.input_ack);
                    collected.input_ack = next_offset;
                }
                RuntimeMessage::Output {
                    process_id: actual,
                    stream,
                    offset,
                    data,
                } => {
                    assert_eq!(actual, process_id);
                    let destination = match stream {
                        RuntimeOutputStream::Stdout => &mut collected.stdout,
                        RuntimeOutputStream::Stderr => &mut collected.stderr,
                        RuntimeOutputStream::Pty => &mut collected.pty,
                    };
                    assert_eq!(offset, destination.len() as u64);
                    destination.extend_from_slice(&data);
                    write_runtime_frame(
                        client,
                        &RuntimeMessage::OutputAck {
                            process_id,
                            stream,
                            next_offset: offset + data.len() as u64,
                        },
                    )
                    .unwrap();
                }
                RuntimeMessage::Exited {
                    process_id: actual,
                    status,
                    output_truncated,
                } => {
                    assert_eq!(actual, process_id);
                    collected.status = Some(status);
                    collected.output_truncated = output_truncated;
                    return collected;
                }
                RuntimeMessage::Error(error) => panic!("runtime failed: {error:?}"),
                message => panic!("unexpected runtime message: {message:?}"),
            }
        }
    }

    fn subprocess_spec(fixture: &str, capability: RuntimeCapability) -> RuntimeProcessSpec {
        let executable = std::env::current_exe().unwrap();
        RuntimeProcessSpec {
            argv: vec![
                executable.to_string_lossy().into_owned(),
                "--exact".to_string(),
                format!("runtime::tests::{fixture}"),
                "--ignored".to_string(),
                "--nocapture".to_string(),
            ],
            cwd: RuntimeCwd::WorkspaceRoot,
            env: RuntimeEnvironment::default(),
            persistence: RuntimePersistence::Attached,
            terminal_size: (capability == RuntimeCapability::ProcessPtyV1).then_some(
                TerminalSize {
                    columns: 80,
                    rows: 24,
                    pixel_width: None,
                    pixel_height: None,
                },
            ),
            timeout_ms: None,
            max_output_bytes: (capability == RuntimeCapability::ProcessPipeV1)
                .then_some(4 * 1024 * 1024),
        }
    }

    fn spec() -> RuntimeProcessSpec {
        RuntimeProcessSpec {
            argv: vec!["program".to_string(), "argument with spaces".to_string()],
            cwd: RuntimeCwd::WorkspaceRoot,
            env: RuntimeEnvironment {
                clear: true,
                set: vec![RuntimeEnvVar {
                    name: "NRM_VALUE".to_string(),
                    value: "raw value".to_string(),
                }],
                unset: vec!["OLD_VALUE".to_string()],
            },
            persistence: RuntimePersistence::Attached,
            terminal_size: Some(TerminalSize {
                columns: 80,
                rows: 24,
                pixel_width: None,
                pixel_height: None,
            }),
            timeout_ms: None,
            max_output_bytes: None,
        }
    }

    #[test]
    fn command_keeps_argument_and_environment_boundaries() {
        let root = tempfile::tempdir().unwrap();
        // Production canonicalizes the workspace before entering the runtime.
        // Preserve that invariant in the test because macOS aliases /var to
        // /private/var when canonicalizing the requested working directory.
        let canonical_root = root.path().canonicalize().unwrap();
        let command = build_command(&canonical_root, &spec()).unwrap();
        assert_eq!(command.program(), "program");
        assert_eq!(command.arguments(), ["argument with spaces"]);
        assert!(command.clears_environment());
        assert_eq!(command.environment().len(), 2);
    }

    #[test]
    fn terminal_dimensions_reject_platform_overflow() {
        let size = TerminalSize {
            columns: u16::MAX,
            rows: 24,
            pixel_width: None,
            pixel_height: None,
        };
        assert!(pty_size(&size).is_err());
    }

    #[test]
    fn output_flow_waits_for_acknowledgement_and_stop_releases_waiter() {
        let flow = OutputFlow::default();
        assert_eq!(
            flow.reserve(OUTPUT_FLOW_WINDOW_BYTES as usize).unwrap(),
            Some((0, OUTPUT_FLOW_WINDOW_BYTES as usize))
        );

        let waiting_flow = flow.clone();
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let waiter = thread::spawn(move || {
            let _ = result_sender.send(waiting_flow.reserve(1));
        });
        assert!(result_receiver
            .recv_timeout(Duration::from_millis(50))
            .is_err());
        flow.acknowledge(OUTPUT_FLOW_WINDOW_BYTES).unwrap();
        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            Some((OUTPUT_FLOW_WINDOW_BYTES, 1))
        );
        waiter.join().unwrap();

        let stopped_flow = OutputFlow::default();
        assert_eq!(
            stopped_flow
                .reserve(OUTPUT_FLOW_WINDOW_BYTES as usize)
                .unwrap(),
            Some((0, OUTPUT_FLOW_WINDOW_BYTES as usize))
        );
        let waiting_flow = stopped_flow.clone();
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let waiter = thread::spawn(move || {
            let _ = result_sender.send(waiting_flow.reserve(1));
        });
        assert!(result_receiver
            .recv_timeout(Duration::from_millis(50))
            .is_err());
        stopped_flow.stop();
        assert_eq!(
            result_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            None
        );
        waiter.join().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn output_worker_teardown_is_bounded_when_a_read_cannot_be_cancelled() {
        let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let (exited_sender, exited_receiver) = mpsc::sync_channel(1);
        let (done_sender, done_receiver) = mpsc::sync_channel(1);
        let join = thread::spawn(move || {
            let done = OutputWorkerDone(done_sender);
            entered_sender.send(()).unwrap();
            let _ = release_receiver.recv_timeout(Duration::from_secs(2));
            drop(done);
            exited_sender.send(()).unwrap();
        });
        let worker = OutputWorker {
            join,
            done: done_receiver,
            force_stop: Arc::new(AtomicBool::new(false)),
            phase: Arc::new(AtomicU8::new(OUTPUT_WORKER_READING)),
        };
        entered_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let started = Instant::now();
        let shutdown = finish_output_workers(vec![worker]);
        assert!(
            started.elapsed() < OUTPUT_CANCEL_TIMEOUT + Duration::from_secs(1),
            "output teardown exceeded its cancellation deadline"
        );
        assert!(shutdown.abandoned);
        assert!(!shutdown.panicked);
        assert_eq!(shutdown.cancellation_error, None);

        // The detached fixture remains owned and can still be released
        // cleanly after the bounded production helper returns.
        release_sender.send(()).unwrap();
        exited_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn output_worker_cancellation_interrupts_a_pipe_with_a_retained_writer() {
        use std::fs::File;
        use std::os::windows::io::{FromRawHandle as _, RawHandle};
        use windows_sys::Win32::Foundation::{ERROR_OPERATION_ABORTED, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Pipes::CreatePipe;

        let mut read_handle = INVALID_HANDLE_VALUE;
        let mut write_handle = INVALID_HANDLE_VALUE;
        // SAFETY: Both output pointers are valid and the null security
        // attributes request the documented defaults.
        assert_ne!(
            unsafe { CreatePipe(&mut read_handle, &mut write_handle, std::ptr::null(), 0,) },
            0,
            "CreatePipe failed: {}",
            io::Error::last_os_error()
        );
        // SAFETY: CreatePipe returned two uniquely owned valid handles. Each
        // ownership is transferred exactly once into a File.
        let mut reader = unsafe { File::from_raw_handle(read_handle as RawHandle) };
        let mut writer = unsafe { File::from_raw_handle(write_handle as RawHandle) };
        let _retained_reader = reader.try_clone().unwrap();
        let (writer_gate_sender, writer_gate_receiver) = mpsc::sync_channel(1);
        let (writer_result_sender, writer_result_receiver) = mpsc::sync_channel(1);
        let writer_watchdog = thread::spawn(move || {
            let released_before_watchdog = writer_gate_receiver
                .recv_timeout(Duration::from_secs(2))
                .is_ok();
            let result = released_before_watchdog
                .then(|| writer.write_all(b"x"))
                .transpose();
            writer_result_sender
                .send((released_before_watchdog, result))
                .unwrap();
            // On a regression, dropping the sole writer after the watchdog
            // deadline releases the blocked read so the test fails instead of
            // hanging the entire native test process.
        });
        let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let (done_sender, done_receiver) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let _done = OutputWorkerDone(done_sender);
            entered_sender.send(()).unwrap();
            let mut byte = [0_u8; 1];
            let result = reader.read(&mut byte).map_err(|error| error.raw_os_error());
            result_sender.send(result).unwrap();
        });
        let force_stop = Arc::new(AtomicBool::new(false));
        let worker = OutputWorker {
            join: worker,
            done: done_receiver,
            force_stop: Arc::clone(&force_stop),
            phase: Arc::new(AtomicU8::new(OUTPUT_WORKER_READING)),
        };
        entered_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let started = Instant::now();
        let shutdown = finish_output_workers(vec![worker]);
        let elapsed = started.elapsed();
        let _ = writer_gate_sender.send(());
        let (writer_released, writer_result) = writer_result_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        writer_watchdog.join().unwrap();
        assert!(
            elapsed < OUTPUT_CANCEL_TIMEOUT + Duration::from_secs(1),
            "pipe output teardown exceeded its cancellation deadline"
        );
        assert!(!shutdown.abandoned);
        assert!(!shutdown.panicked);
        assert_eq!(shutdown.cancellation_error, None);
        assert!(force_stop.load(Ordering::Acquire));
        let result = result_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(result, Err(Some(ERROR_OPERATION_ABORTED as i32)));

        // Cancellation affects only the pending read. The independently held
        // writer remains valid and can still place bytes into the pipe.
        assert!(writer_released);
        writer_result.unwrap();
    }

    #[test]
    fn runtime_writer_rejects_backpressure_without_blocking_sender() {
        let gate = Arc::new((Mutex::new(GateState::default()), Condvar::new()));
        let writer = RuntimeWriter::new(Box::new(GatedWriter {
            gate: Arc::clone(&gate),
        }))
        .unwrap();
        let message = || {
            RuntimeMessage::Error(RuntimeError {
                code: RuntimeErrorCode::Internal,
                message: "bounded writer test".to_string(),
                retryable: false,
            })
        };
        writer.enqueue(message()).unwrap();
        wait_for_gated_writer(&gate);

        for _ in 0..SERVER_QUEUE_DEPTH {
            writer.enqueue(message()).unwrap();
        }
        let started = Instant::now();
        let error = writer.enqueue(message()).unwrap_err();
        assert!(error.to_string().contains("peer is not draining output"));
        assert!(started.elapsed() < Duration::from_millis(100));
        release_gated_writer(&gate);
        assert!(writer.finish().is_err());
        drop(writer);
    }

    #[test]
    fn non_draining_peer_cannot_receive_a_successful_terminal_result() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let gate = Arc::new((Mutex::new(GateState::default()), Condvar::new()));
        let server_gate = Arc::clone(&gate);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = run(
                root_path,
                server_stream,
                Box::new(GatedWriter { gate: server_gate }),
            );
            let _ = result_sender.send(result);
        });

        write_runtime_frame(
            &mut client,
            &RuntimeMessage::ClientHello {
                package_version: env!("CARGO_PKG_VERSION").to_string(),
                protocol_version: PROTOCOL_VERSION,
                capability: RuntimeCapability::ProcessPipeV1,
            },
        )
        .unwrap();
        wait_for_gated_writer(&gate);
        write_runtime_frame(
            &mut client,
            &RuntimeMessage::StartProcess {
                request_id: REQUEST_ID,
                spec: {
                    let mut spec = subprocess_spec(
                        "subprocess_emits_output_flood",
                        RuntimeCapability::ProcessPipeV1,
                    );
                    spec.timeout_ms = Some(50);
                    spec
                },
            },
        )
        .unwrap();

        let started = Instant::now();
        let error = result_receiver
            .recv_timeout(Duration::from_secs(6))
            .expect("runtime remained stuck behind a non-draining peer")
            .unwrap_err();
        assert!(
            error.to_string().contains("runtime transport failed"),
            "unexpected transport result: {error:#}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        release_gated_writer(&gate);
        let _ = client.shutdown(Shutdown::Both);
    }

    #[cfg(unix)]
    #[test]
    fn cwd_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("outside")).unwrap();
        let error = resolve_cwd(
            root.path(),
            &RuntimeCwd::WorkspaceRelative("outside".to_string()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("escapes the workspace"));
    }

    #[test]
    fn attached_pipe_preserves_binary_input_and_separate_output() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPipeV1);
        let process_id = harness.start(subprocess_spec(
            "subprocess_copies_binary_stdin",
            RuntimeCapability::ProcessPipeV1,
        ));
        let input = b"raw\0pipe\nbytes";
        write_runtime_frame(
            &mut harness.client,
            &RuntimeMessage::Input {
                process_id,
                offset: 0,
                data: input.to_vec(),
            },
        )
        .unwrap();
        write_runtime_frame(
            &mut harness.client,
            &RuntimeMessage::CloseInput {
                process_id,
                next_offset: input.len() as u64,
            },
        )
        .unwrap();

        let collected = collect_process(&mut harness.client, process_id);
        assert_eq!(collected.input_ack, input.len() as u64);
        assert!(
            collected
                .stdout
                .windows(input.len())
                .any(|window| window == input),
            "stdout did not contain the binary input: {:?}",
            String::from_utf8_lossy(&collected.stdout)
        );
        assert!(collected
            .stderr
            .windows(b"pipe-stderr".len())
            .any(|window| window == b"pipe-stderr"));
        assert_eq!(collected.status, Some(RuntimeExitStatus::Code(0)));
        assert!(!collected.output_truncated);
        harness.finish();
    }

    #[test]
    fn natural_exit_does_not_wait_for_client_input_eof() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPipeV1);
        let process_id = harness.start(subprocess_spec(
            "subprocess_emits_large_stdout",
            RuntimeCapability::ProcessPipeV1,
        ));

        let collected = collect_process(&mut harness.client, process_id);
        assert_eq!(collected.status, Some(RuntimeExitStatus::Code(0)));
        assert!(!collected.output_truncated);
        // Deliberately retain the client's write half. The server-side frame
        // reader remains blocked, so completion must be driven by the process
        // state rather than transport EOF.
        harness.finish_while_input_is_open();
    }

    #[test]
    fn output_after_exit_waits_for_delayed_ack_without_losing_bytes() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPipeV1);
        let mut spec = subprocess_spec(
            "subprocess_exits_with_more_than_output_window",
            RuntimeCapability::ProcessPipeV1,
        );
        spec.max_output_bytes = Some(2 * 1024 * 1024);
        let process_id = harness.start(spec);
        let mut collected = CollectedProcess::default();

        while collected.stdout.len() < OUTPUT_FLOW_WINDOW_BYTES as usize {
            match read_runtime_frame(&mut harness.client).unwrap() {
                RuntimeMessage::Output {
                    process_id: actual,
                    stream: RuntimeOutputStream::Stdout,
                    offset,
                    data,
                } => {
                    assert_eq!(actual, process_id);
                    assert_eq!(offset, collected.stdout.len() as u64);
                    collected.stdout.extend_from_slice(&data);
                }
                message => panic!("unexpected runtime message: {message:?}"),
            }
        }
        assert_eq!(collected.stdout.len(), OUTPUT_FLOW_WINDOW_BYTES as usize);
        thread::sleep(Duration::from_millis(100));
        write_runtime_frame(
            &mut harness.client,
            &RuntimeMessage::OutputAck {
                process_id,
                stream: RuntimeOutputStream::Stdout,
                next_offset: OUTPUT_FLOW_WINDOW_BYTES,
            },
        )
        .unwrap();

        let collected = collect_process_from(&mut harness.client, process_id, collected);
        assert_eq!(
            collected.stdout.iter().filter(|byte| **byte == 0).count(),
            OUTPUT_FLOW_WINDOW_BYTES as usize + 1
        );
        assert_eq!(collected.status, Some(RuntimeExitStatus::Code(0)));
        assert!(!collected.output_truncated);
        harness.finish();
    }

    #[test]
    fn output_after_exit_without_ack_fails_after_bounded_drain() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPipeV1);
        let mut spec = subprocess_spec(
            "subprocess_exits_with_more_than_output_window",
            RuntimeCapability::ProcessPipeV1,
        );
        spec.max_output_bytes = Some(2 * 1024 * 1024);
        let process_id = harness.start(spec);
        let mut received = 0_usize;
        while received < OUTPUT_FLOW_WINDOW_BYTES as usize {
            match read_runtime_frame(&mut harness.client).unwrap() {
                RuntimeMessage::Output {
                    process_id: actual,
                    stream: RuntimeOutputStream::Stdout,
                    offset,
                    data,
                } => {
                    assert_eq!(actual, process_id);
                    assert_eq!(offset, received as u64);
                    received += data.len();
                }
                message => panic!("unexpected runtime message: {message:?}"),
            }
        }
        let started = Instant::now();
        match read_runtime_frame(&mut harness.client).unwrap() {
            RuntimeMessage::Error(error) => {
                assert_eq!(error.code, RuntimeErrorCode::Internal);
                assert!(error.message.contains("acknowledgement"));
            }
            message => panic!("expected bounded output-drain failure, got {message:?}"),
        }
        assert!(started.elapsed() < OUTPUT_DRAIN_TIMEOUT + Duration::from_secs(1));
        harness.finish();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_exit_output_drain_is_bounded_when_daemon_retains_descriptors() {
        for capability in [
            RuntimeCapability::ProcessPipeV1,
            RuntimeCapability::ProcessPtyV1,
        ] {
            let mut harness = RuntimeHarness::new(capability);
            let process_id = harness.start(subprocess_spec(
                "subprocess_daemon_retains_output",
                capability,
            ));
            let started = Instant::now();
            let collected = collect_process(&mut harness.client, process_id);
            assert_eq!(collected.status, Some(RuntimeExitStatus::Code(0)));
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "runtime waited for a daemonized descriptor holder"
            );
            harness.finish();
        }
    }

    #[test]
    fn attached_pty_has_no_credentials_and_streams_output() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPtyV1);
        let spec = subprocess_spec(
            "subprocess_emits_large_stdout",
            RuntimeCapability::ProcessPtyV1,
        );
        let process_id = harness.start(spec);
        write_runtime_frame(
            &mut harness.client,
            &RuntimeMessage::Resize {
                process_id,
                size: TerminalSize {
                    columns: 100,
                    rows: 30,
                    pixel_width: None,
                    pixel_height: None,
                },
            },
        )
        .unwrap();

        let collected = collect_process(&mut harness.client, process_id);
        assert!(!collected.pty.is_empty());
        assert_eq!(collected.status, Some(RuntimeExitStatus::Code(0)));
        assert!(!collected.output_truncated);
        harness.finish();
    }

    #[cfg(windows)]
    #[test]
    fn attached_pty_interactive_cmd_streams_prompt_accepts_input_and_exits() {
        const PROMPT: &[u8] = b"NRM_RUNTIME_PROMPT>";
        const MARKER: &[u8] = b"NRM_RUNTIME_INTERACTIVE_OK";
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPtyV1);
        let spec = RuntimeProcessSpec {
            argv: vec!["cmd.exe".to_string(), "/d".to_string(), "/q".to_string()],
            cwd: RuntimeCwd::WorkspaceRoot,
            env: RuntimeEnvironment {
                clear: false,
                set: vec![
                    RuntimeEnvVar {
                        name: "PROMPT".to_string(),
                        value: "NRM_RUNTIME_PROMPT$G".to_string(),
                    },
                    RuntimeEnvVar {
                        name: "NRM_RUNTIME_RESULT".to_string(),
                        value: "NRM_RUNTIME_INTERACTIVE_OK".to_string(),
                    },
                ],
                unset: Vec::new(),
            },
            persistence: RuntimePersistence::Attached,
            terminal_size: Some(TerminalSize {
                columns: 80,
                rows: 24,
                pixel_width: None,
                pixel_height: None,
            }),
            timeout_ms: Some(20_000),
            max_output_bytes: None,
        };
        let process_id = harness.start(spec);
        let mut pty = Vec::new();
        while !pty.windows(PROMPT.len()).any(|window| window == PROMPT) {
            match read_runtime_frame(&mut harness.client).expect("read interactive prompt frame") {
                RuntimeMessage::Output {
                    process_id: actual,
                    stream: RuntimeOutputStream::Pty,
                    offset,
                    data,
                } => {
                    assert_eq!(actual, process_id);
                    assert_eq!(offset, pty.len() as u64);
                    pty.extend_from_slice(&data);
                    write_runtime_frame(
                        &mut harness.client,
                        &RuntimeMessage::OutputAck {
                            process_id,
                            stream: RuntimeOutputStream::Pty,
                            next_offset: pty.len() as u64,
                        },
                    )
                    .unwrap();
                }
                message => panic!(
                    "unexpected message before prompt: {message:?}; output: {:?}",
                    String::from_utf8_lossy(&pty)
                ),
            }
        }

        let input = b"echo %NRM_RUNTIME_RESULT%\r\nexit /b 0\r\n";
        assert!(!input.windows(MARKER.len()).any(|window| window == MARKER));
        write_runtime_frame(
            &mut harness.client,
            &RuntimeMessage::Input {
                process_id,
                offset: 0,
                data: input.to_vec(),
            },
        )
        .unwrap();
        let collected = collect_process_from(
            &mut harness.client,
            process_id,
            CollectedProcess {
                pty,
                ..CollectedProcess::default()
            },
        );

        assert_eq!(collected.input_ack, input.len() as u64);
        assert!(
            collected
                .pty
                .windows(MARKER.len())
                .any(|window| window == MARKER),
            "missing interactive marker: {:?}",
            String::from_utf8_lossy(&collected.pty)
        );
        assert_eq!(collected.status, Some(RuntimeExitStatus::Code(0)));
        assert!(!collected.output_truncated);
        harness.finish();
    }

    #[test]
    fn pty_pipe_output_limit_is_rejected_before_spawn() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPtyV1);
        let mut spec = subprocess_spec(
            "subprocess_emits_large_stdout",
            RuntimeCapability::ProcessPtyV1,
        );
        spec.max_output_bytes = Some(16);
        write_runtime_frame(
            &mut harness.client,
            &RuntimeMessage::StartProcess {
                request_id: REQUEST_ID,
                spec,
            },
        )
        .unwrap();
        assert!(matches!(
            read_runtime_frame(&mut harness.client).unwrap(),
            RuntimeMessage::Error(RuntimeError {
                code: RuntimeErrorCode::Protocol,
                retryable: false,
                ..
            })
        ));
        harness.finish();
    }

    #[cfg(unix)]
    #[test]
    fn attached_pty_retries_large_nonblocking_input_for_a_slow_reader() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPtyV1);
        let process_id = harness.start(subprocess_spec(
            "subprocess_slow_pty_reader",
            RuntimeCapability::ProcessPtyV1,
        ));
        let input = vec![b'x'; RUNTIME_MAX_DATA_CHUNK_LEN];
        write_runtime_frame(
            &mut harness.client,
            &RuntimeMessage::Input {
                process_id,
                offset: 0,
                data: input.clone(),
            },
        )
        .unwrap();

        let collected = collect_process(&mut harness.client, process_id);
        assert_eq!(collected.input_ack, input.len() as u64);
        assert!(collected
            .pty
            .windows(b"slow-read-ok".len())
            .any(|window| window == b"slow-read-ok"));
        assert_eq!(collected.status, Some(RuntimeExitStatus::Code(0)));
        harness.finish();
    }

    #[test]
    fn pipe_output_limit_kills_process_with_typed_status() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPipeV1);
        let mut spec = subprocess_spec(
            "subprocess_emits_large_stdout",
            RuntimeCapability::ProcessPipeV1,
        );
        spec.max_output_bytes = Some(1024);
        let process_id = harness.start(spec);

        let collected = collect_process(&mut harness.client, process_id);
        assert_eq!(collected.stdout.len() + collected.stderr.len(), 1024);
        assert_eq!(collected.status, Some(RuntimeExitStatus::OutputLimit));
        assert!(collected.output_truncated);
        harness.finish();
    }

    #[test]
    fn process_timeout_kills_process_with_typed_status() {
        let mut harness = RuntimeHarness::new(RuntimeCapability::ProcessPipeV1);
        let mut spec = subprocess_spec(
            "subprocess_waits_for_timeout",
            RuntimeCapability::ProcessPipeV1,
        );
        spec.timeout_ms = Some(50);
        let process_id = harness.start(spec);

        let collected = collect_process(&mut harness.client, process_id);
        assert_eq!(collected.status, Some(RuntimeExitStatus::TimedOut));
        assert!(!collected.output_truncated);
        harness.finish();
    }

    #[test]
    fn detachable_start_and_attach_fail_closed_without_broker() {
        let mut start_harness = RuntimeHarness::new(RuntimeCapability::ProcessPtyV1);
        let mut spec = subprocess_spec(
            "subprocess_emits_large_stdout",
            RuntimeCapability::ProcessPtyV1,
        );
        spec.persistence = RuntimePersistence::Detachable { ttl_ms: 60_000 };
        write_runtime_frame(
            &mut start_harness.client,
            &RuntimeMessage::StartProcess {
                request_id: REQUEST_ID,
                spec,
            },
        )
        .unwrap();
        assert!(matches!(
            read_runtime_frame(&mut start_harness.client).unwrap(),
            RuntimeMessage::Error(RuntimeError {
                code: RuntimeErrorCode::PersistenceUnavailable,
                retryable: false,
                ..
            })
        ));
        start_harness.finish();

        let mut attach_harness = RuntimeHarness::new(RuntimeCapability::ProcessPtyV1);
        write_runtime_frame(
            &mut attach_harness.client,
            &RuntimeMessage::AttachPty {
                request_id: REQUEST_ID,
                credentials: PtySessionCredentials {
                    session_id: [1; 16],
                    attachment_token: [2; 32],
                },
                replay_from: Some(0),
            },
        )
        .unwrap();
        assert!(matches!(
            read_runtime_frame(&mut attach_harness.client).unwrap(),
            RuntimeMessage::Error(RuntimeError {
                code: RuntimeErrorCode::PersistenceUnavailable,
                retryable: false,
                ..
            })
        ));
        attach_harness.finish();

        let mut detach_harness = RuntimeHarness::new(RuntimeCapability::ProcessPtyV1);
        let process_id = detach_harness.start(subprocess_spec(
            "subprocess_waits_for_timeout",
            RuntimeCapability::ProcessPtyV1,
        ));
        write_runtime_frame(
            &mut detach_harness.client,
            &RuntimeMessage::Detach { process_id },
        )
        .unwrap();
        loop {
            match read_runtime_frame(&mut detach_harness.client).unwrap() {
                RuntimeMessage::Output { .. } => {}
                RuntimeMessage::Error(RuntimeError {
                    code: RuntimeErrorCode::PersistenceUnavailable,
                    retryable: false,
                    ..
                }) => break,
                message => panic!("expected persistence_unavailable, got {message:?}"),
            }
        }
        detach_harness.finish();
    }

    #[test]
    #[ignore = "runtime subprocess fixture"]
    fn subprocess_copies_binary_stdin() {
        let mut input = Vec::new();
        io::stdin().read_to_end(&mut input).unwrap();
        io::stdout().write_all(&input).unwrap();
        io::stdout().flush().unwrap();
        io::stderr().write_all(b"pipe-stderr").unwrap();
        io::stderr().flush().unwrap();
    }

    #[test]
    #[ignore = "runtime subprocess fixture"]
    fn subprocess_emits_large_stdout() {
        let output = vec![b'x'; 256 * 1024];
        io::stdout().write_all(&output).unwrap();
        io::stdout().flush().unwrap();
    }

    #[test]
    #[ignore = "runtime subprocess fixture"]
    fn subprocess_emits_output_flood() {
        let output = vec![b'x'; (SERVER_QUEUE_DEPTH + 8) * RUNTIME_MAX_DATA_CHUNK_LEN];
        io::stdout().write_all(&output).unwrap();
        io::stdout().flush().unwrap();
    }

    #[test]
    #[ignore = "runtime subprocess fixture"]
    fn subprocess_exits_with_more_than_output_window() {
        // Keep the tail small enough for a synchronous pipe to drain so this
        // child exits before the deliberate post-exit ACK stall. Backpressure
        // before exit is expected when a client does not acknowledge output.
        let output = vec![0; OUTPUT_FLOW_WINDOW_BYTES as usize + 1];
        io::stdout().write_all(&output).unwrap();
        io::stdout().flush().unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "runtime subprocess fixture"]
    fn subprocess_slow_pty_reader() {
        let mut terminal = std::mem::MaybeUninit::<libc::termios>::uninit();
        assert_eq!(
            // SAFETY: stdin is the fixture's live PTY slave and `tcgetattr`
            // initializes the termios structure on success.
            unsafe { libc::tcgetattr(libc::STDIN_FILENO, terminal.as_mut_ptr()) },
            0
        );
        // SAFETY: the successful `tcgetattr` above initialized every field.
        let mut terminal = unsafe { terminal.assume_init() };
        // SAFETY: `terminal` is an initialized, uniquely borrowed termios.
        unsafe {
            libc::cfmakeraw(&mut terminal);
        }
        assert_eq!(
            // SAFETY: stdin remains the live PTY slave and `terminal` is
            // initialized for the duration of the call.
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &terminal) },
            0
        );
        thread::sleep(Duration::from_millis(250));
        let mut input = vec![0_u8; RUNTIME_MAX_DATA_CHUNK_LEN];
        io::stdin().read_exact(&mut input).unwrap();
        assert!(input.iter().all(|byte| *byte == b'x'));
        io::stdout().write_all(b"slow-read-ok").unwrap();
        io::stdout().flush().unwrap();
    }

    #[test]
    #[ignore = "runtime subprocess fixture"]
    fn subprocess_waits_for_timeout() {
        thread::sleep(Duration::from_secs(30));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runtime subprocess fixture"]
    fn subprocess_daemon_retains_output() {
        // SAFETY: the child branch uses only async-signal-safe libc calls and
        // exits with `_exit`; it never returns into the Rust test harness after
        // the fork. The parent returns immediately so the runtime-owned leader
        // exits while the new session retains its inherited output descriptor.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed: {}", io::Error::last_os_error());
        if child == 0 {
            // SAFETY: this child branch calls only libc operations and exits
            // with `_exit`, never returning to the Rust test harness.
            unsafe {
                libc::setsid();
                libc::sleep(2);
                libc::_exit(0);
            }
        }
    }
}
