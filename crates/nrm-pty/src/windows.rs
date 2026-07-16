use crate::{PtyCommand, PtyError, PtyExitStatus, PtySignal, PtySize};
use std::cmp::Ordering;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write as _};
use std::mem::{self, ManuallyDrop};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{FromRawHandle as _, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{
    atomic::{AtomicBool, Ordering as AtomicOrdering},
    mpsc, Arc, Condvar, Mutex,
};
use std::thread;
use windows_sys::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, S_OK,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(test)]
use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_GREATER_THAN};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
#[cfg(test)]
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
#[cfg(test)]
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTF_USESTDHANDLES,
    STARTUPINFOEXW,
};

const MAX_CREATE_PROCESS_COMMAND_LINE_UNITS: usize = 32_767;
const MAX_CREATE_PROCESS_ENVIRONMENT_UNITS: usize = 32_767;
// The terminating NUL also occupies one unit in the legacy MAX_PATH buffer.
const MAX_ORDINARY_WIN32_PATH_UNITS: usize = 259;
const DEFAULT_SAFE_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

pub(crate) type Input = File;
pub(crate) type PipeInput = File;
pub(crate) type PipeOutput = File;

pub(crate) fn prepare_input_cancellation(_input: &Input) -> io::Result<()> {
    Ok(())
}

pub(crate) fn prepare_pipe_input_cancellation(_input: &PipeInput) -> io::Result<()> {
    Ok(())
}

pub(crate) struct Output {
    file: File,
    ownership: Arc<OutputOwnership>,
}

struct OutputOwnership {
    taken: AtomicBool,
    release_lock: Mutex<()>,
    released: Condvar,
}

impl OutputOwnership {
    fn new() -> Self {
        Self {
            taken: AtomicBool::new(false),
            release_lock: Mutex::new(()),
            released: Condvar::new(),
        }
    }

    fn mark_taken(&self) {
        self.taken.store(true, AtomicOrdering::Release);
    }

    fn is_taken(&self) -> bool {
        self.taken.load(AtomicOrdering::Acquire)
    }

    fn release(&self) {
        let _guard = self
            .release_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.taken.store(false, AtomicOrdering::Release);
        self.released.notify_all();
    }

    fn wait_until_released(&self) {
        let mut guard = self
            .release_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while self.is_taken() {
            guard = self
                .released
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

impl Read for Output {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Output {
    pub(crate) fn mark_taken(&self) {
        self.ownership.mark_taken();
    }
}

pub(crate) fn prepare_output_cancellation(_output: &Output) -> io::Result<()> {
    // The kill-on-close job owns every descendant and is terminated before
    // process completion is exposed, so all ConPTY writers close without
    // switching the synchronous Windows pipe into polling mode.
    Ok(())
}

pub(crate) fn prepare_pipe_output_cancellation(_output: &PipeOutput) -> io::Result<()> {
    // See `prepare_output_cancellation`; the same job-object lifetime applies
    // to ordinary inherited stdout and stderr handles.
    Ok(())
}

impl Drop for Output {
    fn drop(&mut self) {
        self.ownership.release();
    }
}

pub(crate) struct Spawned {
    pub(crate) process: Process,
    pub(crate) input: Input,
    pub(crate) output: Output,
}

pub(crate) struct PipeSpawned {
    pub(crate) process: PipeProcess,
    pub(crate) input: PipeInput,
    pub(crate) stdout: PipeOutput,
    pub(crate) stderr: PipeOutput,
}

pub(crate) struct Process {
    process: OwnedHandle,
    job: OwnedHandle,
    pseudo_console: Option<PseudoConsole>,
    control_input: File,
    interrupt_pending: Arc<AtomicBool>,
    process_id: u32,
    status: Option<PtyExitStatus>,
}

pub(crate) struct PipeProcess {
    process: OwnedHandle,
    job: OwnedHandle,
    process_id: u32,
    status: Option<PtyExitStatus>,
}

pub(crate) fn environment_names_equal(left: &OsStr, right: &OsStr) -> bool {
    let left: Vec<u16> = left.encode_wide().collect();
    let right: Vec<u16> = right.encode_wide().collect();
    wide_environment_names_equal(&left, &right)
}

pub(crate) fn validate_command(command: &PtyCommand) -> Result<(), PtyError> {
    validate_command_line_size(&native_command_line(command)?)?;
    validate_environment_size(&environment_block(command, &[])?)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationKind {
    Native,
    Batch,
}

#[derive(Debug)]
struct ResolvedApplication {
    path: PathBuf,
    kind: ApplicationKind,
}

struct Launch {
    application: Vec<u16>,
    command_line: Vec<u16>,
    environment: Vec<u16>,
}

struct OwnedHandle(HANDLE);

// SAFETY: A Win32 HANDLE is a process-wide kernel object reference rather than
// a thread-affine pointer. `OwnedHandle` has unique close ownership, so moving
// it to another thread preserves both validity and exactly-once teardown.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE, operation: &'static str) -> Result<Self, PtyError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(PtyError::io(operation, io::Error::last_os_error()));
        }
        Ok(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn into_file(self) -> File {
        let this = ManuallyDrop::new(self);
        // SAFETY: The handle is owned, valid, and supports synchronous file I/O.
        // `ManuallyDrop` prevents `OwnedHandle` from closing it after ownership
        // transfers to `File`.
        unsafe { File::from_raw_handle(this.0 as RawHandle) }
    }

    fn set_inheritable(&self, inheritable: bool) -> Result<(), PtyError> {
        let flags = if inheritable { HANDLE_FLAG_INHERIT } else { 0 };
        // SAFETY: The handle is valid. The mask limits the update to the one
        // inheritance bit and does not change access rights or ownership.
        if unsafe { SetHandleInformation(self.0, HANDLE_FLAG_INHERIT, flags) } == 0 {
            return Err(PtyError::io(
                "set pipe handle inheritance",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn duplicate_file(&self) -> Result<File, PtyError> {
        let process = unsafe { GetCurrentProcess() };
        let mut duplicate = INVALID_HANDLE_VALUE;
        // SAFETY: The source handle and pseudo-process handles are valid. The
        // returned duplicate is non-inheritable and receives the same access.
        if unsafe {
            DuplicateHandle(
                process,
                self.0,
                process,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(PtyError::io(
                "duplicate pseudoconsole test output",
                io::Error::last_os_error(),
            ));
        }
        OwnedHandle::new(duplicate, "open pseudoconsole test output").map(OwnedHandle::into_file)
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: This wrapper uniquely owns a non-null, non-invalid handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn close_raw_handle(handle: HANDLE) {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return;
    }
    // SAFETY: This helper is called only for a valid creation handle that has
    // not been transferred into `OwnedHandle`.
    unsafe {
        CloseHandle(handle);
    }
}

struct PseudoConsole {
    handle: Option<HPCON>,
    creation_input: Option<OwnedHandle>,
    creation_output: Option<OwnedHandle>,
    teardown_output: Option<File>,
    output_ownership: Arc<OutputOwnership>,
    drain_worker: DrainWorker,
    close_worker: CloseWorker,
    #[cfg(test)]
    test_output_writer: Option<File>,
    #[cfg(test)]
    test_close_gate: Option<TestCloseGate>,
}

#[cfg(test)]
struct TestCloseGate {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

struct CloseRequest {
    // HPCON is a process-wide opaque handle value. PseudoConsole moves its
    // sole Option value here before this request crosses to the close thread.
    handle: HPCON,
    #[cfg(test)]
    gate: Option<TestCloseGate>,
}

impl CloseRequest {
    fn new(handle: HPCON) -> Self {
        Self {
            handle,
            #[cfg(test)]
            gate: None,
        }
    }
}

fn close_pseudo_console(request: CloseRequest) {
    #[cfg(test)]
    if let Some(gate) = request.gate {
        gate.entered.send(()).expect("report test close entry");
        gate.release.recv().expect("release test close");
    }
    // SAFETY: Each request uniquely owns the HPCON close responsibility.
    unsafe {
        ClosePseudoConsole(request.handle);
    }
}

enum DrainRequest {
    Immediate(File),
    AfterOutputRelease {
        output: File,
        ownership: Arc<OutputOwnership>,
    },
}

struct DrainWorker {
    sender: Option<mpsc::SyncSender<DrainRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DrainWorker {
    fn new() -> Result<Self, PtyError> {
        let (sender, receiver) = mpsc::sync_channel::<DrainRequest>(1);
        let thread = thread::Builder::new()
            .name("nrm-conpty-drain".to_string())
            .spawn(move || {
                if let Ok(request) = receiver.recv() {
                    let mut output = match request {
                        DrainRequest::Immediate(output) => output,
                        DrainRequest::AfterOutputRelease { output, ownership } => {
                            ownership.wait_until_released();
                            output
                        }
                    };
                    let _ = io::copy(&mut output, &mut io::sink());
                }
            })
            .map_err(|source| PtyError::io("start pseudoconsole drain worker", source))?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }

    fn start(&mut self, output: File) -> bool {
        self.send(DrainRequest::Immediate(output))
    }

    fn start_after_output_release(
        &mut self,
        output: File,
        ownership: Arc<OutputOwnership>,
    ) -> bool {
        self.send(DrainRequest::AfterOutputRelease { output, ownership })
    }

    fn send(&mut self, request: DrainRequest) -> bool {
        self.sender
            .take()
            .is_some_and(|sender| sender.send(request).is_ok())
    }

    fn detach(&mut self) {
        drop(self.sender.take());
        drop(self.thread.take());
    }

    fn join(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for DrainWorker {
    fn drop(&mut self) {
        self.join();
    }
}

struct CloseWorker {
    sender: Option<mpsc::SyncSender<CloseRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl CloseWorker {
    fn new() -> Result<Self, PtyError> {
        let (sender, receiver) = mpsc::sync_channel::<CloseRequest>(1);
        let thread = thread::Builder::new()
            .name("nrm-conpty-close".to_string())
            .spawn(move || {
                if let Ok(request) = receiver.recv() {
                    close_pseudo_console(request);
                }
            })
            .map_err(|source| PtyError::io("start pseudoconsole close worker", source))?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }

    fn start(&mut self, request: CloseRequest) -> bool {
        self.sender
            .take()
            .is_some_and(|sender| sender.send(request).is_ok())
    }

    fn detach(&mut self) {
        drop(self.sender.take());
        drop(self.thread.take());
    }

    fn join(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for CloseWorker {
    fn drop(&mut self) {
        self.join();
    }
}

impl PseudoConsole {
    fn new(
        handle: HPCON,
        creation_input: OwnedHandle,
        creation_output: OwnedHandle,
        teardown_output: File,
        output_ownership: Arc<OutputOwnership>,
        drain_worker: DrainWorker,
        close_worker: CloseWorker,
    ) -> Self {
        Self {
            handle: Some(handle),
            creation_input: Some(creation_input),
            creation_output: Some(creation_output),
            teardown_output: Some(teardown_output),
            output_ownership,
            drain_worker,
            close_worker,
            #[cfg(test)]
            test_output_writer: None,
            #[cfg(test)]
            test_close_gate: None,
        }
    }

    fn raw(&self) -> HPCON {
        self.handle.expect("open pseudoconsole handle")
    }

    fn release_creation_pipes(&mut self) {
        self.creation_input.take();
        self.creation_output.take();
    }

    fn close_request(&mut self) -> CloseRequest {
        let request = CloseRequest::new(self.handle.take().expect("open pseudoconsole handle"));
        #[cfg(test)]
        let request = CloseRequest {
            gate: self.test_close_gate.take(),
            ..request
        };
        request
    }

    fn release_test_output_writer(&mut self) {
        #[cfg(test)]
        {
            self.test_output_writer.take();
        }
    }

    fn close_after_process_exit(&mut self) {
        if self.handle.is_none() {
            return;
        }
        self.release_creation_pipes();
        self.release_test_output_writer();
        if !self.output_ownership.is_taken() {
            self.close_with_drain();
            return;
        }

        let Some(output) = self.teardown_output.take() else {
            return;
        };
        if !self
            .drain_worker
            .start_after_output_release(output, Arc::clone(&self.output_ownership))
        {
            // No safe synchronous fallback exists here: it could either steal
            // caller-owned bytes or block forever on a full pipe. As in the
            // emergency-drain failure path below, leak the opaque HPCON after
            // process-tree termination rather than violating those contracts.
            return;
        }
        // The deferred reader owns its teardown handle now. It remains dormant
        // while the caller owns output, then drains only if that stream is
        // dropped before ConPTY has finished closing.
        self.drain_worker.detach();

        let request = self.close_request();
        if !self.close_worker.start(request) {
            // The preallocated worker can fail only after an unexpected thread
            // exit. Its request owned the sole close responsibility, so avoid
            // retrying synchronously and risking a caller-visible deadlock.
            return;
        }
        // ClosePseudoConsole can wait for output consumption before Windows 11
        // 24H2. Transfer close ownership to the preallocated worker so process
        // teardown never waits for the caller to begin draining.
        self.close_worker.detach();
    }

    fn close_with_drain(&mut self) {
        if self.handle.is_none() {
            return;
        }
        self.release_creation_pipes();
        self.release_test_output_writer();

        let Some(output) = self.teardown_output.take() else {
            return;
        };
        if !self.drain_worker.start(output) {
            // The worker is created before the pseudoconsole, so this can only
            // occur after an unexpected worker failure. ClosePseudoConsole can
            // deadlock without a reader; leaking the opaque HPCON is safer than
            // deadlocking the runtime during unwinding. The kill job handles
            // process-tree teardown independently.
            return;
        }

        // A concurrent reader is draining the final frame that close may emit.
        close_pseudo_console(self.close_request());
        self.drain_worker.join();
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        self.close_with_drain();
    }
}

struct AttributeList {
    // `usize` storage provides the pointer alignment required by the opaque
    // Windows attribute-list representation.
    storage: Vec<usize>,
    initialized: bool,
}

impl AttributeList {
    fn new(pseudo_console: HPCON) -> Result<Self, PtyError> {
        let mut result = Self::with_capacity(1)?;
        // SAFETY: The list is initialized and `pseudo_console` remains valid
        // through process creation. This attribute consumes the opaque HPCON
        // value directly, rather than a pointer to an HPCON variable.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                result.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                pseudo_console as *mut c_void,
                mem::size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if updated == 0 {
            return Err(PtyError::io(
                "set pseudoconsole process attribute",
                io::Error::last_os_error(),
            ));
        }
        Ok(result)
    }

    fn with_handle_list(handles: &[HANDLE]) -> Result<Self, PtyError> {
        let mut result = Self::with_capacity(1)?;
        // SAFETY: The initialized list and handle slice remain live through
        // `CreateProcessW`; every listed handle is explicitly inheritable.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                result.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast::<c_void>(),
                mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if updated == 0 {
            return Err(PtyError::io(
                "set inherited process handle list",
                io::Error::last_os_error(),
            ));
        }
        Ok(result)
    }

    fn with_capacity(attributes: u32) -> Result<Self, PtyError> {
        let mut bytes = 0usize;
        // SAFETY: A null first argument is the documented size-query form.
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), attributes, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(PtyError::io(
                "size process attribute list",
                io::Error::last_os_error(),
            ));
        }
        let words = bytes.div_ceil(mem::size_of::<usize>());
        let mut result = Self {
            storage: vec![0; words],
            initialized: false,
        };
        let mut provided_bytes = words * mem::size_of::<usize>();
        // SAFETY: `storage` is writable, sufficiently sized, and pointer
        // aligned. It remains allocated until the list is deleted on drop.
        let initialized = unsafe {
            InitializeProcThreadAttributeList(
                result.as_mut_ptr(),
                attributes,
                0,
                &mut provided_bytes,
            )
        };
        if initialized == 0 {
            return Err(PtyError::io(
                "initialize process attribute list",
                io::Error::last_os_error(),
            ));
        }
        result.initialized = true;
        Ok(result)
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast::<c_void>()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: Construction only returns after initialization, and this
            // is the one matching deletion call.
            unsafe {
                DeleteProcThreadAttributeList(self.as_mut_ptr());
            }
        }
    }
}

pub(crate) fn spawn(command: &PtyCommand, size: PtySize) -> Result<Spawned, PtyError> {
    // Allocate both teardown workers before an HPCON exists. ClosePseudoConsole
    // may synchronously wait for output consumption on older Windows builds,
    // so teardown must never depend on allocating a thread after creation.
    let close_worker = CloseWorker::new()?;
    let drain_worker = DrainWorker::new()?;
    let (pty_input_read, input_write) = create_pipe()?;
    let (output_read, pty_output_write) = create_pipe()?;
    let coordinate = coordinate(size);
    let mut pseudo_console = 0;
    // Do not request cursor inheritance: ConPTY can emit a cursor-position
    // query and block forever when a byte-stream frontend does not answer it.
    // SAFETY: All pipe handles and the output pointer are valid for this call.
    let result = unsafe {
        CreatePseudoConsole(
            coordinate,
            pty_input_read.raw(),
            pty_output_write.raw(),
            0,
            &mut pseudo_console,
        )
    };
    if result != S_OK {
        return Err(PtyError::io(
            "create Windows pseudoconsole",
            io::Error::from_raw_os_error(result),
        ));
    }
    if pseudo_console == 0 {
        return Err(PtyError::io(
            "create Windows pseudoconsole",
            io::Error::other("CreatePseudoConsole returned a null handle"),
        ));
    }
    let output = output_read.into_file();
    let teardown_output = match output.try_clone() {
        Ok(output) => output,
        Err(source) => {
            // No hosted process exists yet. Drain while closing the HPCON so
            // even this descriptor-exhaustion path cannot block teardown.
            let pseudo_console = PseudoConsole::new(
                pseudo_console,
                pty_input_read,
                pty_output_write,
                output,
                Arc::new(OutputOwnership::new()),
                drain_worker,
                close_worker,
            );
            drop(pseudo_console);
            return Err(PtyError::io("duplicate pseudoconsole output", source));
        }
    };
    let output_ownership = Arc::new(OutputOwnership::new());
    let mut pseudo_console = PseudoConsole::new(
        pseudo_console,
        pty_input_read,
        pty_output_write,
        teardown_output,
        Arc::clone(&output_ownership),
        drain_worker,
        close_worker,
    );
    #[cfg(test)]
    {
        pseudo_console.test_output_writer = Some(
            pseudo_console
                .creation_output
                .as_ref()
                .expect("test output writer exists before creation-pipe release")
                .duplicate_file()?,
        );
    }

    let job = create_kill_job()?;

    let mut attributes = AttributeList::new(pseudo_console.raw())?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    // Prevent console standard handles from the host process from overriding
    // the pseudoconsole attachment. Invalid standard handles are replaced by
    // ConPTY during client initialization.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    startup.lpAttributeList = attributes.as_mut_ptr();

    let Launch {
        mut application,
        mut command_line,
        mut environment,
    } = prepare_launch(command)?;
    let current_directory = process_current_directory(command)?;
    let mut process_info = PROCESS_INFORMATION::default();
    // The child starts suspended so it cannot create untracked descendants
    // before it is assigned to the kill-on-close job.
    // SAFETY: All pointers are either null or reference live, writable buffers
    // for the full duration of `CreateProcessW`.
    let created = unsafe {
        CreateProcessW(
            application.as_mut_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            environment.as_mut_ptr().cast::<c_void>(),
            current_directory
                .as_ref()
                .map_or(ptr::null(), |path| path.as_ptr()),
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(PtyError::io(
            "create pseudoconsole process",
            io::Error::last_os_error(),
        ));
    }
    let process = match OwnedHandle::new(process_info.hProcess, "open child process handle") {
        Ok(process) => process,
        Err(error) => {
            close_raw_handle(process_info.hThread);
            return Err(error);
        }
    };
    let thread = match OwnedHandle::new(process_info.hThread, "open child thread handle") {
        Ok(thread) => thread,
        Err(error) => {
            // SAFETY: CreateProcess succeeded and `process` is the suspended
            // child handle, so it is safe to terminate and reap here.
            unsafe {
                TerminateProcess(process.raw(), 1);
                WaitForSingleObject(process.raw(), INFINITE);
            }
            return Err(error);
        }
    };

    // SAFETY: Both handles are valid. The process remains suspended until the
    // assignment succeeds, closing the creation-time descendant escape race.
    if unsafe { AssignProcessToJobObject(job.raw(), process.raw()) } == 0 {
        let source = io::Error::last_os_error();
        // SAFETY: The process is still suspended and uniquely controlled here.
        unsafe {
            TerminateProcess(process.raw(), 1);
            WaitForSingleObject(process.raw(), INFINITE);
        }
        return Err(PtyError::io("assign process to job", source));
    }
    // SAFETY: `thread` is the suspended primary thread created above.
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        let source = io::Error::last_os_error();
        // SAFETY: The job contains the child and is valid.
        unsafe {
            TerminateJobObject(job.raw(), 1);
            WaitForSingleObject(process.raw(), INFINITE);
        }
        return Err(PtyError::io("resume pseudoconsole process", source));
    }
    // The documented pseudoconsole setup closes these host-side pipe handles
    // after process creation. Because this process is created suspended, keep
    // them alive through ResumeThread so ConPTY cannot observe a broken setup
    // channel before the client has begun initializing.
    pseudo_console.release_creation_pipes();
    drop(thread);
    drop(attributes);

    let input = input_write.into_file();
    let control_input = match input.try_clone() {
        Ok(input) => input,
        Err(source) => {
            // The child is running but already belongs to the kill-on-close
            // job. Terminate and wait before returning the setup failure.
            // SAFETY: Both handles remain valid and owned by this function.
            unsafe {
                TerminateJobObject(job.raw(), 1);
                WaitForSingleObject(process.raw(), INFINITE);
            }
            return Err(PtyError::io("duplicate pseudoconsole input", source));
        }
    };
    Ok(Spawned {
        process: Process {
            process,
            job,
            pseudo_console: Some(pseudo_console),
            control_input,
            interrupt_pending: Arc::new(AtomicBool::new(false)),
            process_id: process_info.dwProcessId,
            status: None,
        },
        input,
        output: Output {
            file: output,
            ownership: output_ownership,
        },
    })
}

pub(crate) fn spawn_pipe(command: &PtyCommand) -> Result<PipeSpawned, PtyError> {
    let (child_stdin, parent_stdin) = create_inheritable_pipe(false)?;
    let (parent_stdout, child_stdout) = create_inheritable_pipe(true)?;
    let (parent_stderr, child_stderr) = create_inheritable_pipe(true)?;
    let job = create_kill_job()?;
    let inherited = [child_stdin.raw(), child_stdout.raw(), child_stderr.raw()];
    let mut attributes = AttributeList::with_handle_list(&inherited)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_stdin.raw();
    startup.StartupInfo.hStdOutput = child_stdout.raw();
    startup.StartupInfo.hStdError = child_stderr.raw();
    startup.lpAttributeList = attributes.as_mut_ptr();

    let Launch {
        mut application,
        mut command_line,
        mut environment,
    } = prepare_launch(command)?;
    let current_directory = process_current_directory(command)?;
    let mut process_info = PROCESS_INFORMATION::default();
    // SAFETY: The handle-list attribute restricts inheritance to the three
    // explicitly inheritable stdio pipe ends. The child remains suspended until
    // assignment to the kill-on-close job succeeds.
    let created = unsafe {
        CreateProcessW(
            application.as_mut_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            environment.as_mut_ptr().cast::<c_void>(),
            current_directory
                .as_ref()
                .map_or(ptr::null(), |path| path.as_ptr()),
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(PtyError::io(
            "create piped process",
            io::Error::last_os_error(),
        ));
    }
    let process = match OwnedHandle::new(process_info.hProcess, "open piped process handle") {
        Ok(process) => process,
        Err(error) => {
            close_raw_handle(process_info.hThread);
            return Err(error);
        }
    };
    let thread = match OwnedHandle::new(process_info.hThread, "open piped thread handle") {
        Ok(thread) => thread,
        Err(error) => {
            // SAFETY: CreateProcess succeeded and the child remains suspended.
            unsafe {
                TerminateProcess(process.raw(), 1);
                WaitForSingleObject(process.raw(), INFINITE);
            }
            return Err(error);
        }
    };
    // SAFETY: Both handles are valid, and the suspended process has not yet
    // had an opportunity to create descendants outside the job.
    if unsafe { AssignProcessToJobObject(job.raw(), process.raw()) } == 0 {
        let source = io::Error::last_os_error();
        // SAFETY: The process is suspended and uniquely owned here.
        unsafe {
            TerminateProcess(process.raw(), 1);
            WaitForSingleObject(process.raw(), INFINITE);
        }
        return Err(PtyError::io("assign piped process to job", source));
    }
    // SAFETY: `thread` is the suspended primary thread created above.
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        let source = io::Error::last_os_error();
        // SAFETY: The job contains the child and is valid.
        unsafe {
            TerminateJobObject(job.raw(), 1);
            WaitForSingleObject(process.raw(), INFINITE);
        }
        return Err(PtyError::io("resume piped process", source));
    }
    drop(thread);
    drop(attributes);
    drop(child_stdin);
    drop(child_stdout);
    drop(child_stderr);

    Ok(PipeSpawned {
        process: PipeProcess {
            process,
            job,
            process_id: process_info.dwProcessId,
            status: None,
        },
        input: parent_stdin.into_file(),
        stdout: parent_stdout.into_file(),
        stderr: parent_stderr.into_file(),
    })
}

fn create_kill_job() -> Result<OwnedHandle, PtyError> {
    let mut job_limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: Null security/name pointers request an unnamed job with default
    // security; the returned handle is validated immediately.
    let job = OwnedHandle::new(
        unsafe { CreateJobObjectW(ptr::null(), ptr::null()) },
        "create process job",
    )?;
    // SAFETY: `job` is valid and the information pointer/length exactly match
    // the requested information class.
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&job_limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
            mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(PtyError::io(
            "configure process job",
            io::Error::last_os_error(),
        ));
    }
    Ok(job)
}

fn create_pipe() -> Result<(OwnedHandle, OwnedHandle), PtyError> {
    let mut read: HANDLE = ptr::null_mut();
    let mut write: HANDLE = ptr::null_mut();
    // SAFETY: Both output pointers are valid; null security attributes create
    // non-inheritable anonymous pipe handles.
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
        return Err(PtyError::io(
            "create pseudoconsole pipe",
            io::Error::last_os_error(),
        ));
    }
    let read = OwnedHandle::new(read, "create pseudoconsole read pipe")?;
    let write = OwnedHandle::new(write, "create pseudoconsole write pipe")?;
    Ok((read, write))
}

fn create_inheritable_pipe(parent_reads: bool) -> Result<(OwnedHandle, OwnedHandle), PtyError> {
    let mut read: HANDLE = ptr::null_mut();
    let mut write: HANDLE = ptr::null_mut();
    let security = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: Output pointers and security attributes are valid. Both returned
    // handles begin inheritable; the parent end is tightened immediately.
    if unsafe { CreatePipe(&mut read, &mut write, &security, 0) } == 0 {
        return Err(PtyError::io(
            "create inherited process pipe",
            io::Error::last_os_error(),
        ));
    }
    let read = OwnedHandle::new(read, "create inherited process read pipe")?;
    let write = OwnedHandle::new(write, "create inherited process write pipe")?;
    if parent_reads {
        read.set_inheritable(false)?;
    } else {
        write.set_inheritable(false)?;
    }
    Ok((read, write))
}

fn coordinate(size: PtySize) -> COORD {
    COORD {
        X: size.cols as i16,
        Y: size.rows as i16,
    }
}

fn native_command_line(command: &PtyCommand) -> Result<Vec<u16>, PtyError> {
    let mut line = Vec::new();
    append_quoted_argument(&mut line, command.program(), "program")?;
    for argument in command.arguments() {
        line.push(b' ' as u16);
        append_quoted_argument(&mut line, argument, "argument")?;
    }
    line.push(0);
    Ok(line)
}

fn process_current_directory(command: &PtyCommand) -> Result<Option<Vec<u16>>, PtyError> {
    command
        .cwd()
        .map(|path| {
            // `canonicalize()` commonly returns a verbatim path on Windows.
            // CreateProcessW exposes that spelling as the child's current
            // directory, and cmd.exe rejects a verbatim drive spelling as an
            // unsupported UNC path. Use the ordinary spelling only when the
            // conversion is short, structurally safe, and preserves identity;
            // otherwise retain the original verbatim path.
            let path = child_compatible_path(path.as_os_str());
            wide_nul(path.as_os_str(), "cwd")
        })
        .transpose()
}

fn prepare_launch(command: &PtyCommand) -> Result<Launch, PtyError> {
    let resolved = resolve_application(command)?;
    match resolved.kind {
        ApplicationKind::Native => {
            // `resolve_application` canonicalizes native images, which commonly
            // adds a verbatim prefix on Windows. CreateProcessW can launch that
            // spelling, but Windows PowerShell 5.1 was observed to exit during
            // ServicePointManager initialization when launched with it here.
            // Keep argv unchanged and use the ordinary application spelling
            // only when conversion is short and semantics-preserving.
            let application = child_compatible_path(resolved.path.as_os_str());
            let command_line = native_command_line(command)?;
            validate_command_line_size(&command_line)?;
            let environment = environment_block(command, &[])?;
            validate_environment_size(&environment)?;
            Ok(Launch {
                application: wide_nul(application.as_os_str(), "program")?,
                command_line,
                environment,
            })
        }
        ApplicationKind::Batch => prepare_batch_launch(command, &resolved.path),
    }
}

fn prepare_batch_launch(command: &PtyCommand, target: &Path) -> Result<Launch, PtyError> {
    validate_batch_value(target.as_os_str())?;
    for argument in command.arguments() {
        validate_batch_value(argument)?;
    }
    let system_directory = system_directory()?;
    let command_interpreter = trusted_system_executable(
        &system_directory,
        Path::new("cmd.exe"),
        "resolve trusted Windows command interpreter",
    )?;
    let command_line = batch_command_line(&command_interpreter, target, command.arguments())?;
    validate_command_line_size(&command_line)?;
    let environment = environment_block(command, &[])?;
    validate_environment_size(&environment)?;
    Ok(Launch {
        application: wide_nul(command_interpreter.as_os_str(), "batch interpreter")?,
        command_line,
        environment,
    })
}

fn batch_command_line(
    command_interpreter: &Path,
    target: &Path,
    arguments: &[OsString],
) -> Result<Vec<u16>, PtyError> {
    let mut line = Vec::new();
    append_quoted_argument(
        &mut line,
        command_interpreter.as_os_str(),
        "batch interpreter",
    )?;
    line.extend(" /d /s /v:off /c \"".encode_utf16());
    let target = child_compatible_path(target.as_os_str());
    append_batch_value(&mut line, target.as_os_str())?;
    for argument in arguments {
        line.push(b' ' as u16);
        append_batch_value(&mut line, argument)?;
    }
    line.push(b'"' as u16);
    line.push(0);
    Ok(line)
}

fn child_compatible_path(path: &OsStr) -> OsString {
    let units: Vec<u16> = path.encode_wide().collect();
    let verbatim = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    if !units.starts_with(&verbatim) {
        return path.to_os_string();
    }
    let unc = [b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];
    if units
        .get(verbatim.len()..verbatim.len() + unc.len())
        .is_some_and(|value| ascii_wide_eq(value, b"UNC\\"))
    {
        let suffix = &units[verbatim.len() + unc.len()..];
        let mut result = vec![b'\\' as u16, b'\\' as u16];
        result.extend_from_slice(suffix);
        if result.len() <= MAX_ORDINARY_WIN32_PATH_UNITS
            && ordinary_win32_components_are_safe(suffix, 2)
        {
            return OsString::from_wide(&result);
        }
        return path.to_os_string();
    }
    let dos_drive_absolute = units
        .get(verbatim.len()..verbatim.len() + 3)
        .is_some_and(|prefix| {
            matches!(prefix[0], 0x41..=0x5a | 0x61..=0x7a)
                && prefix[1] == b':' as u16
                && prefix[2] == b'\\' as u16
        });
    if dos_drive_absolute {
        let result = &units[verbatim.len()..];
        let suffix = &units[verbatim.len() + 3..];
        if result.len() <= MAX_ORDINARY_WIN32_PATH_UNITS
            && ordinary_win32_components_are_safe(suffix, 0)
        {
            return OsString::from_wide(result);
        }
    }
    path.to_os_string()
}

fn ordinary_win32_components_are_safe(path: &[u16], required_components: usize) -> bool {
    if path.is_empty() {
        return required_components == 0;
    }
    let components: Vec<&[u16]> = path.split(|unit| *unit == b'\\' as u16).collect();
    components.len() >= required_components
        && components
            .iter()
            .all(|component| ordinary_win32_component_is_safe(component))
}

fn ordinary_win32_component_is_safe(component: &[u16]) -> bool {
    if component.is_empty()
        || component
            .last()
            .is_some_and(|unit| matches!(*unit, 0x20 | 0x2e))
        || component.iter().any(|unit| {
            matches!(
                *unit,
                0x00..=0x1f | 0x22 | 0x2a | 0x2f | 0x3a | 0x3c | 0x3e | 0x3f | 0x5c | 0x7c
            )
        })
    {
        return false;
    }

    let stem_end = component
        .iter()
        .position(|unit| *unit == b'.' as u16)
        .unwrap_or(component.len());
    let stem = &component[..stem_end];
    let reserved = [
        b"CON".as_slice(),
        b"PRN",
        b"AUX",
        b"NUL",
        b"CONIN$",
        b"CONOUT$",
    ];
    if reserved.iter().any(|name| ascii_wide_eq(stem, name)) {
        return false;
    }
    stem.len() != 4
        || !(ascii_wide_eq(&stem[..3], b"COM") || ascii_wide_eq(&stem[..3], b"LPT"))
        || !matches!(stem[3], 0x31..=0x39 | 0x00b9 | 0x00b2 | 0x00b3)
}

fn append_batch_value(output: &mut Vec<u16>, value: &OsStr) -> Result<(), PtyError> {
    validate_batch_value(value)?;
    let units: Vec<u16> = value.encode_wide().collect();
    output.push(b'"' as u16);
    output.extend_from_slice(&units);
    let trailing_backslashes = units
        .iter()
        .rev()
        .take_while(|unit| **unit == b'\\' as u16)
        .count();
    output.extend(std::iter::repeat_n(b'\\' as u16, trailing_backslashes));
    output.push(b'"' as u16);
    Ok(())
}

fn validate_batch_value(value: &OsStr) -> Result<(), PtyError> {
    if value
        .encode_wide()
        .any(|unit| unit <= 0x1f || (0x7f..=0x9f).contains(&unit))
    {
        return Err(PtyError::io(
            "prepare Windows batch command",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "batch application paths and arguments must not contain control characters",
            ),
        ));
    }
    if value
        .encode_wide()
        .any(|unit| unit == b'"' as u16 || unit == b'%' as u16)
    {
        return Err(PtyError::io(
            "prepare Windows batch command",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "batch application paths and arguments must not contain double quotes or percent signs",
            ),
        ));
    }
    Ok(())
}

fn resolve_application(command: &PtyCommand) -> Result<ResolvedApplication, PtyError> {
    let program = PathBuf::from(command.program());
    let extensions = safe_pathext(command);
    if has_path_component(command.program()) {
        let candidate = if program.is_absolute() {
            program
        } else {
            resolution_base(command)?.join(program)
        };
        return resolved_candidate(&candidate, &extensions).ok_or_else(program_not_found);
    }

    let search_path = effective_search_path(command).ok_or_else(program_not_found)?;
    let base = resolution_base(command)?;
    for directory in std::env::split_paths(&search_path).filter(|path| !path.as_os_str().is_empty())
    {
        let directory = if directory.is_absolute() {
            directory
        } else {
            base.join(directory)
        };
        if let Some(application) = resolved_candidate(&directory.join(&program), &extensions) {
            return Ok(application);
        }
    }
    Err(program_not_found())
}

fn resolution_base(command: &PtyCommand) -> Result<PathBuf, PtyError> {
    let current = std::env::current_dir()
        .map_err(|source| PtyError::io("resolve Windows program", source))?;
    Ok(match command.cwd() {
        Some(cwd) if cwd.is_absolute() => cwd.to_path_buf(),
        Some(cwd) => current.join(cwd),
        None => current,
    })
}

fn has_path_component(program: &OsStr) -> bool {
    program
        .encode_wide()
        .any(|unit| matches!(unit, 0x2f | 0x5c | 0x3a))
}

fn effective_search_path(command: &PtyCommand) -> Option<OsString> {
    effective_environment_value(command, OsStr::new("PATH"))
}

fn effective_environment_value(command: &PtyCommand, requested: &OsStr) -> Option<OsString> {
    let mut value = if command.clears_environment() {
        None
    } else {
        std::env::var_os(requested)
    };
    for (name, replacement) in command.environment() {
        if environment_names_equal(name, requested) {
            value.clone_from(replacement);
        }
    }
    value
}

fn safe_pathext(command: &PtyCommand) -> Vec<ApplicationExtension> {
    let configured = effective_environment_value(command, OsStr::new("PATHEXT"))
        .unwrap_or_else(|| OsString::from(DEFAULT_SAFE_PATHEXT));
    let units: Vec<u16> = configured.encode_wide().collect();
    let mut result = Vec::new();
    for value in units.split(|unit| *unit == b';' as u16) {
        let extension = if ascii_wide_eq(value, b".COM") {
            Some(ApplicationExtension::Com)
        } else if ascii_wide_eq(value, b".EXE") {
            Some(ApplicationExtension::Exe)
        } else if ascii_wide_eq(value, b".BAT") {
            Some(ApplicationExtension::Bat)
        } else if ascii_wide_eq(value, b".CMD") {
            Some(ApplicationExtension::Cmd)
        } else {
            None
        };
        if let Some(extension) = extension.filter(|extension| !result.contains(extension)) {
            result.push(extension);
        }
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationExtension {
    Com,
    Exe,
    Bat,
    Cmd,
}

impl ApplicationExtension {
    fn suffix(self) -> &'static str {
        match self {
            Self::Com => "COM",
            Self::Exe => "EXE",
            Self::Bat => "BAT",
            Self::Cmd => "CMD",
        }
    }

    fn kind(self) -> ApplicationKind {
        match self {
            Self::Com | Self::Exe => ApplicationKind::Native,
            Self::Bat | Self::Cmd => ApplicationKind::Batch,
        }
    }
}

fn ascii_wide_eq(value: &[u16], expected: &[u8]) -> bool {
    value.len() == expected.len()
        && value.iter().zip(expected).all(|(actual, expected)| {
            u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
        })
}

fn classify_explicit_extension(extension: &OsStr) -> Option<ApplicationExtension> {
    let units: Vec<u16> = extension.encode_wide().collect();
    if ascii_wide_eq(&units, b"COM") {
        Some(ApplicationExtension::Com)
    } else if ascii_wide_eq(&units, b"EXE") {
        Some(ApplicationExtension::Exe)
    } else if ascii_wide_eq(&units, b"BAT") {
        Some(ApplicationExtension::Bat)
    } else if ascii_wide_eq(&units, b"CMD") {
        Some(ApplicationExtension::Cmd)
    } else {
        None
    }
}

fn resolved_candidate(
    candidate: &Path,
    extensions: &[ApplicationExtension],
) -> Option<ResolvedApplication> {
    if let Some(extension) = candidate.extension() {
        let extension = classify_explicit_extension(extension)?;
        return resolved_file(candidate, extension.kind());
    }
    for extension in extensions {
        let candidate = candidate.with_extension(extension.suffix());
        if let Some(application) = resolved_file(&candidate, extension.kind()) {
            return Some(application);
        }
    }
    None
}

fn resolved_file(candidate: &Path, kind: ApplicationKind) -> Option<ResolvedApplication> {
    if !fs::metadata(candidate).is_ok_and(|metadata| metadata.is_file()) {
        return None;
    }
    Some(ResolvedApplication {
        path: fs::canonicalize(candidate).ok()?,
        kind,
    })
}

fn system_directory() -> Result<PathBuf, PtyError> {
    let mut buffer = vec![0u16; 260];
    loop {
        let capacity = u32::try_from(buffer.len()).map_err(|_| {
            PtyError::io(
                "resolve Windows system directory",
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "system directory path is too large",
                ),
            )
        })?;
        // SAFETY: `buffer` is writable for `capacity` UTF-16 units. The API
        // returns the length excluding NUL on success and the required size
        // including NUL when the buffer is too small.
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity) } as usize;
        if length == 0 {
            return Err(PtyError::io(
                "resolve Windows system directory",
                io::Error::last_os_error(),
            ));
        }
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        if length > MAX_CREATE_PROCESS_COMMAND_LINE_UNITS {
            return Err(PtyError::io(
                "resolve Windows system directory",
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "system directory path is too large",
                ),
            ));
        }
        buffer.resize(length.saturating_add(1), 0);
    }
}

fn trusted_system_executable(
    system_directory: &Path,
    relative: &Path,
    operation: &'static str,
) -> Result<PathBuf, PtyError> {
    let candidate = system_directory.join(relative);
    if !fs::metadata(&candidate).is_ok_and(|metadata| metadata.is_file()) {
        return Err(PtyError::io(
            operation,
            io::Error::new(
                io::ErrorKind::NotFound,
                "trusted system executable was not found",
            ),
        ));
    }
    fs::canonicalize(candidate).map_err(|source| PtyError::io(operation, source))
}

fn validate_command_line_size(command_line: &[u16]) -> Result<(), PtyError> {
    if command_line.len() > MAX_CREATE_PROCESS_COMMAND_LINE_UNITS {
        return Err(PtyError::CommandLineTooLarge {
            actual: command_line.len(),
            maximum: MAX_CREATE_PROCESS_COMMAND_LINE_UNITS,
        });
    }
    Ok(())
}

fn validate_environment_size(environment: &[u16]) -> Result<(), PtyError> {
    if environment.len() > MAX_CREATE_PROCESS_ENVIRONMENT_UNITS {
        return Err(PtyError::CommandTooLarge {
            actual: environment.len().saturating_mul(2),
            maximum: MAX_CREATE_PROCESS_ENVIRONMENT_UNITS * 2,
        });
    }
    Ok(())
}

fn program_not_found() -> PtyError {
    PtyError::io(
        "resolve Windows program",
        io::Error::new(
            io::ErrorKind::NotFound,
            "program was not found in the effective PATH",
        ),
    )
}

fn append_quoted_argument(
    output: &mut Vec<u16>,
    argument: &OsStr,
    field: &'static str,
) -> Result<(), PtyError> {
    let units: Vec<u16> = argument.encode_wide().collect();
    if units.contains(&0) {
        return Err(PtyError::EmbeddedNul { field });
    }
    let needs_quotes =
        units.is_empty() || units.iter().any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22));
    if !needs_quotes {
        output.extend(units);
        return Ok(());
    }

    output.push(b'"' as u16);
    let mut backslashes = 0usize;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
        } else if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            output.push(unit);
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            output.push(unit);
            backslashes = 0;
        }
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
    Ok(())
}

fn environment_block(
    command: &PtyCommand,
    internal: &[(OsString, OsString)],
) -> Result<Vec<u16>, PtyError> {
    let mut variables = Vec::<(Vec<u16>, Vec<u16>)>::new();
    if !command.clears_environment() {
        for (key, value) in std::env::vars_os() {
            insert_environment_entry(
                &mut variables,
                key.as_os_str(),
                Some(value.as_os_str()),
                true,
            )?;
        }
    }
    for (key, value) in command.environment() {
        insert_environment(&mut variables, key, value.as_deref())?;
    }
    for (key, value) in internal {
        insert_environment_entry(
            &mut variables,
            key.as_os_str(),
            Some(value.as_os_str()),
            false,
        )?;
    }
    Ok(finish_environment_block(variables))
}

fn finish_environment_block(mut variables: Vec<(Vec<u16>, Vec<u16>)>) -> Vec<u16> {
    variables.sort_by(|(left, _), (right, _)| compare_environment_names(left, right));

    let mut block = Vec::new();
    for (key, value) in variables {
        block.extend(key);
        block.push(b'=' as u16);
        block.extend(value);
        block.push(0);
    }
    // Windows requires an empty environment to contain two NULs. A populated
    // block already ends in one entry NUL and needs one additional terminator.
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

fn insert_environment(
    variables: &mut Vec<(Vec<u16>, Vec<u16>)>,
    key: &OsStr,
    value: Option<&OsStr>,
) -> Result<(), PtyError> {
    insert_environment_entry(variables, key, value, false)
}

fn insert_environment_entry(
    variables: &mut Vec<(Vec<u16>, Vec<u16>)>,
    key: &OsStr,
    value: Option<&OsStr>,
    inherited: bool,
) -> Result<(), PtyError> {
    let key: Vec<u16> = key.encode_wide().collect();
    let drive_current_directory = inherited
        && key.len() == 3
        && key[0] == b'=' as u16
        && matches!(key[1], 0x41..=0x5a | 0x61..=0x7a)
        && key[2] == b':' as u16;
    if key.is_empty()
        || key.contains(&0)
        || (!drive_current_directory && key.contains(&(b'=' as u16)))
    {
        return Err(PtyError::InvalidEnvironmentName);
    }
    if let Some(index) = variables
        .iter()
        .position(|(existing, _)| wide_environment_names_equal(existing, &key))
    {
        variables.remove(index);
    }
    if let Some(value) = value {
        // Windows keeps one hidden `=X:` current-directory entry per drive.
        // A canonical verbatim value is inherited by children independently
        // of lpCurrentDirectory, so drive-relative resolution can still
        // observe the incompatible spelling after the explicit cwd is
        // normalized.
        let normalized_value = drive_current_directory.then(|| child_compatible_path(value));
        let value = normalized_value.as_deref().unwrap_or(value);
        let value: Vec<u16> = value.encode_wide().collect();
        if value.contains(&0) {
            return Err(PtyError::EmbeddedNul {
                field: "environment value",
            });
        }
        variables.push((key, value));
    }
    Ok(())
}

fn wide_environment_names_equal(left: &[u16], right: &[u16]) -> bool {
    // SAFETY: The pointers and explicit lengths describe valid slices; no NUL
    // termination is required by `CompareStringOrdinal` with positive lengths.
    unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        ) == CSTR_EQUAL
    }
}

fn compare_environment_names(left: &[u16], right: &[u16]) -> Ordering {
    // SAFETY: See `wide_environment_names_equal`.
    let result = unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        )
    };
    match result {
        CSTR_EQUAL => left.cmp(right),
        CSTR_GREATER_THAN => Ordering::Greater,
        1 => Ordering::Less,
        _ => left.cmp(right),
    }
}

fn wide_nul(value: &OsStr, field: &'static str) -> Result<Vec<u16>, PtyError> {
    let mut result: Vec<u16> = value.encode_wide().collect();
    if result.contains(&0) {
        return Err(PtyError::EmbeddedNul { field });
    }
    result.push(0);
    Ok(result)
}

impl Process {
    pub(crate) fn id(&self) -> u32 {
        self.process_id
    }

    #[cfg(test)]
    fn take_test_output_writer(&mut self) -> File {
        self.pseudo_console
            .as_mut()
            .and_then(|pseudo_console| pseudo_console.test_output_writer.take())
            .expect("test output writer")
    }

    #[cfg(test)]
    fn set_test_close_gate(&mut self, gate: TestCloseGate) {
        self.pseudo_console
            .as_mut()
            .expect("test pseudoconsole")
            .test_close_gate = Some(gate);
    }

    pub(crate) fn resize(&self, size: PtySize) -> Result<(), PtyError> {
        let Some(pseudo_console) = &self.pseudo_console else {
            return Ok(());
        };
        // SAFETY: The HPCON remains owned by this process wrapper.
        let result = unsafe { ResizePseudoConsole(pseudo_console.raw(), coordinate(size)) };
        if result != S_OK {
            return Err(PtyError::io(
                "resize Windows pseudoconsole",
                io::Error::from_raw_os_error(result),
            ));
        }
        Ok(())
    }

    pub(crate) fn signal(&mut self, signal: PtySignal) -> Result<(), PtyError> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        match signal {
            PtySignal::Interrupt => self.queue_interrupt(),
            // Windows has no SIGHUP. Treat loss of the controlling transport
            // as termination of the kill-on-close job, which preserves the
            // attached-session lifetime contract without leaking descendants.
            PtySignal::Hangup | PtySignal::Terminate | PtySignal::Kill => self.terminate(1),
            PtySignal::Continue => Err(PtyError::Unsupported {
                operation: "continue signal",
            }),
        }
    }

    fn queue_interrupt(&self) -> Result<(), PtyError> {
        if self.interrupt_pending.swap(true, AtomicOrdering::AcqRel) {
            return Ok(());
        }
        let mut input = match self.control_input.try_clone() {
            Ok(input) => input,
            Err(source) => {
                self.interrupt_pending.store(false, AtomicOrdering::Release);
                return Err(PtyError::io(
                    "duplicate pseudoconsole control input",
                    source,
                ));
            }
        };
        let pending = Arc::clone(&self.interrupt_pending);
        let queued = thread::Builder::new()
            .name("nrm-conpty-interrupt".to_string())
            .spawn(move || {
                let _ = input.write_all(&[0x03]);
                pending.store(false, AtomicOrdering::Release);
            });
        if let Err(source) = queued {
            self.interrupt_pending.store(false, AtomicOrdering::Release);
            return Err(PtyError::io("queue pseudoconsole interrupt", source));
        }
        Ok(())
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<PtyExitStatus>, PtyError> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        // SAFETY: The process handle remains valid for the wrapper lifetime.
        match unsafe { WaitForSingleObject(self.process.raw(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => self.read_exit_status().map(Some),
            _ => Err(PtyError::io(
                "poll pseudoconsole process",
                io::Error::last_os_error(),
            )),
        }
    }

    pub(crate) fn wait(&mut self) -> Result<PtyExitStatus, PtyError> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        // SAFETY: The process handle remains valid for the wrapper lifetime.
        if unsafe { WaitForSingleObject(self.process.raw(), INFINITE) } != WAIT_OBJECT_0 {
            return Err(PtyError::io(
                "wait for pseudoconsole process",
                io::Error::last_os_error(),
            ));
        }
        self.read_exit_status()
    }

    fn read_exit_status(&mut self) -> Result<PtyExitStatus, PtyError> {
        let mut code = 0;
        // SAFETY: The process is signaled and the output pointer is valid.
        if unsafe { GetExitCodeProcess(self.process.raw(), &mut code) } == 0 {
            return Err(PtyError::io(
                "read pseudoconsole exit status",
                io::Error::last_os_error(),
            ));
        }
        // The primary process can exit while descendants remain in the job.
        // Match POSIX process-group semantics by terminating that remainder
        // before completion becomes observable.
        // SAFETY: The job handle remains valid and owns the process tree.
        if unsafe { TerminateJobObject(self.job.raw(), 1) } == 0 {
            return Err(PtyError::io(
                "terminate remaining pseudoconsole process tree",
                io::Error::last_os_error(),
            ));
        }
        if let Some(mut pseudo_console) = self.pseudo_console.take() {
            pseudo_console.close_after_process_exit();
        }
        let status = PtyExitStatus {
            code: Some(code),
            signal: None,
        };
        self.status = Some(status);
        Ok(status)
    }

    fn terminate(&self, code: u32) -> Result<(), PtyError> {
        // SAFETY: The job is valid and owns the full process tree.
        if unsafe { TerminateJobObject(self.job.raw(), code) } == 0 {
            return Err(PtyError::io(
                "terminate pseudoconsole process job",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.status.is_none() {
            match self.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    let _ = self.terminate(1);
                    // Job termination is synchronous with respect to starting
                    // termination, not process object signaling. Wait so the
                    // child cannot outlive this ownership handle.
                    // SAFETY: The process handle remains valid until drop ends.
                    unsafe {
                        WaitForSingleObject(self.process.raw(), INFINITE);
                    }
                }
            }
        }
        // Close the ConPTY after its process tree has exited. This ordering
        // avoids both leaked conhost instances and children blocked on output.
        // Honor caller ownership here just as `read_exit_status` does: the
        // emergency reader must not race a stream returned by `take_output`.
        if let Some(mut pseudo_console) = self.pseudo_console.take() {
            pseudo_console.close_after_process_exit();
        }
    }
}

impl PipeProcess {
    pub(crate) fn id(&self) -> u32 {
        self.process_id
    }

    pub(crate) fn signal(&mut self, signal: PtySignal) -> Result<(), PtyError> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        match signal {
            // A process launched with anonymous pipes has no console to which
            // Windows can deliver CTRL_C_EVENT. Preserve the portable
            // interrupt contract by terminating its owned job with the
            // conventional shell status instead of returning an unsupported
            // error and leaving the caller uncertain about process lifetime.
            PtySignal::Interrupt => self.terminate(130),
            PtySignal::Hangup | PtySignal::Terminate | PtySignal::Kill => self.terminate(1),
            PtySignal::Continue => Err(PtyError::Unsupported {
                operation: "continue signal",
            }),
        }
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<PtyExitStatus>, PtyError> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        // SAFETY: The process handle remains valid for the wrapper lifetime.
        match unsafe { WaitForSingleObject(self.process.raw(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => self.read_exit_status().map(Some),
            _ => Err(PtyError::io(
                "poll piped process",
                io::Error::last_os_error(),
            )),
        }
    }

    pub(crate) fn wait(&mut self) -> Result<PtyExitStatus, PtyError> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        // SAFETY: The process handle remains valid for the wrapper lifetime.
        if unsafe { WaitForSingleObject(self.process.raw(), INFINITE) } != WAIT_OBJECT_0 {
            return Err(PtyError::io(
                "wait for piped process",
                io::Error::last_os_error(),
            ));
        }
        self.read_exit_status()
    }

    fn read_exit_status(&mut self) -> Result<PtyExitStatus, PtyError> {
        let mut code = 0;
        // SAFETY: The process is signaled and the output pointer is valid.
        if unsafe { GetExitCodeProcess(self.process.raw(), &mut code) } == 0 {
            return Err(PtyError::io(
                "read piped process exit status",
                io::Error::last_os_error(),
            ));
        }
        // A piped leader exiting does not imply its job has no descendants.
        // SAFETY: The job handle remains valid and owns the process tree.
        if unsafe { TerminateJobObject(self.job.raw(), 1) } == 0 {
            return Err(PtyError::io(
                "terminate remaining piped process tree",
                io::Error::last_os_error(),
            ));
        }
        let status = PtyExitStatus {
            code: Some(code),
            signal: None,
        };
        self.status = Some(status);
        Ok(status)
    }

    fn terminate(&self, code: u32) -> Result<(), PtyError> {
        // SAFETY: The job is valid and owns the full process tree.
        if unsafe { TerminateJobObject(self.job.raw(), code) } == 0 {
            return Err(PtyError::io(
                "terminate piped process job",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
}

impl Drop for PipeProcess {
    fn drop(&mut self) {
        if self.status.is_none() {
            match self.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    let _ = self.terminate(1);
                    // SAFETY: The process handle remains valid.
                    unsafe {
                        WaitForSingleObject(self.process.raw(), INFINITE);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(units: &[u16]) -> String {
        String::from_utf16_lossy(units.strip_suffix(&[0]).unwrap_or(units))
    }

    #[test]
    fn quoting_preserves_spaces_quotes_and_trailing_backslashes() {
        let mut command = PtyCommand::new("program.exe");
        command.args(["plain", "two words", "quoted\"value", "ends\\"]);
        let line = native_command_line(&command).expect("command line");
        assert_eq!(
            decode(&line),
            "program.exe plain \"two words\" \"quoted\\\"value\" ends\\"
        );
    }

    #[test]
    fn child_path_conversion_is_limited_to_dos_namespaces() {
        for (input, expected) in [
            (r"\\?\B:\repos\workspace", r"B:\repos\workspace"),
            (
                r"\\?\UNC\server\share\workspace",
                r"\\server\share\workspace",
            ),
            (
                r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\workspace",
                r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\workspace",
            ),
            (
                r"\\?\GLOBALROOT\Device\HarddiskVolume1\workspace",
                r"\\?\GLOBALROOT\Device\HarddiskVolume1\workspace",
            ),
            (r"\\?\B:drive-relative", r"\\?\B:drive-relative"),
            (r"\\?\malformed", r"\\?\malformed"),
        ] {
            let mut command = PtyCommand::new("program.exe");
            command.current_dir(input);

            let current_directory = process_current_directory(&command)
                .expect("current directory")
                .expect("configured current directory");

            assert_eq!(decode(&current_directory), expected);
        }
    }

    #[test]
    fn child_path_conversion_preserves_verbatim_only_names_and_long_paths() {
        let dos_boundary = format!(r"B:\{}\{}", "x".repeat(128), "y".repeat(127));
        let dos_long = format!(r"B:\{}\{}", "x".repeat(128), "y".repeat(128));
        let unc_boundary = format!(r"\\server\share\{}", "x".repeat(244));
        let unc_long = format!(r"\\server\share\{}", "x".repeat(245));
        assert_eq!(dos_boundary.encode_utf16().count(), 259);
        assert_eq!(dos_long.encode_utf16().count(), 260);
        assert_eq!(unc_boundary.encode_utf16().count(), 259);
        assert_eq!(unc_long.encode_utf16().count(), 260);

        for (input, expected) in [
            (format!(r"\\?\{dos_boundary}"), dos_boundary),
            (
                format!(r"\\?\UNC\server\share\{}", "x".repeat(244)),
                unc_boundary,
            ),
            (format!(r"\\?\{dos_long}"), format!(r"\\?\{dos_long}")),
            (
                format!(r"\\?\UNC\server\share\{}", "x".repeat(245)),
                format!(r"\\?\UNC\server\share\{}", "x".repeat(245)),
            ),
        ] {
            assert_eq!(
                child_compatible_path(OsStr::new(&input)),
                OsString::from(expected)
            );
        }

        for input in [
            r"\\?\B:\repos\trailing.",
            r"\\?\B:\repos\trailing ",
            r"\\?\B:\repos\.\workspace",
            r"\\?\B:\repos\..\workspace",
            r"\\?\B:\repos\NUL.txt",
            r"\\?\B:\repos\COM1",
            r"\\?\UNC\server\share\NUL.txt",
            r"\\?\B:/repos/workspace",
        ] {
            assert_eq!(child_compatible_path(OsStr::new(input)), input);
        }
    }

    #[test]
    fn validation_enforces_create_process_command_line_limit() {
        // program + separator + argument + trailing NUL must fit exactly in
        // CreateProcessW's documented 32,767 UTF-16-unit limit.
        let program = "program.exe";
        let fixed_units = program.encode_utf16().count() + 2;
        let mut boundary = PtyCommand::new(program);
        boundary.arg("x".repeat(MAX_CREATE_PROCESS_COMMAND_LINE_UNITS - fixed_units));
        boundary.validate().expect("maximum command-line size");

        let mut command = boundary.clone();
        command.args[0].push("x");
        assert!(matches!(
            command.validate(),
            Err(PtyError::CommandLineTooLarge { .. })
        ));
    }

    #[test]
    fn validation_enforces_create_process_environment_limit() {
        // key + '=' + value + entry NUL + block NUL must fit in 32,767
        // UTF-16 units. The public aggregate-byte limit is intentionally
        // larger, so this exercises the Windows API boundary itself.
        let fixed_units = "BIG".encode_utf16().count() + 3;
        let mut boundary = PtyCommand::new("program.exe");
        boundary.env_clear().env(
            "BIG",
            "x".repeat(MAX_CREATE_PROCESS_ENVIRONMENT_UNITS - fixed_units),
        );
        boundary.validate().expect("maximum environment size");

        let mut oversized = boundary;
        oversized.environment[0]
            .1
            .as_mut()
            .expect("environment value")
            .push("x");
        assert!(matches!(
            oversized.validate(),
            Err(PtyError::CommandTooLarge { .. })
        ));
    }

    #[test]
    fn bare_program_resolution_uses_the_effective_path() {
        let inherited = PtyCommand::new("cmd.exe");
        assert!(resolve_application(&inherited).is_ok());

        let mut cleared = PtyCommand::new("cmd.exe");
        cleared.env_clear();
        assert!(matches!(
            resolve_application(&cleared),
            Err(PtyError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound
        ));

        let empty_path = tempfile::tempdir().expect("empty PATH directory");
        let mut replaced = PtyCommand::new("cmd.exe");
        replaced.env("Path", empty_path.path().as_os_str());
        assert!(matches!(
            resolve_application(&replaced),
            Err(PtyError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound
        ));

        let comspec = std::env::var_os("ComSpec").expect("ComSpec");
        let mut absolute = PtyCommand::new(comspec);
        absolute.env_clear();
        assert!(resolve_application(&absolute).is_ok());
    }

    #[test]
    fn resolution_honors_path_then_safe_pathext_order() {
        let root = tempfile::tempdir().expect("temporary root");
        let first = root.path().join("first");
        let second = root.path().join("second");
        fs::create_dir_all(&first).expect("first PATH directory");
        fs::create_dir_all(&second).expect("second PATH directory");
        fs::write(first.join("tool.exe"), b"first exe").expect("first executable");
        fs::write(first.join("tool.cmd"), b"first cmd").expect("first command script");
        fs::write(second.join("tool.cmd"), b"second cmd").expect("second command script");
        let path = std::env::join_paths([&first, &second]).expect("join PATH");

        let mut extension_first = PtyCommand::new("tool");
        extension_first
            .env_clear()
            .env("PATH", path.clone())
            .env("PATHEXT", ".CMD;.EXE");
        let resolved = resolve_application(&extension_first).expect("resolve PATHEXT first");
        assert_eq!(
            resolved.path,
            fs::canonicalize(first.join("tool.cmd")).unwrap()
        );
        assert_eq!(resolved.kind, ApplicationKind::Batch);

        fs::remove_file(first.join("tool.cmd")).expect("remove first command script");
        let resolved = resolve_application(&extension_first).expect("resolve PATH first");
        assert_eq!(
            resolved.path,
            fs::canonicalize(first.join("tool.exe")).unwrap()
        );
        assert_eq!(resolved.kind, ApplicationKind::Native);

        fs::write(second.join("batch.bat"), b"@exit /b 0\r\n").expect("second batch script");
        let mut bat = PtyCommand::new("batch");
        bat.env_clear()
            .env("PATH", second.as_os_str())
            .env("PATHEXT", ".bAt;.BAT;.EXE");
        let resolved = resolve_application(&bat).expect("resolve .bat from PATHEXT");
        assert_eq!(
            resolved.path,
            fs::canonicalize(second.join("batch.bat")).unwrap()
        );
        assert_eq!(resolved.kind, ApplicationKind::Batch);

        let mut explicit = PtyCommand::new(first.join("tool.exe"));
        explicit.env_clear().env("PATHEXT", ".CMD");
        assert_eq!(
            resolve_application(&explicit)
                .expect("resolve explicit executable")
                .kind,
            ApplicationKind::Native
        );
    }

    #[test]
    fn resolution_filters_unsafe_pathext_entries() {
        let root = tempfile::tempdir().expect("temporary root");
        fs::write(root.path().join("tool.ps1"), b"Write-Output unsafe").expect("PowerShell script");
        let mut command = PtyCommand::new("tool");
        command
            .env_clear()
            .env("PATH", root.path().as_os_str())
            .env("PATHEXT", ".PS1;.JS");
        assert!(matches!(
            resolve_application(&command),
            Err(PtyError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn batch_launch_enforces_the_final_cmd_command_line_limit() {
        let root = tempfile::tempdir().expect("temporary root");
        let script = root.path().join("runner.cmd");
        fs::write(&script, b"@exit /b 0\r\n").expect("command script");

        let mut one = PtyCommand::new(&script);
        one.arg("x").env_clear();
        let fixed_units = native_command_line(&one)
            .expect("native command line")
            .len()
            - 1;
        let mut command = PtyCommand::new(&script);
        command
            .arg("x".repeat(MAX_CREATE_PROCESS_COMMAND_LINE_UNITS - fixed_units))
            .env_clear();
        command.validate().expect("original command-line boundary");
        assert!(matches!(
            prepare_launch(&command),
            Err(PtyError::CommandLineTooLarge { .. })
        ));
    }

    #[test]
    fn environment_edits_are_case_insensitive() {
        let mut command = PtyCommand::new("ignored.exe");
        command.env("Path", "old").env("PATH", "new");
        assert!(matches!(
            command.validate(),
            Err(PtyError::DuplicateEnvironmentName)
        ));

        let mut values = Vec::new();
        insert_environment(&mut values, OsStr::new("Path"), Some(OsStr::new("old")))
            .expect("insert Path");
        insert_environment(&mut values, OsStr::new("PATH"), Some(OsStr::new("new")))
            .expect("replace PATH");
        assert_eq!(values.len(), 1);
        assert_eq!(String::from_utf16_lossy(&values[0].1), "new");
    }

    #[test]
    fn inherited_drive_current_directories_are_preserved_but_not_user_settable() {
        let mut values = Vec::new();
        insert_environment_entry(
            &mut values,
            OsStr::new("=C:"),
            Some(OsStr::new("C:\\workspace")),
            true,
        )
        .expect("insert inherited drive current directory");
        assert_eq!(values.len(), 1);
        insert_environment_entry(
            &mut values,
            OsStr::new("=D:"),
            Some(OsStr::new(r"\\?\D:\verbatim\workspace")),
            true,
        )
        .expect("insert inherited verbatim drive current directory");
        assert_eq!(
            String::from_utf16_lossy(&values[1].1),
            r"D:\verbatim\workspace"
        );
        assert!(matches!(
            insert_environment(
                &mut values,
                OsStr::new("=D:"),
                Some(OsStr::new("D:\\workspace"))
            ),
            Err(PtyError::InvalidEnvironmentName)
        ));
    }

    #[test]
    fn conpty_spawns_and_returns_raw_output() {
        let mut command = PtyCommand::new("cmd.exe");
        command.args(["/d", "/s", "/c", "echo nrm-pty"]);
        let mut process = crate::PtyProcess::spawn(&command, PtySize::default()).expect("spawn");
        let mut output = process.take_output().expect("output");
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes).expect("read output");
            bytes
        });
        let status = process.wait().expect("wait");
        let output = reader.join().expect("join output reader");
        assert!(
            status.success(),
            "unexpected exit status: {status:?}; output: {}",
            String::from_utf8_lossy(&output)
        );
        assert!(String::from_utf8_lossy(&output).contains("nrm-pty"));
    }

    #[test]
    fn conpty_wait_drains_output_when_stream_was_not_taken() {
        let mut command = PtyCommand::new("cmd.exe");
        command.args(["/d", "/s", "/c", "echo discarded-output"]);
        let mut process = crate::PtyProcess::spawn(&command, PtySize::default()).expect("spawn");

        assert!(process.wait().expect("wait").success());
    }

    #[test]
    fn dropping_live_conpty_preserves_taken_output_for_caller() {
        use std::time::{Duration, Instant};

        const MARKER: &str = "nrm-caller-owned-output-5f5de9e6";
        let root = tempfile::tempdir().expect("temporary root");
        let ready = root.path().join("output-written");
        let script = root.path().join("writer.cmd");
        fs::write(
            &script,
            format!(
                "@echo off\r\necho {MARKER}\r\n>\"{}\" type nul\r\nset /p \"_hold=\"\r\n",
                ready.display()
            ),
        )
        .expect("write command script");

        let command = PtyCommand::new(&script);
        let mut process = crate::PtyProcess::spawn(&command, PtySize::default()).expect("spawn");
        let mut output = process.take_output().expect("caller-owned output");

        // The child creates this file only after writing MARKER to its console.
        // This is a semantic handoff, rather than a sleep that merely hopes the
        // output has been produced before the live process is dropped.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "child did not report writing its output"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(process.try_wait().expect("poll live process"), None);

        // Process teardown must not activate the emergency reader while the
        // caller still owns the output stream. Otherwise that reader drains the
        // marker before this handle can observe it.
        drop(process);
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).expect("read caller output");
        assert!(
            String::from_utf8_lossy(&bytes).contains(MARKER),
            "caller-owned output was drained during process teardown: {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[test]
    fn dropping_live_conpty_with_full_taken_output_returns_before_caller_drains() {
        use std::os::windows::io::AsRawHandle as _;
        use std::time::{Duration, Instant};

        const MARKER: &str = "nrm-full-caller-output-950b96de";
        const FILL_BYTES: usize = 16 * 1024 * 1024;
        let root = tempfile::tempdir().expect("temporary root");
        let ready = root.path().join("writer-started");
        let script = root.path().join("fill-output.cmd");
        fs::write(
            &script,
            format!(
                "@echo off\r\necho {MARKER}\r\n>\"{}\" type nul\r\nset /p \"_hold=\"\r\n",
                ready.display()
            ),
        )
        .expect("write output-filler script");

        let command = PtyCommand::new(&script);
        let mut process = crate::PtyProcess::spawn(&command, PtySize::default()).expect("spawn");
        let mut output = process.take_output().expect("caller-owned output");
        let mut output_writer = process.inner.take_test_output_writer();
        let output_handle = output.0.file.as_raw_handle() as HANDLE;

        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "output writer did not start");
            thread::yield_now();
        }
        assert_eq!(process.try_wait().expect("poll live writer"), None);

        // A single synchronous write much larger than the anonymous-pipe quota
        // cannot complete without a reader. Once PeekNamedPipe observes part of
        // that write while the completion channel remains empty, the writer is
        // blocked on caller-owned output rather than merely scheduled late.
        let (write_started_tx, write_started_rx) = mpsc::sync_channel(1);
        let (write_done_tx, write_done_rx) = mpsc::sync_channel(1);
        let filler_bytes = vec![b'Z'; FILL_BYTES];
        let filler = thread::spawn(move || {
            write_started_tx.send(()).expect("report filler start");
            let result = output_writer.write_all(&filler_bytes);
            drop(output_writer);
            write_done_tx
                .send(result)
                .expect("report filler completion");
        });
        write_started_rx.recv().expect("wait for filler start");
        loop {
            let mut peeked = [0u8; 64 * 1024];
            let mut bytes_read = 0u32;
            let mut available = 0u32;
            // SAFETY: The pipe handle is live and the byte-count output pointer
            // and peek buffer are valid. PeekNamedPipe does not consume bytes.
            assert_ne!(
                unsafe {
                    PeekNamedPipe(
                        output_handle,
                        peeked.as_mut_ptr().cast::<c_void>(),
                        peeked.len() as u32,
                        &mut bytes_read,
                        &mut available,
                        ptr::null_mut(),
                    )
                },
                0,
                "inspect ConPTY output pipe: {}",
                io::Error::last_os_error()
            );
            let filler_is_buffered = peeked[..bytes_read as usize]
                .windows(1_024)
                .any(|window| window.iter().all(|&byte| byte == b'Z'));
            if filler_is_buffered {
                match write_done_rx.try_recv() {
                    Err(mpsc::TryRecvError::Empty) => break,
                    Ok(result) => panic!(
                        "synchronous filler completed without a reader: {result:?}; {available} bytes buffered"
                    ),
                    Err(mpsc::TryRecvError::Disconnected) => {
                        panic!("synchronous filler completion channel disconnected")
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "synchronous filler did not block with bytes in the output pipe"
            );
            thread::yield_now();
        }

        // Windows 11 24H2 makes ClosePseudoConsole return immediately, while
        // earlier supported builds can wait for output consumption. Hold the
        // close call at its entry point to deterministically model that older
        // behavior and prove Process::drop itself no longer waits on it.
        let (close_entered_tx, close_entered_rx) = mpsc::sync_channel(1);
        let (close_release_tx, close_release_rx) = mpsc::sync_channel(1);
        process.inner.set_test_close_gate(TestCloseGate {
            entered: close_entered_tx,
            release: close_release_rx,
        });
        let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);
        let dropper = thread::spawn(move || {
            drop(process);
            dropped_tx.send(()).expect("report process drop");
        });
        close_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("wait for pseudoconsole close entry");
        let returned_before_drain = dropped_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        close_release_tx
            .send(())
            .expect("release pseudoconsole close");
        if !returned_before_drain {
            // Unblock the old synchronous close so the failing regression test
            // cleans up its process and thread before reporting the failure.
            let _ = io::copy(&mut output, &mut io::sink());
        }
        dropper.join().expect("join process dropper");
        assert!(
            returned_before_drain,
            "dropping the process blocked on a full caller-owned output pipe"
        );

        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).expect("drain caller output");
        write_done_rx
            .recv()
            .expect("wait for filler completion")
            .expect("write filler output");
        filler.join().expect("join output filler");
        assert!(
            String::from_utf8_lossy(&bytes).contains(MARKER),
            "caller lost full-pipe output after asynchronous process drop"
        );
        assert_eq!(
            bytes.iter().filter(|&&byte| byte == b'Z').count(),
            FILL_BYTES,
            "caller lost bytes from the saturated output pipe"
        );
    }

    #[test]
    fn hangup_terminates_conpty_job() {
        let mut command = PtyCommand::new("cmd.exe");
        command.args(["/d", "/s", "/c", "ping -t 127.0.0.1 >nul"]);
        let mut process = crate::PtyProcess::spawn(&command, PtySize::default()).expect("spawn");
        drop(process.take_input());
        let mut output = process.take_output().expect("output");
        let reader = thread::spawn(move || io::copy(&mut output, &mut io::sink()));

        process.signal(PtySignal::Hangup).expect("hang up");
        assert_eq!(process.wait().expect("wait").code, Some(1));
        assert!(reader.join().expect("join output reader").is_ok());
    }

    #[test]
    fn piped_process_keeps_stdout_and_stderr_separate() {
        let mut command = PtyCommand::new("cmd.exe");
        command.args([
            "/d",
            "/s",
            "/c",
            "(echo standard-output)&(echo standard-error 1>&2)",
        ]);
        let mut process = crate::PipeProcess::spawn(&command).expect("spawn");
        drop(process.take_input());
        let mut stdout = String::new();
        let mut stderr = String::new();
        process
            .take_stdout()
            .expect("stdout")
            .read_to_string(&mut stdout)
            .expect("read stdout");
        process
            .take_stderr()
            .expect("stderr")
            .read_to_string(&mut stderr)
            .expect("read stderr");
        assert!(stdout.contains("standard-output"));
        assert!(stderr.contains("standard-error"));
        assert!(process.wait().expect("wait").success());
    }

    #[test]
    fn piped_windows_powershell_starts_from_canonical_paths() {
        const MARKER: &str = "NRM_PTY_POWERSHELL_OK";
        let system = system_directory().expect("Windows system directory");
        let powershell = system
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        assert!(powershell.is_file(), "Windows PowerShell is missing");
        let root = tempfile::tempdir().expect("temporary workspace");
        let canonical_root = fs::canonicalize(root.path()).expect("canonical workspace");

        let mut command = PtyCommand::new(powershell);
        command.args(["-NoProfile", "-NonInteractive", "-Command"]);
        command.arg(format!("[Console]::Out.Write('{MARKER}')"));
        command.current_dir(canonical_root);

        let mut process = crate::PipeProcess::spawn(&command).expect("spawn Windows PowerShell");
        drop(process.take_input());
        let mut stdout = process.take_stdout().expect("stdout");
        let mut stderr = process.take_stderr().expect("stderr");
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).expect("read stdout");
            bytes
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).expect("read stderr");
            bytes
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            if let Some(status) = process.try_wait().expect("poll Windows PowerShell") {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        };
        let timed_out = status.is_none();
        if timed_out {
            let _ = process.signal(PtySignal::Kill);
        }
        // Dropping the kill-on-close job after the bounded poll guarantees
        // both pipe readers are released before their diagnostics are joined.
        drop(process);
        let stdout = stdout_reader.join().expect("join stdout reader");
        let stderr = stderr_reader.join().expect("join stderr reader");

        assert!(
            !timed_out,
            "Windows PowerShell timed out; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        let status = status.expect("status checked above");

        assert!(
            status.success(),
            "Windows PowerShell failed with {status:?}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(stdout, MARKER.as_bytes());
        assert!(stderr.is_empty(), "unexpected stderr: {stderr:?}");
    }

    #[test]
    fn com_image_resolves_from_pathext_and_spawns_natively() {
        let root = tempfile::tempdir().expect("temporary root");
        let system = system_directory().expect("Windows system directory");
        let source = trusted_system_executable(&system, Path::new("cmd.exe"), "resolve cmd")
            .expect("trusted cmd.exe");
        fs::copy(source, root.path().join("runner.com")).expect("copy PE image as .com");

        let mut command = PtyCommand::new("runner");
        command
            .args(["/d", "/s", "/c", "echo com-ran"])
            .env_clear()
            .env("PATH", root.path().as_os_str())
            .env("PATHEXT", ".COM;.EXE");
        let mut process = crate::PipeProcess::spawn(&command).expect("spawn .com image");
        drop(process.take_input());
        let mut stdout = process.take_stdout().expect("stdout");
        let mut stderr = process.take_stderr().expect("stderr");
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).expect("read stdout");
            bytes
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).expect("read stderr");
            bytes
        });
        let status = process.wait().expect("wait");
        let stdout = stdout_reader.join().expect("join stdout reader");
        let stderr = stderr_reader.join().expect("join stderr reader");
        assert!(
            status.success(),
            "unexpected status {status:?}; stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(String::from_utf8_lossy(&stdout).contains("com-ran"));
    }

    #[test]
    fn cmd_launch_round_trips_safe_metacharacters_without_command_injection() {
        use std::process::Command as StdCommand;

        let root = tempfile::tempdir().expect("temporary root");
        let scripts = root.path().join("batch & scripts");
        fs::create_dir(&scripts).expect("script directory");
        let capture_source = root.path().join("capture.rs");
        let capture = root.path().join("capture.exe");
        fs::write(
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
    for name in [
        "NRM_PTY_BATCH_459DA3301D7C4BFD",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "NRM_CUSTOM",
    ] {
        match std::env::var(name) {
            Ok(value) => {
                let bytes = value.as_bytes();
                stdout.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
                stdout.write_all(bytes).unwrap();
            }
            Err(std::env::VarError::NotPresent) => {
                stdout.write_all(&u32::MAX.to_le_bytes()).unwrap();
            }
            Err(error) => panic!("invalid {name}: {error}"),
        }
    }
}"#,
        )
        .expect("capture source");
        let compile = StdCommand::new("rustc")
            .arg(&capture_source)
            .arg("-o")
            .arg(&capture)
            .output()
            .expect("run rustc");
        assert!(
            compile.status.success(),
            "capture compilation failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        assert!(!capture
            .as_os_str()
            .encode_wide()
            .any(|unit| { unit == b'"' as u16 || unit == b'%' as u16 }));
        let script = scripts.join("runner with spaces.cmd");
        fs::write(
            &script,
            format!(
                "@echo off\r\n\"{}\" %*\r\nexit /b %ERRORLEVEL%\r\n",
                capture.display()
            ),
        )
        .expect("command script");
        let sentinel = root.path().join("INJECTION_SENTINEL");
        let injection = format!("&echo injected>{}", sentinel.display());
        let arguments = vec![
            OsString::new(),
            OsString::from("value with spaces"),
            OsString::from("meta&pipe|redirect>less<than^(paren)caret^bang!"),
            OsString::from("single'quote"),
            OsString::from("trailing\\"),
            OsString::from(injection),
        ];

        let mut command = PtyCommand::new("runner with spaces");
        command
            .args(arguments.clone())
            .env_clear()
            .env("PATH", scripts.as_os_str())
            .env("PATHEXT", ".CMD;.EXE")
            .env("NRM_CUSTOM", "visible");
        let mut process = crate::PipeProcess::spawn(&command).expect("spawn .cmd script");
        drop(process.take_input());
        let mut stdout = process.take_stdout().expect("stdout");
        let mut stderr = process.take_stderr().expect("stderr");
        let stdout_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).expect("read stdout");
            bytes
        });
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).expect("read stderr");
            bytes
        });
        let status = process.wait().expect("wait");
        let stdout = stdout_reader.join().expect("join stdout reader");
        let stderr = stderr_reader.join().expect("join stderr reader");
        assert!(
            status.success(),
            "unexpected status {status:?}; stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        let mut expected = (arguments.len() as u32).to_le_bytes().to_vec();
        for argument in &arguments {
            let argument = argument.to_string_lossy();
            expected.extend_from_slice(&(argument.len() as u32).to_le_bytes());
            expected.extend_from_slice(argument.as_bytes());
        }
        // cmd.exe synthesizes ComSpec for itself even when it is absent from
        // the supplied environment block. Other bootstrap state must remain
        // absent, and explicit user edits must survive unchanged.
        let expected_comspec = trusted_system_executable(
            &system_directory().expect("Windows system directory"),
            Path::new("cmd.exe"),
            "resolve cmd.exe",
        )
        .expect("trusted cmd.exe")
        .to_string_lossy()
        .into_owned();
        for value in [
            None,
            None,
            None,
            Some(expected_comspec.as_str()),
            Some("visible"),
        ] {
            match value {
                Some(value) => {
                    expected.extend_from_slice(&(value.len() as u32).to_le_bytes());
                    expected.extend_from_slice(value.as_bytes());
                }
                None => expected.extend_from_slice(&u32::MAX.to_le_bytes()),
            }
        }
        assert_eq!(stdout, expected, "batch forwarding changed argv boundaries");
        assert!(
            !sentinel.exists(),
            "a batch argument was evaluated as command text"
        );
    }

    #[test]
    fn cmd_launch_rejects_controls_quotes_percent_expansion_and_percent_paths() {
        let root = tempfile::tempdir().expect("temporary root");
        let script = root.path().join("runner.cmd");
        fs::write(&script, b"@echo off\r\nexit /b 0\r\n").expect("command script");
        let sentinel = root.path().join("INJECTION_SENTINEL");

        for hostile in [
            format!("quote\" &echo injected>{}", sentinel.display()),
            format!("%PATH% &echo injected>{}", sentinel.display()),
            format!("line\n&echo injected>{}", sentinel.display()),
        ] {
            let mut command = PtyCommand::new(&script);
            command.arg(hostile);
            assert!(matches!(
                crate::PipeProcess::spawn(&command),
                Err(PtyError::Io { source, .. })
                    if source.kind() == io::ErrorKind::InvalidInput
            ));
            assert!(!sentinel.exists(), "rejected batch input executed");
        }

        let percent_directory = root.path().join("percent%directory");
        fs::create_dir(&percent_directory).expect("percent directory");
        let percent_script = percent_directory.join("runner.cmd");
        fs::copy(&script, &percent_script).expect("percent-path script");
        let command = PtyCommand::new(percent_script);
        assert!(matches!(
            crate::PipeProcess::spawn(&command),
            Err(PtyError::Io { source, .. }) if source.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn interrupt_terminates_a_consoleless_piped_job_with_status_130() {
        let mut command = PtyCommand::new("cmd.exe");
        command.args(["/d", "/s", "/c", "ping -t 127.0.0.1 >nul"]);
        let mut process = crate::PipeProcess::spawn(&command).expect("spawn");
        process
            .signal(PtySignal::Interrupt)
            .expect("interrupt piped job");
        assert_eq!(process.wait().expect("wait").code, Some(130));
    }
}
