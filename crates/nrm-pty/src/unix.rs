use crate::{PtyCommand, PtyError, PtyExitStatus, PtySignal, PtySize};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

pub(crate) type Input = File;

pub(crate) fn prepare_input_cancellation(input: &Input) -> io::Result<()> {
    set_nonblocking(input.as_raw_fd())
}

pub(crate) struct Output(File);

impl Read for Output {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.0.read(buffer) {
            // Linux PTY masters report EIO after the final slave descriptor is
            // closed. At this byte-stream boundary that state is EOF. Other
            // I/O errors must remain visible to the runtime.
            Err(error) if error.raw_os_error() == Some(libc::EIO) => Ok(0),
            result => result,
        }
    }
}

pub(crate) fn prepare_output_cancellation(output: &Output) -> io::Result<()> {
    set_nonblocking(output.0.as_raw_fd())
}

pub(crate) struct Spawned {
    pub(crate) process: Process,
    pub(crate) input: Input,
    pub(crate) output: Output,
}

pub(crate) type PipeInput = ChildStdin;

pub(crate) fn prepare_pipe_input_cancellation(input: &PipeInput) -> io::Result<()> {
    set_nonblocking(input.as_raw_fd())
}
pub(crate) enum PipeOutput {
    Stdout(ChildStdout),
    Stderr(ChildStderr),
}

impl Read for PipeOutput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(output) => output.read(buffer),
            Self::Stderr(output) => output.read(buffer),
        }
    }
}

pub(crate) fn prepare_pipe_output_cancellation(output: &PipeOutput) -> io::Result<()> {
    let descriptor = match output {
        PipeOutput::Stdout(output) => output.as_raw_fd(),
        PipeOutput::Stderr(output) => output.as_raw_fd(),
    };
    set_nonblocking(descriptor)
}

pub(crate) struct PipeSpawned {
    pub(crate) process: PipeProcess,
    pub(crate) input: PipeInput,
    pub(crate) stdout: PipeOutput,
    pub(crate) stderr: PipeOutput,
}

pub(crate) struct PipeProcess {
    child: Child,
    process_group: libc::pid_t,
    status: Option<PtyExitStatus>,
}

pub(crate) struct Process {
    child: Child,
    master: File,
    process_group: libc::pid_t,
    status: Option<PtyExitStatus>,
}

pub(crate) fn environment_names_equal(left: &OsStr, right: &OsStr) -> bool {
    left == right
}

pub(crate) fn validate_command(_command: &PtyCommand) -> Result<(), PtyError> {
    Ok(())
}

pub(crate) fn spawn(command: &PtyCommand, size: PtySize) -> Result<Spawned, PtyError> {
    let window_size = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.pixel_width,
        ws_ypixel: size.pixel_height,
    };
    let (master_fd, slave_fd) = open_pty(&window_size)?;

    // SAFETY: `openpty` returned two new, owned descriptors. Each descriptor is
    // wrapped exactly once, and the resulting `File`s close them on every exit
    // path.
    let master = unsafe { File::from_raw_fd(master_fd) };
    // SAFETY: See the ownership argument above.
    let slave = unsafe { File::from_raw_fd(slave_fd) };

    let mut child_command = Command::new(command.program());
    child_command.args(command.arguments());
    if let Some(cwd) = command.cwd() {
        child_command.current_dir(cwd);
    }
    if command.clears_environment() {
        child_command.env_clear();
    }
    for (key, value) in command.environment() {
        match value {
            Some(value) => {
                child_command.env(key, value);
            }
            None => {
                child_command.env_remove(key);
            }
        }
    }

    child_command
        .stdin(Stdio::from(slave.try_clone().map_err(|source| {
            PtyError::io("duplicate PTY slave for stdin", source)
        })?))
        .stdout(Stdio::from(slave.try_clone().map_err(|source| {
            PtyError::io("duplicate PTY slave for stdout", source)
        })?))
        .stderr(Stdio::from(slave));

    // `Command` installs the requested stdio descriptors before running this
    // callback. Only async-signal-safe libc operations are used between fork
    // and exec: the child becomes a new session leader, then claims fd 0 (the
    // PTY slave) as its controlling terminal.
    // SAFETY: The callback is invoked after fork and before exec. It captures
    // no borrowed state and calls only async-signal-safe libc operations.
    unsafe {
        child_command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = child_command
        .spawn()
        .map_err(|source| PtyError::io("spawn PTY child", source))?;
    let process_group = child.id() as libc::pid_t;
    // Establish the kill-and-reap guard before any fallible stream cloning.
    // A descriptor-exhaustion error below must not leave the child running.
    let process = Process {
        child,
        master,
        process_group,
        status: None,
    };
    let input = process
        .master
        .try_clone()
        .map_err(|source| PtyError::io("duplicate PTY master for input", source))?;
    let output = Output(
        process
            .master
            .try_clone()
            .map_err(|source| PtyError::io("duplicate PTY master for output", source))?,
    );

    Ok(Spawned {
        process,
        input,
        output,
    })
}

pub(crate) fn spawn_pipe(command: &PtyCommand) -> Result<PipeSpawned, PtyError> {
    let mut child_command = Command::new(command.program());
    child_command.args(command.arguments());
    if let Some(cwd) = command.cwd() {
        child_command.current_dir(cwd);
    }
    if command.clears_environment() {
        child_command.env_clear();
    }
    for (key, value) in command.environment() {
        match value {
            Some(value) => {
                child_command.env(key, value);
            }
            None => {
                child_command.env_remove(key);
            }
        }
    }
    child_command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);

    let child = child_command
        .spawn()
        .map_err(|source| PtyError::io("spawn piped child", source))?;
    let process_group = child.id() as libc::pid_t;
    // Install the process-tree guard before extracting fallible stdio handles.
    let mut process = PipeProcess {
        child,
        process_group,
        status: None,
    };
    let input =
        process.child.stdin.take().ok_or_else(|| {
            PtyError::io("open piped child stdin", io::Error::other("missing pipe"))
        })?;
    let stdout =
        process.child.stdout.take().ok_or_else(|| {
            PtyError::io("open piped child stdout", io::Error::other("missing pipe"))
        })?;
    let stderr =
        process.child.stderr.take().ok_or_else(|| {
            PtyError::io("open piped child stderr", io::Error::other("missing pipe"))
        })?;
    Ok(PipeSpawned {
        process,
        input,
        stdout: PipeOutput::Stdout(stdout),
        stderr: PipeOutput::Stderr(stderr),
    })
}

fn open_pty(size: &libc::winsize) -> Result<(RawFd, RawFd), PtyError> {
    let mut master = -1;
    let mut slave = -1;
    let mut size = *size;
    let size = std::ptr::from_mut(&mut size);
    // SAFETY: Both output pointers are valid and uniquely borrowed. The name
    // and termios pointers are null as permitted by `openpty`; `size` points to
    // a fully initialized `winsize` for the duration of the call.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            size,
        )
    };
    if result == -1 {
        return Err(PtyError::io("open PTY", io::Error::last_os_error()));
    }

    if let Err(error) = set_close_on_exec(master).and_then(|()| set_close_on_exec(slave)) {
        // SAFETY: Both descriptors are owned by this function until successful
        // return, and this failure path closes each exactly once.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(PtyError::io("set PTY close-on-exec", error));
    }
    Ok((master, slave))
}

fn set_close_on_exec(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor and `F_GETFD` has no pointer argument.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` remains live, and the third argument is the flags value
    // returned above with `FD_CLOEXEC` added.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor and `F_GETFL` has no pointer argument.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` remains live and the third argument is the current status
    // flags with nonblocking reads enabled.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Process {
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn resize(&self, size: PtySize) -> Result<(), PtyError> {
        let window_size = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };
        // SAFETY: `master` owns a live PTY master descriptor and the pointer is
        // valid for the duration of `ioctl`.
        let result =
            unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ as _, &window_size) };
        if result == -1 {
            return Err(PtyError::io("resize PTY", io::Error::last_os_error()));
        }
        Ok(())
    }

    pub(crate) fn signal(&mut self, signal: PtySignal) -> Result<(), PtyError> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        let signal_number = match signal {
            PtySignal::Interrupt => libc::SIGINT,
            PtySignal::Hangup => libc::SIGHUP,
            PtySignal::Terminate => libc::SIGTERM,
            PtySignal::Kill => libc::SIGKILL,
            PtySignal::Continue => libc::SIGCONT,
        };
        let foreground = self.foreground_process_group();
        let foreground_group = foreground.unwrap_or(self.process_group);
        let foreground_result = self.signal_group_id(foreground_group, signal_number);

        // Interactive shells place foreground jobs in their own process
        // groups. Destructive lifecycle signals must also tear down the shell
        // group so the attached runtime cannot survive after its foreground
        // command exits. Interrupt/continue retain terminal semantics and are
        // delivered only to the current foreground group.
        if foreground.is_some_and(|group| group != self.process_group)
            && matches!(
                signal,
                PtySignal::Hangup | PtySignal::Terminate | PtySignal::Kill
            )
        {
            // A foreground job can exit or hand the terminal back while the
            // signal is being delivered. macOS may report EPERM for that
            // transitional group. Always attempt the owned session leader's
            // group as well; its failure is authoritative because leaving the
            // shell alive would violate the runtime's ownership boundary.
            self.signal_group_id(self.process_group, signal_number)?;
            if foreground_result.is_err() {
                // Retry once after signalling the owner. A shell handoff can
                // make the original foreground group signalable only after
                // the session leader begins teardown. Failure remains safe to
                // ignore once the owned shell group was successfully killed.
                let _ = self.signal_group_id(foreground_group, signal_number);
            }
            return Ok(());
        }
        foreground_result
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<PtyExitStatus>, PtyError> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let status = self
            .child
            .try_wait()
            .map_err(|source| PtyError::io("poll PTY child", source))?
            .map(convert_status);
        if let Some(status) = status {
            // The session leader may have launched background descendants. It
            // has already been reaped, so terminate the remaining group before
            // exposing completion and allowing the ownership guard to vanish.
            let _ = self.signal_group(libc::SIGKILL);
            self.status = Some(status);
        }
        Ok(status)
    }

    pub(crate) fn wait(&mut self) -> Result<PtyExitStatus, PtyError> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let status = self
            .child
            .wait()
            .map(convert_status)
            .map_err(|source| PtyError::io("wait for PTY child", source))?;
        let _ = self.signal_group(libc::SIGKILL);
        self.status = Some(status);
        Ok(status)
    }

    fn signal_group(&self, signal: libc::c_int) -> Result<(), PtyError> {
        self.signal_group_id(self.process_group, signal)
    }

    fn foreground_process_group(&self) -> Option<libc::pid_t> {
        // SAFETY: `master` owns a live PTY master descriptor. `tcgetpgrp`
        // returns the foreground process-group ID without retaining memory.
        let process_group = unsafe { libc::tcgetpgrp(self.master.as_raw_fd()) };
        (process_group > 0).then_some(process_group)
    }

    fn signal_group_id(
        &self,
        process_group: libc::pid_t,
        signal: libc::c_int,
    ) -> Result<(), PtyError> {
        // A successful `setsid` made the child PID its process-group ID. The
        // negative argument targets the selected terminal group, including
        // grandchildren that remain in that group.
        // SAFETY: `kill` accepts any integer PID and does not dereference memory.
        let result = unsafe { libc::kill(-process_group, signal) };
        if result == -1 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::ESRCH) {
                return Err(PtyError::io("signal PTY process group", source));
            }
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.status.is_some() {
            return;
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                // The session leader may exit while background descendants
                // remain in its process group. Dropping the owner must still
                // tear down that full group.
                let _ = self.signal_group(libc::SIGKILL);
                self.status = Some(convert_status(status));
            }
            Ok(None) | Err(_) => {
                let _ = self.signal_group(libc::SIGKILL);
                if let Ok(status) = self.child.wait() {
                    self.status = Some(convert_status(status));
                }
            }
        }
    }
}

impl PipeProcess {
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn signal(&mut self, signal: PtySignal) -> Result<(), PtyError> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        self.signal_group(match signal {
            PtySignal::Interrupt => libc::SIGINT,
            PtySignal::Hangup => libc::SIGHUP,
            PtySignal::Terminate => libc::SIGTERM,
            PtySignal::Kill => libc::SIGKILL,
            PtySignal::Continue => libc::SIGCONT,
        })
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<PtyExitStatus>, PtyError> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let status = self
            .child
            .try_wait()
            .map_err(|source| PtyError::io("poll piped child", source))?
            .map(convert_status);
        if let Some(status) = status {
            let _ = self.signal_group(libc::SIGKILL);
            self.status = Some(status);
        }
        Ok(status)
    }

    pub(crate) fn wait(&mut self) -> Result<PtyExitStatus, PtyError> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let status = self
            .child
            .wait()
            .map(convert_status)
            .map_err(|source| PtyError::io("wait for piped child", source))?;
        let _ = self.signal_group(libc::SIGKILL);
        self.status = Some(status);
        Ok(status)
    }

    fn signal_group(&self, signal: libc::c_int) -> Result<(), PtyError> {
        // SAFETY: `kill` accepts any integer PID and the negative process group
        // is owned by this child guard.
        let result = unsafe { libc::kill(-self.process_group, signal) };
        if result == -1 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::ESRCH) {
                return Err(PtyError::io("signal piped process group", source));
            }
        }
        Ok(())
    }
}

impl Drop for PipeProcess {
    fn drop(&mut self) {
        if self.status.is_some() {
            return;
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let _ = self.signal_group(libc::SIGKILL);
                self.status = Some(convert_status(status));
            }
            Ok(None) | Err(_) => {
                let _ = self.signal_group(libc::SIGKILL);
                if let Ok(status) = self.child.wait() {
                    self.status = Some(convert_status(status));
                }
            }
        }
    }
}

fn convert_status(status: std::process::ExitStatus) -> PtyExitStatus {
    PtyExitStatus {
        code: status.code().map(|code| code as u32),
        signal: status.signal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn shell(script: &str) -> PtyCommand {
        let mut command = PtyCommand::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn child_has_controlling_terminal_and_raw_byte_streams() {
        let mut process = crate::PtyProcess::spawn(
            &shell("test -t 0 && test -t 1 && printf '\\377\\376'"),
            PtySize::default(),
        )
        .expect("spawn shell in PTY");
        drop(process.take_input());
        let mut bytes = Vec::new();
        process
            .take_output()
            .expect("PTY output")
            .read_to_end(&mut bytes)
            .expect("read PTY output");
        assert_eq!(bytes, [0xff, 0xfe]);
        assert!(process.wait().expect("wait for shell").success());
    }

    #[test]
    fn input_and_environment_are_forwarded_without_shell_flattening() {
        let mut command = shell(
            "stty -echo; printf 'READY\\n'; IFS= read -r line; printf '%s|%s\\n' \"$NRM_PTY_VALUE\" \"$line\"",
        );
        command.env("NRM_PTY_VALUE", "space and ' quote");
        let mut process = crate::PtyProcess::spawn(&command, PtySize::default()).expect("spawn");
        let mut output = BufReader::new(process.take_output().expect("PTY output"));
        let mut ready = String::new();
        output.read_line(&mut ready).expect("read ready marker");
        assert_eq!(ready, "READY\r\n");
        let mut input = process.take_input().expect("PTY input");
        input.write_all(b"raw input value\n").expect("write input");
        drop(input);

        let mut remaining = String::new();
        output.read_to_string(&mut remaining).expect("read output");
        assert_eq!(remaining, "space and ' quote|raw input value\r\n");
        assert!(process.wait().expect("wait").success());
    }

    #[test]
    fn resize_updates_kernel_terminal_size() {
        let mut process = crate::PtyProcess::spawn(
            &shell("stty -echo; stty size; IFS= read -r ready; stty size"),
            PtySize::new(24, 80),
        )
        .expect("spawn");
        let mut input = process.take_input().expect("PTY input");
        let mut output = BufReader::new(process.take_output().expect("PTY output"));
        let mut line = String::new();
        output.read_line(&mut line).expect("initial size");
        assert_eq!(line, "24 80\r\n");

        process.resize(PtySize::new(43, 132)).expect("resize");
        input.write_all(b"ready\n").expect("release child");
        drop(input);
        line.clear();
        output.read_line(&mut line).expect("resized size");
        assert_eq!(line, "43 132\r\n");
        assert!(process.wait().expect("wait").success());
    }

    #[test]
    fn interrupt_targets_an_interactive_shells_foreground_job() {
        fn wait_for_marker(
            receiver: &mpsc::Receiver<Vec<u8>>,
            pending: &mut Vec<u8>,
            marker: &[u8],
        ) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(position) = pending
                    .windows(marker.len())
                    .position(|window| window == marker)
                {
                    pending.drain(..position + marker.len());
                    return;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(!remaining.is_zero(), "timed out waiting for PTY marker");
                let chunk = receiver
                    .recv_timeout(remaining)
                    .expect("PTY output ended before marker");
                pending.extend_from_slice(&chunk);
            }
        }

        let mut script = tempfile::NamedTempFile::new().expect("temporary foreground script");
        script
            .write_all(
                b"trap 'printf \\\"NRM_CHILD_INTERRUPTED\\n\\\"; exit 42' INT\n\
                  printf 'NRM_CHILD_READY\\n'\n\
                  while :; do sleep 1; done\n",
            )
            .expect("write foreground script");
        script.flush().expect("flush foreground script");

        let mut command = PtyCommand::new("/bin/sh");
        command.arg("-i");
        command.env("PS1", "NRM_PROMPT> ");
        command.env("ENV", "/dev/null");
        let mut process = crate::PtyProcess::spawn(&command, PtySize::default())
            .expect("spawn interactive shell");
        let mut input = process.take_input().expect("PTY input");
        let mut output = process.take_output().expect("PTY output");
        let (sender, receiver) = mpsc::channel();
        let output_worker = std::thread::spawn(move || {
            let mut buffer = [0_u8; 1024];
            loop {
                match output.read(&mut buffer) {
                    Ok(0) | Err(_) => return,
                    Ok(read) if sender.send(buffer[..read].to_vec()).is_err() => return,
                    Ok(_) => {}
                }
            }
        });
        let mut pending = Vec::new();
        wait_for_marker(&receiver, &mut pending, b"NRM_PROMPT> ");
        input.write_all(b"stty -echo\n").expect("disable echo");
        input.flush().expect("flush echo command");
        wait_for_marker(&receiver, &mut pending, b"NRM_PROMPT> ");

        let invocation = format!("/bin/sh '{}'\n", script.path().display());
        input
            .write_all(invocation.as_bytes())
            .expect("start foreground child");
        input.flush().expect("flush foreground command");
        wait_for_marker(&receiver, &mut pending, b"NRM_CHILD_READY");

        process
            .signal(PtySignal::Interrupt)
            .expect("interrupt foreground process group");
        wait_for_marker(&receiver, &mut pending, b"NRM_CHILD_INTERRUPTED");

        process
            .signal(PtySignal::Kill)
            .expect("kill interactive shell");
        drop(input);
        let _ = process.wait().expect("reap interactive shell");
        output_worker.join().expect("join PTY output reader");
    }

    #[test]
    fn dropping_process_kills_its_process_group() {
        let mut process = crate::PtyProcess::spawn(
            &shell("trap 'exit 0' TERM; while :; do sleep 1; done"),
            PtySize::default(),
        )
        .expect("spawn");
        let pid = process.id() as libc::pid_t;
        process
            .signal(PtySignal::Terminate)
            .expect("terminate process group");
        let deadline = Instant::now() + Duration::from_secs(3);
        while process.try_wait().expect("poll").is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(process);

        // SAFETY: Signal zero performs an existence check and does not mutate
        // the (now reaped) child process.
        let result = unsafe { libc::kill(pid, 0) };
        assert_eq!(result, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dropping_reaped_session_leader_kills_background_group() {
        let mut process = crate::PtyProcess::spawn(
            &shell(
                "(trap '' HUP; exec sleep 30) </dev/null >/dev/null 2>&1 & printf '%s\\n' \"$!\"; exit 0",
            ),
            PtySize::default(),
        )
        .expect("spawn leader with background child");
        drop(process.take_input());
        let mut output = BufReader::new(process.take_output().expect("PTY output"));
        let mut child_pid = String::new();
        output
            .read_line(&mut child_pid)
            .expect("read background PID");
        let child_pid: libc::pid_t = child_pid.trim().parse().expect("numeric background PID");
        let process_group = process.id() as libc::pid_t;

        // Give the shell leader time to exit without calling try_wait(), whose
        // documented behavior already cleans the group.
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: Signal zero only checks group existence.
        assert_eq!(unsafe { libc::kill(-process_group, 0) }, 0);
        drop(output);
        drop(process);

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            // SAFETY: Signal zero only checks process existence.
            if unsafe { libc::kill(child_pid, 0) } == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "background descendant survived PTY owner drop"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn piped_process_keeps_raw_streams_separate() {
        let mut process = crate::PipeProcess::spawn(&shell(
            "IFS= read -r line; printf 'out:%s' \"$line\"; printf 'err:%s' \"$line\" >&2",
        ))
        .expect("spawn piped shell");
        let mut input = process.take_input().expect("pipe input");
        input.write_all(b"byte value\n").expect("write pipe input");
        drop(input);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        process
            .take_stdout()
            .expect("stdout")
            .read_to_end(&mut stdout)
            .expect("read stdout");
        process
            .take_stderr()
            .expect("stderr")
            .read_to_end(&mut stderr)
            .expect("read stderr");
        assert_eq!(stdout, b"out:byte value");
        assert_eq!(stderr, b"err:byte value");
        assert!(process.wait().expect("wait").success());
    }
}
