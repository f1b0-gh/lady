//! Streaming capture for archives that cannot fit the bounded in-memory helper.
use crate::error::{ensure, Error, Result};
use std::{
    fs::File,
    io::{self, Read, Seek, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    // SAFETY: pipe retains ownership throughout both fcntl calls.
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn exited(child: &Child) -> io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: waitid initializes this storage without reaping the owned child.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init().si_pid() } != 0)
}
struct Owned(Option<Child>);
impl Owned {
    fn finish(&mut self) -> io::Result<std::process::ExitStatus> {
        let mut child = self
            .0
            .take()
            .ok_or_else(|| io::Error::other("Client already reaped"))?;
        // A competing reaper invalidates PID ownership. Never signal afterwards.
        exited(&child)?;
        // SAFETY: this owned, unreaped leader reserves its private process group.
        unsafe {
            libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = child.kill();
        child.wait()
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if self.0.is_some() {
            let _ = self.finish();
        }
    }
}
struct Pipe<R> {
    reader: R,
    eof: bool,
    bytes: u64,
}
impl<R: Read> Pipe<R> {
    fn drain(&mut self, output: &mut impl Write, limit: u64) -> Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let mut bytes = [0; 8192];
        match self.reader.read(&mut bytes) {
            Ok(0) => {
                self.eof = true;
                Ok(false)
            }
            Ok(n) => {
                ensure!(
                    n as u64 <= limit.saturating_sub(self.bytes),
                    "Streaming process output exceeds limit {limit}"
                );
                output.write_all(&bytes[..n])?;
                self.bytes += n as u64;
                Ok(true)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Stream stdout to a fresh private file with bounded stderr and a transport
/// deadline. Caller retains partial output on failure and validates its format
/// only after successful exit. This supervises the local client, not remote work;
/// it neither publishes/fsyncs the file nor proves remote task retirement.
/// Local filesystem writes remain subject to the host's I/O scheduling.
pub fn capture_to_file(
    mut command: Command,
    input: &[u8],
    output: &mut File,
    limit: u64,
    timeout: Duration,
) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let metadata = output.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() <= 1
            && metadata.len() == 0
            && output.stream_position()? == 0
            && limit > 0
            && !timeout.is_zero()
            && input.len() <= 16384,
        "Streaming capture requires fresh output and bounded input"
    );
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid("Invalid stream deadline".into()))?;
    let mut request = tempfile::tempfile()?;
    request.write_all(input)?;
    request.rewind()?;
    let program = command.get_program().to_os_string();
    let mut child = Owned(Some(
        command
            .stdin(Stdio::from(request))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|source| Error::ProcessSpawn {
                program: program.clone(),
                source,
            })?,
    ));
    let process = child
        .0
        .as_mut()
        .ok_or_else(|| invalid("Missing streaming client".into()))?;
    let mut stdout = Pipe {
        reader: process.stdout.take().ok_or_else(|| Error::MissingPipe {
            program: program.clone(),
            stream: "stdout",
        })?,
        eof: false,
        bytes: 0,
    };
    let mut stderr = Pipe {
        reader: process.stderr.take().ok_or_else(|| Error::MissingPipe {
            program: program.clone(),
            stream: "stderr",
        })?,
        eof: false,
        bytes: 0,
    };
    nonblocking(&stdout.reader)?;
    nonblocking(&stderr.reader)?;
    let mut diagnostics = Vec::new();
    let mut drain_until = None;
    loop {
        let out = stdout.drain(output, limit)?;
        let err = stderr.drain(&mut diagnostics, 16384)?;
        let now = Instant::now();
        let done = match exited(process) {
            Ok(done) => done,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => false,
            Err(error) => return Err(error.into()),
        };
        if done {
            if stdout.eof && stderr.eof {
                break;
            }
            let end = drain_until.get_or_insert(now + Duration::from_millis(100));
            ensure!(now < *end, "Client exited with incomplete output pipes");
        }
        if now >= deadline {
            return Err(Error::ProcessTimeout { program, timeout });
        }
        if !out && !err {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let status = child.finish()?;
    if !status.success() {
        return Err(Error::ProcessExit {
            program,
            status,
            stderr: String::from_utf8_lossy(&diagnostics).into_owned(),
        });
    }
    Ok(stdout.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use std::{
        io::{Read, Seek},
        process::Command,
        time::Duration,
    };
    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }
    #[test]
    fn streams_exact_input_and_output_to_a_file() -> Result<()> {
        let mut file = tempfile::tempfile()?;
        let input = vec![b'z'; 16384];
        capture_to_file(
            shell("head -c 131072 /dev/zero; cat; printf diagnostic >&2"),
            &input,
            &mut file,
            147456,
            Duration::from_secs(3),
        )?;
        file.rewind()?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        assert_eq!(&bytes[..131072], vec![0; 131072]);
        assert_eq!(&bytes[131072..], input);
        Ok(())
    }
    #[test]
    fn rejects_nonzero_exit_oversize_and_pipes_held_after_exit() -> Result<()> {
        for script in [
            "printf partial; exit 3",
            "head -c 65537 /dev/zero",
            "sleep 20 & exit 0",
        ] {
            let mut file = tempfile::tempfile()?;
            let before = std::time::Instant::now();
            assert!(
                capture_to_file(
                    shell(script),
                    b"",
                    &mut file,
                    65536,
                    Duration::from_millis(200)
                )
                .is_err(),
                "{script}"
            );
            assert!(before.elapsed() < Duration::from_secs(3));
            assert!(file.metadata()?.len() <= 65536);
        }
        Ok(())
    }
    #[test]
    fn continuous_streams_cannot_starve_deadline_or_stderr_budget() -> Result<()> {
        for script in ["exec yes", "exec yes >&2"] {
            let mut file = tempfile::tempfile()?;
            let before = std::time::Instant::now();
            assert!(capture_to_file(
                shell(script),
                b"",
                &mut file,
                1048576,
                Duration::from_millis(100)
            )
            .is_err());
            assert!(before.elapsed() < Duration::from_secs(3));
        }
        Ok(())
    }
}
