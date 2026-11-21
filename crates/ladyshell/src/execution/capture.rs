//! Local OpenShell client supervision. An escaped pipe writer cannot hold a receipt open.
use super::{CapturedOutputs, CapturedStream, ClientResult};
use std::{
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::process::{CommandExt, ExitStatusExt},
    },
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const EXIT_DRAIN: Duration = Duration::from_millis(100);

fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: the pipe owns this descriptor for both fcntl calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Pipe<R> {
    reader: Option<R>,
    output: CapturedStream,
}
impl<R: Read> Pipe<R> {
    // One bounded read per stream per round, even when the writer never yields.
    fn drain(&mut self, limit: usize) -> io::Result<bool> {
        let Some(reader) = self.reader.as_mut() else {
            return Ok(false);
        };
        let mut buf = [0u8; 8192];
        match reader.read(&mut buf) {
            Ok(0) => {
                self.reader = None;
                Ok(false)
            }
            Ok(n) => {
                let keep = n.min(limit - self.output.bytes.len());
                self.output.bytes.extend_from_slice(&buf[..keep]);
                self.output.truncated |= keep < n;
                Ok(true)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(e) => {
                self.reader = None;
                self.output.truncated = true;
                Err(e)
            }
        }
    }
    fn finish(mut self) -> CapturedStream {
        self.output.truncated |= self.reader.is_some();
        self.output
    }
}
/// Observe without reaping: the group leader reserves its numeric PID through
/// the final drain, including when its descendants overflow after client exit.
fn exited(child: &Child) -> io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: waitid initializes info or leaves the zero PID when no exit is ready.
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
fn terminate(child: &mut Child) -> io::Result<ExitStatus> {
    // Called only before wait has reaped this owned group leader. Its
    // unreaped PID reserves the PGID. Never signal a remembered numeric ID after wait.
    // SAFETY: process_group(0) created this child's private group on spawn.
    unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
    // Also covers a leader that changed its group membership.
    let _ = child.kill();
    child.wait()
}
fn observation(status: ExitStatus) -> ClientResult {
    if let Some(code) = status.code() {
        ClientResult::Exit { code }
    } else if let Some(signal) = status.signal() {
        ClientResult::Signal { signal }
    } else {
        ClientResult::IoFailure
    }
}
pub(super) fn run(
    mut command: Command,
    timeout: Duration,
    limit: usize,
) -> (ClientResult, CapturedOutputs) {
    let deadline = Instant::now() + timeout;
    let Ok(mut child) = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
    else {
        return (ClientResult::SpawnFailure, CapturedOutputs::default());
    };
    let mut stdout = Pipe {
        reader: child.stdout.take(),
        output: CapturedStream::default(),
    };
    let mut stderr = Pipe {
        reader: child.stderr.take(),
        output: CapturedStream::default(),
    };
    if !stdout
        .reader
        .as_ref()
        .is_some_and(|p| nonblocking(p).is_ok())
        || !stderr
            .reader
            .as_ref()
            .is_some_and(|p| nonblocking(p).is_ok())
    {
        let _ = terminate(&mut child);
        return (
            ClientResult::IoFailure,
            CapturedOutputs {
                stdout: stdout.finish(),
                stderr: stderr.finish(),
            },
        );
    }
    let mut reaped = None;
    let mut drain_until = None;
    let mut failure = None;
    loop {
        let a = stdout.drain(limit);
        let b = stderr.drain(limit);
        let progress = matches!(a, Ok(true)) || matches!(b, Ok(true));
        if a.is_err() || b.is_err() {
            failure.get_or_insert(ClientResult::IoFailure);
        } else if stdout.output.truncated || stderr.output.truncated {
            failure.get_or_insert(ClientResult::OutputLimit);
        }
        let at = Instant::now();
        if reaped.is_none() {
            let done = match exited(&child) {
                Ok(done) => done,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => false,
                // A competing reaper invalidates ownership. Do not signal a remembered PID.
                Err(_) => {
                    failure.get_or_insert(ClientResult::IoFailure);
                    break;
                }
            };
            if done {
                drain_until.get_or_insert(at + EXIT_DRAIN);
            } else if at >= deadline {
                failure.get_or_insert(ClientResult::Timeout);
            }
            if failure.is_some() {
                reaped = Some(
                    terminate(&mut child)
                        .map(observation)
                        .unwrap_or(ClientResult::IoFailure),
                );
                drain_until.get_or_insert(at + EXIT_DRAIN);
            }
        }
        if let Some(end) = drain_until {
            if (stdout.reader.is_none() && stderr.reader.is_none()) || at >= end {
                if reaped.is_none() {
                    reaped = Some(
                        child
                            .wait()
                            .map(observation)
                            .unwrap_or(ClientResult::IoFailure),
                    );
                }
                break;
            }
        }
        if !progress {
            thread::sleep(Duration::from_millis(2));
        }
    }
    (
        failure.or(reaped).unwrap_or(ClientResult::IoFailure),
        CapturedOutputs {
            stdout: stdout.finish(),
            stderr: stderr.finish(),
        },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn shell(script: &str, millis: u64, limit: usize) -> (ClientResult, CapturedOutputs) {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        run(command, Duration::from_millis(millis), limit)
    }
    #[test]
    fn preserves_both_streams_and_client_exit() {
        let (r, o) = shell("printf out; printf err >&2; exit 23", 3000, 3);
        assert_eq!(r, ClientResult::Exit { code: 23 });
        assert_eq!(o.stdout.bytes, b"out");
        assert_eq!(o.stderr.bytes, b"err");
        assert!(!o.stdout.truncated && !o.stderr.truncated);
    }
    #[test]
    fn distinguishes_signal_and_failed_spawn() {
        assert_eq!(
            shell("kill -TERM $$", 1000, 5).0,
            ClientResult::Signal {
                signal: libc::SIGTERM
            }
        );
        assert_eq!(
            run(
                Command::new("/no-such-retained-program"),
                Duration::from_secs(1),
                8
            )
            .0,
            ClientResult::SpawnFailure
        );
    }
    #[test]
    fn deadline_keeps_partial_bytes_and_reaps_client() {
        let (r, o) = shell("printf out; printf err >&2; exec sleep 10", 350, 1024);
        assert_eq!(r, ClientResult::Timeout);
        assert_eq!(o.stdout.bytes, b"out");
        assert_eq!(o.stderr.bytes, b"err");
    }
    #[test]
    fn flood_cannot_starve_stderr_or_overrun_budget() {
        let (r, o) = shell("printf seen >&2; exec yes flood", 2000, 4096);
        assert_eq!(r, ClientResult::OutputLimit);
        assert_eq!(o.stdout.bytes.len(), 4096);
        assert!(o.stdout.truncated);
        assert_eq!(o.stderr.bytes, b"seen");
    }
    #[test]
    fn escaped_pipe_writer_cannot_hold_client_receipt() {
        let start = Instant::now();
        let (r, o) = shell("printf ok; setsid sleep 2 & exit 0", 5000, 16);
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(r, ClientResult::Exit { code: 0 });
        assert_eq!(o.stdout.bytes, b"ok");
        assert!(o.stdout.truncated && o.stderr.truncated);
    }

    #[test]
    fn overflow_after_client_exit_kills_only_its_still_owned_group() -> crate::error::Result<()> {
        let tmp = tempfile::tempdir()?;
        let lock = tmp.path().join("lock");
        let mut cmd = Command::new("sh");
        // The writer waits for its parent to exit before overflowing, then retains
        // a flock. The group leader must still reserve the PGID during that drain.
        cmd.args(["-c",r#"parent=$$
            ( exec 9>"$1"
              flock -x 9 || exit 1
              while test -r "/proc/$parent/stat" && ! grep -q ') Z ' "/proc/$parent/stat"; do :; done
              printf excess
              exec sleep 2 ) &
            exit 0"#,"sh"]).arg(&lock);
        let (r, _) = run(cmd, Duration::from_secs(3), 1);
        assert_eq!(r, ClientResult::OutputLimit);
        let file = std::fs::File::open(lock)?;
        assert!(
            file.try_lock().is_ok(),
            "Surviving overflow writer retains group resources"
        );
        Ok(())
    }
}
