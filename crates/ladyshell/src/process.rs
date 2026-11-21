//! Bounded process helpers retaining Ladyshell's typed application errors.
use crate::error::Result;
use std::{io, os::unix::process::CommandExt, process::Command, time::Duration};
pub fn capture(command: Command, timeout: Duration, limit: usize) -> Result<Vec<u8>> {
    nickel_util::process::capture(command, timeout, limit).map_err(Into::into)
}
pub fn capture_input(
    command: Command,
    input: &[u8],
    timeout: Duration,
    limit: usize,
) -> Result<Vec<u8>> {
    nickel_util::process::capture_input(command, input, timeout, limit).map_err(Into::into)
}

/// Start the command in a new Unix session and prevent inheritance of extra FDs.
pub fn detached_session(command: &mut Command) {
    // SAFETY: The hook only invokes kernel operations and reads errno on failure.
    // Marking descriptors CLOEXEC preserves the spawn error channel until exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0
                || libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
