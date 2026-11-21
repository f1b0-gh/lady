//! Bounded process helpers retaining Ladyshell's typed application errors.
use crate::error::Result;
use std::{process::Command, time::Duration};
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
