use super::invalid;
use crate::{
    error::{ensure, Result},
    files,
    state::StateLock,
    storage::export,
};
use std::{
    ffi::OsStr,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

fn regular(file: &File, limit: u64) -> Result<()> {
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o600
            && metadata.len() <= limit,
        "Broker archive must be a private bounded regular file with one link"
    );
    Ok(())
}
pub(super) fn scratch(lock: &StateLock, limit: u64) -> Result<File> {
    lock.verify_directory()?;
    let directory = files::open_directory(&lock.directory)?;
    // No truncation until caller has durably recorded the attempt against the
    // verified original sealed source. O_NONBLOCK avoids substituted FIFO waits.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"export.partial".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the successful openat descriptor transfers ownership once.
    let file = unsafe { File::from_raw_fd(fd) };
    regular(&file, limit)?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: directory is live and stat is writable for fstatvfs.
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut stat) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let available = u128::from(stat.f_bavail) * u128::from(stat.f_frsize)
        + u128::from(file.metadata()?.blocks()) * 512;
    ensure!(
        available >= u128::from(limit) + 65536,
        "Insufficient host space for bounded broker export"
    );
    lock.verify_directory()?;
    Ok(file)
}
pub(super) fn verify(lock: &StateLock, name: &str, receipt: &export::Receipt) -> Result<()> {
    lock.verify_directory()?;
    let directory = files::open_directory(&lock.directory)?;
    let file = files::open_child(&directory, OsStr::new(name), false)?;
    regular(&file, receipt.request.max_bytes()?)?;
    ensure!(
        export::verify(&receipt.request, file)? == *receipt,
        "Retained broker archive differs from its receipt"
    );
    lock.verify_directory()
}
pub(super) fn publish(lock: &StateLock, receipt: &export::Receipt) -> Result<()> {
    let destination = lock.directory.join("export.tar");
    match std::fs::symlink_metadata(&destination) {
        Ok(_) => verify(lock, "export.tar", receipt)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            verify(lock, "export.partial", receipt)?;
            let directory = files::open_directory(&lock.directory)?;
            // SAFETY: both paths are fixed names relative to the owned live dirfd.
            if unsafe {
                libc::renameat2(
                    directory.as_raw_fd(),
                    c"export.partial".as_ptr(),
                    directory.as_raw_fd(),
                    c"export.tar".as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    files::open_directory(&lock.directory)?.sync_all()?;
    lock.verify_directory()
}
