use super::{
    archive::{self, Budget},
    invalid, Request,
};
use crate::error::{ensure, Error, Result};
use std::{
    ffi::{CStr, OsStr},
    fs::{File, Metadata},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

fn reopen(directory: &File) -> Result<File> {
    // SAFETY: directory remains open; openat returns an independent descriptor.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd is newly owned and transferred once.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}
struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: fdopendir transferred one owned stream to this guard.
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn names(directory: &File, budget: &mut Budget<'_>) -> Result<Vec<String>> {
    let fd = reopen(directory)?;
    // SAFETY: fd is valid. Ownership transfers only on successful fdopendir.
    let stream = unsafe { libc::fdopendir(fd.as_raw_fd()) };
    if stream.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    std::mem::forget(fd);
    let stream = Directory(stream);
    let mut names = Vec::new();
    loop {
        // SAFETY: this thread owns the directory stream; errno distinguishes EOF.
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        // SAFETY: readdir's name is terminated and valid until the next call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        budget.entry()?;
        let name = std::str::from_utf8(name).map_err(|_| invalid("Non-UTF-8 storage entry"))?;
        ensure!(archive::path(name)?.len() == 1, "Invalid storage entry");
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}
fn walk<W: Write>(
    file: &File,
    path: &str,
    device: u64,
    budget: &mut Budget<'_>,
    tar: &mut tar::Builder<W>,
) -> Result<()> {
    archive::path(path)?;
    let before = file.metadata()?;
    ensure!(
        before.dev() == device && (before.is_dir() || before.is_file()),
        "Export crossed a mount or found a special file"
    );
    if before.is_dir() {
        tar.append(&archive::header(path, true, 0)?, std::io::empty())?;
        for name in names(file, budget)? {
            let child = crate::files::open_entry(file, OsStr::new(&name))?;
            walk(&child, &format!("{path}/{name}"), device, budget, tar)?;
        }
    } else {
        ensure!(before.nlink() == 1, "Export refuses hard-linked files");
        budget.content(before.len())?;
        tar.append(&archive::header(path, false, before.len())?, file)?;
    }
    ensure!(
        unchanged(&before, &file.metadata()?),
        "Storage changed during export"
    );
    Ok(())
}
pub(super) fn snapshot(request: &Request, roots: &[File; 3], output: impl Write) -> Result<()> {
    request.validate()?;
    let guard = reopen(&roots[0])?;
    // SAFETY: the independent control descriptor lives through snapshot finish.
    if unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let lifecycle = crate::files::open_child(&roots[0], OsStr::new(".lifecycle"), true)?;
    match crate::files::open_child(&lifecycle, OsStr::new("open"), true) {
        Err(Error::PathIo { source, .. }) if source.raw_os_error() == Some(libc::ENOENT) => (),
        Err(error) => return Err(error),
        Ok(_) => return Err(invalid("Broker must be sealed before export")),
    }
    let mut tar = tar::Builder::new(output);
    let manifest = serde_json::to_vec(request)?;
    tar.append(
        &archive::header(archive::MANIFEST, false, manifest.len() as u64)?,
        manifest.as_slice(),
    )?;
    let limits = [
        &request.profile.control,
        &request.profile.artifacts,
        &request.profile.incoming,
    ];
    for ((root, name), limits) in roots.iter().zip(archive::AREAS).zip(limits) {
        let mut budget = Budget::new(limits);
        budget.entry()?;
        walk(root, name, root.metadata()?.dev(), &mut budget, &mut tar)?;
    }
    tar.finish()?;
    tar.into_inner()?.flush()?;
    Ok(())
}
