//! Host-owned state locks. Kernel-held session leases survive neither exit nor crashes.
use crate::{
    error::{ensure, Error, Result},
    files,
};
use serde_json::Value;
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};
pub struct StateLock {
    _file: File,
    directory_file: File,
    pub directory: PathBuf,
}
pub struct SessionLock {
    directory_file: File,
    _file: File,
}
impl Drop for StateLock {
    fn drop(&mut self) {
        // A concurrently forked child may retain this open-file description
        // until exec. Release our ownership now; close remains the fallback.
        let _ = self._file.unlock();
    }
}
impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}
pub fn create_directory(path: &Path) -> Result<()> {
    let path = files::absolute(path)?;
    let mut parent = files::open_directory_path(Path::new("/"))?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                match files::open_directory_child_path(&parent, name) {
                    Ok(child) => {
                        parent = child;
                        continue;
                    }
                    Err(error) if not_found(&error) => (),
                    Err(error) => return Err(error),
                }
                let c = CString::new(name.as_bytes())?;
                // SAFETY: parent owns the fd, and c lives throughout mkdirat.
                if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(e.into());
                    }
                }
                parent = files::open_directory_child_path(&parent, name)?;
            }
            _ => {
                return Err(Error::InvalidPath {
                    path: path.clone(),
                    reason: "State path is not normalized",
                })
            }
        }
    }
    let meta = parent.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
        "State directory must be owned by the current user, without group/other write access"
    );
    Ok(())
}
fn lock_file_at(parent: &File, directory: &Path, name: &str, exclusive: bool) -> Result<File> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1,
        "Lock file is not regular or is shared"
    );
    // SAFETY: file owns a valid descriptor; the lock is released by closing it.
    let result = unsafe {
        libc::flock(
            file.as_raw_fd(),
            libc::LOCK_NB
                | if exclusive {
                    libc::LOCK_EX
                } else {
                    libc::LOCK_SH
                },
        )
    };
    if result < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()).context(format!("State {} is busy ({name}); wait for the operation/session to finish, do not delete the lock",directory.display())));
    }
    Ok(file)
}
impl StateLock {
    /// Lock an existing state without recreating a vanished directory.
    pub fn acquire_existing(directory: &Path) -> Result<Self> {
        let parent = files::open_directory(directory)?;
        let meta = parent.metadata()?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
            "State directory must be owned by the current user, without group/other write access"
        );
        let lock = Self {
            _file: lock_file_at(&parent, directory, ".lock", true)?,
            directory_file: parent,
            directory: files::absolute(directory)?,
        };
        lock.verify_directory()?;
        Ok(lock)
    }
    pub fn acquire(directory: &Path) -> Result<Self> {
        create_directory(directory)?;
        Self::acquire_existing(directory)
    }
    /// Recheck the named directory at external-operation boundaries. The lock
    /// remains attached to the original descriptor if another process renames it.
    pub fn verify_directory(&self) -> Result<()> {
        let current = files::open_directory(&self.directory)?.metadata()?;
        let pinned = self.directory_file.metadata()?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            current.dev() == pinned.dev()
                && current.ino() == pinned.ino()
                && current.uid() == unsafe { libc::geteuid() }
                && current.mode() & 0o022 == 0,
            "State directory replaced or permissions changed during the operation"
        );
        Ok(())
    }
}
impl SessionLock {
    pub fn acquire(directory: &Path, exclusive: bool) -> Result<Self> {
        let dir = files::open_directory(directory)?;
        let lease = Self::lock_directory(dir, directory, exclusive)?;
        crate::execution::fence::available(lease.directory_file())?;
        Ok(lease)
    }
    fn lock_directory(dir: File, path: &Path, exclusive: bool) -> Result<Self> {
        Ok(Self {
            _file: lock_file_at(&dir, path, ".sessions", exclusive)?,
            directory_file: dir,
        })
    }
    pub(crate) fn directory_file(&self) -> &File {
        &self.directory_file
    }
    /// Only a matching original receipt may cross an installed execution fence.
    pub(crate) fn for_reconciliation(
        lock: &StateLock,
        fence: &crate::execution::fence::Fence,
    ) -> Result<(Self, bool)> {
        lock.verify_directory()?;
        let lease = Self::lock_directory(lock.directory_file.try_clone()?, &lock.directory, true)?;
        let present = fence.matches_or_absent(lease.directory_file())?;
        Ok((lease, present))
    }
}
fn not_found(error: &Error) -> bool {
    match error {
        Error::Io(e) | Error::PathIo { source: e, .. } => e.kind() == std::io::ErrorKind::NotFound,
        Error::Context { source, .. } => not_found(source),
        _ => false,
    }
}
pub fn read(path: &Path) -> Result<Option<Value>> {
    match files::read_limited(path, 16 * 1024 * 1024) {
        Ok(bytes) => Ok(Some(crate::json::parse(&bytes)?)),
        Err(e) if not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}
pub fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid(format!("Required field: {field}")))
}
pub fn load(directory: &Path) -> Result<Option<Value>> {
    let state = read(&directory.join("state.json"))?;
    if let Some(value) = &state {
        validate(value)?;
    }
    Ok(state)
}
pub(crate) fn validate(value: &Value) -> Result<()> {
    ensure!(
        value["schema_version"] == 2,
        "Incompatible state format: use migrate-state to a new directory"
    );
    for field in [
        "sandbox_name",
        "sandbox_id",
        "policy_hash",
        "codex_binary",
        "owner",
        "desired_hash",
        "image_id",
        "project_snapshot",
        "build_dir",
    ] {
        text(value, field)?;
    }
    ensure!(
        value["context"]["gateway"].is_string() && value["context"]["workspace"].is_string(),
        "Missing state context"
    );
    Ok(())
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

#[cfg(test)]
mod inherited_lock_tests {
    use super::*;
    #[test]
    fn existing_lock_never_recreates_a_missing_state_directory() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("vanished");
        assert!(StateLock::acquire_existing(&directory).is_err());
        assert!(!directory.exists());
        Ok(())
    }
    // dup and fork retain the same open-file description. Keep that description
    // alive to model a concurrent spawned child before its CLOEXEC descriptors close.
    #[test]
    fn dropped_controller_releases_lock_even_with_inherited_description() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("state");
        let lock = StateLock::acquire(&directory)?;
        let inherited = lock._file.try_clone()?;
        drop(lock);
        let acquired = StateLock::acquire(&directory);
        drop(inherited);
        assert!(
            acquired.is_ok(),
            "A finished controller must release its own flock immediately"
        );
        Ok(())
    }
    #[test]
    fn inherited_session_does_not_outlive_owner_or_release_another_session() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("state");
        create_directory(&directory)?;
        let first = SessionLock::acquire(&directory, false)?;
        let inherited = first._file.try_clone()?;
        let second = SessionLock::acquire(&directory, false)?;
        drop(first);
        assert!(SessionLock::acquire(&directory, true).is_err());
        drop(second);
        let acquired = SessionLock::acquire(&directory, true);
        drop(inherited);
        assert!(
            acquired.is_ok(),
            "Inherited pre-exec descriptors must not retain finished sessions"
        );
        Ok(())
    }
}
