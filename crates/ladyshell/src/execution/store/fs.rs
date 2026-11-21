//! Linux descriptor-relative filesystem operations. Only fixed names and validated
//! SHA-256 strings reach this layer; caller IDs never become path components.
use super::super::invalid;
use crate::{
    error::{ensure, Result},
    files,
};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub(in crate::execution) fn anchored(f: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd()))
}
pub(in crate::execution) fn same(a: &File, b: &File) -> Result<()> {
    let a = a.metadata()?;
    let b = b.metadata()?;
    ensure!(
        a.dev() == b.dev() && a.ino() == b.ino(),
        "Retained directory identity changed"
    );
    Ok(())
}
pub(in crate::execution) fn trusted(dir: &File, private: bool) -> Result<()> {
    let m = dir.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        m.uid() == unsafe { libc::geteuid() }
            && m.is_dir()
            && if private {
                m.mode() & 0o7777 == 0o700
            } else {
                m.mode() & 0o022 == 0
            },
        "Unsafe retained directory ownership or mode"
    );
    Ok(())
}
pub(super) fn child(parent: &File, name: &OsStr) -> Result<File> {
    let f = files::open_child(parent, name, true)?;
    trusted(&f, true)?;
    Ok(f)
}
pub(super) fn mkdir(parent: &File, name: &OsStr) -> Result<File> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(anchored(parent).join(name))?;
    // O_PATH pins even a directory created with all owner bits masked.
    let pin = files::open_directory_child_path(parent, name)?;
    let dir = finish_private_directory(parent, name, &pin)?;
    parent.sync_all()?;
    Ok(dir)
}

/// Complete the private mode on a newly created or interrupted directory.
/// O_PATH plus /proc/self/fd applies chmod to the pinned inode even at 0000.
pub(super) fn finish_private_directory(parent: &File, name: &OsStr, pin: &File) -> Result<File> {
    same(pin, &files::open_directory_child_path(parent, name)?)?;
    fs::set_permissions(anchored(pin), fs::Permissions::from_mode(0o700))?;
    let dir = child(parent, name)?;
    same(pin, &dir)?;
    dir.sync_all()?;
    Ok(dir)
}
pub(super) fn regular(dir: &File, name: &str) -> Result<File> {
    let f = files::open_child(dir, name.as_ref(), false)?;
    private_file(&f)?;
    Ok(f)
}
fn private_file(f: &File) -> Result<()> {
    let m = f.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1,
        "Unsafe retained file ownership, sharing or mode"
    );
    Ok(())
}
pub(in crate::execution) fn bytes(dir: &File, name: &str, limit: usize) -> Result<Vec<u8>> {
    files::read_file(regular(dir, name)?, limit)
}
pub(in crate::execution) fn exists(dir: &File, name: &str) -> Result<bool> {
    match fs::symlink_metadata(anchored(dir).join(name)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
/// A dead writer may have completed rename before its containing-directory
/// fsync. Readers establish that barrier before acknowledging the visible name.
pub(super) fn observation_barrier(dir: &File) -> Result<()> {
    #[cfg(test)]
    super::super::store_tests::observation_fault(dir)?;
    dir.sync_all()?;
    Ok(())
}

// Stage names are reserved implementation slots in a private directory. O_PATH
// permits inspection without following a link, opening a device or requiring
// owner read bits if a process died between open(O_CREAT) and fchmod.
pub(super) fn stage(dir: &File, name: &str, limit: usize) -> Result<Option<File>> {
    let path = anchored(dir).join(name);
    let pin = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let m = pin.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.nlink() == 1
            && m.mode() & 0o7177 == 0
            && m.len() <= limit as u64,
        "Unsafe or oversized retained staging file"
    );
    Ok(Some(pin))
}

pub(in crate::execution) enum Publication {
    Immutable,
    StateFence { limit: usize },
    ReplaceLedger,
    Recover,
}
pub(in crate::execution) fn publish(
    dir: &File,
    name: &str,
    bytes: &[u8],
    kind: Publication,
) -> Result<()> {
    let parent = anchored(dir);
    let path = parent.join(name);
    let slot = match kind {
        Publication::Recover => ".recovery.pending".to_owned(),
        _ => format!(".{name}.pending"),
    };
    let reusable = match kind {
        Publication::Immutable => None,
        Publication::StateFence { limit } => Some(limit),
        Publication::ReplaceLedger => {
            regular(dir, name)?;
            Some(super::ledger::INDEX_LIMIT)
        }
        Publication::Recover => {
            // An abandoned worker receipt can contain the only copy of its
            // client observation. Preserve it; administrative recovery writes
            // a separate slot whose only payload is our uncertainty decision.
            stage(
                dir,
                ".receipt.json.pending",
                super::ledger::RECEIPT_LIMIT / 2,
            )?;
            Some(super::ledger::RECEIPT_LIMIT / 2)
        }
    };
    if let Some(limit) = reusable {
        ensure!(
            bytes.len() <= limit,
            "Retained publication exceeds its reserved slot"
        );
        if let Some(old) = stage(dir, &slot, limit)? {
            let named = fs::symlink_metadata(parent.join(&slot))?;
            let pinned = old.metadata()?;
            ensure!(
                named.dev() == pinned.dev() && named.ino() == pinned.ino(),
                "Staging file replaced"
            );
            // Only an uncommitted ledger, recovery draft or unpublished
            // environment fence uses a reusable slot. Their owning lock is
            // held. A worker receipt is never discarded here.
            fs::remove_file(parent.join(&slot))?;
        }
    }
    let mut tmp = tempfile::Builder::new()
        .prefix(&slot)
        .rand_bytes(0)
        .tempfile_in(&parent)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    private_file(tmp.as_file())?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    if matches!(kind, Publication::ReplaceLedger) {
        regular(dir, name)?;
        tmp.persist(&path)
    } else {
        tmp.persist_noclobber(&path)
    }
    .map_err(|e| e.error)?;
    dir.sync_all()?;
    Ok(())
}
// Each caller passes a newly opened file description (never a dup of its
// pinned fd). Close releases this participant's flock, including on crash.
pub(super) fn lock(dir: &File, nonblocking: bool) -> Result<bool> {
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    loop {
        // SAFETY: dir owns the live fd; flock borrows it for this call.
        if unsafe { libc::flock(dir.as_raw_fd(), flags) } == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        match e.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock if nonblocking => return Ok(false),
            _ => return Err(e.into()),
        }
    }
}
pub(super) struct Root {
    pub path: PathBuf,
    pub parent: File,
    pub dir: File,
}
impl Root {
    pub fn load(path: &Path, create: bool) -> Result<Self> {
        let path = files::absolute(path)?;
        super::super::model::normalized(&path)?;
        let parent = files::open_directory(
            path.parent()
                .ok_or_else(|| invalid("Receiver needs a parent"))?,
        )?;
        trusted(&parent, false)?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("Missing receiver name"))?;
        let dir = if create {
            mkdir(&parent, name)?
        } else {
            child(&parent, name)?
        };
        let root = Self { path, parent, dir };
        root.verify()?;
        Ok(root)
    }
    pub fn verify(&self) -> Result<File> {
        let current = files::open_directory(
            self.path
                .parent()
                .ok_or_else(|| invalid("Missing receiver parent"))?,
        )?;
        trusted(&current, false)?;
        same(&current, &self.parent)?;
        let dir = child(
            &current,
            self.path
                .file_name()
                .ok_or_else(|| invalid("Missing receiver name"))?,
        )?;
        same(&dir, &self.dir)?;
        Ok(dir)
    }
}
