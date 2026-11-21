use super::{invalid, model::VerifiedRun, report};
use crate::{error::Result, files};
use serde_json::{json, Value};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
};

/// Export the retained, verified bytes. No second reads from attacker-controlled paths.
pub fn export(run: &VerifiedRun, destination: &Path) -> Result<Value> {
    let destination = files::absolute(destination)?;
    let parent = files::open_directory(
        destination
            .parent()
            .ok_or_else(|| invalid("Parent absent"))?,
    )?;
    let name = destination
        .file_name()
        .ok_or_else(|| invalid("Destination absente"))?;
    let target = CString::new(name.as_bytes())?;
    let anchored = std::path::PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
    let staging = tempfile::Builder::new()
        .prefix(".audit-export-")
        .tempdir_in(&anchored)?;
    for (path, bytes) in &run.files {
        write_new(staging.path(), path, bytes)?;
    }
    write_new(staging.path(), "REPORT.md", report::render(run).as_bytes())?;
    File::open(staging.path())?.sync_all()?;
    let stage = CString::new(
        staging
            .path()
            .file_name()
            .ok_or_else(|| invalid("Staging absent"))?
            .as_bytes(),
    )?;
    // SAFETY: parent owns both directory references; names are valid NUL-terminated
    // single components. RENAME_NOREPLACE prevents overwriting even on a race.
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            stage.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    parent.sync_all()?;
    // TempDir's old name no longer exists. Its drop cannot delete the published path.
    Ok(
        json!({"schema_version":1,"operation":"export","destination":destination,"applied_to_project":false}),
    )
}

fn write_new(root: &Path, path: &str, bytes: &[u8]) -> Result<()> {
    crate::config::relative_path(path)?;
    let target = root.join(path);
    let parent = target.parent().ok_or_else(|| invalid("Parent absent"))?;
    // The private staging tree contains only directories created here, never received links.
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&target)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let mut current = Some(parent);
    while let Some(directory) = current {
        File::open(directory)?.sync_all()?;
        if directory == root {
            break;
        }
        current = directory.parent();
    }
    Ok(())
}
