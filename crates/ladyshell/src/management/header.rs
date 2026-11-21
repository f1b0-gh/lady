//! Inspect the SQLite-owned descriptor before any SQL can recover journals or
//! open WAL sidecars. A separate std::fs descriptor is unsafe here: closing it
//! would drop POSIX locks held by other SQLite connections in this process.
use crate::error::{ensure, Error, Result};
use rusqlite::{ffi, Connection};

pub(super) fn validate(connection: &mut Connection, create: bool) -> Result<()> {
    let mut file: *mut ffi::sqlite3_file = std::ptr::null_mut();
    // SAFETY: exclusive borrow of the live connection; the C API writes one
    // sqlite3_file pointer into our correctly aligned output. "main" is static.
    check(unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_FILE_POINTER,
            std::ptr::from_mut(&mut file).cast(),
        )
    })?;
    ensure!(!file.is_null(), "Missing SQLite file handle");
    // SAFETY: SQLITE_FCNTL_FILE_POINTER succeeded; this pointer and its method
    // table remain owned by the borrowed connection. We never close/free them.
    let methods = unsafe { (*file).pMethods };
    ensure!(!methods.is_null(), "Missing SQLite file handle methods");
    // SAFETY: valid method table for the live file, checked above.
    let (size_fn, read_fn) = unsafe { ((*methods).xFileSize, (*methods).xRead) };
    let size_fn = size_fn.ok_or_else(|| invalid("SQLite size reading is unavailable".into()))?;
    let read_fn = read_fn.ok_or_else(|| invalid("SQLite header reading is unavailable".into()))?;
    let mut size = 0;
    // SAFETY: live SQLite-owned file and valid writable i64 output.
    check(unsafe { size_fn(file, &mut size) })?;
    if size == 0 {
        ensure!(create, "Empty catalog; explicitly run manage refresh");
        return Ok(());
    }
    ensure!(size >= 100, "Truncated SQLite header");
    let mut header = [0u8; 100];
    // SAFETY: the output buffer has exactly the requested 100 bytes. xRead only
    // reads the main file; it neither reads SQL schema nor recovers journals.
    check(unsafe { read_fn(file, header.as_mut_ptr().cast(), 100, 0) })?;
    ensure!(
        &header[..16] == b"SQLite format 3\0",
        "Invalid SQLite header"
    );
    ensure!(
        header[18] == 1 && header[19] == 1,
        "WAL catalog refused; a rollback journal is required"
    );
    let app = i32::from_be_bytes([header[68], header[69], header[70], header[71]]);
    let version = i32::from_be_bytes([header[60], header[61], header[62], header[63]]);
    ensure!(
        app == super::store::APPLICATION_ID && version == 1,
        "Foreign catalog or incompatible version ({version}); no implicit recovery"
    );
    Ok(())
}
fn check(code: i32) -> Result<()> {
    if code == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None).into())
    }
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
