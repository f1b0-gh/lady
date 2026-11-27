//! Typed failures shared by the library and CLI. Source chains are never flattened.
use std::{ffi::OsString, io, path::PathBuf, process::ExitStatus, time::Duration};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SQLite catalog error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Audit document rejected: {0}")]
    AuditDocument(#[from] crate::audit::validator::Error),
    #[error("Authentication rejected: {message}")]
    Authentication { message: String },
    #[error("Identity mismatch: {resource}")]
    IdentityMismatch { resource: String },
    #[error("Invalid configuration: {message}")]
    InvalidConfiguration { message: String },
    #[error("Invalid path {path:?}: {reason}")]
    InvalidPath { path: PathBuf, reason: &'static str },
    #[error("Input rejected: {message}")]
    InvalidInput { message: String },
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("{path:?} : {source}")]
    PathIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Non-UTF-8 output: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("NUL byte in a path: {0}")]
    Nul(#[from] std::ffi::NulError),
    #[error("Failed to start {program:?}: {source}")]
    ProcessSpawn {
        program: OsString,
        #[source]
        source: io::Error,
    },
    #[error("{program:?} failed ({status}): {stderr}")]
    ProcessExit {
        program: OsString,
        status: ExitStatus,
        stderr: String,
    },
    #[error("Sandbox readiness deadline exceeded for {name} ({timeout:?}); resume the original apply operation")]
    SandboxReadinessTimeout { name: String, timeout: Duration },
    #[error("{program:?} timed out ({timeout:?})")]
    ProcessTimeout {
        program: OsString,
        timeout: Duration,
    },
    #[error("{stream} output from {program:?} is too large (limit {limit} bytes)")]
    ProcessOutputLimit {
        program: OsString,
        stream: &'static str,
        limit: usize,
    },
    #[error("Missing {stream} pipe for {program:?}")]
    MissingPipe {
        program: OsString,
        stream: &'static str,
    },
    #[error("Nickel evaluation rejected: {source}")]
    Nickel {
        #[source]
        source: Box<Error>,
    },
    #[error("Lock mismatch {path:?}: review the changes, then run lock explicitly")]
    LockMismatch { path: PathBuf },
    #[error("{message} : {source}")]
    Context {
        message: String,
        #[source]
        source: Box<Error>,
    },
    #[error("Command {command} has not yet been ported; no state changed")]
    UnsupportedCommand { command: &'static str },
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn context(self, message: impl Into<String>) -> Self {
        Self::Context {
            message: message.into(),
            source: Box::new(self),
        }
    }
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_)
            | Self::PathIo { .. }
            | Self::ProcessSpawn { .. }
            | Self::ProcessExit { .. }
            | Self::ProcessTimeout { .. }
            | Self::SandboxReadinessTimeout { .. }
            | Self::ProcessOutputLimit { .. }
            | Self::MissingPipe { .. }
            | Self::Utf8(_) => 1,
            Self::Context { source, .. } => source.exit_code(),
            Self::Nickel { source } => match source.as_ref() {
                Self::ProcessExit { .. } => 2,
                _ => source.exit_code(),
            },
            Self::Json(error) if error.is_io() => 1,
            _ => 2,
        }
    }
}
pub fn exit_code(error: &Error) -> i32 {
    error.exit_code()
}
// These macros only construct the module's typed validation error, never panic.
macro_rules! ensure {
 ($condition:expr,$($message:tt)*) => {if !$condition {return Err(invalid(format!($($message)*)));}};
}
macro_rules! bail {($($message:tt)*) => {return Err(invalid(format!($($message)*)))};}
pub(crate) use {bail, ensure};

// Convert by variant to preserve the historical application API and every typed
// cause, including nested context and the evaluator's validation exit status.
impl From<nickel_util::error::Error> for Error {
    fn from(error: nickel_util::error::Error) -> Self {
        use nickel_util::error::Error as Core;
        match error {
            Core::InvalidConfiguration { message } => Self::InvalidConfiguration { message },
            Core::InvalidPath { path, reason } => Self::InvalidPath { path, reason },
            Core::InvalidInput { message } => Self::InvalidInput { message },
            Core::Io(source) => Self::Io(source),
            Core::PathIo { path, source } => Self::PathIo { path, source },
            Core::Json(source) => Self::Json(source),
            Core::Utf8(source) => Self::Utf8(source),
            Core::Nul(source) => Self::Nul(source),
            Core::ProcessSpawn { program, source } => Self::ProcessSpawn { program, source },
            Core::ProcessExit {
                program,
                status,
                stderr,
            } => Self::ProcessExit {
                program,
                status,
                stderr,
            },
            Core::ProcessTimeout { program, timeout } => Self::ProcessTimeout { program, timeout },
            Core::ProcessOutputLimit {
                program,
                stream,
                limit,
            } => Self::ProcessOutputLimit {
                program,
                stream,
                limit,
            },
            Core::MissingPipe { program, stream } => Self::MissingPipe { program, stream },
            Core::Nickel { source } => Self::Nickel {
                source: Box::new((*source).into()),
            },
            Core::Context { message, source } => Self::Context {
                message,
                source: Box::new((*source).into()),
            },
        }
    }
}
