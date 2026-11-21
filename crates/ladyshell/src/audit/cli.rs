//! Audit requests retained under their historical module path, without CLI parsing.
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct AuditArgs {
    pub command: AuditCommand,
}
#[derive(Clone, Debug)]
pub enum AuditCommand {
    /// Prepare the scope and diagnose missing capabilities.
    Plan {
        state: PathBuf,
        profile: Option<super::model::Profile>,
    },
    /// Request execution; refuse if required guarantees are unavailable.
    Run {
        state: PathBuf,
        profile: Option<super::model::Profile>,
    },
    /// Verify a native run and its evidence offline.
    Verify { path: PathBuf },
    /// Resume cleanup of an interrupted run without replaying the target.
    Recover { path: PathBuf },
    /// Compare two runs without transferring their confirmations.
    Compare { old: PathBuf, new: PathBuf },
    /// Publish a verified export in a new directory.
    Export { path: PathBuf, destination: PathBuf },
    /// Validate a document; does not confirm a vulnerability.
    Validate { mode: DocumentMode, path: PathBuf },
}
#[derive(Clone, Copy, Debug)]
pub enum DocumentMode {
    Findings,
    Coverage,
}
impl From<DocumentMode> for crate::audit::validator::Mode {
    fn from(mode: DocumentMode) -> Self {
        match mode {
            DocumentMode::Findings => Self::Findings,
            DocumentMode::Coverage => Self::Coverage,
        }
    }
}
