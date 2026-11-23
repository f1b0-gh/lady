//! Parser-independent inputs for the OpenShell lifecycle operations.
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Desired {
    pub config: PathBuf,
    pub project: PathBuf,
    pub state: PathBuf,
    pub resources: PathBuf,
    pub codex: PathBuf,
    pub codex_code_mode_host: PathBuf,
    pub lock: Option<PathBuf>,
    pub ladybom: Option<PathBuf>,
    pub mission: String,
}

/// Explicit fixed-broker image inputs for an embedding host such as Ladyness.
/// Application component versions are staged separately after provisioning.
#[derive(Clone, Debug)]
pub struct BrokerDesired {
    pub config: PathBuf,
    pub project: PathBuf,
    pub state: PathBuf,
    pub resources: PathBuf,
    pub worker: PathBuf,
    pub runtime: PathBuf,
    pub lock: Option<PathBuf>,
    pub ladybom: Option<PathBuf>,
    pub mission: String,
}

#[derive(Clone, Debug)]
pub struct Existing {
    pub state: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Destroy {
    pub state: PathBuf,
    pub discard_work: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DestroyAll {
    pub dry_run: bool,
    pub discard_work: bool,
}

#[derive(Clone, Debug)]
pub struct SyncArgs {
    pub state: Option<PathBuf>,
    pub dry_run: bool,
    pub apply: bool,
    pub export: bool,
    pub json: bool,
}

impl SyncArgs {
    pub fn applies(&self) -> bool {
        !self.dry_run && !self.export
    }
}
