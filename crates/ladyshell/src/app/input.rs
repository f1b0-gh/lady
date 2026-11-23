//! Shared source/lock assembly; profile-specific artifacts remain explicit.
use crate::{
    environment_lock::{self, EnvironmentLock},
    error::{ensure, Error, Result},
    files, nickel,
    request::{BrokerDesired, Desired},
    scan, sources,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(super) struct Sources<'a> {
    pub config: &'a Path,
    pub project: &'a Path,
    pub state: &'a Path,
    pub resources: &'a Path,
    pub lock: Option<&'a Path>,
    pub ladybom: Option<&'a Path>,
    pub mission: &'a str,
}
impl<'a> From<&'a Desired> for Sources<'a> {
    fn from(args: &'a Desired) -> Self {
        Self {
            config: &args.config,
            project: &args.project,
            state: &args.state,
            resources: &args.resources,
            lock: args.lock.as_deref(),
            ladybom: args.ladybom.as_deref(),
            mission: &args.mission,
        }
    }
}
impl<'a> From<&'a BrokerDesired> for Sources<'a> {
    fn from(args: &'a BrokerDesired) -> Self {
        Self {
            config: &args.config,
            project: &args.project,
            state: &args.state,
            resources: &args.resources,
            lock: args.lock.as_deref(),
            ladybom: args.ladybom.as_deref(),
            mission: &args.mission,
        }
    }
}
impl Sources<'_> {
    pub fn lock_path(&self) -> PathBuf {
        self.lock.map(Path::to_path_buf).unwrap_or_else(|| {
            self.config
                .with_extension(format!("{}.lock.json", self.mission))
        })
    }
}
pub(super) enum Artifacts<'a> {
    Native {
        codex: &'a Path,
        code_mode: &'a Path,
        runtime: &'a Path,
    },
    Broker {
        worker: &'a Path,
        runtime: &'a Path,
    },
}
impl Artifacts<'_> {
    fn lock(&self, configuration: nickel::Evaluated, resources: &Path) -> Result<EnvironmentLock> {
        match self {
            Self::Native {
                codex, code_mode, ..
            } => environment_lock::create(configuration, resources, codex, code_mode),
            Self::Broker { worker, runtime } => {
                environment_lock::create_broker(configuration, resources, worker, runtime)
            }
        }
    }
    fn entries(&self) -> Vec<(&'static str, &Path)> {
        match self {
            Self::Native {
                codex,
                code_mode,
                runtime,
            } => vec![
                ("codex", codex),
                ("codex-code-mode-host", code_mode),
                ("ladyshell", runtime),
            ],
            Self::Broker { worker, runtime } => {
                vec![("worker", worker), ("ladyshell", runtime)]
            }
        }
    }
}

pub(super) fn prepare(
    args: Sources<'_>,
    selected: Artifacts<'_>,
    verify_lock: bool,
) -> Result<(Value, EnvironmentLock)> {
    let project = files::absolute(args.project)?;
    files::open_directory(&project)?;
    let directory = files::absolute(args.state)?;
    ensure!(
        !directory.starts_with(&project),
        "State must reside outside the project"
    );
    let resources = files::absolute(args.resources)?;
    let evaluated = nickel::evaluate(args.config, args.mission, &resources)?;
    let mut receipt = selected.lock(evaluated.clone(), &resources)?;
    let source_files = sources::snapshot(&project, &evaluated.config.sources, None)?;
    let report = scan::scan(&project, &source_files, &evaluated.config)?;
    let (inventory, digest) = crate::deps::input::verified_report(
        &project,
        &evaluated.config.sources,
        &source_files,
        args.ladybom,
    )?;
    receipt.ladybom_sha256 = digest;
    if verify_lock {
        environment_lock::verify(&args.lock_path(), &receipt)?;
    }
    let preparation = evaluated
        .config
        .dependencies
        .as_ref()
        .map(|config| {
            crate::deps::prepare::plan(&project, &source_files, config, &evaluated.config.tools)
        })
        .transpose()?;
    let mut artifacts = serde_json::Map::new();
    for (name, path) in selected.entries() {
        let path = files::absolute(path)?;
        let sha256 = match receipt.artifacts_sha256.get(name) {
            Some(digest) => digest.clone(),
            // Preserve the legacy native receipt shape. Broker receipts always
            // lock their explicitly supplied receiver and worker artifacts.
            None if name == "ladyshell" && matches!(selected, Artifacts::Native { .. }) => {
                environment_lock::artifact_hash(&path)?
            }
            None => return Err(invalid("Missing artifact digest".into())),
        };
        artifacts.insert(name.into(), json!({"path":path,"sha256":sha256}));
    }
    let desired = json!({"schema_version":2,"context":{"gateway":evaluated.config.sandbox.gateway,"workspace":evaluated.config.sandbox.workspace},"evaluated":evaluated,"environment_lock":receipt,"project":project,"resources":resources,"sources":source_files,"dependency_scan":report,"dependency_inventory":inventory,"dependency_preparation":preparation,"artifacts":artifacts});
    Ok((desired, receipt))
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
