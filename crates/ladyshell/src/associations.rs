//! Host-owned project/state associations. No repository file can redirect discovery.
use crate::{
    error::{ensure, Error, Result},
    files, state,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Association {
    pub(crate) schema_version: u32,
    pub(crate) project: PathBuf,
    pub directory: PathBuf,
    pub(crate) name: String,
    pub(crate) sandbox_id: String,
    pub(crate) gateway: String,
    pub(crate) workspace: String,
}
pub fn registry() -> Result<PathBuf> {
    let base =
        if let Some(path) = std::env::var_os("XDG_STATE_HOME").filter(|p| !p.is_empty()) {
            PathBuf::from(path)
        } else {
            PathBuf::from(std::env::var_os("HOME").ok_or_else(|| {
                invalid("HOME or XDG_STATE_HOME is required to locate state".into())
            })?)
            .join(".local/state")
        };
    ensure!(
        base.is_absolute(),
        "The associations directory path must be absolute"
    );
    Ok(base.join("ladyshell/associations"))
}
pub fn register(directory: &Path) -> Result<()> {
    register_at(&registry()?, directory)
}
pub fn register_at(registry: &Path, directory: &Path) -> Result<()> {
    let directory = files::absolute(directory)?;
    let current = state::load(&directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let project = PathBuf::from(state::text(&current["desired_inputs"], "project")?);
    ensure!(
        project.is_absolute() && !directory.starts_with(&project),
        "Invalid project/state association"
    );
    files::open_directory(&project)?;
    let association = Association {
        schema_version: 1,
        project,
        directory: directory.clone(),
        name: state::text(&current, "sandbox_name")?.into(),
        sandbox_id: state::text(&current, "sandbox_id")?.into(),
        gateway: state::text(&current["context"], "gateway")?.into(),
        workspace: state::text(&current["context"], "workspace")?.into(),
    };
    let lock = lock_registry(registry)?;
    let key = files::hash(directory.as_os_str().as_encoded_bytes());
    crate::environment_lock::atomic_json(
        &lock.directory.join(format!("{key}.json")),
        &serde_json::to_value(association)?,
    )
}
pub fn candidates_at(registry: &Path, cwd: &Path) -> Result<Vec<Association>> {
    let cwd = files::absolute(cwd)?;
    files::open_directory(&cwd)?;
    // The lock serializes registry reads/writes, never state operations or terminal input.
    let lock = lock_registry(registry)?;
    let dir = files::open_directory(&lock.directory)?;
    let mut found = Vec::new();
    let mut count = 0;
    for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        let entry = entry?;
        count += 1;
        ensure!(count <= 1001, "Too many registered associations");
        if entry.file_name() == ".lock" {
            continue;
        }
        let bytes = files::read_file(
            files::open_child(&dir, &entry.file_name(), false)?,
            64 * 1024,
        )?;
        let association: Association = serde_json::from_value(crate::json::parse(&bytes)?)?;
        ensure!(
            association.schema_version == 1
                && association.project.is_absolute()
                && association.directory.is_absolute(),
            "Incompatible association"
        );
        if !cwd.starts_with(&association.project) {
            continue;
        }
        let Some(current) = state::load(&association.directory)? else {
            continue;
        };
        association.verify(&current)?;
        found.push(association);
    }
    // A nested registered project takes precedence over its enclosing project.
    if let Some(depth) = found.iter().map(|a| a.project.components().count()).max() {
        found.retain(|a| a.project.components().count() == depth);
    }
    found.sort_by(|a, b| a.directory.cmp(&b.directory));
    Ok(found)
}
pub fn choose(
    candidates: &[Association],
    input: &mut impl BufRead,
    output: &mut impl Write,
    interactive: bool,
) -> Result<PathBuf> {
    ensure!(!candidates.is_empty(),"No sandbox is associated with this project. Run ladyshell sync --state PATH once (or --state PATH --dry-run)");
    if candidates.len() == 1 {
        return Ok(candidates[0].directory.clone());
    }
    let choices = candidates
        .iter()
        .enumerate()
        .map(|(i, a)| {
            format!(
                "{}. {} ({}/{}) — {:?}",
                i + 1,
                a.name,
                a.gateway,
                a.workspace,
                a.directory
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ensure!(
        interactive,
        "Multiple sandboxes match the project; use --state:\n{choices}"
    );
    writeln!(
        output,
        "Multiple sandboxes match the project:\n{choices}\nSandbox number:"
    )?;
    output.flush()?;
    let mut line = String::new();
    input.take(65).read_line(&mut line)?;
    ensure!(line.len() <= 64, "Selection is too long");
    let selected = line
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| candidates.get(i))
        .ok_or_else(|| invalid("Invalid selection; no synchronization performed".into()))?;
    Ok(selected.directory.clone())
}
pub struct Selection {
    pub directory: PathBuf,
    pub expected: Option<Association>,
}
impl Association {
    pub fn verify(&self, current: &serde_json::Value) -> Result<()> {
        ensure!(
            current["sandbox_id"] == self.sandbox_id
                && current["sandbox_name"] == self.name
                && current["context"]["gateway"] == self.gateway
                && current["context"]["workspace"] == self.workspace
                && current["desired_inputs"]["project"] == serde_json::to_value(&self.project)?,
            "Stale association for {:?}: verify the state, then use --state explicitly",
            self.directory
        );
        Ok(())
    }
}
pub fn resolve(explicit: Option<&Path>) -> Result<Selection> {
    if let Some(path) = explicit {
        return Ok(Selection {
            directory: files::absolute(path)?,
            expected: None,
        });
    }
    let candidates = candidates_at(&registry()?, &std::env::current_dir()?)?;
    use std::io::IsTerminal;
    let directory = choose(
        &candidates,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
        std::io::stdin().is_terminal(),
    )?;
    let expected = candidates
        .into_iter()
        .find(|candidate| candidate.directory == directory)
        .ok_or_else(|| invalid("Selected association is missing".into()))?;
    Ok(Selection {
        directory,
        expected: Some(expected),
    })
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

// Independent tasks share this short metadata transaction. Brief contention is
// normal; task and session authority locks elsewhere retain immediate refusal.
fn lock_registry(registry: &Path) -> Result<state::StateLock> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match state::StateLock::acquire(registry) {
            Err(error) if busy(&error) && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            result => return result,
        }
    }
}
fn busy(error: &Error) -> bool {
    match error {
        Error::Io(source) => source.kind() == std::io::ErrorKind::WouldBlock,
        Error::Context { source, .. } => busy(source),
        _ => false,
    }
}
