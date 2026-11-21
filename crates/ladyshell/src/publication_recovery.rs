//! Durable, explicit reconciliation of one retained publication attempt.
use crate::{
    error::{ensure, Error, Result},
    files,
    publish::{oid, Git},
    state::{SessionLock, StateLock},
};
use serde_json::{json, Value};
use std::path::Path;

fn read(directory: &Path) -> Result<Option<Value>> {
    match files::read_limited(&directory.join("publication.json"), 4 * 1024 * 1024) {
        Ok(bytes) => {
            let receipt = crate::json::parse(&bytes)?;
            ensure!(receipt.is_object(), "Invalid publication receipt");
            ensure!(
                matches!(receipt["schema_version"].as_u64(), Some(1 | 2)),
                "Unsupported publication receipt schema"
            );
            if receipt["schema_version"] == 2 {
                ensure!(
                    matches!(
                        receipt["phase"].as_str(),
                        Some(
                            "acquiring"
                                | "exported"
                                | "committed"
                                | "push_unconfirmed"
                                | "published"
                                | "abandoned"
                        )
                    ),
                    "Invalid publication phase"
                );
                for key in ["project", "destination", "reference", "base", "export"] {
                    crate::state::text(&receipt, key)?;
                }
                oid(crate::state::text(&receipt, "base")?)?;
                let expected = receipt["expected_remote"]
                    .as_str()
                    .ok_or_else(|| invalid("Missing expected remote".into()))?;
                if !expected.is_empty() {
                    oid(expected)?;
                }
                if receipt["phase"] != "acquiring"
                    && receipt["phase"] != "exported"
                    && receipt["phase"] != "abandoned"
                {
                    oid(crate::state::text(&receipt, "commit")?)?;
                }
                ensure!(
                    receipt["reference"]
                        .as_str()
                        .is_some_and(|s| s.starts_with("refs/heads/")),
                    "Publication receipt is not a branch"
                );
                ensure!(
                    receipt["confirmed"] == (receipt["phase"] == "published"),
                    "Inconsistent publication confirmation"
                );
            }
            Ok(Some(receipt))
        }
        Err(e) if not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}
/// Call while holding the state lock, before beginning any new sandbox work.
/// Unknown, malformed, legacy-unconfirmed, and incomplete journals fail closed.
pub fn ensure_available(directory: &Path) -> Result<()> {
    if let Some(receipt) = read(directory)? {
        let complete = if receipt["schema_version"] == 1 {
            receipt["confirmed"] == true || receipt["phase"] == "abandoned"
        } else {
            receipt["phase"] == "published" || receipt["phase"] == "abandoned"
        };
        ensure!(
            complete,
            "A pending publication must be reconciled or explicitly abandoned before a new run"
        );
    }
    Ok(())
}
pub(crate) fn write(directory: &Path, receipt: &Value) -> Result<()> {
    // The primary journal is the authority. Updating it first keeps every partial
    // write fail-closed even if the retained export later becomes unavailable.
    crate::environment_lock::atomic_json(&directory.join("publication.json"), receipt)?;
    let export = Path::new(crate::state::text(receipt, "export")?);
    crate::environment_lock::atomic_json(&export.join("publication.json"), receipt)?;
    Ok(())
}
fn observe(receipt: &Value) -> Result<Value> {
    let mut result = receipt.clone();
    if receipt["schema_version"] == 1 {
        result["remote_status"] = json!("legacy_unbound");
        return Ok(result);
    }
    let git = Git::new(Path::new(crate::state::text(receipt, "project")?))?;
    let observed = git.remote_head(
        crate::state::text(receipt, "destination")?,
        crate::state::text(receipt, "reference")?,
    );
    match observed {
        Ok(actual) => {
            result["remote_status"] =
                json!(if receipt["commit"].as_str() == Some(actual.as_str()) {
                    "commit"
                } else if receipt["expected_remote"] == actual {
                    "expected"
                } else {
                    "advanced"
                });
            result["observed_remote"] = json!(actual);
        }
        Err(error) => {
            result["remote_status"] = json!("unavailable");
            result["observation_error"] = json!(error.to_string());
        }
    }
    Ok(result)
}
pub fn status(directory: &Path) -> Result<Value> {
    let _state = StateLock::acquire(directory)?;
    let _sessions = SessionLock::acquire(directory, true)?;
    let directory = _state.directory.as_path();
    match read(directory)? {
        Some(receipt) => observe(&receipt),
        None => Ok(json!({"schema_version":2,"phase":"none"})),
    }
}
/// Re-read the retained destination. Retry publishes only the recorded exact
/// object with the original lease; abandonment archives evidence without resets.
pub fn reconcile(directory: &Path, retry: bool, abandon: bool) -> Result<Value> {
    ensure!(
        !(retry && abandon),
        "Retry and abandonment are mutually exclusive"
    );
    let _state = StateLock::acquire(directory)?;
    let _sessions = SessionLock::acquire(directory, true)?;
    let directory = _state.directory.as_path();
    let mut receipt =
        read(directory)?.ok_or_else(|| invalid("No publication receipt exists".into()))?;
    if receipt["phase"] == "abandoned"
        || receipt["phase"] == "published"
        || (receipt["schema_version"] == 1 && receipt["confirmed"] == true)
    {
        return Ok(receipt);
    }
    if abandon {
        let archive = directory.join("publication-archives");
        crate::state::create_directory(&archive)?;
        let digest = files::hash(&serde_json::to_vec(&receipt)?);
        let archived = archive.join(format!("{digest}.json"));
        // A deterministic immutable copy makes repeated abandonment idempotent.
        if archived.exists() {
            ensure!(
                crate::json::parse(&files::read_limited(&archived, 4 * 1024 * 1024)?)? == receipt,
                "Archived publication differs"
            );
        } else {
            files::publish_json(&archived, &receipt, false)?;
        }
        let released = crate::publish::release_owned_index_lock(&receipt)?;
        receipt["owned_index_lock_released"] = json!(released);
        receipt["phase"] = json!("abandoned");
        receipt["confirmed"] = json!(false);
        receipt["archive"] = json!(archived);
        crate::environment_lock::atomic_json(&directory.join("publication.json"), &receipt)?;
        return Ok(receipt);
    }
    ensure!(receipt["schema_version"] == 2, "Legacy receipt lacks a pinned destination; inspect and explicitly abandon it, never retry automatically");
    let observed = observe(&receipt)?;
    if let Err(error) = authorize(&receipt) {
        if observed["remote_status"] == "commit" {
            let mut historical = observed;
            historical["current_authorization"] = json!("rejected");
            historical["authorization_error"] = json!(error.to_string());
            historical["historical_remote_confirmation"] = json!(true);
            return Ok(historical);
        }
        return Err(error);
    }
    if observed["remote_status"] == "commit" {
        crate::publish::finish_local(directory, &mut receipt)?;
        receipt["phase"] = json!("published");
        receipt["confirmed"] = json!(true);
        write(directory, &receipt)?;
        return Ok(receipt);
    }
    if !retry {
        if observed["remote_status"] == "expected" && receipt["phase"] == "committed" {
            crate::publish::finish_local(directory, &mut receipt)?;
            return observe(&receipt);
        }
        return Ok(observed);
    }
    ensure!(
        observed["remote_status"] == "expected",
        "Remote unavailable or advanced; exact publication evidence is retained"
    );
    let _parents = crate::stacks::guard(directory)?;
    crate::publish::finish_local(directory, &mut receipt)?;
    let commit = crate::state::text(&receipt, "commit")?;
    oid(commit)?;
    let git = Git::new(Path::new(crate::state::text(&receipt, "project")?))?;
    git.call(&["cat-file", "-e", &format!("{commit}^{{commit}}")])?;
    let reference = crate::state::text(&receipt, "reference")?;
    let destination = crate::state::text(&receipt, "destination")?;
    let expected = receipt["expected_remote"]
        .as_str()
        .ok_or_else(|| invalid("Missing expected remote".into()))?;
    let mut pushing = receipt.clone();
    pushing["phase"] = json!("push_unconfirmed");
    write(directory, &pushing)?;
    git.transport(&[
        "push",
        "--porcelain",
        &format!("--force-with-lease={reference}:{expected}"),
        destination,
        &format!("{commit}:{reference}"),
    ])?;
    ensure!(
        git.remote_head(destination, reference)? == commit,
        "Push read-back unconfirmed; exact object retained"
    );
    receipt["phase"] = json!("published");
    receipt["confirmed"] = json!(true);
    write(directory, &receipt)?;
    Ok(receipt)
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

fn not_found(error: &Error) -> bool {
    match error {
        Error::Io(e) | Error::PathIo { source: e, .. } => e.kind() == std::io::ErrorKind::NotFound,
        Error::Context { source, .. } => not_found(source),
        _ => false,
    }
}

fn authorize(receipt: &Value) -> Result<()> {
    if !receipt["policy_digests"].is_null() {
        let digests: std::collections::BTreeMap<std::path::PathBuf, String> =
            serde_json::from_value(receipt["policy_digests"].clone())?;
        for (path, expected) in digests {
            ensure!(
                files::hash(&files::read_limited(&path, 32 * 1024 * 1024)?) == expected,
                "Publication policy input changed; recovery requires explicit abandonment"
            );
        }
    }
    if !receipt["checks"].is_null() {
        crate::publication_checks::revalidate(
            Path::new(crate::state::text(receipt, "export")?),
            &receipt["checks"],
        )?;
    }
    if !receipt["signing"].is_null() {
        let signing: crate::publication_policy::Signing =
            serde_json::from_value(receipt["signing"].clone())?;
        let mut git = Git::new(Path::new(crate::state::text(receipt, "project")?))?;
        git.configure(signing.git_config());
        signing.verify_commit(&git, crate::state::text(receipt, "commit")?)?;
    }
    Ok(())
}
