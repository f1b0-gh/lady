//! Read-only inventory of registered local states, never provider discovery.
use crate::{
    associations::{self, Association},
    error::{ensure, Error, Result},
    files, state,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::Write,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path},
};

pub fn list() -> Result<Value> {
    list_at(&associations::registry()?)
}

/// An absent registry is empty. Existing registries are read without creating locks.
pub fn list_at(registry: &Path) -> Result<Value> {
    inventory_at(registry, false)
}

pub(crate) fn inventory_at(registry: &Path, include_deleted: bool) -> Result<Value> {
    let registry_text = registry.to_str().ok_or_else(|| Error::InvalidPath {
        path: registry.to_path_buf(),
        reason: "A UTF-8 registry path is required",
    })?;
    let mut report = json!({"schema_version":1,"scope":"registered_local_states",
        "registry":registry_text,"provider_checked":false,"complete":true,
        "instances":[],"diagnostics":[],"excluded_deleted":0});
    let directory = match files::open_directory(registry) {
        Ok(directory) => directory,
        Err(error) if missing(&error) => return Ok(report),
        Err(error) => return Err(error),
    };
    private_directory(&directory)?;
    let lock = match files::open_child(&directory, ".lock".as_ref(), false) {
        Ok(lock) => {
            let metadata = lock.metadata()?;
            ensure!(metadata.nlink() == 1, "Shared registry lock is not allowed");
            // SAFETY: lock owns this descriptor; closing it releases our shared lock.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } < 0 {
                return Err(Error::Io(std::io::Error::last_os_error())
                    .context("Registry is busy; run ladyshell list again"));
            }
            Some(lock)
        }
        Err(error) if missing(&error) => None,
        Err(error) => return Err(error),
    };
    let mut entries = Vec::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        let entry = entry?;
        if entry.file_name() == ".lock" {
            continue;
        }
        if entries.len() == 1000 {
            diagnostic(&mut report, registry, None, "registry_limit");
            break;
        }
        entries.push(entry.file_name());
    }
    entries.sort();
    if lock.is_none() && !entries.is_empty() {
        diagnostic(&mut report, registry, None, "missing_registry_lock");
        return Ok(report);
    }
    for name in entries {
        let path = registry.join(&name);
        let association = (|| -> Result<Association> {
            let bytes = files::read_file(files::open_child(&directory, &name, false)?, 64 * 1024)?;
            let association: Association = serde_json::from_value(crate::json::parse(&bytes)?)?;
            ensure!(
                association.schema_version == 1
                    && normal_absolute(&association.project)
                    && normal_absolute(&association.directory)
                    && !association.directory.starts_with(&association.project),
                "Incompatible association"
            );
            Ok(association)
        })();
        let association = match association {
            Ok(association) => association,
            Err(_) => {
                diagnostic(&mut report, &path, None, "invalid_association");
                continue;
            }
        };
        match files::open_directory(&association.directory) {
            Ok(directory) => inspect_association(
                &directory,
                &association,
                &path,
                &mut report,
                include_deleted,
            ),
            Err(error) => diagnostic(
                &mut report,
                &path,
                Some(&association.directory),
                if missing(&error) {
                    "missing_state"
                } else {
                    "invalid_state"
                },
            ),
        }
    }
    Ok(report)
}

fn inspect_association(
    directory: &File,
    association: &Association,
    path: &Path,
    report: &mut Value,
    include_deleted: bool,
) {
    let current = (|| -> Result<Option<Value>> {
        private_directory(directory)?;
        let current = read_at(directory, "state.json")?;
        if let Some(current) = &current {
            state::validate(current)?;
            ensure!(valid_identity(current), "Incomplete state identity");
        }
        Ok(current)
    })();
    let current = match current {
        Ok(Some(current)) => current,
        result => {
            diagnostic(
                report,
                path,
                Some(&association.directory),
                if result.is_err() {
                    "invalid_state"
                } else {
                    "missing_state"
                },
            );
            return;
        }
    };
    if association.verify(&current).is_err() {
        diagnostic(
            report,
            path,
            Some(&association.directory),
            "stale_association",
        );
        return;
    }
    let receipt = match read_at(directory, "destroy.json") {
        Ok(Some(receipt)) if valid_receipt(&receipt) => Some(receipt),
        Ok(None) => None,
        _ => {
            diagnostic(
                report,
                path,
                Some(&association.directory),
                "invalid_deletion_receipt",
            );
            None
        }
    };
    append_instance(
        report,
        association,
        &current,
        "current",
        receipt.as_ref(),
        include_deleted,
    );
    match current.get("retained") {
        None => (),
        Some(Value::Array(retained)) => {
            for previous in retained {
                if valid_identity(previous) {
                    append_instance(
                        report,
                        association,
                        previous,
                        "previous",
                        receipt.as_ref(),
                        include_deleted,
                    );
                } else {
                    diagnostic(
                        report,
                        path,
                        Some(&association.directory),
                        "invalid_retained_instance",
                    );
                }
            }
        }
        Some(_) => diagnostic(
            report,
            path,
            Some(&association.directory),
            "invalid_retained_instance",
        ),
    }
}

fn read_at(directory: &File, name: &str) -> Result<Option<Value>> {
    match files::open_child(directory, name.as_ref(), false) {
        Ok(file) => Ok(Some(crate::json::parse(&files::read_file(
            file,
            16 * 1024 * 1024,
        )?)?)),
        Err(error) if missing(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn append_instance(
    report: &mut Value,
    association: &Association,
    instance: &Value,
    kind: &str,
    receipt: Option<&Value>,
    include_deleted: bool,
) {
    let receipt = receipt.filter(|receipt| {
        receipt["sandbox_id"] == instance["sandbox_id"]
            && receipt["sandbox_name"] == instance["sandbox_name"]
            && receipt["context"] == instance["context"]
            && (kind == "previous" || receipt["owner"] == instance["owner"])
    });
    let deleted = receipt.is_some_and(|receipt| receipt["deleted"] == true);
    if deleted && !include_deleted {
        report["excluded_deleted"] = json!(report["excluded_deleted"].as_u64().unwrap_or(0) + 1);
        return;
    }
    let entry = json!({"sandbox_name":instance["sandbox_name"],"sandbox_id":instance["sandbox_id"],
        "gateway":instance["context"]["gateway"],"workspace":instance["context"]["workspace"],
        "project":association.project,"directory":association.directory,"kind":kind,
        "recorded_status":if deleted { "deleted" } else if receipt.is_some() { "deletion_pending" } else { "retained" }});
    if let Some(instances) = report["instances"].as_array_mut() {
        instances.push(entry);
    }
}

fn valid_identity(value: &Value) -> bool {
    state::text(value, "sandbox_name").is_ok()
        && state::text(value, "sandbox_id").is_ok()
        && state::text(&value["context"], "gateway").is_ok()
        && state::text(&value["context"], "workspace").is_ok()
}

fn valid_receipt(value: &Value) -> bool {
    value["schema_version"] == 1
        && valid_identity(value)
        && state::text(value, "owner").is_ok()
        && value["deleted"].is_boolean()
}

fn private_directory(directory: &File) -> Result<()> {
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
        "State directory must be owned by the current user, without group/other write access"
    );
    Ok(())
}

fn normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn missing(error: &Error) -> bool {
    match error {
        Error::Io(error) | Error::PathIo { source: error, .. } => {
            error.kind() == std::io::ErrorKind::NotFound
        }
        Error::Context { source, .. } => missing(source),
        _ => false,
    }
}

fn diagnostic(report: &mut Value, association: &Path, directory: Option<&Path>, code: &str) {
    report["complete"] = json!(false);
    let message = match code {
        "registry_limit" => "Limit of 1,000 associations reached",
        "missing_registry_lock" => "Populated registry without an existing lock",
        "invalid_association" => "Invalid or unreadable association",
        "invalid_state" => "Invalid or unreadable state",
        "missing_state" => "State is missing",
        "stale_association" => "Stale association: identity mismatch",
        "invalid_deletion_receipt" => "Invalid or unreadable deletion receipt",
        "invalid_retained_instance" => "Invalid recorded previous instance",
        _ => "Unverified entry",
    };
    if let Some(diagnostics) = report["diagnostics"].as_array_mut() {
        diagnostics.push(json!({"association":association.to_str(),
                "association_display":format!("{association:?}"),
                "directory":directory,"code":code,"message":message}));
    }
}

fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

pub fn write(report: &Value, output: &mut impl Write) -> Result<()> {
    writeln!(
        output,
        "Locally registered instances — OpenShell was not queried (presence and status unknown)."
    )?;
    writeln!(output, "Registry: {}", report["registry"])?;
    if let Some(instances) = report["instances"].as_array() {
        for instance in instances {
            let kind = if instance["kind"] == "previous" {
                "previous"
            } else {
                "current"
            };
            let status = if instance["recorded_status"] == "deletion_pending" {
                "deletion pending"
            } else {
                "retained"
            };
            writeln!(
                output,
                "{} ({}) — {kind}, {status} — {} / {}\n  project: {}\n  state: {}",
                instance["sandbox_name"],
                instance["sandbox_id"],
                instance["gateway"],
                instance["workspace"],
                instance["project"],
                instance["directory"]
            )?;
        }
        writeln!(
            output,
            "{} instance(s); {} confirmed deletion(s) excluded.",
            instances.len(),
            report["excluded_deleted"]
        )?;
    }
    if let Some(diagnostics) = report["diagnostics"].as_array() {
        for diagnostic in diagnostics {
            writeln!(
                output,
                "Incomplete inventory: {} — association {}; state {}",
                diagnostic["message"], diagnostic["association_display"], diagnostic["directory"]
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn replaced_directory_cannot_supply_a_deletion_receipt_for_pinned_state() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("state");
        state::create_directory(&directory)?;
        let project = root.path().join("project");
        let current = json!({"schema_version":2,"sandbox_name":"original","sandbox_id":"original-id",
            "policy_hash":"hash","codex_binary":"codex","owner":"owner","desired_hash":"desired",
            "image_id":"image","project_snapshot":"snapshot","build_dir":"build",
            "context":{"gateway":"gateway","workspace":"default"},"desired_inputs":{"project":project}});
        crate::environment_lock::atomic_json(&directory.join("state.json"), &current)?;
        let association: Association = serde_json::from_value(json!({"schema_version":1,
            "project":project,"directory":directory,"name":"original","sandbox_id":"original-id",
            "gateway":"gateway","workspace":"default"}))?;
        let pinned = files::open_directory(&directory)?;
        private_directory(&pinned)?;
        fs::rename(&directory, root.path().join("preserved-state"))?;
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777))?;
        crate::environment_lock::atomic_json(&directory.join("state.json"), &current)?;
        crate::environment_lock::atomic_json(
            &directory.join("destroy.json"),
            &json!({
            "schema_version":1,"sandbox_name":"original","sandbox_id":"original-id",
            "context":{"gateway":"gateway","workspace":"default"},"owner":"owner","deleted":true}),
        )?;
        let mut report =
            json!({"complete":true,"instances":[],"diagnostics":[],"excluded_deleted":0});
        inspect_association(
            &pinned,
            &association,
            &root.path().join("association.json"),
            &mut report,
            false,
        );
        assert_eq!(
            report["complete"], true,
            "The pinned directory remains valid"
        );
        assert_eq!(
            report["excluded_deleted"], 0,
            "The replacement receipt has no authority"
        );
        assert_eq!(report["instances"][0]["sandbox_id"], "original-id");
        let mut replacement = current;
        replacement["sandbox_id"] = json!("replacement-id");
        crate::environment_lock::atomic_json(&directory.join("state.json"), &replacement)?;
        let mut report =
            json!({"complete":true,"instances":[],"diagnostics":[],"excluded_deleted":0});
        inspect_association(
            &pinned,
            &association,
            &root.path().join("association.json"),
            &mut report,
            false,
        );
        assert_eq!(
            report["complete"], true,
            "Replacement state must not replace the pinned identity"
        );
        assert_eq!(report["instances"][0]["sandbox_id"], "original-id");
        Ok(())
    }
}
