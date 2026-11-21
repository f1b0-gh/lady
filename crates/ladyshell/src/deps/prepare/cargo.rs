//! Separate selected workspace targets from libraries reached through local dependencies.
use super::{invalid, read_toml};
use crate::{
    deps::{Component, Project},
    error::{ensure, Result},
    sources::Snapshot,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component as PathComponent, Path, PathBuf},
};
use toml::Value;

type Manifests = BTreeMap<String, Value>;

pub(super) fn validate(
    root: &Path,
    snapshot: &Snapshot,
    selected: &Project,
    projects: &[Project],
) -> Result<Vec<Project>> {
    let manifests: Manifests = projects
        .iter()
        .filter(|p| p.ecosystem == "rust")
        .map(|p| Ok((p.manifest.clone(), read_toml(root, &p.manifest)?)))
        .collect::<Result<_>>()?;
    // Ladybom assigns this lock only through the manifest's actual workspace membership.
    // A matching package name in Cargo.lock does not establish membership or reachability.
    let members: BTreeSet<String> = projects
        .iter()
        .filter(|p| p.ecosystem == "rust" && p.lockfile == selected.lockfile)
        .map(|p| p.manifest.clone())
        .collect();
    let lock = selected
        .lockfile
        .as_deref()
        .ok_or_else(|| invalid("Missing Cargo lock".into()))?;
    let workspace_root = Path::new(lock)
        .with_file_name("Cargo.toml")
        .to_string_lossy()
        .into_owned();
    let mut active = members.clone();
    let mut pending = members.clone();
    let mut libraries = BTreeSet::new();
    while let Some(name) = pending.pop_first() {
        let value = manifests
            .get(&name)
            .ok_or_else(|| invalid(format!("Missing Cargo manifest: {name}")))?;
        for dependency in dependencies(
            &name,
            value,
            &manifests,
            members.contains(&name),
            name == workspace_root,
        )? {
            ensure!(
                snapshot.contains_key(&dependency.manifest),
                "Cargo dependency manifest is missing from sources: {}",
                dependency.manifest
            );
            let value = manifests.get(&dependency.manifest).ok_or_else(|| {
                invalid(format!(
                    "Cargo dependency manifest is missing from the report: {}",
                    dependency.manifest
                ))
            })?;
            let locked = locked_package(
                &dependency.manifest,
                value,
                &manifests,
                &selected.components,
            )?;
            ensure!(
                locked.is_some() || dependency.conditional,
                "Local Cargo dependency is missing from the lock: {}",
                dependency.manifest
            );
            if locked.is_some() {
                libraries.insert(dependency.manifest.clone());
                if active.insert(dependency.manifest.clone()) {
                    pending.insert(dependency.manifest);
                }
            }
        }
    }
    for (name, manifest) in &manifests {
        let complete = active.contains(name);
        // A workspace-root request selects every member's targets. An explicit
        // member selects only its own targets; the full workspace still supplies
        // lock constraints, local dependencies, libraries and build inputs.
        let selected_targets = members.contains(name)
            && (selected.manifest == workspace_root || name == &selected.manifest);
        for (field, value) in manifest
            .as_table()
            .ok_or_else(|| invalid("A Cargo table is required".into()))?
        {
            let target = matches!(field.as_str(), "bin" | "test" | "example" | "bench");
            check_paths(
                value,
                name,
                snapshot,
                complete && (!target || selected_targets),
            )?;
        }
        if let Some(workspace) = manifest.get("workspace") {
            for field in ["members", "default-members", "exclude"] {
                if let Some(paths) = workspace.get(field).and_then(Value::as_array) {
                    for path in paths {
                        resolve(
                            name,
                            path.as_str().ok_or_else(|| {
                                invalid("Cargo workspace path must be a string".into())
                            })?,
                        )?;
                    }
                }
            }
        }
        check_build_inputs(
            root,
            name,
            manifest,
            snapshot,
            complete,
            libraries.contains(name),
        )?;
    }
    let mut contexts = Vec::new();
    for project in projects.iter().filter(|p| active.contains(&p.manifest)) {
        let mut context = project.clone();
        if !members.contains(&project.manifest) {
            let value = manifests
                .get(&project.manifest)
                .ok_or_else(|| invalid("Missing Cargo dependency manifest".into()))?;
            let package =
                locked_package(&project.manifest, value, &manifests, &selected.components)?
                    .ok_or_else(|| {
                        invalid("Local Cargo dependency is missing from the lock".into())
                    })?;
            let locked_names: BTreeSet<&str> = package.metadata["dependencies"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|dependency| dependency["name"].as_str())
                .collect();
            // Dependency development requirements do not propagate to consumers.
            // Optional dependencies absent from this package's locked edges are inactive.
            context.requirements.retain(|requirement| {
                requirement.kind != "dev"
                    && (requirement.source["optional"] != true
                        || locked_names.contains(requirement.name.as_str()))
            });
        }
        contexts.push(context);
    }
    Ok(contexts)
}

struct Dependency {
    manifest: String,
    conditional: bool,
}

fn dependencies(
    name: &str,
    value: &Value,
    manifests: &Manifests,
    include_dev: bool,
    root: bool,
) -> Result<Vec<Dependency>> {
    let mut result = Vec::new();
    dependency_sections(name, value, manifests, include_dev, &mut result)?;
    if let Some(targets) = value.get("target").and_then(Value::as_table) {
        for target in targets.values() {
            dependency_sections(name, target, manifests, include_dev, &mut result)?;
        }
    }
    if root {
        if let Some(patches) = value.get("patch").and_then(Value::as_table) {
            for patch in patches.values() {
                dependency_table(name, patch, manifests, true, &mut result)?;
            }
        }
        if let Some(replacements) = value.get("replace") {
            dependency_table(name, replacements, manifests, true, &mut result)?;
        }
    }
    Ok(result)
}

fn dependency_sections(
    name: &str,
    value: &Value,
    manifests: &Manifests,
    include_dev: bool,
    result: &mut Vec<Dependency>,
) -> Result<()> {
    for field in ["dependencies", "build-dependencies", "dev-dependencies"] {
        if field == "dev-dependencies" && !include_dev {
            continue;
        }
        if let Some(table) = value.get(field) {
            dependency_table(name, table, manifests, false, result)?;
        }
    }
    Ok(())
}

fn dependency_table(
    name: &str,
    value: &Value,
    manifests: &Manifests,
    conditional: bool,
    result: &mut Vec<Dependency>,
) -> Result<()> {
    let table = value
        .as_table()
        .ok_or_else(|| invalid("A Cargo dependency table is required".into()))?;
    for (alias, declaration) in table {
        let (origin, spec) = if declaration.get("workspace").and_then(Value::as_bool) == Some(true)
        {
            let (origin, workspace) = workspace(name, manifests)
                .ok_or_else(|| invalid(format!("Cargo workspace not found: {name}")))?;
            let spec = workspace
                .get("dependencies")
                .and_then(|deps| deps.get(alias))
                .ok_or_else(|| invalid(format!("Missing Cargo workspace dependency: {alias}")))?;
            (origin, spec)
        } else {
            (name, declaration)
        };
        let Some(path) = spec.get("path") else {
            continue;
        };
        let path = path
            .as_str()
            .ok_or_else(|| invalid("Cargo dependency path must be a string".into()))?;
        let path = resolve(origin, path)?;
        let manifest = if path.is_empty() {
            "Cargo.toml".into()
        } else {
            format!("{path}/Cargo.toml")
        };
        result.push(Dependency {
            manifest,
            conditional: conditional
                || declaration
                    .get("optional")
                    .and_then(Value::as_bool)
                    .or_else(|| spec.get("optional").and_then(Value::as_bool))
                    == Some(true),
        });
    }
    Ok(())
}

fn workspace<'a>(name: &'a str, manifests: &'a Manifests) -> Option<(&'a str, &'a Value)> {
    let mut current = name;
    loop {
        if let Some(value) = manifests
            .get(current)
            .and_then(|value| value.get("workspace"))
        {
            return Some((current, value));
        }
        let parent = Path::new(current).parent()?.parent()?;
        let ancestor = parent.join("Cargo.toml");
        // All returned names borrow the independently selected manifest index.
        current = manifests
            .get_key_value(ancestor.to_str()?)
            .map(|(name, _)| name.as_str())
            .or_else(|| {
                let mut ancestor = parent.parent();
                while let Some(parent) = ancestor {
                    let candidate = parent.join("Cargo.toml");
                    if let Some((name, _)) = manifests.get_key_value(candidate.to_str()?) {
                        return Some(name.as_str());
                    }
                    ancestor = parent.parent();
                }
                None
            })?;
    }
}

fn locked_package<'a>(
    name: &str,
    value: &Value,
    manifests: &Manifests,
    components: &'a [Component],
) -> Result<Option<&'a Component>> {
    let Some(package) = value.get("package") else {
        return Ok(None);
    };
    let package_name = package
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("Missing Cargo name: {name}")))?;
    let version = match package.get("version") {
        Some(value) if value.get("workspace").and_then(Value::as_bool) == Some(true) => {
            workspace(name, manifests)
                .and_then(|(_, workspace)| workspace.get("package"))
                .and_then(|package| package.get("version"))
                .and_then(Value::as_str)
                .ok_or_else(|| invalid(format!("Missing Cargo workspace version: {name}")))?
        }
        Some(value) => value
            .as_str()
            .ok_or_else(|| invalid(format!("Invalid Cargo version: {name}")))?,
        None => "0.0.0",
    };
    Ok(components.iter().find(|component| {
        component.source.is_null() && component.name == package_name && component.version == version
    }))
}

fn resolve(manifest: &str, path: &str) -> Result<String> {
    ensure!(
        !path.is_empty() && !path.contains('\\') && !path.chars().any(char::is_control),
        "Invalid Cargo path"
    );
    let parent = Path::new(manifest)
        .parent()
        .ok_or_else(|| invalid("Missing manifest parent".into()))?;
    let mut resolved = PathBuf::new();
    for part in parent.join(path).components() {
        match part {
            PathComponent::Normal(value) => resolved.push(value),
            PathComponent::CurDir => {}
            PathComponent::ParentDir => ensure!(resolved.pop(), "Cargo path is outside the scope"),
            _ => return Err(invalid("Absolute Cargo paths are not allowed".into())),
        }
    }
    resolved
        .into_os_string()
        .into_string()
        .map_err(|_| invalid("Non-UTF-8 Cargo path".into()))
}

fn check_paths(value: &Value, manifest: &str, snapshot: &Snapshot, complete: bool) -> Result<()> {
    match value {
        Value::Table(table) => {
            if let Some(path) = table.get("path").and_then(Value::as_str) {
                let path = resolve(manifest, path)?;
                if complete {
                    ensure!(
                        snapshot.contains_key(&path)
                            || snapshot.keys().any(
                                |name| path.is_empty() || name.starts_with(&format!("{path}/"))
                            ),
                        "Cargo path is missing from sources: {path}"
                    );
                }
            }
            for value in table.values() {
                check_paths(value, manifest, snapshot, complete)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                check_paths(value, manifest, snapshot, complete)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_build_inputs(
    root: &Path,
    name: &str,
    value: &Value,
    snapshot: &Snapshot,
    active: bool,
    library: bool,
) -> Result<()> {
    let Some(package) = value.get("package") else {
        return Ok(());
    };
    let build = match package.get("build") {
        Some(Value::String(path)) => Some(resolve(name, path)?),
        Some(Value::Boolean(true)) => Some(resolve(name, "build.rs")?),
        Some(Value::Boolean(false)) => None,
        None if active && exists(root, &resolve(name, "build.rs")?)? => {
            Some(resolve(name, "build.rs")?)
        }
        None => None,
        _ => return Err(invalid(format!("Invalid Cargo build entry: {name}"))),
    };
    if active {
        if let Some(build) = build {
            require_file(snapshot, &build)?;
        }
        if let Some(lib) = value.get("lib") {
            let path = lib
                .get("path")
                .map(|path| {
                    path.as_str()
                        .ok_or_else(|| invalid("Invalid Cargo lib path".into()))
                })
                .transpose()?
                .unwrap_or("src/lib.rs");
            require_file(snapshot, &resolve(name, path)?)?;
        } else {
            let path = resolve(name, "src/lib.rs")?;
            let enabled = package.get("autolib").and_then(Value::as_bool) != Some(false);
            ensure!(
                !library || enabled,
                "A Cargo library is required for a local dependency: {name}"
            );
            if library || (enabled && exists(root, &path)?) {
                require_file(snapshot, &path)?;
            }
        }
    }
    Ok(())
}

fn require_file(snapshot: &Snapshot, path: &str) -> Result<()> {
    ensure!(
        snapshot.contains_key(path),
        "Cargo build entry is missing from sources: {path}"
    );
    Ok(())
}

fn exists(root: &Path, path: &str) -> Result<bool> {
    match std::fs::symlink_metadata(root.join(path)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
