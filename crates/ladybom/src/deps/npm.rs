use super::{
    ancestors, diagnostic, invalid, missing_lock, purl, sibling, Artifact, Component, Diagnostic,
    Inputs, Project, Requirement,
};
use crate::error::Result;
use serde_json::Value;
pub(crate) mod local;

pub(super) fn parse(
    name: &str,
    content: &str,
    inputs: &Inputs,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Project> {
    let manifest = crate::json::parse(content.as_bytes())?;
    if !manifest.is_object() {
        return Err(invalid("package.json object required".into()));
    }
    let mut project = Project::new("npm", "npm", name);
    project.manifest_package = local::manifest_package(&manifest);
    for (field, kind) in [
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    ] {
        if let Some(deps) = manifest.get(field) {
            for (name, spec) in deps
                .as_object()
                .ok_or_else(|| invalid(format!("Npm object required: {field}")))?
            {
                project.requirements.push(Requirement {
                    declared_name: None,
                    name: name.clone(),
                    constraint: spec
                        .as_str()
                        .ok_or_else(|| invalid("Npm constraint must be a string".into()))?
                        .into(),
                    kind: kind.into(),
                    marker: None,
                    extras: Vec::new(),
                    source: Value::Null,
                });
            }
        }
    }
    if let Some(engines) = manifest.get("engines") {
        let engines = engines
            .as_object()
            .ok_or_else(|| invalid("engines object required".into()))?;
        for (tool, constraint) in engines {
            let constraint = constraint
                .as_str()
                .ok_or_else(|| invalid("engines constraint must be a string".into()))?;
            project.tool(tool, constraint, name);
        }
    }
    if let Some(manager) = manifest.get("packageManager").and_then(Value::as_str) {
        if let Some((manager, version)) = manager.split_once('@') {
            project.manager = manager.into();
            project.tool(manager, version, name);
            if manager != "npm" {
                diagnostic(
                    diagnostics,
                    "unsupported_manager",
                    name,
                    format!("Declared package manager {manager}; npm preparation refused"),
                    true,
                );
            }
        } else {
            return Err(invalid(
                "packageManager must identify a package manager and its version".into(),
            ));
        }
    }
    for file in [".node-version", ".nvmrc"] {
        let path = sibling(name, file);
        if let Some(version) = inputs.get(&path) {
            project.tool("node", version.trim(), &path);
        }
    }
    project.workspace = manifest.get("workspaces").cloned().unwrap_or(Value::Null);
    let shrinkwrap = sibling(name, "npm-shrinkwrap.json");
    let mut lock_name = if inputs.contains_key(&shrinkwrap) {
        shrinkwrap
    } else {
        sibling(name, "package-lock.json")
    };
    if !inputs.contains_key(&lock_name) {
        if let Some(inherited) = workspace_lock(name, inputs)? {
            lock_name = inherited;
        }
    }
    if let Some(content) = inputs.get(&lock_name) {
        let lock = crate::json::parse(content.as_bytes())?;
        if !matches!(lock["lockfileVersion"].as_u64(), Some(2 | 3)) {
            return Err(invalid("package-lock.json version 2 or 3 required".into()));
        }
        let packages = lock["packages"]
            .as_object()
            .ok_or_else(|| invalid("packages object missing from the npm lockfile".into()))?;
        for (path, package) in packages {
            if path.is_empty() {
                continue;
            }
            crate::config::relative_path(path)?;
            let inferred = path.rsplit_once("node_modules/").map(|(_, name)| name);
            let package_name = package
                .get("name")
                .and_then(Value::as_str)
                .or(inferred)
                .unwrap_or(path);
            let version = package
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let source = package.get("resolved").cloned().unwrap_or(Value::Null);
            let local = !path.split('/').any(|part| part == "node_modules")
                || package["link"] == true
                || source
                    .as_str()
                    .is_some_and(|s| s.starts_with("file:") || !s.contains("://"));
            let artifacts = source
                .as_str()
                .filter(|s| s.starts_with("https://") || s.starts_with("http://"))
                .map(|url| {
                    vec![Artifact {
                        url: url.into(),
                        hash: package
                            .get("integrity")
                            .and_then(Value::as_str)
                            .map(String::from),
                    }]
                })
                .unwrap_or_default();
            project.components.push(Component {
                name: package_name.into(),
                version: version.into(),
                purl: if !local && !version.is_empty() {
                    Some(purl("npm", package_name, version)?)
                } else {
                    None
                },
                context: path.clone(),
                source,
                artifacts,
                metadata: package.clone(),
            });
        }
        project.lockfile = Some(lock_name);
        project.locked = true;
    } else {
        for other in ["yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"] {
            let path = sibling(name, other);
            if inputs.contains_key(&path) {
                diagnostic(
                    diagnostics,
                    "unsupported_lockfile",
                    &path,
                    "Lockfile from another package manager; npm resolution is not assumed",
                    true,
                );
            }
        }
        missing_lock(&project, diagnostics);
    }
    Ok(project)
}

// Inheritance is inventory evidence only. Preparation independently validates the
// complete selected workspace, manifests, links, artifacts and authorization.
fn workspace_lock(name: &str, inputs: &Inputs) -> Result<Option<String>> {
    let mut inherited = None;
    for ancestor in ancestors(name, "package.json").into_iter().skip(1) {
        let Some(content) = inputs.get(&ancestor) else {
            continue;
        };
        let manifest = crate::json::parse(content.as_bytes())?;
        let Some(members) = manifest["workspaces"].as_array() else {
            continue;
        };
        let prefix = ancestor
            .strip_suffix("package.json")
            .ok_or_else(|| invalid("Invalid npm manifest".into()))?;
        let declared = members.iter().filter_map(Value::as_str).any(|member| {
            crate::config::relative_path(member).is_ok()
                && !member.chars().any(|c| "*?[]{}!\\():".contains(c))
                && name == format!("{prefix}{member}/package.json")
        });
        if !declared {
            continue;
        }
        let shrinkwrap = sibling(&ancestor, "npm-shrinkwrap.json");
        let lock = if inputs.contains_key(&shrinkwrap) {
            shrinkwrap
        } else {
            sibling(&ancestor, "package-lock.json")
        };
        if inputs.contains_key(&lock) {
            if inherited.is_some() {
                return Err(invalid(format!(
                    "Ambiguous npm workspace membership: {name}"
                )));
            }
            inherited = Some(lock);
        }
    }
    Ok(inherited)
}
