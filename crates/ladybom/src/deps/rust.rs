use super::{
    diagnostic, invalid, missing_lock, parse_toml, purl, sibling, Artifact, Component, Diagnostic,
    Inputs, ManifestPackage, Project, Requirement,
};
use crate::error::Result;

pub(super) mod git;
mod lock;

fn requirements(
    project: &mut Project,
    table: &toml::Value,
    marker: Option<&str>,
    workspace: Option<&toml::Value>,
    workspace_manifest: Option<&str>,
) -> Result<()> {
    for (key, kind) in [
        ("dependencies", "runtime"),
        ("build-dependencies", "build"),
        ("dev-dependencies", "dev"),
    ] {
        if let Some(values) = table.get(key) {
            let values = values
                .as_table()
                .ok_or_else(|| invalid(format!("Table Cargo requise : {key}")))?;
            for (alias, spec) in values {
                if !spec.is_str() && !spec.is_table() {
                    return Err(invalid(format!("Dépendance Cargo invalide : {alias}")));
                }
                let inherited;
                let is_inherited =
                    spec.get("workspace").and_then(toml::Value::as_bool) == Some(true);
                let spec = if is_inherited {
                    let value = workspace
                        .and_then(|w| w.get("dependencies"))
                        .and_then(|d| d.get(alias))
                        .ok_or_else(|| {
                            invalid(format!("Dépendance workspace introuvable : {alias}"))
                        })?;
                    let mut table = if let Some(version) = value.as_str() {
                        toml::map::Map::from_iter([(
                            "version".into(),
                            toml::Value::String(version.into()),
                        )])
                    } else {
                        value
                            .as_table()
                            .ok_or_else(|| invalid("Dépendance workspace invalide".into()))?
                            .clone()
                    };
                    if let Some(extra) = spec.get("features") {
                        let mut features = table
                            .get("features")
                            .and_then(toml::Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        features.extend(
                            extra
                                .as_array()
                                .ok_or_else(|| invalid("Liste features requise".into()))?
                                .clone(),
                        );
                        table.insert("features".into(), toml::Value::Array(features));
                    }
                    if let Some(optional) = spec.get("optional") {
                        table.insert("optional".into(), optional.clone());
                    }
                    inherited = toml::Value::Table(table);
                    &inherited
                } else {
                    spec
                };
                let name = spec
                    .get("package")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(alias);
                let constraint = spec
                    .as_str()
                    .or_else(|| spec.get("version").and_then(toml::Value::as_str))
                    .unwrap_or_default();
                let extras = if let Some(features) = spec.get("features") {
                    features
                        .as_array()
                        .ok_or_else(|| invalid("Liste features requise".into()))?
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .map(String::from)
                                .ok_or_else(|| invalid("Feature textuelle requise".into()))
                        })
                        .collect::<Result<Vec<_>>>()?
                } else {
                    Vec::new()
                };
                let mut source = serde_json::to_value(spec)?;
                if let Some(table) = source.as_object_mut() {
                    // This reserved evidence is always overwritten, never accepted
                    // from arbitrary fields supplied by a manifest author.
                    table.remove("_ladybom_declaration_manifest");
                    if table.contains_key("path") {
                        let origin = if is_inherited {
                            workspace_manifest.unwrap_or(&project.manifest)
                        } else {
                            &project.manifest
                        };
                        table.insert("_ladybom_declaration_manifest".into(), origin.into());
                    }
                }
                project.requirements.push(Requirement {
                    name: name.into(),
                    declared_name: (alias != name).then(|| alias.clone()),
                    constraint: constraint.into(),
                    kind: kind.into(),
                    marker: marker.map(String::from),
                    extras,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn workspace(
    name: &str,
    manifest: &toml::Value,
    inputs: &Inputs,
) -> Result<Option<(String, toml::Value)>> {
    if let Some(workspace) = manifest.get("workspace") {
        return Ok(Some((name.into(), workspace.clone())));
    }
    if manifest
        .get("package")
        .and_then(|p| p.get("workspace"))
        .is_some()
    {
        return Err(invalid(
            "package.workspace explicite non pris en charge ; aucun chemin externe suivi".into(),
        ));
    }
    let member_root = name.rsplit_once('/').map_or("", |(root, _)| root);
    for candidate in super::ancestors(name, "Cargo.toml").into_iter().skip(1) {
        let Some(content) = inputs.get(&candidate) else {
            continue;
        };
        let manifest = parse_toml(content)?;
        let Some(workspace) = manifest.get("workspace") else {
            continue;
        };
        let root = candidate.rsplit_once('/').map_or("", |(root, _)| root);
        let relative = if root.is_empty() {
            member_root
        } else {
            member_root
                .strip_prefix(&format!("{root}/"))
                .ok_or_else(|| invalid("Racine workspace invalide".into()))?
        };
        let matches = |key: &str| -> Result<bool> {
            let Some(patterns) = workspace.get(key) else {
                return Ok(false);
            };
            for pattern in patterns
                .as_array()
                .ok_or_else(|| invalid("Liste workspace requise".into()))?
            {
                let pattern = pattern
                    .as_str()
                    .ok_or_else(|| invalid("Motif workspace textuel requis".into()))?;
                crate::config::relative_path(pattern)?;
                let glob = globset::GlobBuilder::new(pattern)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| invalid(e.to_string()))?;
                if glob.compile_matcher().is_match(relative) {
                    return Ok(true);
                }
            }
            Ok(false)
        };
        if matches("members")? && !matches("exclude")? {
            return Ok(Some((candidate, workspace.clone())));
        }
        break;
    }
    Ok(None)
}

pub(super) fn parse(
    name: &str,
    content: &str,
    inputs: &Inputs,
    diagnostics: &mut Vec<Diagnostic>,
    locks: &mut std::collections::BTreeMap<String, Vec<Component>>,
) -> Result<Project> {
    let manifest = parse_toml(content)?;
    if manifest.get("package").is_none() && manifest.get("workspace").is_none() {
        return Err(invalid("Cargo.toml sans package ni workspace".into()));
    }
    let mut project = Project::new("rust", "cargo", name);
    let workspace = workspace(name, &manifest, inputs)?;
    let workspace_data = workspace.as_ref().map(|(_, value)| value);
    let workspace_manifest = workspace.as_ref().map(|(name, _)| name.as_str());
    if let Some(package) = manifest.get("package") {
        let version = package.get("version");
        let version = if version
            .and_then(|v| v.get("workspace"))
            .and_then(toml::Value::as_bool)
            == Some(true)
        {
            workspace_data
                .and_then(|w| w.get("package"))
                .and_then(|p| p.get("version"))
        } else {
            version
        };
        if let (Some(name), Some(version)) = (
            package.get("name").and_then(toml::Value::as_str),
            version.and_then(toml::Value::as_str),
        ) {
            semver::Version::parse(version).map_err(|e| invalid(e.to_string()))?;
            project.manifest_package = Some(ManifestPackage {
                name: name.into(),
                version: version.into(),
            });
        }
    }
    let minimum = manifest.get("package").and_then(|p| p.get("rust-version"));
    let minimum = if minimum
        .and_then(|v| v.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true)
    {
        Some(
            workspace_data
                .and_then(|v| v.get("package"))
                .and_then(|p| p.get("rust-version"))
                .ok_or_else(|| invalid("rust-version workspace introuvable".into()))?,
        )
    } else {
        minimum
    };
    if let Some(minimum) = minimum.and_then(toml::Value::as_str) {
        project.tool("rust", &format!(">={minimum}"), name);
    }
    for candidate in super::ancestors(name, "rust-toolchain.toml") {
        let mut found = false;
        for file in ["rust-toolchain.toml", "rust-toolchain"] {
            let path = sibling(&candidate, file);
            if let Some(content) = inputs.get(&path) {
                found = true;
                if file.ends_with(".toml") || content.trim_start().starts_with('[') {
                    let data = parse_toml(content)?;
                    if let Some(channel) = data
                        .get("toolchain")
                        .and_then(|v| v.get("channel"))
                        .and_then(toml::Value::as_str)
                    {
                        project.tool("rust", channel, &path);
                    }
                } else {
                    project.tool("rust", content.trim(), &path);
                }
            }
        }
        if found {
            break;
        }
    }
    requirements(
        &mut project,
        &manifest,
        None,
        workspace_data,
        workspace_manifest,
    )?;
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for (target, table) in targets {
            requirements(
                &mut project,
                table,
                Some(target),
                workspace_data,
                workspace_manifest,
            )?;
        }
    }
    if let Some(workspace) = manifest.get("workspace") {
        project.workspace = serde_json::to_value(workspace)?;
    }
    let lock_name = sibling(
        workspace.as_ref().map_or(name, |(name, _)| name),
        "Cargo.lock",
    );
    if let Some(content) = inputs.get(&lock_name) {
        if let Some(components) = locks.get(&lock_name) {
            project.components = components.clone();
        } else {
            let lock: cargo_lock::Lockfile = content
                .parse()
                .map_err(|e| invalid(format!("Cargo.lock invalide : {e}")))?;
            let metadata = lock::metadata(content, &lock)?;
            for (package, metadata) in lock.packages.into_iter().zip(metadata) {
                let package_name = package.name.to_string();
                let version = package.version.to_string();
                let source = metadata
                    .get("source")
                    .and_then(serde_json::Value::as_str)
                    .map(String::from);
                let registry = source.as_deref()
                    == Some("registry+https://github.com/rust-lang/crates.io-index");
                let artifacts = if registry {
                    vec![Artifact { url: format!("https://static.crates.io/crates/{package_name}/{package_name}-{version}.crate"),
                    hash: package.checksum.as_ref().map(|h| format!("sha256:{h}")) }]
                } else {
                    Vec::new()
                };
                if source.is_some() && !registry {
                    diagnostic(diagnostics, "non_default_source", &lock_name, format!("Source Cargo spécifique pour {package_name} : validation requise avant préparation"), false);
                }
                project.components.push(Component {
                    name: package_name.clone(),
                    version: version.clone(),
                    purl: if registry {
                        Some(purl("cargo", &package_name, &version)?)
                    } else {
                        git::purl(&package_name, &version, source.as_deref())?
                    },
                    context: source.clone().unwrap_or_else(|| "workspace".into()),
                    source: serde_json::to_value(source)?,
                    artifacts,
                    metadata,
                });
            }
            locks.insert(lock_name.clone(), project.components.clone());
        }
        project.lockfile = Some(lock_name);
        project.locked = true;
    } else {
        missing_lock(&project, diagnostics);
    }
    Ok(project)
}
