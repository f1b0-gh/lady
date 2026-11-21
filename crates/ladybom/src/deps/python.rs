use super::{
    basename, diagnostic, invalid, missing_lock, parse_toml, purl, sibling, Artifact, Component,
    Diagnostic, Inputs, Project, Requirement,
};
use crate::error::Result;
use pep508_rs::{Requirement as PepRequirement, VerbatimUrl, VersionOrUrl};
use serde_json::Value;

pub(crate) mod local;
mod pip;

/// Naming conventions for static discovery; pip also accepts arbitrary filenames.
pub(super) fn is_requirements_file(name: &str) -> bool {
    let file = basename(name);
    let Some(stem) = file
        .strip_suffix(".txt")
        .or_else(|| file.strip_suffix(".in"))
        .or_else(|| file.strip_suffix(".lock"))
    else {
        return false;
    };
    if stem.is_empty() {
        return false;
    }
    stem == "requirements"
        || stem
            .strip_prefix("requirements")
            .is_some_and(|suffix| suffix.len() > 1 && suffix.starts_with(['-', '_', '.']))
        || stem
            .strip_suffix("requirements")
            .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with(['-', '_', '.']))
        || name
            .rsplit_once('/')
            .is_some_and(|(parent, _)| basename(parent) == "requirements")
}

fn requirement(text: &str, kind: &str) -> Result<Requirement> {
    let parsed: PepRequirement<VerbatimUrl> = text
        .parse()
        .map_err(|e| invalid(format!("Exigence PEP 508 invalide : {e}")))?;
    let (constraint, source) = match parsed.version_or_url {
        Some(VersionOrUrl::VersionSpecifier(spec)) => (spec.to_string(), Value::Null),
        Some(VersionOrUrl::Url(url)) => (String::new(), Value::String(url.to_string())),
        None => (String::new(), Value::Null),
    };
    Ok(Requirement {
        declared_name: None,
        name: parsed.name.to_string(),
        constraint,
        kind: kind.into(),
        marker: parsed.marker.contents().map(|m| m.to_string()),
        extras: parsed.extras.into_iter().map(|e| e.to_string()).collect(),
        source,
    })
}

fn add_requirements(project: &mut Project, values: Option<&toml::Value>, kind: &str) -> Result<()> {
    if let Some(values) = values {
        let values = values
            .as_array()
            .ok_or_else(|| invalid(format!("Liste de dépendances Python requise : {kind}")))?;
        for value in values {
            if let Some(group) = value.get("include-group").and_then(toml::Value::as_str) {
                project.requirements.push(Requirement {
                    declared_name: None,
                    name: group.into(),
                    constraint: String::new(),
                    kind: format!("{kind}:include"),
                    marker: None,
                    extras: Vec::new(),
                    source: Value::Null,
                });
            } else {
                project.requirements.push(requirement(
                    value
                        .as_str()
                        .ok_or_else(|| invalid("Exigence Python textuelle requise".into()))?,
                    kind,
                )?);
            }
        }
    }
    Ok(())
}

pub(super) fn parse(
    name: &str,
    content: &str,
    inputs: &Inputs,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Project> {
    let manifest = parse_toml(content)?;
    let mut project = Project::new("python", "uv", name);
    project.manifest_package = local::manifest_package(&manifest);
    let declared = manifest.get("project");
    if let Some(value) = declared
        .and_then(|v| v.get("requires-python"))
        .and_then(toml::Value::as_str)
    {
        project.tool("python", value, name);
    }
    let version_file = sibling(name, ".python-version");
    if let Some(version) = inputs.get(&version_file) {
        project.tool("python", version.trim(), &version_file);
    }
    add_requirements(
        &mut project,
        declared.and_then(|v| v.get("dependencies")),
        "runtime",
    )?;
    if let Some(groups) = declared.and_then(|v| v.get("optional-dependencies")) {
        let groups = groups
            .as_table()
            .ok_or_else(|| invalid("Table optional-dependencies requise".into()))?;
        for (extra, values) in groups {
            add_requirements(&mut project, Some(values), &format!("extra:{extra}"))?;
        }
    }
    if let Some(groups) = manifest.get("dependency-groups") {
        let groups = groups
            .as_table()
            .ok_or_else(|| invalid("Table dependency-groups requise".into()))?;
        for (group, values) in groups {
            add_requirements(&mut project, Some(values), &format!("group:{group}"))?;
        }
    }
    add_requirements(
        &mut project,
        manifest.get("build-system").and_then(|v| v.get("requires")),
        "build",
    )?;
    let uv = manifest.get("tool").and_then(|v| v.get("uv"));
    add_requirements(
        &mut project,
        uv.and_then(|v| v.get("dev-dependencies")),
        "group:dev",
    )?;
    if let Some(workspace) = uv.and_then(|v| v.get("workspace")) {
        project.workspace = serde_json::to_value(workspace)?;
    }
    if let Some(sources) = uv
        .and_then(|v| v.get("sources"))
        .and_then(toml::Value::as_table)
    {
        for requirement in &mut project.requirements {
            if let Some(source) = sources.get(&requirement.name) {
                requirement.source = serde_json::to_value(source)?;
            }
        }
    }
    if declared
        .and_then(|v| v.get("dynamic"))
        .and_then(toml::Value::as_array)
        .is_some_and(|a| {
            a.iter()
                .any(|v| matches!(v.as_str(), Some("dependencies" | "optional-dependencies")))
        })
    {
        diagnostic(
            diagnostics,
            "dynamic_dependencies",
            name,
            "Métadonnées dynamiques : préparation confinée nécessaire",
            true,
        );
    }
    if declared.is_none() && manifest.get("tool").and_then(|v| v.get("poetry")).is_some() {
        diagnostic(
            diagnostics,
            "unsupported_manifest",
            name,
            "Métadonnées Poetry historiques non encore prises en charge",
            true,
        );
    }
    let lock_name = sibling(name, "uv.lock");
    if let Some(content) = inputs.get(&lock_name) {
        let lock = parse_toml(content)?;
        if lock.get("version").and_then(toml::Value::as_integer) != Some(1) {
            return Err(invalid("Version uv.lock non prise en charge".into()));
        }
        if let Some(value) = lock.get("requires-python").and_then(toml::Value::as_str) {
            project.tool("python", value, &lock_name);
        }
        let packages = lock
            .get("package")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| invalid("Liste package absente de uv.lock".into()))?;
        for package in packages {
            let package_name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("Nom de paquet Python absent".into()))?;
            let version = package
                .get("version")
                .and_then(toml::Value::as_str)
                .unwrap_or_default();
            let source = package
                .get("source")
                .map(serde_json::to_value)
                .transpose()?
                .unwrap_or(Value::Null);
            let registry = source.get("registry").is_some();
            let mut artifacts = Vec::new();
            for artifact in package.get("sdist").into_iter().chain(
                package
                    .get("wheels")
                    .and_then(toml::Value::as_array)
                    .into_iter()
                    .flatten(),
            ) {
                if let Some(url) = artifact.get("url").and_then(toml::Value::as_str) {
                    artifacts.push(Artifact {
                        url: url.into(),
                        hash: artifact
                            .get("hash")
                            .and_then(toml::Value::as_str)
                            .map(String::from),
                    });
                }
            }
            project.components.push(Component {
                name: package_name.into(),
                version: version.into(),
                purl: if registry && !version.is_empty() {
                    Some(purl("pypi", package_name, version)?)
                } else {
                    None
                },
                context: serde_json::to_string(&source)?,
                source,
                artifacts,
                metadata: serde_json::to_value(package)?,
            });
        }
        project.lockfile = Some(lock_name);
        project.locked = true;
    } else {
        for other in ["poetry.lock", "pylock.toml"] {
            let path = sibling(name, other);
            if inputs.contains_key(&path) {
                diagnostic(
                    diagnostics,
                    "unsupported_lockfile",
                    &path,
                    "Adaptateur de verrou non encore qualifié",
                    true,
                );
            }
        }
        missing_lock(&project, diagnostics);
    }
    Ok(project)
}

pub(super) fn requirements(
    name: &str,
    content: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Project> {
    if let Some(project) = pip::try_parse(name, content, diagnostics)? {
        return Ok(project);
    }
    let mut project = Project::new("python", "pip", name);
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') || line.ends_with('\\') || line.contains(" --hash=") {
            diagnostic(
                diagnostics,
                "unsupported_requirement_option",
                name,
                "Directive pip conservée dans la source ; résolution explicite nécessaire",
                true,
            );
            continue;
        }
        let line = line
            .split_once(" #")
            .map_or(line, |(requirement, _)| requirement);
        project.requirements.push(requirement(line, "runtime")?);
    }
    missing_lock(&project, diagnostics);
    Ok(project)
}
