//! Validate an explicit preparation request without launching programs or fetching.
mod cargo;
mod npm;
use super::{invalid, Artifact, DependencyConfig, Preparation, Project};
use crate::{
    config::Tool,
    error::{ensure, Result},
    files,
    sources::Snapshot,
};
use base64::Engine;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub fn plan(
    root: &Path,
    snapshot: &Snapshot,
    config: &DependencyConfig,
    tools: &BTreeMap<String, Tool>,
) -> Result<Preparation> {
    config.validate()?;
    // Bind the entire selected source set, including workspace manifests and build inputs.
    for (name, record) in snapshot {
        crate::config::relative_path(name)?;
        ensure!(
            files::hash(&files::read_limited(&root.join(name), 16 * 1024 * 1024)?) == record.sha256,
            "Source modifiée depuis scan : {name}"
        );
    }
    let report = super::scan_snapshot(root, snapshot)?;
    report.validate()?;
    ensure!(
        report.complete,
        "Scan incomplet : {}",
        report
            .diagnostics
            .iter()
            .filter(|d| d.blocking)
            .map(|d| format!("{}: {}", d.file, d.message))
            .collect::<Vec<_>>()
            .join(" ; ")
    );
    let mut projects = Vec::new();
    for name in &config.projects {
        let inventory_project = report
            .projects
            .iter()
            .find(|p| &p.manifest == name)
            .ok_or_else(|| invalid(format!("Manifest absent du périmètre : {name}")))?;
        // Preparation remains self-contained even when inventory projects share a lock.
        let mut selected = inventory_project.clone();
        selected.components = report.components_for(inventory_project)?.to_vec();
        selected.components_from = None;
        let project = &selected;
        ensure!(project.locked, "Verrou requis avant préparation : {name}");
        let tool = match project.ecosystem.as_str() {
            "rust" => "rust",
            "python" => "python",
            "npm" => "node",
            _ => return Err(invalid("Écosystème non pris en charge".into())),
        };
        ensure!(
            tools.contains_key(tool),
            "Version exacte de {tool} requise dans les outils de la mission"
        );
        for (name, spec) in tools {
            ensure!(
                spec.phase == "runtime" && semver::Version::parse(&spec.version).is_ok(),
                "Version exacte invalide : {name}"
            );
        }
        let mut contexts = vec![project];
        let mut npm_local = BTreeSet::new();
        if project.ecosystem == "npm" {
            let validated = npm::validate(root, snapshot, project, &report.projects)?;
            contexts = validated.contexts;
            npm_local = validated.local_components;
        }
        let cargo_contexts = if project.ecosystem == "rust" {
            cargo::validate(root, snapshot, project, &report.projects)?
        } else {
            Vec::new()
        };
        if project.ecosystem == "rust" {
            contexts = cargo_contexts.iter().collect();
        }
        for required in contexts.iter().flat_map(|context| &context.tools) {
            // npm is bundled with Node; its constraints are checked against the actual
            // executable inside the Nix build, before any install scripts can run.
            if required.name == "npm" {
                continue;
            }
            let actual = tools.get(&required.name).ok_or_else(|| {
                invalid(format!("Outil requis non configuré : {}", required.name))
            })?;
            ensure!(
                tool_matches(&required.name, &actual.version, &required.constraint)?,
                "Version {} {} incompatible avec {} ({})",
                required.name,
                actual.version,
                required.constraint,
                required.file
            );
        }
        for component in &project.components {
            match project.ecosystem.as_str() {
                "rust" => ensure!(
                    component.source.is_null()
                        || component.source
                            == "registry+https://github.com/rust-lang/crates.io-index",
                    "Source Cargo non prise en charge : {}",
                    component.name
                ),
                "python" => {
                    let source = &component.source;
                    ensure!(
                        source.get("registry").is_some()
                            || source.get("virtual").is_some_and(|v| v == ".")
                            || source.get("editable").is_some_and(|v| v == "."),
                        "Source Python locale ou Git non prise en charge : {}",
                        component.name
                    );
                    if source.get("registry").is_some() {
                        ensure!(
                            !component.artifacts.is_empty(),
                            "Artefacts Python absents : {}",
                            component.name
                        );
                    }
                }
                "npm" => ensure!(
                    npm_local.contains(&component.context)
                        || (!component.artifacts.is_empty() && component.metadata["link"] != true),
                    "Source npm locale, Git ou sans intégrité non prise en charge : {}",
                    component.context
                ),
                _ => {}
            }
            if project.ecosystem == "npm" && !npm_local.contains(&component.context) {
                ensure!(
                    component.metadata["hasInstallScript"] != true,
                    "Script d’installation npm nécessitant une recette qualifiée : {}",
                    component.context
                );
            }
            for artifact in &component.artifacts {
                validate_artifact(artifact, config)?;
            }
        }
        match project.ecosystem.as_str() {
            "rust" => {
                for name in snapshot.keys() {
                    if name.ends_with(".cargo/config") || name.ends_with(".cargo/config.toml") {
                        super::cargo_config::validate(root, name)?;
                    }
                }
                for context in &contexts {
                    validate_requirements(context, &project.components, tools)?;
                }
            }
            "python" => {
                ensure!(
                    project.workspace.is_null(),
                    "Workspace uv non encore pris en charge pour la préparation"
                );
                validate_requirements(project, &project.components, tools)?;
            }
            _ => {}
        }
        let mut prepared = project.clone();
        if project.ecosystem == "npm" {
            prepared.tools = contexts
                .iter()
                .flat_map(|context| context.tools.clone())
                .collect();
        }
        projects.push(prepared);
    }
    Ok(Preparation {
        schema_version: 1,
        inputs: snapshot.clone(),
        projects,
        allowed_hosts: config.allowed_hosts.clone(),
        tools: tools.clone(),
    })
}

fn validate_artifact(artifact: &Artifact, config: &DependencyConfig) -> Result<()> {
    let url =
        url::Url::parse(&artifact.url).map_err(|_| invalid("URL de dépendance invalide".into()))?;
    ensure!(url.scheme() == "https" && url.username().is_empty() && url.password().is_none()
        && url.port().is_none_or(|port| port == 443) && url.query().is_none() && url.fragment().is_none()
        && !artifact.url.contains('\\') && url.host_str().is_some_and(|host| config.allowed_hosts.iter().any(|allowed| allowed == host)),
        "Source de dépendance HTTPS non autorisée (hôte explicite, sans identifiants ni redirection requis)");
    let hash = artifact
        .hash
        .as_deref()
        .ok_or_else(|| invalid("Empreinte de dépendance absente".into()))?;
    if let Some(hex) = hash.strip_prefix("sha256:") {
        ensure!(
            hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "Empreinte SHA-256 invalide"
        );
    } else {
        let (algorithm, encoded) = hash
            .split_once('-')
            .ok_or_else(|| invalid("Empreinte SRI requise".into()))?;
        let length = match algorithm {
            "sha256" => 32,
            "sha512" => 64,
            _ => return Err(invalid("SHA-256 ou SHA-512 requis".into())),
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("Empreinte SRI invalide".into()))?;
        ensure!(bytes.len() == length, "Taille d’empreinte invalide");
    }
    Ok(())
}

fn tool_matches(tool: &str, version: &str, requirement: &str) -> Result<bool> {
    match tool {
        "python" => {
            let requirement = if requirement.starts_with(|c: char| c.is_ascii_digit()) {
                if requirement.split('.').count() < 3 {
                    format!("=={requirement}.*")
                } else {
                    format!("=={requirement}")
                }
            } else {
                requirement.into()
            };
            python_matches(version, &requirement)
        }
        "node" | "npm" => npm_matches(version, requirement),
        "rust" => {
            let requirement = if requirement.starts_with(|c: char| c.is_ascii_digit()) {
                format!("={requirement}")
            } else {
                requirement.into()
            };
            rust_matches(version, &requirement)
        }
        _ => Err(invalid(format!(
            "Contrainte d’outil non prise en charge : {tool}"
        ))),
    }
}
fn python_matches(version: &str, requirement: &str) -> Result<bool> {
    ladybom::deps::constraints::python_matches(version, requirement).map_err(Into::into)
}
fn npm_matches(version: &str, requirement: &str) -> Result<bool> {
    ladybom::deps::constraints::npm_matches(version, requirement).map_err(Into::into)
}
fn rust_matches(version: &str, requirement: &str) -> Result<bool> {
    ladybom::deps::constraints::rust_matches(version, requirement).map_err(Into::into)
}

fn validate_requirements(
    project: &Project,
    components: &[super::Component],
    tools: &BTreeMap<String, Tool>,
) -> Result<()> {
    for requirement in &project.requirements {
        // Python build backends are unnecessary for wheel-only dependency installation.
        if project.ecosystem == "python"
            && (requirement.kind == "build" || requirement.kind.ends_with(":include"))
        {
            continue;
        }
        if project.ecosystem == "python" {
            if let Some(marker) = &requirement.marker {
                let version = &tools
                    .get("python")
                    .ok_or_else(|| invalid("Python non configuré".into()))?
                    .version;
                let marker: pep508_rs::MarkerTree = marker
                    .parse()
                    .map_err(|e| invalid(format!("Marqueur Python invalide : {e}")))?;
                // Only constrain facts known from the supported Nix target. Kernel
                // release/version remain symbolic; uv checks the actual build target.
                let target: pep508_rs::MarkerTree = format!("python_full_version == '{version}' and implementation_version == '{version}' and implementation_name == 'cpython' and platform_python_implementation == 'CPython' and sys_platform == 'linux' and os_name == 'posix' and platform_system == 'Linux' and platform_machine == 'x86_64'")
                    .parse().map_err(|e| invalid(format!("Cible Python invalide : {e}")))?;
                if marker.is_disjoint(&target) {
                    continue;
                }
            }
        }
        if project.ecosystem == "rust" && requirement.source.get("path").is_some() {
            continue;
        }
        let mut found = false;
        for component in components.iter().filter(|c| c.name == requirement.name) {
            if requirement.constraint.is_empty()
                || match project.ecosystem.as_str() {
                    "python" => python_matches(&component.version, &requirement.constraint)?,
                    "rust" => rust_matches(&component.version, &requirement.constraint)?,
                    _ => false,
                }
            {
                found = true;
                break;
            }
        }
        ensure!(
            found,
            "Exigence absente ou incompatible avec le verrou : {} {} ({})",
            requirement.name,
            requirement.constraint,
            project.manifest
        );
    }
    Ok(())
}

fn read_toml(root: &Path, name: &str) -> Result<toml::Value> {
    super::parse_toml(&String::from_utf8(files::read_limited(
        &root.join(name),
        8 * 1024 * 1024,
    )?)?)
}
