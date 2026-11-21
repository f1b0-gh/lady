//! Verify explicitly selected npm workspaces against source manifests and the root lock.
use super::{invalid, npm_matches};
use crate::{
    deps::Project,
    error::{ensure, Result},
    files,
    sources::Snapshot,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(super) struct Validated<'a> {
    pub contexts: Vec<&'a Project>,
    pub local_components: BTreeSet<String>,
}

pub(super) fn validate<'a>(
    root: &Path,
    snapshot: &Snapshot,
    project: &'a Project,
    projects: &'a [Project],
) -> Result<Validated<'a>> {
    let manifest = read(root, &project.manifest)?;
    let lockfile = project
        .lockfile
        .as_ref()
        .ok_or_else(|| invalid("Verrou npm absent".into()))?;
    ensure!(
        Path::new(lockfile).parent() == Path::new(&project.manifest).parent(),
        "Préparation npm requise depuis la racine du verrou partagé"
    );
    let lock = read(root, lockfile)?;
    let packages = lock["packages"]
        .as_object()
        .ok_or_else(|| invalid("Objet packages absent du verrou npm".into()))?;
    let entry = packages
        .get("")
        .ok_or_else(|| invalid("Entrée racine absente du verrou npm".into()))?;
    compare_dependencies(&manifest, entry, &project.manifest)?;
    ensure!(
        manifest.get("workspaces") == entry.get("workspaces"),
        "Workspaces npm divergents entre manifest et verrou"
    );
    let members = explicit_members(&project.workspace)?;
    let mut validated = Validated {
        contexts: vec![project],
        local_components: BTreeSet::new(),
    };
    let mut names = BTreeSet::new();
    let mut manifests = BTreeMap::from([(String::new(), manifest)]);
    for member in &members {
        let name = if project.root == "." {
            format!("{member}/package.json")
        } else {
            format!("{}/{member}/package.json", project.root)
        };
        ensure!(
            snapshot.contains_key(&name),
            "Manifest workspace npm absent des sources : {name}"
        );
        let context = projects
            .iter()
            .find(|p| p.ecosystem == "npm" && p.manifest == name)
            .ok_or_else(|| invalid(format!("Manifest workspace npm absent du rapport : {name}")))?;
        ensure!(
            context.workspace.is_null(),
            "Workspace npm imbriqué non pris en charge : {name}"
        );
        for filename in ["package-lock.json", "npm-shrinkwrap.json"] {
            let local_lock = format!(
                "{}{filename}",
                name.strip_suffix("package.json")
                    .ok_or_else(|| invalid("Manifest npm invalide".into()))?
            );
            ensure!(
                !snapshot.contains_key(&local_lock),
                "Verrou npm membre ambigu : {local_lock}"
            );
        }
        let manifest = read(root, &name)?;
        let entry = packages
            .get(member)
            .ok_or_else(|| invalid(format!("Membre absent du verrou npm : {member}")))?;
        ensure!(
            entry.get("resolved").is_none()
                && entry.get("link").is_none()
                && entry.get("integrity").is_none(),
            "Entrée locale workspace npm invalide : {member}"
        );
        compare_dependencies(&manifest, entry, &name)?;
        for field in [
            "name",
            "version",
            "engines",
            "peerDependenciesMeta",
            "bin",
            "os",
            "cpu",
            "libc",
        ] {
            ensure!(
                manifest.get(field) == entry.get(field),
                "Manifest et verrou npm divergents : {name} ({field})"
            );
        }
        let package_name = manifest["name"]
            .as_str()
            .ok_or_else(|| invalid(format!("Nom workspace npm absent : {name}")))?;
        validate_package_name(package_name)?;
        ensure!(
            names.insert(package_name.to_owned()),
            "Nom workspace npm dupliqué : {package_name}"
        );
        let version = manifest["version"]
            .as_str()
            .ok_or_else(|| invalid(format!("Version workspace npm absente : {name}")))?;
        npm_matches(version, "*")?;
        let link_path = format!("node_modules/{package_name}");
        let link = packages
            .get(&link_path)
            .ok_or_else(|| invalid(format!("Lien workspace npm absent : {link_path}")))?;
        ensure!(
            link["link"] == true
                && link["resolved"] == member.as_str()
                && link.get("integrity").is_none(),
            "Lien workspace npm invalide : {link_path}"
        );
        validated.local_components.insert(member.clone());
        validated.local_components.insert(link_path);
        validated.contexts.push(context);
        manifests.insert(member.clone(), manifest);
    }
    // Only declared members and their exact links may omit an authorized archive.
    for component in &project.components {
        if component.metadata["link"] == true {
            ensure!(
                validated.local_components.contains(&component.context),
                "Lien npm hors workspace autorisé : {}",
                component.context
            );
        }
        if !validated.local_components.contains(&component.context) {
            ensure!(
                component.context.starts_with("node_modules/")
                    || members.iter().any(|member| component
                        .context
                        .starts_with(&format!("{member}/node_modules/"))),
                "Emplacement npm hors des racines de paquets déclarées : {}",
                component.context
            );
        }
    }
    for (scope, manifest) in &manifests {
        let context = if scope.is_empty() {
            project
        } else {
            validated
                .contexts
                .iter()
                .copied()
                .find(|p| {
                    let suffix = format!("{scope}/package.json");
                    p.manifest == suffix || p.manifest == format!("{}/{suffix}", project.root)
                })
                .ok_or_else(|| invalid("Contexte workspace npm absent".into()))?
        };
        for requirement in &context.requirements {
            validate_package_name(&requirement.name)?;
            ensure!(
                !requirement.constraint.starts_with("npm:"),
                "Alias npm non encore qualifié : {}",
                requirement.name
            );
            let component = resolve(packages, scope, &requirement.name);
            if let Some(component) = component {
                let target = if component["link"] == true {
                    let target = component["resolved"]
                        .as_str()
                        .ok_or_else(|| invalid("Cible lien npm absente".into()))?;
                    ensure!(
                        members.contains(target),
                        "Cible lien npm hors workspace : {target}"
                    );
                    packages
                        .get(target)
                        .ok_or_else(|| invalid("Membre lié absent".into()))?
                } else {
                    component
                };
                ensure!(
                    npm_matches(
                        target["version"].as_str().unwrap_or(""),
                        &requirement.constraint
                    )?,
                    "Version npm incompatible : {} ({})",
                    requirement.name,
                    context.manifest
                );
            } else {
                ensure!(
                    requirement.kind == "peer"
                        && manifest["peerDependenciesMeta"][&requirement.name]["optional"] == true,
                    "Dépendance npm absente du verrou : {} ({})",
                    requirement.name,
                    context.manifest
                );
            }
        }
    }
    Ok(validated)
}

fn explicit_members(workspace: &Value) -> Result<BTreeSet<String>> {
    if workspace.is_null() {
        return Ok(BTreeSet::new());
    }
    let values = workspace
        .as_array()
        .ok_or_else(|| invalid("Tableau de chemins npm explicites requis".into()))?;
    ensure!(values.len() <= 64, "Maximum 64 membres workspace npm");
    let mut members = BTreeSet::new();
    for value in values {
        let path = value
            .as_str()
            .ok_or_else(|| invalid("Chemin workspace npm textuel requis".into()))?;
        crate::config::relative_path(path)?;
        ensure!(
            !path.chars().any(|c| "*?[]{}!\\():".contains(c))
                && !path.split('/').any(|p| p == "node_modules"),
            "Chemin workspace npm explicite requis : {path}"
        );
        ensure!(
            members.insert(path.to_owned()),
            "Membre workspace npm dupliqué : {path}"
        );
    }
    Ok(members)
}

fn validate_package_name(name: &str) -> Result<()> {
    let parts: Vec<_> = name.split('/').collect();
    ensure!(
        (parts.len() == 1 && !name.starts_with('@'))
            || (parts.len() == 2 && parts[0].starts_with('@') && parts[0].len() > 1),
        "Nom npm invalide : {name}"
    );
    crate::config::relative_path(name)?;
    ensure!(
        !name.contains('\\') && !name.contains(':'),
        "Nom npm invalide : {name}"
    );
    Ok(())
}

fn compare_dependencies(manifest: &Value, entry: &Value, name: &str) -> Result<()> {
    ensure!(
        entry.is_object(),
        "Entrée manifest absente du verrou npm : {name}"
    );
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        ensure!(
            manifest.get(field) == entry.get(field),
            "Manifest et verrou npm divergents : {name} ({field})"
        );
    }
    Ok(())
}

fn resolve<'a>(
    packages: &'a serde_json::Map<String, Value>,
    initial: &str,
    name: &str,
) -> Option<&'a Value> {
    let mut scope = initial;
    loop {
        let path = if scope.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{scope}/node_modules/{name}")
        };
        if let Some(value) = packages.get(&path) {
            return Some(value);
        }
        if scope.is_empty() {
            return None;
        }
        scope = scope.rsplit_once('/').map_or("", |(parent, _)| parent);
    }
}

fn read(root: &Path, name: &str) -> Result<Value> {
    crate::json::parse(&files::read_limited(&root.join(name), 8 * 1024 * 1024)?)
}
