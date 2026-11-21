//! Preserve Git evidence before using cargo-lock's normalized package model.
use super::git;
use crate::{
    deps::{invalid, parse_toml},
    error::{ensure, Result},
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn metadata(content: &str, lock: &cargo_lock::Lockfile) -> Result<Vec<Value>> {
    let raw = parse_toml(content)?;
    let packages = raw
        .get("package")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    ensure!(
        packages.len() == lock.packages.len(),
        "Paquets Cargo divergents"
    );
    let mut index = BTreeMap::<(&str, Option<&str>), Vec<&toml::Value>>::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        index.entry((name, None)).or_default().push(package);
        index
            .entry((name, Some(version)))
            .or_default()
            .push(package);
        if let Some(source) = package.get("source").and_then(toml::Value::as_str) {
            git::validate_selector(source)?;
        }
    }
    packages
        .iter()
        .zip(&lock.packages)
        .map(|(raw, package)| {
            // The native decoder preserves order; verify this before attaching raw evidence.
            ensure!(
                raw["name"].as_str() == Some(package.name.as_str())
                    && raw["version"].as_str() == Some(package.version.to_string().as_str()),
                "Ordre des paquets Cargo divergent"
            );
            let mut metadata = serde_json::to_value(package)?;
            if let Some(source) = raw
                .get("source")
                .and_then(toml::Value::as_str)
                .filter(|s| s.starts_with("git+"))
            {
                metadata["source"] = source.into();
            }
            if let Some(dependencies) = raw.get("dependencies").and_then(toml::Value::as_array) {
                ensure!(
                    dependencies.len() == package.dependencies.len(),
                    "Dépendances Cargo divergentes"
                );
                for (i, dependency) in dependencies.iter().enumerate() {
                    let dependency = dependency
                        .as_str()
                        .ok_or_else(|| invalid("Référence Cargo textuelle requise".into()))?;
                    let mut parts = dependency.split_whitespace();
                    let name = parts.next().unwrap_or_default();
                    let version = parts.next();
                    if let Some(source) = parts.next() {
                        let source = source
                            .strip_prefix('(')
                            .and_then(|s| s.strip_suffix(')'))
                            .ok_or_else(|| invalid("Source de référence Cargo invalide".into()))?;
                        git::validate_selector(source)?;
                        if source.starts_with("git+") {
                            metadata["dependencies"][i]["source"] = source.into();
                        }
                    } else if let Some(candidates) = index.get(&(name, version)) {
                        // With an explicit version, an omitted source can denote
                        // the local package among same-version remote packages.
                        let local: Vec<_> = candidates
                            .iter()
                            .filter(|p| p.get("source").is_none())
                            .collect();
                        if version.is_some() && local.len() == 1 {
                            metadata["dependencies"][i]["source"] = Value::Null;
                            continue;
                        }
                        ensure!(
                            candidates.len() <= 1,
                            "Référence Cargo abrégée ambiguë : {dependency}"
                        );
                        if let Some(source) = candidates
                            .first()
                            .and_then(|p| p.get("source"))
                            .and_then(toml::Value::as_str)
                            .filter(|s| s.starts_with("git+"))
                        {
                            metadata["dependencies"][i]["source"] = source.into();
                        }
                    }
                }
            }
            Ok(metadata)
        })
        .collect()
}
