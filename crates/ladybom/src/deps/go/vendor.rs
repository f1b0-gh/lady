//! Observations from vendor/modules.txt, with selected-manifest consistency checks.
use super::{
    manifest::{self, Manifest, Replacement},
    syntax::MAX_ITEMS,
};
use crate::{
    deps::{diagnostic, invalid, Component, Inputs, Report},
    error::Result,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Default)]
struct Entry {
    path: String,
    version: Option<String>,
    replacement: Option<Replacement>,
    explicit: bool,
    go: Option<String>,
    packages: Vec<String>,
}
fn parse(content: &str) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;
    let mut seen = BTreeSet::new();
    let mut package_count = 0;
    let mut packaged_versions = BTreeMap::new();
    for line in content.lines().map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(header) = line.strip_prefix("# ") {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            let words: Vec<String> = header
                .split_whitespace()
                .take(7)
                .map(String::from)
                .collect();
            if words.is_empty()
                || words.len() > 6
                || words
                    .iter()
                    .any(|w| w.len() > 4096 || w.chars().any(char::is_control))
            {
                return Err(invalid("Empty Go vendor module header".into()));
            }
            manifest::path(&words[0])?;
            let replacement = if words.iter().any(|w| w == "=>") {
                Some(manifest::replacement(&words)?)
            } else {
                None
            };
            let version = words.get(1).filter(|s| s.as_str() != "=>").cloned();
            if let Some(version) = &version {
                manifest::version(version)?;
            }
            if replacement.is_none() && (version.is_none() || words.len() != 2) {
                return Err(invalid("Invalid Go vendor module header".into()));
            }
            if !seen.insert((words[0].clone(), version.clone())) {
                return Err(invalid("Duplicate Go vendor module".into()));
            }
            if seen.len() > MAX_ITEMS {
                return Err(invalid("Go vendor module count limit exceeded".into()));
            }
            current = Some(Entry {
                path: words[0].clone(),
                version,
                replacement,
                ..Entry::default()
            });
        } else if let Some(metadata) = line.strip_prefix("## ") {
            if metadata == "workspace" && current.is_none() {
                continue;
            }
            let entry = current
                .as_mut()
                .ok_or_else(|| invalid("Go vendor metadata without a module".into()))?;
            for field in metadata.split(';').map(str::trim) {
                if field == "explicit" && !entry.explicit {
                    entry.explicit = true;
                } else if let Some(version) = field.strip_prefix("go ") {
                    if entry.go.is_some() || !manifest::go_version(version) {
                        return Err(invalid("Duplicate vendor Go version".into()));
                    }
                    entry.go = Some(version.into());
                } else {
                    return Err(invalid("Unsupported Go vendor metadata".into()));
                }
            }
        } else {
            manifest::path(line)?;
            let entry = current
                .as_mut()
                .ok_or_else(|| invalid("Go vendor package without a module".into()))?;
            if !(line == entry.path || line.starts_with(&format!("{}/", entry.path))) {
                return Err(invalid("Go vendor package outside its module".into()));
            }
            if entry.packages.iter().any(|p| p == line) {
                return Err(invalid("Duplicate Go vendor package".into()));
            }
            if let Some(previous) =
                packaged_versions.insert(entry.path.clone(), entry.version.clone())
            {
                if previous != entry.version {
                    return Err(invalid(
                        "Multiple vendored package versions for one Go module".into(),
                    ));
                }
            }
            package_count += 1;
            if package_count > MAX_ITEMS {
                return Err(invalid("Go vendor package count limit exceeded".into()));
            }
            entry.packages.push(line.into());
        }
    }
    if let Some(entry) = current {
        entries.push(entry);
    }
    Ok(entries)
}
fn purl(path: &str, version: &str) -> Result<String> {
    let (namespace, name) = path.rsplit_once('/').unwrap_or(("", path));
    let mut purl =
        packageurl::PackageUrl::new("golang", name).map_err(|e| invalid(e.to_string()))?;
    if !namespace.is_empty() {
        purl.with_namespace(namespace)
            .map_err(|e| invalid(e.to_string()))?;
    }
    purl.with_version(version)
        .map_err(|e| invalid(e.to_string()))?;
    Ok(purl.to_string())
}
pub(super) fn scan(
    inputs: &Inputs,
    manifests: &BTreeMap<String, Manifest>,
    memberships: &BTreeMap<String, Vec<String>>,
    report: &mut Report,
) {
    for (name, content) in inputs.iter().filter(|(n, _)| super::is_vendor(n)) {
        let Some(prefix) = name.strip_suffix("vendor/modules.txt") else {
            continue;
        };
        let work = format!("{prefix}go.work");
        let module = format!("{prefix}go.mod");
        let owner = if manifests.contains_key(&work) {
            &work
        } else {
            &module
        };
        let Some(index) = report.projects.iter().position(|p| &p.manifest == owner) else {
            diagnostic(
                &mut report.diagnostics,
                "go_orphan_input",
                name,
                "Vendor inventory has no selected valid owning Go manifest",
                true,
            );
            continue;
        };
        let entries = match parse(content) {
            Ok(e) => e,
            Err(e) => {
                diagnostic(
                    &mut report.diagnostics,
                    "invalid_go_vendor",
                    name,
                    e.to_string(),
                    true,
                );
                continue;
            }
        };
        let contexts: Vec<_> = if owner == &work {
            memberships
                .iter()
                .filter(|(_, ws)| ws.contains(&work))
                .filter_map(|(n, _)| report.projects.iter().find(|p| &p.manifest == n))
                .collect()
        } else {
            vec![&report.projects[index]]
        };
        let mut issues = Vec::new();
        let entry_index: BTreeMap<_, _> = entries
            .iter()
            .map(|e| ((e.path.as_str(), e.version.as_deref()), e))
            .collect();
        let requirements: BTreeSet<_> = contexts
            .iter()
            .flat_map(|p| {
                p.requirements
                    .iter()
                    .map(|r| (r.name.as_str(), r.constraint.as_str()))
            })
            .collect();
        let exclusions: BTreeSet<_> = contexts
            .iter()
            .filter_map(|p| manifests.get(&p.manifest))
            .flat_map(|m| m.excludes.iter().map(|(p, v)| (p.as_str(), v.as_str())))
            .collect();
        let modern = owner == &work
            || manifests
                .get(owner)
                .and_then(|m| m.go.as_deref())
                .is_some_and(|v| {
                    let mut parts = v.split('.');
                    let major = parts
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                    let minor = parts
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                    major > 1 || major == 1 && minor >= 14
                });
        if modern {
            for project in &contexts {
                for requirement in &project.requirements {
                    if !entry_index
                        .get(&(
                            requirement.name.as_str(),
                            Some(requirement.constraint.as_str()),
                        ))
                        .is_some_and(|e| e.explicit)
                    {
                        issues.push(format!(
                            "{} is missing, has a different version, or is not marked explicit",
                            requirement.name
                        ));
                        continue;
                    }
                }
            }
            let replacements: Vec<_> = report.projects[index].workspace["go"]
                ["effective_replacements"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let replacement_index: BTreeMap<_, _> = replacements
                .iter()
                .map(|r| {
                    (
                        (
                            r["path"].as_str().unwrap_or_default(),
                            r["version"].as_str(),
                        ),
                        r,
                    )
                })
                .collect();
            let destination = |origin: &str,
                               target: &str,
                               version: Option<&str>|
             -> Option<(String, Option<String>)> {
                if let Some(version) = version {
                    Some((target.to_owned(), Some(version.to_owned())))
                } else {
                    super::local_manifest(origin, target).map(|p| (p, None))
                }
            };
            for expected in &replacements {
                let path = expected["path"].as_str().unwrap_or_default();
                let version = expected["version"].as_str();
                let workspace_member = owner == &work
                    && contexts
                        .iter()
                        .any(|p| p.manifest_package.as_ref().is_some_and(|m| m.name == path));
                if version.is_none() && workspace_member {
                    continue;
                }
                if !entry_index
                    .get(&(path, version))
                    .is_some_and(|e| e.replacement.is_some())
                {
                    issues.push(format!("Replacement marker missing for {path}"));
                }
            }
            for entry in &entries {
                let expected = replacement_index
                    .get(&(entry.path.as_str(), entry.version.as_deref()))
                    .or_else(|| replacement_index.get(&(entry.path.as_str(), None)))
                    .copied();
                let observed = entry
                    .replacement
                    .as_ref()
                    .and_then(|r| destination(owner, &r.target, r.target_version.as_deref()));
                let expected_destination = expected.and_then(|r| {
                    destination(
                        r["origin"].as_str().unwrap_or(owner),
                        r["target"].as_str().unwrap_or_default(),
                        r["target_version"].as_str(),
                    )
                });
                if entry.replacement.is_some() != expected.is_some()
                    || entry.replacement.is_some()
                        && (observed.is_none() || observed != expected_destination)
                {
                    issues.push(format!("Replacement differs for {}", entry.path));
                }

                if entry.explicit
                    && !entry
                        .version
                        .as_deref()
                        .is_some_and(|v| requirements.contains(&(entry.path.as_str(), v)))
                {
                    issues.push(format!("Unexpected explicit module {}", entry.path));
                }
                if entry
                    .version
                    .as_deref()
                    .is_some_and(|v| exclusions.contains(&(entry.path.as_str(), v)))
                {
                    issues.push(format!(
                        "Excluded module {} appears in vendor inventory",
                        entry.path
                    ));
                }
            }
        } else {
            diagnostic(&mut report.diagnostics,"go_vendor_legacy_coverage",name,"Vendor consistency for absent or pre-1.14 Go directives is not qualified; recorded modules remain observations",true);
        }
        let mut components = Vec::new();
        for entry in entries.iter().filter(|e| !e.packages.is_empty()) {
            let local = entry
                .replacement
                .as_ref()
                .is_some_and(|r| r.target_version.is_none());
            let effective_name = entry
                .replacement
                .as_ref()
                .filter(|_| !local)
                .map_or(&entry.path, |r| &r.target);
            let version = if local {
                ""
            } else {
                entry
                    .replacement
                    .as_ref()
                    .and_then(|r| r.target_version.as_deref())
                    .or(entry.version.as_deref())
                    .unwrap_or("")
            };
            let identity = if local || version.is_empty() {
                None
            } else {
                match purl(effective_name, version) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        issues.push(e.to_string());
                        None
                    }
                }
            };
            components.push(Component{name:effective_name.clone(),version:version.into(),purl:identity,context:entry.path.clone(),source:json!({"type":"go-vendor","manifest":name,"local":local,"replacement":entry.replacement}),artifacts:Vec::new(),metadata:json!({"go":{"module":entry.path,"version":entry.version,"explicit":entry.explicit,"go":entry.go,"packages":entry.packages},"evidence":"vendor/modules.txt"})});
        }
        report.projects[index].components = components;
        report.projects[index].workspace["go"]["vendor_manifest"] = json!(name);
        report.projects[index].workspace["go"]["vendor_consistent"] = if modern {
            json!(issues.is_empty())
        } else {
            serde_json::Value::Null
        };
        for issue in issues {
            diagnostic(
                &mut report.diagnostics,
                "go_vendor_inconsistent",
                name,
                issue,
                true,
            );
        }
        diagnostic(&mut report.diagnostics,"go_vendor_content_unverified",name,"Vendor metadata records observed versions; source authenticity, selected build and transitive dependency edges are not verified",false);
    }
}
