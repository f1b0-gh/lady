//! Static Go module evidence. Checksums and vendoring are never lockfiles.
mod manifest;
mod syntax;
mod vendor;
use super::{
    diagnostic, sibling, Component, Inputs, ManifestPackage, Project, Report, Requirement,
};
use crate::error::Result;
use manifest::Replacement;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn is_vendor(name: &str) -> bool {
    name == "vendor/modules.txt" || name.ends_with("/vendor/modules.txt")
}
pub(super) fn local_manifest(origin: &str, value: &str) -> Option<String> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains(['\\', ':'])
        || value.chars().any(char::is_control)
    {
        return None;
    }
    let mut parts: Vec<_> = origin.split('/').collect();
    parts.pop();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    parts.push("go.mod");
    Some(parts.join("/"))
}
fn checksum(content: &str) -> Result<Value> {
    let mut sums = BTreeMap::new();
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        let words: Vec<_> = line.split_whitespace().take(4).collect();
        if words.len() != 3 {
            return Err(super::invalid("Invalid Go checksum record".into()));
        }
        manifest::path(words[0])?;
        let (version, kind) = words[1]
            .strip_suffix("/go.mod")
            .map_or((words[1], "module"), |v| (v, "go.mod"));
        manifest::version(version)?;
        let hash = words[2];
        let encoded = hash
            .strip_prefix("h1:")
            .ok_or_else(|| super::invalid("Unsupported Go checksum algorithm".into()))?;
        if encoded.len() != 44
            || !encoded.ends_with('=')
            || !encoded.as_bytes()[..43]
                .iter()
                .copied()
                .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(&b))
            || !b"AEIMQUYcgkosw048".contains(&encoded.as_bytes()[42])
        {
            return Err(super::invalid("Invalid Go h1 checksum".into()));
        }
        let key = (words[0], version, kind);
        if let Some(previous) = sums.insert(key, hash) {
            if previous != hash {
                return Err(super::invalid("Conflicting Go checksums".into()));
            }
        }
        if sums.len() > syntax::MAX_ITEMS {
            return Err(super::invalid("Go checksum count limit exceeded".into()));
        }
    }
    Ok(Value::Array(sums.into_iter().map(|((path,version,kind),hash)| json!({"path":path,"version":version,"kind":kind,"hash":hash})).collect()))
}
pub(super) fn scan(inputs: &Inputs, report: &mut Report) {
    let mut manifests = BTreeMap::new();
    let mut retained_items = 0usize;
    for (name, content) in inputs {
        if !matches!(super::basename(name), "go.mod" | "go.work") {
            continue;
        }
        match manifest::parse(content, super::basename(name) == "go.work") {
            Ok(parsed) => {
                retained_items += parsed.requires.len()
                    + parsed.replacements.len()
                    + parsed.uses.len()
                    + parsed.excludes.len()
                    + parsed.directives.values().map(Vec::len).sum::<usize>();
                if retained_items > 100_000 {
                    diagnostic(
                        &mut report.diagnostics,
                        "go_limit",
                        name,
                        "Total Go declaration limit exceeded",
                        true,
                    );
                    continue;
                }
                manifests.insert(name.clone(), parsed);
            }
            Err(error) => diagnostic(
                &mut report.diagnostics,
                "invalid_manifest",
                name,
                error.to_string(),
                true,
            ),
        }
    }
    let mut memberships: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, workspace) in &manifests {
        if super::basename(name) != "go.work" {
            continue;
        }
        let mut members = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for local in &workspace.uses {
            let member = local_manifest(name, local);
            let selected = member
                .as_ref()
                .and_then(|m| manifests.get(m))
                .filter(|m| m.module.is_some());
            if let (Some(member), Some(parsed)) = (member, selected) {
                if !members.insert(member.clone()) || !identities.insert(parsed.module.clone()) {
                    diagnostic(
                        &mut report.diagnostics,
                        "go_workspace_conflict",
                        name,
                        "Duplicate workspace module or directory",
                        true,
                    );
                }
                memberships.entry(member).or_default().push(name.clone());
            } else {
                diagnostic(
                    &mut report.diagnostics,
                    "go_workspace_member_unavailable",
                    name,
                    "Workspace member is outside the selected valid manifests",
                    true,
                );
            }
        }
    }
    let mut workspace_replacements: BTreeMap<String, Vec<(String, Replacement)>> = BTreeMap::new();
    for (name, workspace) in manifests
        .iter()
        .filter(|(n, _)| super::basename(n) == "go.work")
    {
        let mut selected: BTreeMap<(String, Option<String>), (String, Replacement)> =
            BTreeMap::new();
        for (member, _) in memberships.iter().filter(|(_, ws)| ws.contains(name)) {
            if let Some(module) = manifests.get(member) {
                for replacement in &module.replacements {
                    if workspace.replacements.iter().any(|r| {
                        r.path == replacement.path
                            && (r.version.is_none() || r.version == replacement.version)
                    }) {
                        continue;
                    }
                    let key = (replacement.path.clone(), replacement.version.clone());
                    selected
                        .entry(key)
                        .or_insert_with(|| (member.clone(), replacement.clone()));
                }
            }
        }
        for replacement in &workspace.replacements {
            if replacement.version.is_none()
                && memberships.iter().any(|(member, ws)| {
                    ws.contains(name)
                        && manifests
                            .get(member)
                            .is_some_and(|m| m.module.as_deref() == Some(&replacement.path))
                })
            {
                diagnostic(&mut report.diagnostics,"go_workspace_conflict",name,"Wildcard workspace replacement of a workspace module is invalid; use a version-specific replacement",true);
            }
        }
        // Compare each member's effective rule at observed versions before
        // deduplicating shared evidence. A member's specific rule shadows only
        // that member's wildcard, not another member's rules.
        let members: Vec<_> = memberships
            .iter()
            .filter(|(_, ws)| ws.contains(name))
            .filter_map(|(origin, _)| manifests.get(origin).map(|m| (origin, m)))
            .collect();
        let mut versions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (_, member) in &members {
            for required in &member.requires {
                versions
                    .entry(&required.path)
                    .or_default()
                    .insert(&required.version);
            }
            for replacement in &member.replacements {
                if let Some(v) = &replacement.version {
                    versions.entry(&replacement.path).or_default().insert(v);
                }
            }
        }
        let mut comparisons = 0usize;
        'compare: for (path, versions) in versions {
            for version in versions {
                if workspace.replacements.iter().any(|r| {
                    r.path == path && (r.version.is_none() || r.version.as_deref() == Some(version))
                }) {
                    continue;
                }
                let mut previous: Option<(String, Option<String>)> = None;
                for (origin, member) in &members {
                    comparisons += member.replacements.len();
                    if comparisons > 1_000_000 {
                        diagnostic(
                            &mut report.diagnostics,
                            "go_limit",
                            name,
                            "Workspace replacement comparison limit exceeded",
                            true,
                        );
                        break 'compare;
                    }
                    let effective = member
                        .replacements
                        .iter()
                        .find(|r| r.path == path && r.version.as_deref() == Some(version))
                        .or_else(|| {
                            member
                                .replacements
                                .iter()
                                .find(|r| r.path == path && r.version.is_none())
                        });
                    if let Some(rule) = effective {
                        let target = if let Some(version) = &rule.target_version {
                            Some((rule.target.clone(), Some(version.clone())))
                        } else {
                            local_manifest(origin, &rule.target).map(|p| (p, None))
                        };
                        if let Some(target) = target {
                            if previous.as_ref().is_some_and(|p| p != &target) {
                                diagnostic(&mut report.diagnostics,"go_workspace_conflict",name,"Effective replacements from workspace members have conflicting targets",true);
                                break 'compare;
                            }
                            previous = Some(target);
                        }
                    }
                }
            }
        }
        let mut shared: Vec<_> = selected.into_values().collect();
        shared.extend(
            workspace
                .replacements
                .iter()
                .cloned()
                .map(|r| (name.clone(), r)),
        );
        workspace_replacements.insert(name.clone(), shared);
    }
    for (name, parsed) in &manifests {
        let mut project = Project::new("go", "go", name);
        project.manifest_package = parsed.module.as_ref().map(|module| ManifestPackage {
            name: module.clone(),
            version: String::new(),
        });
        if let Some(go) = &parsed.go {
            project.tool("go", go, name);
        }
        if let Some(toolchain) = &parsed.toolchain {
            project.tool("go-toolchain", toolchain, name);
        }
        let work = memberships.get(name).and_then(|names| {
            if names.len() != 1 {
                diagnostic(
                    &mut report.diagnostics,
                    "go_workspace_conflict",
                    name,
                    "Module belongs to multiple selected workspaces; effective context is unknown",
                    true,
                );
                None
            } else {
                Some(&names[0])
            }
        });

        let mut evidence = serde_json::to_value(parsed).unwrap_or(Value::Null);
        evidence["workspace"] = work.map_or(Value::Null, |s| json!(s));
        evidence["checksums"] = json!([]);
        let context_replacements: Vec<_> = work
            .or_else(|| (super::basename(name) == "go.work").then_some(name))
            .and_then(|w| workspace_replacements.get(w))
            .cloned()
            .unwrap_or_else(|| {
                parsed
                    .replacements
                    .iter()
                    .cloned()
                    .map(|r| (name.clone(), r))
                    .collect()
            });
        retained_items += context_replacements.len();
        if retained_items > 100_000 {
            diagnostic(
                &mut report.diagnostics,
                "go_limit",
                name,
                "Total retained Go context limit exceeded",
                true,
            );
            continue;
        }
        let effective_replacements: Vec<_> = context_replacements
            .iter()
            .map(|(origin, r)| {
                let mut value = json!(r);
                value["origin"] = json!(origin);
                value
            })
            .collect();
        for required in &parsed.requires {
            let mut source = json!({"minimum":required.version,"indirect":required.indirect});
            if let Some(workspace_name) = work {
                // A selected workspace module supersedes the versioned requirement.
                let matching: Vec<_> = memberships
                    .iter()
                    .filter(|(_, ws)| ws.contains(workspace_name))
                    .filter_map(|(m, _)| {
                        manifests
                            .get(m)
                            .filter(|p| p.module.as_deref() == Some(&required.path))
                            .map(|_| m)
                    })
                    .collect();
                if matching.len() == 1 {
                    source["workspace_member"] = json!(matching[0]);
                }
            }
            let pick = |origin: Option<&str>| {
                let eligible = |item: &&(String, Replacement)| {
                    item.1.path == required.path && origin.is_none_or(|o| o == item.0)
                };
                context_replacements
                    .iter()
                    .filter(eligible)
                    .find(|(_, r)| r.version.as_deref() == Some(&required.version))
                    .or_else(|| {
                        context_replacements
                            .iter()
                            .filter(eligible)
                            .find(|(_, r)| r.version.is_none())
                    })
            };
            let replacement = work.and_then(|w| pick(Some(w))).or_else(|| pick(None));
            if let Some((origin, replacement)) = replacement {
                let mut value = serde_json::to_value(replacement).unwrap_or(Value::Null);
                value["origin"] = json!(origin);
                if replacement.target_version.is_none() {
                    let local = local_manifest(origin, &replacement.target);
                    let selected = local.as_ref().and_then(|m| manifests.get(m));
                    if selected.is_some_and(|m| m.module.as_deref() == Some(&required.path)) {
                        value["manifest"] = json!(local);
                    } else if source.get("workspace_member").is_none() {
                        diagnostic(
                            &mut report.diagnostics,
                            "go_local_source_unavailable",
                            name,
                            format!(
                                "Local replacement for {} lacks a matching selected module",
                                required.path
                            ),
                            true,
                        );
                    }
                }
                source["replacement"] = value;
            }
            project.requirements.push(Requirement {
                name: required.path.clone(),
                declared_name: None,
                constraint: required.version.clone(),
                kind: if required.indirect {
                    "indirect"
                } else {
                    "runtime"
                }
                .into(),
                marker: None,
                extras: Vec::new(),
                source,
            });
        }
        evidence["effective_replacements"] = json!(effective_replacements);
        project.workspace = json!({"go":evidence});
        if !project.requirements.is_empty()
            || parsed.module.is_some() && parsed.directives.contains_key("tool")
        {
            diagnostic(&mut report.diagnostics,"go_resolution_unknown",name,"Go requirements are minimum versions; selected build versions, transitive edges and build activation are not established by static manifests",true);
        }
        report.projects.push(project);
    }
    for (name, content) in inputs {
        let owner = match super::basename(name) {
            "go.sum" => sibling(name, "go.mod"),
            "go.work.sum" => sibling(name, "go.work"),
            _ => continue,
        };
        match checksum(content) {
            Ok(sums) => {
                retained_items += sums.as_array().map_or(0, Vec::len);
                if retained_items > 100_000 {
                    diagnostic(
                        &mut report.diagnostics,
                        "go_limit",
                        name,
                        "Total retained Go evidence limit exceeded",
                        true,
                    );
                    continue;
                }
                if let Some(project) = report.projects.iter_mut().find(|p| p.manifest == owner) {
                    project.workspace["go"]["checksums"] = sums;
                } else {
                    diagnostic(
                        &mut report.diagnostics,
                        "go_orphan_input",
                        name,
                        "Checksum file has no selected valid owning manifest",
                        true,
                    );
                }
            }
            Err(error) => diagnostic(
                &mut report.diagnostics,
                "invalid_go_checksum",
                name,
                error.to_string(),
                true,
            ),
        }
    }
    vendor::scan(inputs, &manifests, &memberships, report);
}
/// Recognizes only versioned vendor observations; local replacements have no public PURL.
pub(super) fn public_component(project: &Project, component: &Component) -> bool {
    project.ecosystem == "go"
        && component.source.get("type").and_then(Value::as_str) == Some("go-vendor")
        && component.source.get("local").and_then(Value::as_bool) == Some(false)
        && component
            .purl
            .as_deref()
            .and_then(|p| p.parse::<packageurl::PackageUrl>().ok())
            .is_some_and(|p| {
                p.ty() == "golang"
                    && p.version() == Some(component.version.as_str())
                    && p.qualifiers().is_empty()
                    && p.subpath().is_none()
                    && p.namespace()
                        .map_or_else(|| p.name().to_owned(), |ns| format!("{ns}/{}", p.name()))
                        == component.name
            })
}
