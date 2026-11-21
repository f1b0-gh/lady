//! Static local identities from selected manifests, never from registry guesses.
use crate::deps::{invalid, Component, ManifestPackage, Project, Report};
use crate::error::Result;
#[cfg(feature = "graph")]
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn manifest_package(manifest: &toml::Value) -> Option<ManifestPackage> {
    let project = manifest.get("project")?;
    if let Some(dynamic) = project.get("dynamic") {
        let fields = dynamic.as_array()?;
        if fields.iter().any(|v| {
            v.as_str()
                .is_none_or(|field| matches!(field, "name" | "version"))
        }) {
            return None;
        }
    }
    let name = project
        .get("name")?
        .as_str()?
        .parse::<pep508_rs::PackageName>()
        .ok()?;
    let version = project
        .get("version")?
        .as_str()?
        .parse::<pep440_rs::Version>()
        .ok()?;
    Some(ManifestPackage {
        name: name.to_string(),
        version: version.to_string(),
    })
}

pub(crate) struct Identity {
    name: String,
    version: String,
    pub source: String,
}

impl Identity {
    pub fn purl(&self) -> Result<String> {
        let mut purl = packageurl::PackageUrl::new("generic", &self.name)
            .map_err(|e| invalid(e.to_string()))?;
        purl.with_namespace("python-local")
            .map_err(|e| invalid(e.to_string()))?;
        purl.with_version(&self.version)
            .map_err(|e| invalid(e.to_string()))?;
        Ok(purl.to_string())
    }

    #[cfg(feature = "graph")]
    pub fn source(&self) -> Value {
        json!({"local": self.source})
    }
}

pub(crate) struct LocalPackages {
    identities: BTreeMap<(String, String), Identity>,
}

impl LocalPackages {
    pub fn new(report: &Report) -> Self {
        let projects: BTreeMap<_, _> = report
            .projects
            .iter()
            .map(|p| (p.manifest.as_str(), p))
            .collect();
        let mut identities = BTreeMap::new();
        for project in report
            .projects
            .iter()
            .filter(|p| p.ecosystem == "python" && p.manager == "uv")
        {
            let Some(lock) = project.lockfile.as_deref() else {
                continue;
            };
            let root_manifest = super::sibling(lock, "pyproject.toml");
            let Some(root) = projects.get(root_manifest.as_str()) else {
                continue;
            };
            if super::basename(lock) != "uv.lock"
                || !project.locked
                || root.ecosystem != "python"
                || root.manager != "uv"
                || root.lockfile.as_deref() != Some(lock)
                || !report.inputs.contains_key(lock)
                || !report.inputs.contains_key(&root_manifest)
            {
                continue;
            }
            let mut counts = BTreeMap::new();
            for component in project.components.iter().filter(|c| is_local(project, c)) {
                *counts.entry(component.context.as_str()).or_insert(0usize) += 1;
            }
            for component in &project.components {
                if counts.get(component.context.as_str()) != Some(&1) {
                    continue;
                }
                let Some(source) = component.source.as_object().filter(|s| s.len() == 1) else {
                    continue;
                };
                let Some(path) = ["editable", "directory", "virtual"]
                    .iter()
                    .find_map(|kind| source.get(*kind).and_then(Value::as_str))
                else {
                    continue;
                };
                if component.purl.is_some()
                    || !component.artifacts.is_empty()
                    || component.metadata.get("sdist").is_some()
                    || component.metadata.get("wheels").is_some()
                    || component.metadata["name"] != component.name
                    || component.metadata["version"] != component.version
                    || component.metadata["source"] != component.source
                    || serde_json::to_string(&component.source).ok().as_deref()
                        != Some(component.context.as_str())
                {
                    continue;
                }
                let Some(target) = local_directory(lock, path) else {
                    continue;
                };
                let manifest = if target == "." {
                    "pyproject.toml".into()
                } else {
                    format!("{target}/pyproject.toml")
                };
                let Some(member) = projects.get(manifest.as_str()) else {
                    continue;
                };
                let Some(package) = member.manifest_package.as_ref() else {
                    continue;
                };
                if member.ecosystem != "python"
                    || member.manager != "uv"
                    || !report.inputs.contains_key(&manifest)
                    || package.name != component.name
                    || component
                        .name
                        .parse::<pep508_rs::PackageName>()
                        .ok()
                        .is_none_or(|n| n.to_string() != component.name)
                {
                    continue;
                }
                let (Ok(declared), Ok(locked)) = (
                    package.version.parse::<pep440_rs::Version>(),
                    component.version.parse::<pep440_rs::Version>(),
                ) else {
                    continue;
                };
                if declared != locked {
                    continue;
                }
                identities.insert(
                    (lock.into(), component.context.clone()),
                    Identity {
                        name: component.name.clone(),
                        version: component.version.clone(),
                        source: target,
                    },
                );
            }
        }
        Self { identities }
    }

    pub fn qualified(&self, project: &Project, component: &Component) -> Option<&Identity> {
        if project.ecosystem != "python" || component.purl.is_some() {
            return None;
        }
        let identity = self
            .identities
            .get(&(project.lockfile.clone()?, component.context.clone()))?;
        (identity.name == component.name && identity.version == component.version)
            .then_some(identity)
    }

    #[cfg(feature = "graph")]
    pub fn evidence_source(
        &self,
        lock: &str,
        context: &str,
        name: &str,
        version: &str,
    ) -> Option<Value> {
        let identity = self.identities.get(&(lock.into(), context.into()))?;
        (identity.name == name && identity.version == version).then(|| identity.source())
    }
}

pub(crate) fn is_local(project: &Project, component: &Component) -> bool {
    has_local_source(&component.source)
        || component
            .purl
            .as_deref()
            .is_some_and(|p| p.starts_with("pkg:generic/python-local/"))
        // Imported fields can contradict the native uv evidence. A public PURL
        // must not hide that evidence from graph or advisory consumers.
        || (project.manager == "uv"
            && (has_local_source(&component.metadata["source"])
                || serde_json::from_str::<Value>(&component.context)
                    .ok()
                    .is_some_and(|source| has_local_source(&source))))
}

fn has_local_source(source: &Value) -> bool {
    ["editable", "directory", "virtual"]
        .iter()
        .any(|key| source.get(*key).is_some())
}

// Resolve only lexical paths already represented by selected manifest evidence.
// Parent traversal inside the scan scope is valid; escaping it is not.
fn local_directory(lock: &str, path: &str) -> Option<String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.chars().any(|c| c.is_control() || "\\:".contains(c))
    {
        return None;
    }
    let mut parts: Vec<_> = lock
        .rsplit_once('/')
        .map_or_else(Vec::new, |(p, _)| p.split('/').collect());
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value),
        }
    }
    if parts.is_empty() {
        return Some(".".into());
    }
    let result = parts.join("/");
    crate::config::relative_path(&result).ok()?;
    Some(result)
}
