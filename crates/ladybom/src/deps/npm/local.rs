//! Selected workspace proofs, shared by scanning and graph consumers.
use crate::deps::{invalid, Component, ManifestPackage, Project, Report};
use crate::error::Result;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone)]
pub(crate) struct Identity {
    pub name: String,
    pub version: String,
    pub target: String,
    pub source: String,
    pub link: bool,
}

impl Identity {
    pub fn purl(&self) -> Result<String> {
        let (namespace, name) = self.name.rsplit_once('/').map_or_else(
            || ("npm-local".into(), self.name.as_str()),
            |(scope, name)| (format!("npm-local/{scope}"), name),
        );
        let mut purl =
            packageurl::PackageUrl::new("generic", name).map_err(|e| invalid(e.to_string()))?;
        purl.with_namespace(namespace)
            .map_err(|e| invalid(e.to_string()))?;
        purl.with_version(&self.version)
            .map_err(|e| invalid(e.to_string()))?;
        Ok(purl.to_string())
    }

    pub fn source(&self) -> Value {
        serde_json::json!({"local":self.source})
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
        for project in report.projects.iter().filter(|p| p.ecosystem == "npm") {
            let Some(lock) = project.lockfile.as_deref() else {
                continue;
            };
            let root_name = super::sibling(lock, "package.json");
            let Some(root) = projects.get(root_name.as_str()) else {
                continue;
            };
            if root.ecosystem != "npm"
                || root.lockfile.as_deref() != Some(lock)
                || !report.inputs.contains_key(lock)
                || !report.inputs.contains_key(&root_name)
            {
                continue;
            }
            let Some(members) = root.workspace.as_array() else {
                continue;
            };
            let prefix = root_name.strip_suffix("package.json").unwrap_or_default();
            let components: BTreeMap<_, _> = project
                .components
                .iter()
                .map(|c| (c.context.as_str(), c))
                .collect();
            if components.len() != project.components.len() {
                continue;
            }
            let mut targets = BTreeMap::new();
            for component in &project.components {
                let path = &component.context;
                if !safe_path(path)
                    || path.split('/').any(|p| p == "node_modules")
                    || members.iter().filter(|m| m.as_str() == Some(path)).count() != 1
                    || component.purl.is_some()
                    || !component.source.is_null()
                    || !component.artifacts.is_empty()
                    || !component
                        .metadata
                        .get("resolved")
                        .is_none_or(Value::is_null)
                    || !component.metadata.get("link").is_none_or(|v| v == false)
                {
                    continue;
                }
                let manifest = format!("{prefix}{path}/package.json");
                let Some(member) = projects.get(manifest.as_str()) else {
                    continue;
                };
                let Some(package) = &member.manifest_package else {
                    continue;
                };
                if !report.inputs.contains_key(&manifest)
                    || member.ecosystem != "npm"
                    || member.lockfile.as_deref() != Some(lock)
                    || !valid_name(&package.name)
                    || !valid_version(&package.version)
                    || component.name != package.name
                    || component.version != package.version
                    || component.metadata["name"] != package.name
                    || component.metadata["version"] != package.version
                {
                    continue;
                }
                targets.insert(
                    path.clone(),
                    Identity {
                        name: package.name.clone(),
                        version: package.version.clone(),
                        target: path.clone(),
                        source: format!("{prefix}{path}"),
                        link: false,
                    },
                );
            }
            for component in &project.components {
                let Some(target) = component.source.as_str().and_then(|path| targets.get(path))
                else {
                    continue;
                };
                let alias = component
                    .context
                    .rsplit_once("node_modules/")
                    .filter(|(prefix, _)| prefix.is_empty() || prefix.ends_with('/'))
                    .map(|(_, alias)| alias);
                if !safe_path(&component.context)
                    || !alias.is_some_and(valid_name)
                    || component.purl.is_some()
                    || !component.artifacts.is_empty()
                    || component.metadata["link"] != true
                    || component.metadata["resolved"] != component.source
                    || !component
                        .metadata
                        .get("name")
                        .is_none_or(|v| v == &target.name)
                    || !component
                        .metadata
                        .get("version")
                        .is_none_or(|v| v == &target.version)
                    || [
                        "dependencies",
                        "devDependencies",
                        "optionalDependencies",
                        "peerDependencies",
                    ]
                    .iter()
                    .any(|f| component.metadata.get(*f).is_some())
                {
                    continue;
                }
                let mut identity = target.clone();
                identity.link = true;
                identities.insert((lock.into(), component.context.clone()), identity);
            }
            for (path, identity) in targets {
                identities.insert((lock.into(), path), identity);
            }
        }
        Self { identities }
    }

    pub fn qualified(&self, project: &Project, component: &Component) -> Option<&Identity> {
        if project.ecosystem != "npm" || component.purl.is_some() {
            return None;
        }
        let identity = self
            .identities
            .get(&(project.lockfile.clone()?, component.context.clone()))?;
        (identity.name == component.name && identity.version == component.version)
            .then_some(identity)
    }

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

/// Enrich only newly scanned links, never upgrade an old report's missing proof.
pub(in crate::deps) fn enrich(report: &mut Report) {
    let locals = LocalPackages::new(report);
    for project in &mut report.projects {
        if project.ecosystem != "npm" {
            continue;
        }
        let Some(lock) = &project.lockfile else {
            continue;
        };
        for component in &mut project.components {
            if let Some(identity) = locals
                .identities
                .get(&(lock.clone(), component.context.clone()))
            {
                if identity.link {
                    component.name.clone_from(&identity.name);
                    component.version.clone_from(&identity.version);
                }
            }
        }
    }
}

pub(super) fn manifest_package(manifest: &Value) -> Option<ManifestPackage> {
    let name = manifest["name"].as_str()?;
    let version = manifest["version"].as_str()?;
    (valid_name(name) && valid_version(version)).then(|| ManifestPackage {
        name: name.into(),
        version: version.into(),
    })
}

pub(crate) fn is_local(component: &Component) -> bool {
    !component.context.split('/').any(|p| p == "node_modules")
        || component.metadata["link"] == true
        || component
            .source
            .as_str()
            .is_some_and(|s| s.starts_with("file:") || !s.contains("://"))
}

fn safe_path(path: &str) -> bool {
    crate::config::relative_path(path).is_ok() && !path.chars().any(|c| "*?[]{}!\\():%".contains(c))
}

fn valid_version(version: &str) -> bool {
    semver::Version::parse(version).is_ok_and(|v| v.to_string() == version)
}

fn valid_name(name: &str) -> bool {
    fn segment(value: &str) -> bool {
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.~".contains(&c))
    }
    name.len() <= 214
        && if let Some(scoped) = name.strip_prefix('@') {
            scoped
                .split_once('/')
                .is_some_and(|(scope, name)| segment(scope) && segment(name))
        } else {
            segment(name)
        }
}
