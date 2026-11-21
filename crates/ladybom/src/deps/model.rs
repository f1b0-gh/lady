use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use super::invalid;
use crate::error::{ensure, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema_version: u32,
    /// Coverage of static parsing, not a claim that dependencies are installed.
    pub complete: bool,
    pub inputs: BTreeMap<String, String>,
    pub projects: Vec<Project>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Report {
    /// Validate the canonical shared-lock representation before consuming it.
    pub fn validate(&self) -> Result<()> {
        self.validate_bounds()?;
        let mut manifests = BTreeMap::new();
        let mut owners = BTreeMap::new();
        for project in &self.projects {
            Self::validate_project(project)?;
            ensure!(
                manifests
                    .insert(project.manifest.as_str(), project)
                    .is_none(),
                "Manifest dupliqué dans le rapport"
            );
            if let Some(lockfile) = &project.lockfile {
                let key = (&project.ecosystem, lockfile);
                if let Some(owner) = owners.get(&key) {
                    ensure!(
                        project.components_from.as_ref() == Some(*owner),
                        "Référence au propriétaire du verrou partagé requise"
                    );
                } else {
                    ensure!(
                        project.components_from.is_none(),
                        "Le premier projet doit posséder les composants du verrou"
                    );
                    owners.insert(key, &project.manifest);
                }
            }
        }
        for project in &self.projects {
            let owner = project
                .components_from
                .as_deref()
                .and_then(|name| manifests.get(name).copied());
            Self::resolve_components(project, owner)?;
        }
        Ok(())
    }

    /// Resolve one project's components, validating its identity and direct owner.
    /// Call `validate` once at the consumer boundary to validate the whole report;
    /// unrelated projects' references are not revalidated by this accessor.
    pub fn components_for(&self, project: &Project) -> Result<&[Component]> {
        self.validate_bounds()?;
        let stored = self.project_for_manifest(&project.manifest)?;
        Self::validate_project(stored)?;
        ensure!(
            stored.ecosystem == project.ecosystem
                && stored.lockfile == project.lockfile
                && stored.locked == project.locked
                && stored.components_from == project.components_from
                && stored.components == project.components,
            "Identité de résolution du projet divergente du rapport"
        );
        if let Some(lockfile) = &stored.lockfile {
            let first = self
                .projects
                .iter()
                .find(|candidate| {
                    candidate.ecosystem == stored.ecosystem
                        && candidate.lockfile.as_ref() == Some(lockfile)
                })
                .ok_or_else(|| invalid("Propriétaire du verrou absent".into()))?;
            ensure!(
                if first.manifest == stored.manifest {
                    stored.components_from.is_none()
                } else {
                    stored.components_from.as_ref() == Some(&first.manifest)
                },
                "Référence au propriétaire du verrou partagé requise"
            );
        }
        let owner = stored
            .components_from
            .as_deref()
            .map(|name| self.project_for_manifest(name))
            .transpose()?;
        if let Some(owner) = owner {
            Self::validate_project(owner)?;
        }
        Self::resolve_components(stored, owner)
    }

    fn validate_bounds(&self) -> Result<()> {
        ensure!(
            self.schema_version == 2,
            "Version de rapport Ladybom non prise en charge : régénérer le rapport et les graphes"
        );
        ensure!(
            self.projects.len() <= 5000,
            "Maximum 5000 projets dans le rapport Ladybom"
        );
        ensure!(
            self.inputs.len() <= 5000,
            "Maximum 5000 entrées dans le rapport Ladybom"
        );
        Ok(())
    }

    fn validate_project(project: &Project) -> Result<()> {
        crate::config::relative_path(&project.manifest)?;
        if let Some(lockfile) = &project.lockfile {
            crate::config::relative_path(lockfile)?;
        }
        ensure!(
            project.locked == project.lockfile.is_some(),
            "Verrou et état du projet divergents"
        );
        ensure!(
            project.locked || project.components_from.is_none(),
            "Référence de composants sans verrou"
        );
        Ok(())
    }

    fn project_for_manifest(&self, manifest: &str) -> Result<&Project> {
        let mut matching = self
            .projects
            .iter()
            .filter(|project| project.manifest == manifest);
        let project = matching
            .next()
            .ok_or_else(|| invalid("Projet absent du rapport".into()))?;
        ensure!(
            matching.next().is_none(),
            "Manifest dupliqué dans le rapport"
        );
        Ok(project)
    }

    fn resolve_components<'a>(
        project: &'a Project,
        owner: Option<&'a Project>,
    ) -> Result<&'a [Component]> {
        let Some(manifest) = &project.components_from else {
            return Ok(&project.components);
        };
        crate::config::relative_path(manifest)?;
        ensure!(
            project.components.is_empty(),
            "Composants inline et référence mutuellement exclusifs"
        );
        ensure!(
            manifest != &project.manifest,
            "Référence de composants cyclique"
        );
        let owner =
            owner.ok_or_else(|| invalid("Propriétaire des composants absent du rapport".into()))?;
        ensure!(
            owner.components_from.is_none(),
            "Chaîne de références de composants interdite"
        );
        ensure!(
            owner.locked
                && project.locked
                && owner.lockfile == project.lockfile
                && owner.ecosystem == project.ecosystem,
            "Propriétaire des composants issu d’un autre verrou ou écosystème"
        );
        Ok(&owner.components)
    }

    pub(super) fn compact_components(&mut self) -> Result<()> {
        let mut owners: BTreeMap<(String, String), usize> = BTreeMap::new();
        for index in 0..self.projects.len() {
            let project = &self.projects[index];
            let Some(lockfile) = &project.lockfile else {
                continue;
            };
            let key = (project.ecosystem.clone(), lockfile.clone());
            if let Some(owner) = owners.get(&key).copied() {
                ensure!(
                    self.projects[owner].components == project.components,
                    "Composants divergents dans un verrou partagé"
                );
                let manifest = self.projects[owner].manifest.clone();
                self.projects[index].components.clear();
                self.projects[index].components_from = Some(manifest);
            } else {
                owners.insert(key, index);
            }
        }
        self.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// Selected manifest package identity, distinct from lockfile components.
    /// Older v2 reports omit this evidence and cannot qualify local npm/Python
    /// packages or bind local Cargo roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_package: Option<ManifestPackage>,
    pub ecosystem: String,
    pub root: String,
    pub manifest: String,
    pub lockfile: Option<String>,
    /// A supported lockfile was parsed; consistency is checked at preparation.
    pub locked: bool,
    pub manager: String,
    pub tools: Vec<ToolRequirement>,
    pub requirements: Vec<Requirement>,
    pub components: Vec<Component>,
    /// Manifest of the first project sharing this ecosystem and lockfile.
    /// References are direct, and mutually exclusive with inline components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components_from: Option<String>,
    pub workspace: Value,
}

impl Project {
    pub(super) fn new(ecosystem: &str, manager: &str, manifest: &str) -> Self {
        Self {
            manifest_package: None,
            ecosystem: ecosystem.into(),
            manager: manager.into(),
            root: manifest
                .rsplit_once('/')
                .map_or(".", |(root, _)| root)
                .into(),
            manifest: manifest.into(),
            lockfile: None,
            locked: false,
            tools: Vec::new(),
            requirements: Vec::new(),
            components: Vec::new(),
            components_from: None,
            workspace: Value::Null,
        }
    }

    pub(super) fn tool(&mut self, name: &str, constraint: &str, file: &str) {
        self.tools.push(ToolRequirement {
            name: name.into(),
            constraint: constraint.into(),
            file: file.into(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPackage {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequirement {
    pub name: String,
    pub constraint: String,
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub name: String,
    /// Manifest key when it differs from the resolved package name (Cargo rename).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_name: Option<String>,
    pub constraint: String,
    pub kind: String,
    pub marker: Option<String>,
    pub extras: Vec<String>,
    pub source: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub purl: Option<String>,
    /// Native resolution context, e.g. the npm installation path, never a UUID.
    pub context: String,
    pub source: Value,
    pub artifacts: Vec<Artifact>,
    /// Keep ecosystem metadata until its projection has been qualified.
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub url: String,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub code: String,
    pub file: String,
    pub message: String,
    pub blocking: bool,
}

pub(super) fn diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    code: &str,
    file: &str,
    message: impl Into<String>,
    blocking: bool,
) {
    diagnostics.push(Diagnostic {
        code: code.into(),
        file: file.into(),
        message: message.into(),
        blocking,
    });
}
