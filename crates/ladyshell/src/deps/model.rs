use super::invalid;
use super::Project;
use serde::{Deserialize, Serialize};

/// Explicit build-time authorization, independent of sandbox runtime networking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyConfig {
    pub projects: Vec<String>,
    pub allowed_hosts: Vec<String>,
}

impl DependencyConfig {
    pub fn validate(&self) -> crate::error::Result<()> {
        use crate::error::ensure;
        ensure!(
            !self.projects.is_empty() && self.projects.len() <= 64,
            "Entre 1 et 64 projets de dépendances requis"
        );
        let mut unique = std::collections::BTreeSet::new();
        for project in &self.projects {
            crate::config::relative_path(project)?;
            ensure!(
                unique.insert(project),
                "Projet de dépendances dupliqué : {project}"
            );
            ensure!(
                ["Cargo.toml", "pyproject.toml", "package.json"]
                    .contains(&super::basename(project)),
                "Manifest non pris en charge : {project}"
            );
        }
        ensure!(
            self.allowed_hosts.len() <= 64,
            "Maximum 64 hôtes de préparation"
        );
        for host in &self.allowed_hosts {
            ensure!(
                !host.is_empty()
                    && host.len() <= 253
                    && host.split('.').all(|label| !label.is_empty()
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')),
                "Hôte explicite invalide : {host}"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preparation {
    pub schema_version: u32,
    pub inputs: crate::sources::Snapshot,
    pub projects: Vec<Project>,
    pub allowed_hosts: Vec<String>,
    pub tools: std::collections::BTreeMap<String, crate::config::Tool>,
}
