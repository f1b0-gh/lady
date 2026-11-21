//! Manifest-backed local npm and Python identities in a selected inventory.
use super::{npm, python, Component, Project, Report};
use crate::error::Result;
use serde_json::Value;

/// Index of the selected inventory's local package evidence. Missing or ambiguous
/// evidence cannot qualify an occurrence, even if it resembles a registry package.
pub struct LocalIdentities {
    npm: npm::local::LocalPackages,
    python: python::local::LocalPackages,
}

impl LocalIdentities {
    pub fn new(report: &Report) -> Self {
        Self {
            npm: npm::local::LocalPackages::new(report),
            python: python::local::LocalPackages::new(report),
        }
    }

    /// Recognize native local evidence, including unresolved or contradictory records.
    pub fn is_local(project: &Project, component: &Component) -> bool {
        match project.ecosystem.as_str() {
            "npm" => npm::local::is_local(component),
            "python" => python::local::is_local(project, component),
            _ => false,
        }
    }

    /// Return the proved local PURL. A recognized local with no result stays unresolved.
    pub fn qualified_purl(
        &self,
        project: &Project,
        component: &Component,
    ) -> Result<Option<String>> {
        match project.ecosystem.as_str() {
            "npm" => self
                .npm
                .qualified(project, component)
                .map(|i| i.purl())
                .transpose(),
            "python" => self
                .python
                .qualified(project, component)
                .map(|i| i.purl())
                .transpose(),
            _ => Ok(None),
        }
    }

    /// Return the qualified source for an occurrence matching its owning project and lock.
    pub fn qualified_source(&self, project: &Project, component: &Component) -> Option<Value> {
        self.npm
            .qualified(project, component)
            .map(|i| i.source())
            .or_else(|| {
                self.python
                    .qualified(project, component)
                    .map(|i| i.source())
            })
    }

    /// Look up exact lock, context, name and version evidence, including unprojected
    /// occurrences. Missing or ambiguous identities have no qualified source.
    pub fn evidence_source(
        &self,
        lock: &str,
        context: &str,
        name: &str,
        version: &str,
    ) -> Option<Value> {
        self.npm
            .evidence_source(lock, context, name, version)
            .or_else(|| self.python.evidence_source(lock, context, name, version))
    }
}
