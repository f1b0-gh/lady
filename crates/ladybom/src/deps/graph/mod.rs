//! Context-qualified dependency snapshots and bounded native LadybugDB queries.
#[cfg(feature = "graph")]
mod alignment;
#[cfg(feature = "graph")]
mod alignment_plan;
#[cfg(feature = "graph")]
mod alignment_policy;
#[cfg(feature = "graph")]
pub use alignment_plan::*;
#[cfg(feature = "graph")]
pub use alignment_policy::*;
#[cfg(feature = "graph")]
mod explain_alignment;
#[cfg(feature = "graph")]
mod ladybug;
mod project;
#[cfg(feature = "graph")]
mod prune;
#[cfg(feature = "graph")]
pub use alignment::*;
#[cfg(feature = "graph")]
pub use explain_alignment::*;
#[cfg(feature = "graph")]
pub use ladybug::*;
#[cfg(feature = "graph")]
pub use prune::*;
#[cfg(feature = "graph")]
mod snapshot;
pub use project::project;
pub(crate) use project::project_with_origins;
#[cfg(feature = "graph")]
pub use snapshot::{read_snapshot, write_snapshot};

pub use super::declarations::{IdentifiedRoot, NodeRef, Root};
use super::{invalid, Component, Report};
use crate::{
    error::{ensure, Result},
    files,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_COMPONENTS: usize = 100_000;
pub const MAX_EDGES: usize = super::declarations::MAX_DECLARATIONS;
pub const MAX_CONTEXTS: usize = 4096;
pub const MAX_BYTES: usize = 128 * 1024 * 1024;

impl NodeRef {
    /// Injective encoding, not a hash or an occurrence UUID.
    pub fn engine_key(&self) -> Result<String> {
        use std::fmt::Write;
        let mut result = String::new();
        for byte in serde_json::to_vec(&(&self.graph, &self.purl))? {
            write!(result, "{byte:02x}").map_err(|e| invalid(e.to_string()))?;
        }
        Ok(result)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub manifest: String,
    pub native: Value,
}
impl Context {
    pub fn path(&self) -> Result<String> {
        Ok(format!(
            "graphs/{}",
            files::hash(&serde_json::to_vec(self)?)
        ))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub key: NodeRef,
    pub component: Component,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub from: NodeRef,
    pub to: NodeRef,
    pub kind: String,
    /// Null means unconditional within this static lock graph. Other values are unevaluated.
    pub condition: Value,
    pub evidence: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Graph {
    pub schema_version: u32,
    pub inventory: Report,
    pub contexts: BTreeMap<String, Context>,
    pub components: Vec<Node>,
    pub dependencies: Vec<Edge>,
    pub roots: Vec<Root>,
    pub limitations: Vec<String>,
}
impl Graph {
    pub(super) fn canonicalize(&mut self) -> Result<()> {
        self.components.sort_by(|a, b| a.key.cmp(&b.key));
        let mut edges = self
            .dependencies
            .iter()
            .map(|e| Ok((serde_json::to_string(e)?, e.clone())))
            .collect::<Result<Vec<_>>>()?;
        edges.sort_by(|a, b| a.0.cmp(&b.0));
        self.dependencies = edges.into_iter().map(|(_, e)| e).collect();
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.inventory.complete
            && self.limitations.is_empty()
            && self.dependencies.iter().all(|e| e.condition.is_null())
            && self.roots.iter().all(|r| r.condition.is_null())
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "Version de graphe inconnue");
        self.inventory.validate()?;
        ensure!(
            self.components.len() <= MAX_COMPONENTS
                && self.dependencies.len() <= MAX_EDGES
                && self.contexts.len() <= MAX_CONTEXTS
                && self.roots.len() <= MAX_EDGES,
            "Limites du graphe dépassées"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_BYTES,
            "Graphe supérieur à 128 Mio"
        );
        for (path, context) in &self.contexts {
            ensure!(*path == context.path()?, "Identité de contexte divergente");
            crate::config::relative_path(&context.manifest)?;
        }
        for project in &self.inventory.projects {
            if project.ecosystem == "rust" {
                for component in &project.components {
                    crate::deps::rust::git::validate_component(component)?;
                }
            }
        }
        let mut keys = BTreeSet::new();
        for node in &self.components {
            let parsed = node
                .key
                .purl
                .parse::<packageurl::PackageUrl>()
                .map_err(|e| invalid(format!("PURL invalide : {e}")))?;
            ensure!(
                parsed.to_string() == node.key.purl && parsed.version().is_some(),
                "PURL canonique et versionnée requise"
            );
            ensure!(
                node.key.purl.len() <= 8192 && self.contexts.contains_key(&node.key.graph),
                "Contexte absent ou PURL trop longue"
            );
            ensure!(
                node.component.purl.as_ref() == Some(&node.key.purl),
                "PURL du composant divergente"
            );
            if parsed.ty() == "cargo" {
                crate::deps::rust::git::validate_component(&node.component)?;
            }
            ensure!(
                keys.insert(&node.key),
                "Composant dupliqué dans un contexte"
            );
        }
        let mut edges = BTreeSet::new();
        for edge in &self.dependencies {
            ensure!(
                keys.contains(&edge.from) && keys.contains(&edge.to),
                "Référence de dépendance absente"
            );
            ensure!(
                !edge.kind.is_empty() && edge.kind.len() <= 256,
                "Type de dépendance invalide"
            );
            ensure!(
                edges.insert(serde_json::to_string(edge)?),
                "Relation dupliquée"
            );
        }
        for root in &self.roots {
            ensure!(keys.contains(&root.to), "Référence racine absente");
            crate::config::relative_path(&root.manifest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct Diff {
    pub added: Vec<NodeRef>,
    pub removed: Vec<NodeRef>,
    pub added_edges: Vec<Edge>,
    pub removed_edges: Vec<Edge>,
    pub complete: bool,
}
/// Compare identities and edge semantics; version changes are remove/add pairs.
pub fn diff(before: &Graph, after: &Graph) -> Result<Diff> {
    before.validate()?;
    after.validate()?;
    let a: BTreeSet<_> = before.components.iter().map(|n| n.key.clone()).collect();
    let b: BTreeSet<_> = after.components.iter().map(|n| n.key.clone()).collect();
    let edge_map = |g: &Graph| -> Result<BTreeMap<String, Edge>> {
        g.dependencies
            .iter()
            .map(|e| Ok((serde_json::to_string(e)?, e.clone())))
            .collect()
    };
    let ea = edge_map(before)?;
    let eb = edge_map(after)?;
    Ok(Diff {
        added: b.difference(&a).cloned().collect(),
        removed: a.difference(&b).cloned().collect(),
        added_edges: eb
            .iter()
            .filter(|(k, _)| !ea.contains_key(*k))
            .map(|(_, e)| e.clone())
            .collect(),
        removed_edges: ea
            .iter()
            .filter(|(k, _)| !eb.contains_key(*k))
            .map(|(_, e)| e.clone())
            .collect(),
        complete: before.complete() && after.complete(),
    })
}
