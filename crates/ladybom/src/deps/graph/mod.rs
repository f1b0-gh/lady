//! Context-qualified dependency graph model and static projection.
mod project;
pub use project::project;
pub(crate) use project::project_with_origins;

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
    /// Sort components and edges into the deterministic order used by snapshot version 1.
    pub fn canonicalize(&mut self) -> Result<()> {
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
        ensure!(self.schema_version == 1, "Unknown graph version");
        self.inventory.validate()?;
        ensure!(
            self.components.len() <= MAX_COMPONENTS
                && self.dependencies.len() <= MAX_EDGES
                && self.contexts.len() <= MAX_CONTEXTS
                && self.roots.len() <= MAX_EDGES,
            "Graph limits exceeded"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_BYTES,
            "Graph exceeds 128 MiB"
        );
        for (path, context) in &self.contexts {
            ensure!(*path == context.path()?, "Context identity mismatch");
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
                .map_err(|e| invalid(format!("Invalid PURL: {e}")))?;
            ensure!(
                parsed.to_string() == node.key.purl && parsed.version().is_some(),
                "Canonical versioned PURL required"
            );
            ensure!(
                node.key.purl.len() <= 8192 && self.contexts.contains_key(&node.key.graph),
                "Missing context or PURL too long"
            );
            ensure!(
                node.component.purl.as_ref() == Some(&node.key.purl),
                "Component PURL mismatch"
            );
            if parsed.ty() == "cargo" {
                crate::deps::rust::git::validate_component(&node.component)?;
            }
            ensure!(
                keys.insert(&node.key),
                "Duplicate component within a context"
            );
        }
        let mut edges = BTreeSet::new();
        for edge in &self.dependencies {
            ensure!(
                keys.contains(&edge.from) && keys.contains(&edge.to),
                "Missing dependency reference"
            );
            ensure!(
                !edge.kind.is_empty() && edge.kind.len() <= 256,
                "Invalid dependency type"
            );
            ensure!(
                edges.insert(serde_json::to_string(edge)?),
                "Duplicate relationship"
            );
        }
        for root in &self.roots {
            ensure!(keys.contains(&root.to), "Missing root reference");
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

/// SHA-256 of the graph in its current serialized order.
pub fn graph_digest(graph: &Graph) -> Result<String> {
    Ok(files::hash(&serde_json::to_vec(graph)?))
}
