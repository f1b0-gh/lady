//! Pure, source-bound validation plans for explicit dependency removals.
use super::{
    declarations::{IdentifiedRoot, MAX_DECLARATIONS},
    invalid,
};
#[cfg(feature = "graph")]
use super::{graph, Requirement};
use crate::{
    error::{ensure, Result},
    files,
    inventory::{self as snapshot, Inventory},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[cfg(feature = "graph")]
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationPlan {
    pub schema_version: u32,
    pub before_graph_sha256: String,
    pub after_graph_sha256: String,
    pub request_sha256: String,
    pub removed_declarations: Vec<IdentifiedRoot>,
    pub expected: Inventory,
    pub exclusions: Vec<String>,
}
impl ValidationPlan {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "Unknown validation plan version");
        for digest in [
            &self.before_graph_sha256,
            &self.after_graph_sha256,
            &self.request_sha256,
        ] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "Invalid validation digest"
            );
        }
        snapshot::validate(&self.expected)?;
        ensure!(
            !self.expected.is_empty()
                && !self.removed_declarations.is_empty()
                && self.removed_declarations.len() <= MAX_DECLARATIONS,
            "Removal plan empty or too large"
        );
        ensure!(self.exclusions.len() <= 1000, "Too many exclusions");
        for path in &self.exclusions {
            crate::config::relative_path(path)?;
        }
        let mut seen = BTreeSet::new();
        for r in &self.removed_declarations {
            ensure!(
                seen.insert(&r.id) && r.id == files::hash(&serde_json::to_vec(&r.root)?),
                "Invalid or duplicate removal identity"
            );
            ensure!(
                self.expected.contains_key(&r.root.manifest),
                "Removal manifest missing from the expected inventory"
            );
        }
        Ok(())
    }
}
/// Capture an explicitly edited project; no file is modified and no check is executed.
#[cfg(feature = "graph")]
pub fn plan(
    before: &graph::Graph,
    after: &graph::Graph,
    request: &graph::RemovalRequest,
    project: &Path,
    exclusions: &[String],
) -> Result<ValidationPlan> {
    request.validate(before)?;
    after.validate()?;
    let expected = snapshot::inventory_filtered(project, exclusions)?;
    for (path, hash) in &after.inventory.inputs {
        ensure!(
            expected.get(path).is_some_and(|e| &e.sha256 == hash),
            "Sources differ from the graph after removal: {path}"
        );
    }
    let ids: BTreeSet<_> = request.remove_roots.iter().collect();
    let removed_declarations: Vec<_> = graph::root_catalog(before)?
        .into_iter()
        .filter(|r| ids.contains(&r.id))
        .collect();
    for removal in &removed_declarations {
        let root = &removal.root;
        let previous = before
            .inventory
            .projects
            .iter()
            .find(|p| p.manifest == root.manifest)
            .ok_or_else(|| invalid("Missing source project".into()))?;
        let current = after
            .inventory
            .projects
            .iter()
            .find(|p| p.manifest == root.manifest && p.ecosystem == previous.ecosystem)
            .ok_or_else(|| invalid("The project must be retained after removal".into()))?;
        // Cargo/conditional roots retain the original requirement. Otherwise match the
        // exact declared name, including npm aliases, against the resolved component.
        let embedded = serde_json::from_value::<Requirement>(root.condition.clone()).ok();
        let component = before
            .components
            .iter()
            .find(|n| n.key == root.to)
            .ok_or_else(|| invalid("Missing source component".into()))?;
        let candidates: Vec<_> = previous
            .requirements
            .iter()
            .filter(|r| {
                if r.kind != root.kind {
                    return false;
                }
                if let Some(e) = &embedded {
                    return r.name == e.name
                        && r.declared_name == e.declared_name
                        && r.marker == e.marker
                        && r.source == e.source;
                }
                if previous.ecosystem == "npm" {
                    return component.component.context == format!("node_modules/{}", r.name);
                }
                r.name == component.component.name
                    || r.constraint.strip_prefix("npm:").is_some_and(|alias| {
                        alias.rsplit_once('@').map_or(alias, |(name, _)| name)
                            == component.component.name
                    })
            })
            .collect();
        ensure!(
            candidates.len() == 1,
            "Ambiguous source declaration: automatic validation refused"
        );
        let removed = candidates[0];
        ensure!(
            !current
                .requirements
                .iter()
                .any(|r| r.declared_name.as_ref().unwrap_or(&r.name)
                    == removed.declared_name.as_ref().unwrap_or(&removed.name)
                    && r.kind == removed.kind
                    && r.marker == removed.marker),
            "Declaration still present: {} {}",
            root.manifest,
            removed.name
        );
        ensure!(
            after.inventory.inputs.contains_key(&root.manifest),
            "Manifest after removal has not been hashed"
        );
    }
    let result = ValidationPlan {
        schema_version: 1,
        before_graph_sha256: graph::graph_digest(before)?,
        after_graph_sha256: graph::graph_digest(after)?,
        request_sha256: files::hash(&serde_json::to_vec(request)?),
        removed_declarations,
        expected,
        exclusions: exclusions.to_vec(),
    };
    result.validate()?;
    Ok(result)
}
pub fn verify_inventory(plan: &ValidationPlan, actual: &Inventory) -> Result<()> {
    plan.validate()?;
    snapshot::validate(actual)?;
    ensure!(
        &plan.expected == actual,
        "Validation sources differ: no success can be attributed to this plan"
    );
    Ok(())
}
