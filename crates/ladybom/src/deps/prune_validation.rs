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
        ensure!(
            self.schema_version == 1,
            "Version de plan de validation inconnue"
        );
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
                "Empreinte de validation invalide"
            );
        }
        snapshot::validate(&self.expected)?;
        ensure!(
            !self.expected.is_empty()
                && !self.removed_declarations.is_empty()
                && self.removed_declarations.len() <= MAX_DECLARATIONS,
            "Plan de retrait vide ou trop volumineux"
        );
        ensure!(self.exclusions.len() <= 1000, "Trop d'exclusions");
        for path in &self.exclusions {
            crate::config::relative_path(path)?;
        }
        let mut seen = BTreeSet::new();
        for r in &self.removed_declarations {
            ensure!(
                seen.insert(&r.id) && r.id == files::hash(&serde_json::to_vec(&r.root)?),
                "Identité de retrait invalide ou dupliquée"
            );
            ensure!(
                self.expected.contains_key(&r.root.manifest),
                "Manifest retiré absent de l'inventaire attendu"
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
            "Sources divergentes du graphe après retrait : {path}"
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
            .ok_or_else(|| invalid("Projet source absent".into()))?;
        let current = after
            .inventory
            .projects
            .iter()
            .find(|p| p.manifest == root.manifest && p.ecosystem == previous.ecosystem)
            .ok_or_else(|| invalid("Le projet doit être conservé après retrait".into()))?;
        // Cargo/conditional roots retain the original requirement. Otherwise match the
        // exact declared name, including npm aliases, against the resolved component.
        let embedded = serde_json::from_value::<Requirement>(root.condition.clone()).ok();
        let component = before
            .components
            .iter()
            .find(|n| n.key == root.to)
            .ok_or_else(|| invalid("Composant source absent".into()))?;
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
            "Déclaration source ambiguë : validation automatique refusée"
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
            "Déclaration toujours présente : {} {}",
            root.manifest,
            removed.name
        );
        ensure!(
            after.inventory.inputs.contains_key(&root.manifest),
            "Manifest après retrait non empreinté"
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
        "Sources de validation divergentes : aucune réussite attribuable à ce plan"
    );
    Ok(())
}
