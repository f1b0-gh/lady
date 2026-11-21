//! Pure, source-bound validation plans for explicit dependency removals.
use super::{
    declarations::{IdentifiedRoot, MAX_DECLARATIONS},
    invalid,
};
use crate::{
    error::{ensure, Result},
    files,
    inventory::{self as snapshot, Inventory},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
pub fn verify_inventory(plan: &ValidationPlan, actual: &Inventory) -> Result<()> {
    plan.validate()?;
    snapshot::validate(actual)?;
    ensure!(
        &plan.expected == actual,
        "Validation sources differ: no success can be attributed to this plan"
    );
    Ok(())
}
