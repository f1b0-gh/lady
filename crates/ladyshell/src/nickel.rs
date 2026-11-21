//! OpenShell adapter over the shared Nickel evaluator; serialized receipts stay compatible.
use crate::{
    config::{Config, ResolvedConfig},
    error::Result,
    evaluation::{self, EvaluationRequest},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluated {
    pub config: ResolvedConfig,
    pub modules_sha256: BTreeMap<String, String>,
    pub schema_sha256: String,
    pub flake_lock_sha256: String,
    pub evaluator: String,
}
pub fn evaluate(entry: &Path, mission: &str, resources: &Path) -> Result<Evaluated> {
    let result = evaluation::evaluate(&EvaluationRequest {
        entry,
        contract: Some(&resources.join("config/schema.ncl")),
        nix: &resources.join("nix"),
    })?;
    Ok(Evaluated {
        config: Config::from_value(result.value)?.resolve(mission)?,
        modules_sha256: result.modules_sha256,
        schema_sha256: result
            .contract_sha256
            .ok_or_else(|| crate::error::Error::InvalidInput {
                message: "Missing Nickel contract".into(),
            })?,
        flake_lock_sha256: result.flake_lock_sha256,
        evaluator: result.evaluator,
    })
}
