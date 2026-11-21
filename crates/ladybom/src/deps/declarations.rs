//! Versioned declaration identities shared by analysis and execution-plan verification.
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_DECLARATIONS: usize = 500_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct NodeRef {
    pub graph: String,
    pub purl: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub manifest: String,
    pub native: Option<String>,
    pub to: NodeRef,
    pub kind: String,
    pub condition: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentifiedRoot {
    pub id: String,
    pub root: Root,
}
