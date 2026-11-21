use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u32,
    pub source: String,
    pub fetched_at: String,
    /// Explicit assertion by the snapshot producer, never inferred from record count.
    pub complete: bool,
    pub ecosystems: Vec<String>,
    pub advisories: Vec<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStatus {
    Matched,
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct MatchResult {
    pub status: Option<MatchStatus>,
    pub fixed_versions: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub inventory_complete: bool,
    pub advisories_complete: bool,
    pub identities_complete: bool,
    pub matching_complete: bool,
    pub fresh: bool,
    pub components: usize,
    pub assessed_components: usize,
    pub withdrawn_advisories: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub component_ref: String,
    pub purl: Option<String>,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub manifest: String,
    pub lockfile: Option<String>,
    pub context: String,
    pub status: MatchStatus,
    pub advisory_ids: Vec<String>,
    pub aliases: Vec<String>,
    pub fixed_versions: Vec<String>,
    /// Original OSV records, including ranges, severity vectors and references.
    pub evidence: Vec<Value>,
    pub limitations: Vec<String>,
}

/// Produced by assessment, not accepted as a substitute for its source inputs by the CLI.
#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub schema_version: u32,
    pub report_digest: String,
    pub snapshot_digest: String,
    pub sbom_serial: String,
    pub as_of: String,
    pub snapshot_fetched_at: String,
    pub snapshot_source: String,
    pub max_age_seconds: u64,
    pub complete: bool,
    pub coverage: Coverage,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionState {
    InTriage,
    Exploitable,
    NotAffected,
    FalsePositive,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub finding_id: String,
    pub state: DecisionState,
    pub justification: Option<String>,
    pub detail: String,
    pub author: String,
    pub evidence: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decisions {
    pub schema_version: u32,
    pub report_digest: String,
    pub snapshot_digest: String,
    pub decisions: Vec<Decision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub finding_id: String,
    pub report_digest: String,
    pub snapshot_digest: String,
    pub author: String,
    pub reason: String,
    pub evidence: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    pub max_age_seconds: u64,
    pub exceptions: Vec<Exception>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            max_age_seconds: 604800,
            exceptions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signals {
    pub schema_version: u32,
    pub source: String,
    pub fetched_at: String,
    pub entries: Vec<Signal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    pub id: String,
    pub known_exploited: bool,
    pub epss: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingDecision {
    pub finding_id: String,
    pub state: DecisionState,
    pub priority: String,
    pub accepted_risk: bool,
    pub blocking: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyResult {
    pub schema_version: u32,
    pub report_digest: String,
    pub snapshot_digest: String,
    pub as_of: String,
    pub allowed: bool,
    pub complete: bool,
    pub findings: Vec<FindingDecision>,
    pub reasons: Vec<String>,
}
