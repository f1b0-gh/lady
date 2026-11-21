use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Planned,
    Running,
    Interrupted,
    Blocked,
    Failed,
    Partial,
    Complete,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Quick,
    Targeted,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub invocations: u32,
    pub seconds: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunMetadata {
    pub schema_version: u32,
    pub document_schema: String,
    pub run_id: String,
    pub status: RunStatus,
    pub profile: Profile,
    pub scope_paths: Vec<String>,
    pub config_sha256: String,
    pub toolchain_sha256: String,
    pub method_sha256: String,
    pub documents: BTreeMap<String, String>,
    pub links: Vec<FindingLink>,
    pub invocations: Vec<InvocationReceipt>,
    pub budget: Budget,
    pub elapsed_seconds: u64,
    pub open_obligations: Vec<String>,
    pub environment_verified: bool,
    pub cleanup_verified: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingLink {
    pub fingerprint: String,
    pub coverage_ids: Vec<String>,
    pub artifact_ids: Vec<String>,
    pub hunter_id: String,
    pub verifier_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Recon,
    Hunter,
    Verifier,
    Critic,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStatus {
    Finished,
    Failed,
    Interrupted,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationReceipt {
    pub id: String,
    pub role: Role,
    pub status: InvocationStatus,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceManifest {
    pub schema_version: u32,
    pub files: Vec<SourceFile>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifest {
    pub schema_version: u32,
    pub artifacts: Vec<Artifact>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub id: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub producer: String,
    pub command: Vec<String>,
}

/// Constructed only by verify::load. The retained bytes are the ones verified.
pub struct VerifiedRun {
    pub(crate) metadata: RunMetadata,
    pub(crate) sources: SourceManifest,
    pub(crate) findings: Vec<Value>,
    pub(crate) coverage: Vec<Value>,
    pub(crate) files: BTreeMap<String, Vec<u8>>,
}
