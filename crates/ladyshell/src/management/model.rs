use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedStatus {
    Retained,
    DeletionPending,
    Deleted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceKind {
    Current,
    Previous,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub sandbox_name: String,
    pub sandbox_id: String,
    pub gateway: String,
    pub workspace: String,
    pub project: PathBuf,
    pub directory: PathBuf,
    pub kind: InstanceKind,
    pub recorded_status: RecordedStatus,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub labels: BTreeMap<String, String>,
    pub note: String,
    pub archived: bool,
}
#[derive(Debug, Clone, Default)]
pub struct Annotation {
    pub labels: BTreeMap<String, String>,
    pub remove_labels: Vec<String>,
    pub note: Option<String>,
    pub archived: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub id: String,
    #[serde(flatten)]
    pub observation: Observation,
    pub metadata: Metadata,
    /// Seen during the last refresh; never a provider liveness claim.
    pub observed: bool,
    /// Unix seconds, describing catalogue observations only.
    pub first_seen: i64,
    pub last_seen: i64,
}
#[derive(Debug, Clone)]
pub struct Filter {
    pub project: Option<PathBuf>,
    pub status: Option<RecordedStatus>,
    pub label: Option<(String, String)>,
    pub include_archived: bool,
    pub include_deleted: bool,
    pub after: Option<String>,
    pub limit: u32,
}
impl Default for Filter {
    fn default() -> Self {
        Self {
            project: None,
            status: None,
            label: None,
            include_archived: false,
            include_deleted: false,
            after: None,
            limit: 100,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refresh {
    pub schema_version: u32,
    pub registry: PathBuf,
    pub refreshed_at: i64,
    pub provider_checked: bool,
    pub complete: bool,
    pub observed: usize,
    pub diagnostics: Vec<Value>,
}
#[derive(Debug, Serialize)]
pub struct Inventory {
    pub schema_version: u32,
    pub provider_checked: bool,
    pub last_refresh: Option<Refresh>,
    pub instances: Vec<Instance>,
    pub next: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub sequence: i64,
    pub instance_id: String,
    pub recorded_at: i64,
    pub kind: String,
    pub observation: Observation,
    pub metadata: Metadata,
}
#[derive(Debug, Serialize)]
pub struct History {
    pub schema_version: u32,
    pub events: Vec<Event>,
    pub next: Option<i64>,
}
