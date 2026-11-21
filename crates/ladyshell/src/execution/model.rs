use super::invalid;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub schema_version: u32,
    pub receiver_id: String,
    pub catalog_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPin {
    pub state: PathBuf,
    pub state_dev: u64,
    pub state_ino: u64,
    pub sandbox_name: String,
    pub sandbox_id: String,
    pub owner: String,
    pub policy_hash: String,
    pub desired_hash: String,
    pub image_id: String,
    pub context: Value,
    pub runtime: String,
    pub continuous: Value,
    pub source_sha256: String,
    pub exclusions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDefinition {
    pub id: String,
    pub argv: Vec<String>,
    pub timeout_seconds: u32,
    pub output_limit_bytes: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub environment: EnvironmentPin,
    pub tasks: Vec<TaskDefinition>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub scope: String,
    pub id: String,
    pub task: String,
    pub definition_sha256: String,
    pub intent: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub scope: String,
    pub id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerFence {
    pub task: String,
    pub deployment: String,
    pub epoch: u64,
    pub incarnation: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub reference: String,
    pub admit_before: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub owner: Option<OwnerFence>,
    pub claim: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Accepted,
    Dispatching,
    Completed,
    Refused,
    Uncertain,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientResult {
    Exit { code: i32 },
    Signal { signal: i32 },
    Timeout,
    OutputLimit,
    SpawnFailure,
    IoFailure,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    OpenshellClient,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Stdout,
    Stderr,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRef {
    pub stream: Stream,
    pub length: u32,
    pub sha256: String,
    pub truncated: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub provenance: Provenance,
    pub result: ClientResult,
    pub stdout: OutputRef,
    pub stderr: OutputRef,
}
#[derive(Clone, Debug, Default)]
pub struct CapturedStream {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}
#[derive(Clone, Debug, Default)]
pub struct CapturedOutputs {
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    pub at: u64,
    pub reason: String,
    pub evidence: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub reconciliations: Vec<Reconciliation>,
    pub schema_version: u32,
    pub binding: Binding,
    pub invocation: Invocation,
    pub intent_sha256: String,
    pub admission: Admission,
    pub environment: EnvironmentPin,
    pub definition: TaskDefinition,
    pub accepted_at: u64,
    pub phase: Phase,
    #[serde(deserialize_with = "Option::deserialize")]
    pub dispatched_at: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub finished_at: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub reason: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub outcome: Option<Outcome>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Acceptance {
    pub record: Record,
    pub is_new: bool,
}
impl Invocation {
    pub fn key(&self) -> Key {
        Key {
            scope: self.scope.clone(),
            id: self.id.clone(),
        }
    }
}

use crate::{error::ensure, files};
use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

pub(super) fn text(s: &str, limit: usize) -> Result<()> {
    ensure!(
        !s.is_empty() && s.len() <= limit && !s.contains('\0'),
        "Invalid or overlong retained text"
    );
    Ok(())
}
pub(super) fn hex(s: &str, len: usize) -> Result<()> {
    ensure!(
        s.len() == len
            && s.bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "Invalid retained hexadecimal identity"
    );
    Ok(())
}
// Check typed callers before invoking recursive Serde or cloning arbitrary JSON.
// Charge a lower bound on encoded bytes during the walk, then check escaping.
pub(super) fn bounded_value(value: &Value, limit: usize) -> Result<()> {
    fn visit(value: &Value, depth: usize, budget: &mut usize) -> Result<()> {
        ensure!(depth <= 48, "Retained JSON nesting limit exceeded");
        let cost = match value {
            Value::String(s) => s.len().saturating_add(2),
            Value::Object(o) => {
                for (k, v) in o {
                    *budget = budget
                        .checked_sub(k.len() + 2)
                        .ok_or_else(|| invalid("Retained JSON too large"))?;
                    visit(v, depth + 1, budget)?;
                }
                2
            }
            Value::Array(a) => {
                for v in a {
                    visit(v, depth + 1, budget)?;
                }
                2
            }
            _ => 1,
        };
        *budget = budget
            .checked_sub(cost)
            .ok_or_else(|| invalid("Retained JSON too large"))?;
        Ok(())
    }
    let mut remaining = limit;
    visit(value, 0, &mut remaining)?;
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= limit, "Retained JSON too large");
    crate::json::parse(&bytes)?;
    Ok(())
}
pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut sorted = serde_json::to_value(value)?;
    sorted.sort_all_objects();
    Ok(serde_json::to_vec(&sorted)?)
}
pub(super) fn digest(value: &impl Serialize) -> Result<String> {
    Ok(files::hash(&encode(value)?))
}
pub(super) fn normalized(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .to_str()
                .is_some_and(|s| s.len() <= 4096 && !s.contains('\0'))
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
            && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str(),
        "Retained path must be absolute and normalized"
    );
    Ok(())
}
impl Key {
    pub fn digest(&self) -> Result<String> {
        text(&self.scope, 256)?;
        text(&self.id, 256)?;
        digest(&("ladyshell-execution-key/1", &self.scope, &self.id))
    }
}
impl Invocation {
    pub(super) fn validate(&self) -> Result<()> {
        text(&self.scope, 256)?;
        text(&self.id, 256)?;
        crate::config::identifier(&self.task)?;
        hex(&self.definition_sha256, 64)?;
        bounded_value(&self.intent, 16384)
    }
}
impl OwnerFence {
    pub(super) fn validate(&self) -> Result<()> {
        hex(&self.task, 64)?;
        hex(&self.deployment, 64)?;
        hex(&self.incarnation, 32)
    }
}
impl Admission {
    pub(super) fn validate(&self) -> Result<()> {
        text(&self.reference, 1024)?;
        if let Some(owner) = &self.owner {
            owner.validate()?;
        }
        ensure!(self.claim > 0, "Dispatch requires a positive claim epoch");
        Ok(())
    }
}
impl TaskDefinition {
    fn validate(&self) -> Result<()> {
        crate::config::identifier(&self.id)?;
        ensure!(
            (1..=128).contains(&self.argv.len()) && !self.argv[0].is_empty(),
            "Invalid task argument count or program"
        );
        ensure!(
            self.argv
                .iter()
                .all(|v| v.len() <= 4096 && !v.contains('\0'))
                && self.argv.iter().map(String::len).sum::<usize>() <= 32768,
            "Invalid task arguments"
        );
        ensure!(
            (1..=86400).contains(&self.timeout_seconds)
                && (1..=1048576).contains(&self.output_limit_bytes),
            "Invalid task execution bounds"
        );
        Ok(())
    }
}
impl Catalog {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && !self.tasks.is_empty() && self.tasks.len() <= 64,
            "Invalid retained catalogue version or task count"
        );
        let e = &self.environment;
        normalized(&e.state)?;
        ensure!(
            e.state_ino != 0,
            "Invalid retained state directory identity"
        );
        crate::config::identifier(&e.sandbox_name)?;
        for s in [
            &e.sandbox_id,
            &e.owner,
            &e.policy_hash,
            &e.desired_hash,
            &e.image_id,
            &e.runtime,
        ] {
            text(s, 1024)?;
        }
        hex(&e.source_sha256, 64)?;
        ensure!(
            e.context.is_object() && (e.continuous.is_null() || e.continuous.is_object()),
            "Invalid retained environment binding"
        );
        bounded_value(&e.context, 16384)?;
        bounded_value(&e.continuous, 16384)?;
        ensure!(
            e.exclusions.len() <= 1024,
            "Too many retained source exclusions"
        );
        let mut names = BTreeSet::new();
        let mut bytes = 0;
        for s in &e.exclusions {
            text(s, 4096)?;
            bytes += s.len();
            ensure!(
                bytes <= 32768 && names.insert(s),
                "Excessive or duplicate source exclusions"
            );
        }
        let mut ids = BTreeSet::new();
        for t in &self.tasks {
            t.validate()?;
            ensure!(ids.insert(&t.id), "Duplicate retained task identifier");
        }
        Ok(())
    }
    pub fn definition(&self, task: &str) -> Result<&TaskDefinition> {
        self.tasks
            .iter()
            .find(|t| t.id == task)
            .ok_or_else(|| invalid("Unknown retained task"))
    }
    pub fn definition_digest(&self, task: &str) -> Result<String> {
        self.validate()?;
        digest(&(
            "ladyshell-execution-definition/1",
            self.schema_version,
            &self.environment,
            self.definition(task)?,
        ))
    }
}
impl ClientResult {
    pub(super) fn phase(&self, partial: bool) -> Result<Phase> {
        match self {
            Self::Exit { code: 0 } if !partial => Ok(Phase::Completed),
            Self::Exit { code } if !(0..=255).contains(code) => {
                Err(invalid("Invalid OpenShell client exit code"))
            }
            Self::Signal { signal } if !(1..=64).contains(signal) => {
                Err(invalid("Invalid OpenShell client signal"))
            }
            _ => Ok(Phase::Uncertain),
        }
    }
}
impl Stream {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}
