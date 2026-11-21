//! The short receiver lock serializes owner changes, the admission clock and
//! directory reservations. Each entry also pins immutable invocation evidence.
use super::*;
use crate::{
    error::{ensure, Result},
    files,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File};

pub(super) const INDEX_LIMIT: usize = 16 * 1024 * 1024;
// The 1024 bounded scopes and entry headers fit in this base index budget.
// Reconciliation contributions are charged as they are appended.
const INDEX_BASE: usize = 3 * 1024 * 1024;
pub(super) const MANIFEST_LIMIT: usize = 3 * 1024 * 1024;
pub(super) const INTENT_LIMIT: usize = 512 * 1024;
pub(super) const RECEIPT_LIMIT: usize = 16 * 1024;
const TOTAL_LIMIT: u64 = 32 * 1024 * 1024;
pub(super) const COUNT_LIMIT: usize = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installation {
    pub schema_version: u32,
    pub nonce: String,
    pub catalog: Catalog,
}
impl Installation {
    pub fn binding(&self) -> Result<Binding> {
        ensure!(
            self.schema_version == 1,
            "Unknown retained installation version"
        );
        hex(&self.nonce, 64)?;
        self.catalog.validate()?;
        let catalog_sha256 = digest(&self.catalog)?;
        let receiver_id = digest(&("ladyshell-receiver/1", &self.nonce, &catalog_sha256))?;
        Ok(Binding {
            schema_version: 1,
            receiver_id,
            catalog_sha256,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed<T> {
    sha256: String,
    data: T,
}
pub(super) fn seal<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let bytes = encode(&Sealed {
        sha256: digest(value)?,
        data: value,
    })?;
    ensure!(
        bytes.len() <= limit,
        "Retained document exceeds its size limit"
    );
    Ok(bytes)
}
pub(super) fn unseal<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let document: Sealed<T> = serde_json::from_value(crate::json::parse(bytes)?)?;
    ensure!(
        digest(&document.data)? == document.sha256,
        "Retained metadata checksum mismatch"
    );
    Ok(document.data)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    pub schema_version: u32,
    pub binding: Binding,
    pub clock: u64,
    pub scopes: BTreeMap<String, Scope>,
    pub entries: BTreeMap<String, Entry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    #[serde(deserialize_with = "Option::deserialize")]
    pub owner: Option<OwnerFence>,
    pub claim: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub inode: u64,
    pub accepted_sha256: String,
    pub budget: u64,
    pub reconciliations: Vec<Reconciliation>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub dispatch: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub terminal: Option<String>,
}
impl Ledger {
    pub fn new(binding: &Binding) -> Self {
        Self {
            schema_version: 1,
            binding: binding.clone(),
            clock: 0,
            scopes: BTreeMap::new(),
            entries: BTreeMap::new(),
        }
    }
    pub fn load(dir: &File, binding: &Binding, manifest_bytes: u64) -> Result<Self> {
        let l: Self = unseal(&fs::bytes(dir, "ledger.json", INDEX_LIMIT)?)?;
        ensure!(
            l.schema_version == 1
                && &l.binding == binding
                && l.scopes.len() <= COUNT_LIMIT
                && l.entries.len() <= COUNT_LIMIT,
            "Inconsistent retained ledger identity or counts"
        );
        for (scope, f) in &l.scopes {
            text(scope, 256)?;
            if let Some(o) = &f.owner {
                o.validate()?;
            }
        }
        for (key, e) in &l.entries {
            hex(key, 64)?;
            hex(&e.accepted_sha256, 64)?;
            ensure!(
                e.reconciliations.len() <= 16,
                "Retained reconciliation limit exceeded"
            );
            if let Some(h) = &e.terminal {
                hex(h, 64)?;
            }
            ensure!(
                e.inode != 0 && e.budget > 0 && e.dispatch.is_none_or(|at| at <= l.clock),
                "Invalid retained ledger entry"
            );
        }
        l.capacity(manifest_bytes, 0)?;
        Ok(l)
    }
    pub fn capacity(&self, manifest_bytes: u64, extra: u64) -> Result<()> {
        // Keep space for both the existing and replacement index while fsyncing.
        // Each invocation reserves its largest permitted capture before acceptance.
        let mut used = manifest_bytes + 2 * INDEX_BASE as u64;
        for n in self
            .entries
            .values()
            .map(|e| e.budget)
            .chain(std::iter::once(extra))
        {
            used = used
                .checked_add(n)
                .ok_or_else(|| invalid("Retained byte accounting overflow"))?;
        }
        ensure!(
            used <= TOTAL_LIMIT,
            "Retained receiver byte capacity exhausted"
        );
        Ok(())
    }
    pub fn authorize(&self, scope: &str, a: &Admission) -> Result<()> {
        let f = self
            .scopes
            .get(scope)
            .ok_or_else(|| invalid("Unbound retained scope"))?;
        ensure!(
            a.claim > 0 && a.claim == f.claim && a.owner == f.owner,
            "Stale retained owner or claim"
        );
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dispatch {
    pub accepted_sha256: String,
    pub at: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Terminal {
    pub accepted_sha256: String,
    pub finished_at: u64,
    pub phase: Phase,
    #[serde(deserialize_with = "Option::deserialize")]
    pub dispatched_at: Option<u64>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub reason: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub outcome: Option<Outcome>,
}
impl Terminal {
    pub fn apply(self, record: &mut Record, dir: &File, accepted_sha256: &str) -> Result<()> {
        ensure!(
            self.accepted_sha256 == accepted_sha256
                && self.dispatched_at == record.dispatched_at
                && self.finished_at >= record.dispatched_at.unwrap_or(record.accepted_at),
            "Terminal receipt does not match invocation or timestamps"
        );
        match (&self.outcome, &self.reason) {
            (Some(o), None) => {
                ensure!(
                    record.phase == Phase::Dispatching
                        && o.result.phase(o.stdout.truncated || o.stderr.truncated)? == self.phase,
                    "Inconsistent retained client outcome"
                );
                for (reference, stream) in
                    [(&o.stdout, Stream::Stdout), (&o.stderr, Stream::Stderr)]
                {
                    ensure!(
                        reference.stream == stream,
                        "Incorrect retained stream reference"
                    );
                    verify_output(dir, reference, record.definition.output_limit_bytes)?;
                }
            }
            (None, Some(reason)) => {
                text(reason, 1024)?;
                ensure!(
                    self.phase == Phase::Uncertain
                        || (self.phase == Phase::Refused && record.phase == Phase::Accepted),
                    "Inconsistent retained terminal reason"
                );
            }
            _ => return Err(invalid("Missing or ambiguous retained terminal evidence")),
        }
        record.phase = self.phase;
        record.reason = self.reason;
        record.outcome = self.outcome;
        record.finished_at = Some(self.finished_at);
        Ok(())
    }
}
pub(super) fn verify_output(dir: &File, r: &OutputRef, limit: u32) -> Result<Vec<u8>> {
    ensure!(r.length <= limit, "Retained output exceeds catalogue limit");
    hex(&r.sha256, 64)?;
    let bytes = fs::bytes(dir, r.stream.name(), r.length as usize)?;
    ensure!(
        bytes.len() == r.length as usize && files::hash(&bytes) == r.sha256,
        "Retained output integrity mismatch"
    );
    Ok(bytes)
}
