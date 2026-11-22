use super::{invalid, Intent, Profile, Receipt};
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Result},
    state,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

/// Trusted host resource operations. Create must use the exact intent. Delete
/// must freshly compare the original receipt and refuse attached volumes.
/// Authentication, lifecycle policy and sandbox absence belong to the caller.
pub trait Driver {
    fn observe(&mut self, name: &str) -> Result<Option<Value>>;
    fn create(&mut self, intent: &Intent) -> Result<()>;
    fn delete(&mut self, original: &Receipt) -> Result<()>;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    intent: Intent,
    receipt: Option<Receipt>,
    deleted: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u8,
    deleting: bool,
    entries: Vec<Entry>,
}
impl Journal {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 1 && self.entries.len() == 3,
            "Invalid storage journal"
        );
        let first = &self.entries[0].intent;
        let mut areas = std::collections::BTreeSet::new();
        for entry in &self.entries {
            entry.intent.validate()?;
            ensure!(
                entry.intent.owner == first.owner
                    && entry.intent.workspace == first.workspace
                    && areas.insert(entry.intent.area.name())
                    && (!entry.deleted || self.deleting)
                    && entry
                        .receipt
                        .as_ref()
                        .is_none_or(|r| r.intent == entry.intent
                            && r.identity.len() == 64
                            && r.identity
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
                "Invalid retained storage identity"
            );
        }
        Ok(())
    }
    fn save(&self, lock: &state::StateLock) -> Result<()> {
        self.validate()?;
        lock.verify_directory()?;
        atomic_json(&lock.directory.join("storage.json"), self)
    }
}
fn load(lock: &state::StateLock) -> Result<Option<Journal>> {
    lock.verify_directory()?;
    let journal = state::read(&lock.directory.join("storage.json"))?
        .map(serde_json::from_value::<Journal>)
        .transpose()?;
    if let Some(journal) = &journal {
        journal.validate()?;
    }
    Ok(journal)
}

/// Prepare under an independently admitted provisioning operation. The private
/// directory is dedicated to this storage journal and locked for the whole call.
/// An observed volume lost after retention is never silently recreated.
pub fn prepare(
    directory: &Path,
    profile: &Profile,
    owner: &str,
    workspace: &str,
    driver: &mut impl Driver,
) -> Result<Vec<Receipt>> {
    let intents = profile.intents(owner, workspace)?;
    let lock = state::StateLock::acquire(directory)?;
    let mut journal = match load(&lock)? {
        Some(journal) => journal,
        None => {
            let journal = Journal {
                format: 1,
                deleting: false,
                entries: intents
                    .iter()
                    .cloned()
                    .map(|intent| Entry {
                        intent,
                        receipt: None,
                        deleted: false,
                    })
                    .collect(),
            };
            journal.save(&lock)?;
            journal
        }
    };
    ensure!(
        !journal.deleting && journal.entries.iter().map(|e| &e.intent).eq(intents.iter()),
        "Storage operation differs from its original provisioning intent"
    );
    for index in 0..journal.entries.len() {
        let entry = &journal.entries[index];
        let observed = driver.observe(&entry.intent.name())?;
        if let Some(receipt) = &entry.receipt {
            receipt
                .verify(&observed.ok_or_else(|| invalid("Original storage volume is missing"))?)?;
            continue;
        }
        let (observed, result) = match observed {
            Some(value) => (Some(value), Ok(())),
            None => {
                lock.verify_directory()?;
                let result = driver.create(&entry.intent);
                (driver.observe(&entry.intent.name())?, result)
            }
        };
        if let Some(value) = observed {
            journal.entries[index].receipt = Some(entry.intent.observe(&value)?);
            journal.save(&lock)?;
        }
        // Retain successful creation even when its command lost the reply.
        result?;
        ensure!(
            journal.entries[index].receipt.is_some(),
            "Storage creation is not confirmed"
        );
    }
    journal
        .entries
        .into_iter()
        .map(|entry| {
            entry
                .receipt
                .ok_or_else(|| invalid("Storage receipt missing"))
        })
        .collect()
}

/// Remove only the originally journalled storage after its sandbox is proven
/// absent and required exports are retained. This does not attest task retirement.
/// A partially provisioned operation is also eligible for explicit cleanup.
pub fn remove(directory: &Path, driver: &mut impl Driver) -> Result<()> {
    remove_checked(directory, None, driver)
}

/// Remove a published deployment's volumes only when the complete receipt set
/// matches its original journal. Validation precedes any deletion intent/effect.
pub fn remove_original(
    directory: &Path,
    original: &[Receipt],
    driver: &mut impl Driver,
) -> Result<()> {
    remove_checked(directory, Some(original), driver)
}
fn remove_checked(
    directory: &Path,
    original: Option<&[Receipt]>,
    driver: &mut impl Driver,
) -> Result<()> {
    let lock = state::StateLock::acquire_existing(directory)?;
    let mut journal = load(&lock)?.ok_or_else(|| invalid("Storage journal missing"))?;
    if let Some(original) = original {
        ensure!(
            original.len() == journal.entries.len()
                && journal
                    .entries
                    .iter()
                    .zip(original)
                    .all(|(entry, receipt)| entry.receipt.as_ref() == Some(receipt)),
            "Storage journal differs from original deployment receipts"
        );
    }
    if !journal.deleting {
        journal.deleting = true;
        journal.save(&lock)?;
    }
    for index in 0..journal.entries.len() {
        let entry = &journal.entries[index];
        if entry.deleted {
            continue;
        }
        let observed = driver.observe(&entry.intent.name())?;
        let Some(value) = observed else {
            journal.entries[index].deleted = true;
            journal.save(&lock)?;
            continue;
        };
        let receipt = match &entry.receipt {
            Some(receipt) => {
                receipt.verify(&value)?;
                receipt.clone()
            }
            None => {
                let receipt = entry.intent.observe(&value)?;
                journal.entries[index].receipt = Some(receipt.clone());
                journal.save(&lock)?;
                receipt
            }
        };
        lock.verify_directory()?;
        let result = driver.delete(&receipt);
        let remaining = driver.observe(&receipt.intent().name())?;
        if remaining.is_none() {
            journal.entries[index].deleted = true;
            journal.save(&lock)?;
        } else {
            // Keep original evidence even if another resource appeared at the name.
            return Err(invalid("Storage deletion is not confirmed"));
        }
        result?;
    }
    Ok(())
}
