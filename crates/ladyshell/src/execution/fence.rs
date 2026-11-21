//! A durable environment exclusion, operated only under its exclusive session lease.
use super::{invalid, store::fs, Binding, Key, Record, Store};
use crate::{
    error::{ensure, Result},
    files,
    state::SessionLock,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

const NAME: &str = "retained-execution.json";
const LIMIT: usize = 32768;

pub(crate) fn available(dir: &File) -> Result<()> {
    ensure!(
        !fs::exists(dir, NAME)?,
        "Retained execution fence blocks use of this environment"
    );
    // If the last supervisor died after unlink, acknowledge absence only once durable.
    dir.sync_all()?;
    Ok(())
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fence {
    schema_version: u32,
    receiver: PathBuf,
    binding: Binding,
    key: Key,
    intent_sha256: String,
}
impl Fence {
    pub(super) fn for_record(store: &Store, r: &Record) -> Self {
        Self {
            schema_version: 1,
            receiver: store.directory().to_owned(),
            binding: r.binding.clone(),
            key: r.invocation.key(),
            intent_sha256: r.intent_sha256.clone(),
        }
    }
    // Presence is validated against an independently loaded original journal record.
    pub(crate) fn matches_or_absent(&self, dir: &File) -> Result<bool> {
        if !fs::exists(dir, NAME)? {
            available(dir)?;
            return Ok(false);
        }
        let seen: Self =
            serde_json::from_value(crate::json::parse(&fs::bytes(dir, NAME, LIMIT)?)?)?;
        ensure!(
            seen == *self,
            "State fence belongs to another retained invocation"
        );
        dir.sync_all()?;
        Ok(true)
    }
    pub(super) fn install(&self, lease: &SessionLock) -> Result<()> {
        fs::publish(
            lease.directory_file(),
            NAME,
            &serde_json::to_vec(self)?,
            fs::Publication::StateFence { limit: LIMIT },
        )
    }
    pub(super) fn clear(&self, lease: &SessionLock, path: &Path) -> Result<()> {
        let dir = lease.directory_file();
        verify_named(dir, path)?;
        ensure!(
            self.matches_or_absent(dir)?,
            "Matching retained fence is missing"
        );
        std::fs::remove_file(fs::anchored(dir).join(NAME))?;
        dir.sync_all()?;
        verify_named(dir, path)
    }
}
pub(super) fn verify_named(dir: &File, path: &Path) -> Result<()> {
    let named = files::open_directory(path)
        .map_err(|e| e.context("Cannot verify retained state directory"))?;
    fs::trusted(&named, false)?;
    fs::same(dir, &named).map_err(|_| invalid("Retained environment directory changed"))
}
