//! Account crash-interrupted first admissions without adopting their intent.
use super::*;
impl Store {
    pub(super) fn validate_acceptance(&self, l: &Ledger, name: &str, r: &Record) -> Result<()> {
        r.invocation.validate()?;
        r.admission.validate()?;
        ensure!(
            r.schema_version == 1
                && r.binding == self.binding
                && r.invocation.key().digest()? == name
                && r.intent_sha256 == digest(&r.invocation)?
                && r.definition == *self.definition(&r.invocation.task)?
                && r.invocation.definition_sha256
                    == self.catalog.definition_digest(&r.invocation.task)?
                && r.environment == self.catalog.environment
                && r.reconciliations.is_empty()
                && r.phase == Phase::Accepted
                && r.finished_at.is_none()
                && r.dispatched_at.is_none()
                && r.outcome.is_none()
                && r.reason.is_none()
                && r.accepted_at < r.admission.admit_before
                && r.accepted_at <= l.clock,
            "Invalid retained acceptance document"
        );
        Ok(())
    }
    pub(super) fn check_growth(&self, l: &Ledger, extra: u64, new_key: bool) -> Result<()> {
        let mut count = l.entries.len() + usize::from(new_key);
        let mut bytes = extra;
        for item in std::fs::read_dir(fs::anchored(&self.root.dir))? {
            let item = item?;
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("Unexpected retained receiver entry"))?;
            match name {
                "catalog.json" | "ledger.json" => continue,
                ".ledger.json.pending" => {
                    fs::stage(&self.root.dir, name, INDEX_LIMIT)?
                        .ok_or_else(|| invalid("Retained ledger staging disappeared"))?;
                }
                _ if l.entries.contains_key(name) => continue,
                _ => {
                    hex(name, 64)?;
                    count += 1;
                    ensure!(
                        count <= COUNT_LIMIT,
                        "Retained invocation capacity exhausted"
                    );
                    bytes = bytes
                        .checked_add(self.orphan_bytes(l, name)?)
                        .ok_or_else(|| invalid("Retained byte accounting overflow"))?;
                }
            }
        }
        ensure!(
            count <= COUNT_LIMIT,
            "Retained invocation capacity exhausted"
        );
        l.capacity(self.manifest_bytes, bytes)
    }
    fn orphan_bytes(&self, l: &Ledger, name: &str) -> Result<u64> {
        let pin = files::open_directory_child_path(&self.root.dir, name.as_ref())?;
        let metadata = pin.metadata()?;
        let mode = metadata.mode() & 0o7777;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() } && mode & !0o700 == 0,
            "Unsafe unindexed reservation ownership or mode"
        );
        let dir = if mode == 0o700 {
            let dir = fs::child(&self.root.dir, name.as_ref())?;
            fs::same(&pin, &dir)?;
            dir
        } else {
            // mkdir(0700) can leave only a subset of owner bits when interrupted
            // before chmod. Only an explicit growth operation reaches this path.
            // The key stays excluded even when inspection rejects its contents.
            self.root.verify()?;
            let dir = self.persistence(fs::finish_private_directory(
                &self.root.dir,
                name.as_ref(),
                &pin,
            ))?;
            self.persistence(self.root.verify())?;
            dir
        };
        let mut items = std::fs::read_dir(fs::anchored(&dir))?;
        let bytes = match items.next().transpose()? {
            None => 0,
            Some(entry) if entry.file_name() == "intent.json" => {
                let bytes = fs::bytes(&dir, "intent.json", INTENT_LIMIT)?;
                let r: Record = serde_json::from_value(crate::json::parse(&bytes)?)?;
                self.validate_acceptance(l, name, &r)?;
                bytes.len() as u64
            }
            Some(entry) if entry.file_name() == ".intent.json.pending" => {
                fs::stage(&dir, ".intent.json.pending", INTENT_LIMIT)?
                    .ok_or_else(|| invalid("Missing staged intent"))?
                    .metadata()?
                    .len()
            }
            _ => {
                return Err(invalid(
                    "Unexpected evidence in unindexed retained reservation",
                ))
            }
        };
        ensure!(
            items.next().transpose()?.is_none(),
            "Unexpected additional reservation evidence"
        );
        fs::same(&dir, &fs::child(&self.root.dir, name.as_ref())?)?;
        Ok(bytes)
    }
}
