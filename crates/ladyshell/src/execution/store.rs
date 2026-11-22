//! A retained receiver has one short directory flock. Workers additionally
//! hold an independent flock on their invocation directory across dispatch.
pub(super) mod fs;
mod ledger;
mod reservations;
mod transitions;
use super::{invalid, model::*};
use crate::{
    error::{ensure, Result},
    files,
};
use ledger::*;
use std::sync::Arc;
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

pub struct Store {
    instance: Arc<()>,
    root: fs::Root,
    binding: Binding,
    catalog: Catalog,
    manifest_sha256: String,
    manifest_bytes: u64,
    poisoned: AtomicBool,
}
/// Exclusive kernel ownership of the original invocation directory.
pub struct WorkerLease {
    key: Key,
    instance: Arc<()>,
    dir: File,
}
struct Loaded {
    dir: File,
    record: Record,
}
impl Store {
    /// Initialize a new receiver in an existing host-owned, non-writable-by-others parent.
    pub fn create(path: &Path, catalog: Catalog) -> Result<Binding> {
        catalog.validate()?;
        let mut entropy = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut entropy)?;
        let installation = Installation {
            schema_version: 1,
            nonce: files::hash(&entropy),
            catalog,
        };
        let binding = installation.binding()?;
        let bytes = encode(&installation)?;
        ensure!(
            bytes.len() <= MANIFEST_LIMIT,
            "Retained catalogue too large"
        );
        let root = fs::Root::load(path, true)?;
        fs::lock(&root.dir, false)?;
        fs::publish(
            &root.dir,
            "catalog.json",
            &bytes,
            fs::Publication::Immutable,
        )?;
        fs::publish(
            &root.dir,
            "ledger.json",
            &seal(&Ledger::new(&binding), INDEX_LIMIT)?,
            fs::Publication::Immutable,
        )?;
        root.verify()?;
        Ok(binding)
    }
    /// Reopen existing history using an independently pinned receiver identity.
    pub fn open(path: &Path, expected_receiver: &str) -> Result<Self> {
        hex(expected_receiver, 64)?;
        let root = fs::Root::load(path, false)?;
        let lock = root.verify()?;
        fs::lock(&lock, false)?;
        let bytes = fs::bytes(&root.dir, "catalog.json", MANIFEST_LIMIT)?;
        let installation: Installation = serde_json::from_value(crate::json::parse(&bytes)?)?;
        let binding = installation.binding()?;
        ensure!(
            binding.receiver_id == expected_receiver,
            "Unexpected retained receiver identity"
        );
        Ledger::load(&root.dir, &binding, bytes.len() as u64)?;
        fs::observation_barrier(&lock)?;
        root.verify()?;
        Ok(Self {
            instance: Arc::new(()),
            root,
            binding,
            catalog: installation.catalog,
            manifest_sha256: files::hash(&bytes),
            manifest_bytes: bytes.len() as u64,
            poisoned: false.into(),
        })
    }
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    pub fn directory(&self) -> &Path {
        &self.root.path
    }
    pub fn definition(&self, task: &str) -> Result<&TaskDefinition> {
        self.catalog.definition(task)
    }

    fn locked<T>(&self, writing: bool, f: impl FnOnce(&mut Ledger) -> Result<T>) -> Result<T> {
        self.locked_mode(writing, false, f)
    }
    fn locked_mode<T>(
        &self,
        writing: bool,
        nonblocking: bool,
        f: impl FnOnce(&mut Ledger) -> Result<T>,
    ) -> Result<T> {
        let lock = self.root.verify()?;
        ensure!(fs::lock(&lock, nonblocking)?, "Retained receiver is busy");
        self.root.verify()?;
        ensure!(
            !writing || !self.poisoned.load(Ordering::Acquire),
            "Retained write outcome unknown; reopen receiver"
        );
        ensure!(
            files::hash(&fs::bytes(&lock, "catalog.json", MANIFEST_LIMIT)?) == self.manifest_sha256,
            "Retained installation changed"
        );
        let mut ledger = Ledger::load(&lock, &self.binding, self.manifest_bytes)?;
        self.persistence(fs::observation_barrier(&lock))?;
        self.root.verify()?;
        let result = f(&mut ledger)?;
        self.persistence(self.root.verify())?;
        Ok(result)
    }
    fn persistence<T>(&self, r: Result<T>) -> Result<T> {
        if r.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        r
    }
    fn save(&self, l: &Ledger) -> Result<()> {
        let bytes = seal(l, INDEX_LIMIT)?;
        self.persistence(fs::publish(
            &self.root.dir,
            "ledger.json",
            &bytes,
            fs::Publication::ReplaceLedger,
        ))
    }
    fn clock(&self, l: &mut Ledger, now: u64) -> Result<()> {
        ensure!(now >= l.clock, "Retained admission clock regressed");
        if now > l.clock {
            l.clock = now;
            self.save(l)?;
        }
        Ok(())
    }
    /// The trusted host establishes scope ownership independently of admission JSON.
    pub fn bind_owner(&self, scope: &str, owner: Option<&OwnerFence>) -> Result<()> {
        text(scope, 256)?;
        if let Some(o) = owner {
            o.validate()?;
        }
        self.locked(true, |l| {
            if let Some(f) = l.scopes.get(scope) {
                if f.owner.as_ref() == owner {
                    return Ok(());
                }
                if let Some(old) = &f.owner {
                    ensure!(
                        owner.is_some_and(|o| o.task == old.task
                            && o.deployment == old.deployment
                            && o.epoch > old.epoch),
                        "Retained owner change is stale or unrelated"
                    );
                }
            } else {
                ensure!(
                    l.scopes.len() < COUNT_LIMIT,
                    "Retained scope capacity exhausted"
                );
            }
            l.scopes.insert(
                scope.to_owned(),
                Scope {
                    owner: owner.cloned(),
                    claim: 0,
                },
            );
            self.save(l)
        })
    }
    pub fn advance_claim(&self, scope: &str, owner: Option<&OwnerFence>, epoch: u64) -> Result<()> {
        text(scope, 256)?;
        self.locked(true, |l| {
            let f = l
                .scopes
                .get_mut(scope)
                .ok_or_else(|| invalid("Unbound retained scope"))?;
            ensure!(
                f.owner.as_ref() == owner && epoch >= f.claim,
                "Retained claim rollback or wrong owner"
            );
            if epoch != f.claim {
                f.claim = epoch;
                self.save(l)?;
            }
            Ok(())
        })
    }
    fn directory_for(&self, l: &Ledger, name: &str) -> Result<File> {
        let e = l
            .entries
            .get(name)
            .ok_or_else(|| invalid("Unknown retained invocation"))?;
        let dir = fs::child(&self.root.dir, name.as_ref())?;
        ensure!(
            dir.metadata()?.ino() == e.inode,
            "Retained invocation directory replaced"
        );
        Ok(dir)
    }
    fn verify_directory(&self, l: &Ledger, name: &str, dir: &File) -> Result<()> {
        fs::same(dir, &self.directory_for(l, name)?)
    }
    fn read(&self, l: &Ledger, key: &Key) -> Result<Option<Loaded>> {
        let name = key.digest()?;
        let Some(e) = l.entries.get(&name) else {
            ensure!(
                !fs::exists(&self.root.dir, &name)?,
                "Incomplete retained directory reservation"
            );
            return Ok(None);
        };
        let dir = self.directory_for(l, &name)?;
        let bytes = fs::bytes(&dir, "intent.json", INTENT_LIMIT)?;
        ensure!(
            files::hash(&bytes) == e.accepted_sha256,
            "Retained accepted intent changed"
        );
        let mut r: Record = serde_json::from_value(crate::json::parse(&bytes)?)?;
        self.validate_acceptance(l, &name, &r)?;
        ensure!(
            r.invocation.key() == *key,
            "Retained invocation key mismatch"
        );
        if e.dispatch.is_some() || fs::exists(&dir, "dispatch.json")? {
            let marker: Dispatch = unseal(&fs::bytes(&dir, "dispatch.json", 1024)?)?;
            ensure!(
                marker.accepted_sha256 == e.accepted_sha256
                    && marker.at >= r.accepted_at
                    && marker.at < r.admission.admit_before
                    && marker.at <= l.clock
                    && e.dispatch.is_none_or(|at| at == marker.at),
                "Invalid retained dispatch marker"
            );
            r.phase = Phase::Dispatching;
            r.dispatched_at = Some(marker.at);
        }
        if r.phase == Phase::Accepted {
            ensure!(
                !fs::exists(&dir, "stdout")? && !fs::exists(&dir, "stderr")?,
                "Retained output exists without a dispatch marker"
            );
        }
        if e.terminal.is_some() || fs::exists(&dir, "receipt.json")? {
            let bytes = fs::bytes(&dir, "receipt.json", RECEIPT_LIMIT)?;
            ensure!(
                e.terminal
                    .as_ref()
                    .is_none_or(|h| h == &files::hash(&bytes)),
                "Retained terminal receipt changed"
            );
            let terminal: Terminal = unseal(&bytes)?;
            terminal.apply(&mut r, &dir, &e.accepted_sha256)?;
        }
        if !e.reconciliations.is_empty() {
            ensure!(
                r.phase == Phase::Uncertain,
                "Reconciliation requires a terminal uncertain receipt"
            );
            let mut previous = r
                .finished_at
                .ok_or_else(|| invalid("Missing terminal timestamp"))?;
            for note in &e.reconciliations {
                text(&note.reason, 1024)?;
                bounded_value(&note.evidence, 8192)?;
                ensure!(note.at >= previous, "Regressed reconciliation timestamp");
                previous = note.at;
            }
            r.reconciliations.clone_from(&e.reconciliations);
        }
        self.verify_directory(l, &name, &dir)?;
        if (e.dispatch.is_none() && r.dispatched_at.is_some())
            || (e.terminal.is_none() && r.finished_at.is_some())
        {
            self.persistence(fs::observation_barrier(&dir))?;
            self.verify_directory(l, &name, &dir)?;
        }
        Ok(Some(Loaded { dir, record: r }))
    }
    fn required(&self, l: &Ledger, k: &Key) -> Result<Loaded> {
        self.read(l, k)?
            .ok_or_else(|| invalid("Unknown retained invocation"))
    }
    fn matching(&self, l: &Ledger, i: &Invocation) -> Result<Option<Record>> {
        let Some(found) = self.read(l, &i.key())? else {
            return Ok(None);
        };
        ensure!(
            &found.record.invocation == i && found.record.intent_sha256 == digest(i)?,
            "Conflicting original retained invocation"
        );
        Ok(Some(found.record))
    }
    pub fn lookup(&self, invocation: &Invocation) -> Result<Option<Record>> {
        invocation.validate()?;
        self.locked(false, |l| self.matching(l, invocation))
    }
    pub fn inspect(&self, key: &Key) -> Result<Record> {
        self.locked(false, |l| Ok(self.required(l, key)?.record))
    }
    pub fn read_output(
        &self,
        key: &Key,
        stream: Stream,
        offset: u32,
        length: u32,
    ) -> Result<Vec<u8>> {
        ensure!(
            length <= 1048576,
            "Requested output range exceeds capture limit"
        );
        self.locked(false, |l| {
            let found = self.required(l, key)?;
            let o = found
                .record
                .outcome
                .ok_or_else(|| invalid("No client output receipt"))?;
            let r = match stream {
                Stream::Stdout => o.stdout,
                Stream::Stderr => o.stderr,
            };
            ensure!(
                offset <= r.length,
                "Output offset beyond end of retained stream"
            );
            let bytes = verify_output(&found.dir, &r, found.record.definition.output_limit_bytes)?;
            Ok(
                bytes[offset as usize..offset.saturating_add(length).min(r.length) as usize]
                    .to_vec(),
            )
        })
    }
    /// Existing intent wins before consulting new admission metadata or the clock.
    pub fn accept(
        &self,
        invocation: &Invocation,
        admission: &Admission,
        now: u64,
    ) -> Result<Acceptance> {
        self.accept_with_clock(invocation, admission, || Ok(now))
    }
    /// Sample the trusted host clock under the receiver lock after validation.
    /// The callback is used only for new work and must not reenter the store.
    pub fn accept_with_clock(
        &self,
        invocation: &Invocation,
        admission: &Admission,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<Acceptance> {
        self.accept_inner(invocation, admission, clock, false)
    }
    /// Acceptance under a live host authority guard. Check the current owner,
    /// claim and fresh deadline under the same ledger lock before returning even
    /// an exact duplicate. A busy lock refuses immediately. The caller must
    /// authenticate admission and scope ownership independently; JSON is not a grant.
    ///
    /// Duplicate recovery returns the unchanged original record: it neither
    /// renews its admission nor authorizes another dispatch. Clock runs once,
    /// under the lock, and must not reenter this store or other policy stores.
    pub fn accept_protected_with_clock(
        &self,
        invocation: &Invocation,
        admission: &Admission,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<Acceptance> {
        self.accept_inner(invocation, admission, clock, true)
    }
    fn accept_inner(
        &self,
        invocation: &Invocation,
        admission: &Admission,
        clock: impl FnOnce() -> Result<u64>,
        protected: bool,
    ) -> Result<Acceptance> {
        invocation.validate()?;
        self.locked_mode(true, protected, |l| {
            if !protected {
                if let Some(record) = self.matching(l, invocation)? {
                    return Ok(Acceptance {
                        record,
                        is_new: false,
                    });
                }
            }
            admission.validate()?;
            l.authorize(&invocation.scope, admission)?;
            let definition = self.definition(&invocation.task)?;
            definition.stdin_bytes(&invocation.intent)?;
            ensure!(
                self.catalog.definition_digest(&invocation.task)? == invocation.definition_sha256,
                "Retained task definition mismatch"
            );
            let now = clock()?;
            self.clock(l, now)?;
            ensure!(now < admission.admit_before, "Retained admission expired");
            if protected {
                if let Some(record) = self.matching(l, invocation)? {
                    return Ok(Acceptance {
                        record,
                        is_new: false,
                    });
                }
            }
            ensure!(
                l.entries.len() < COUNT_LIMIT,
                "Retained invocation capacity exhausted"
            );
            let record = Record {
                reconciliations: Vec::new(),
                schema_version: 1,
                binding: self.binding.clone(),
                invocation: invocation.clone(),
                intent_sha256: digest(invocation)?,
                admission: admission.clone(),
                environment: self.catalog.environment.clone(),
                definition: definition.clone(),
                accepted_at: now,
                phase: Phase::Accepted,
                dispatched_at: None,
                finished_at: None,
                reason: None,
                outcome: None,
            };
            let bytes = encode(&record)?;
            ensure!(
                bytes.len() <= INTENT_LIMIT,
                "Retained intent document too large"
            );
            let budget = bytes.len() as u64
                + 1024
                + RECEIPT_LIMIT as u64
                + 2 * u64::from(definition.output_limit_bytes);
            self.check_growth(l, budget, true)?;
            let name = invocation.key().digest()?;
            let dir = self.persistence(fs::mkdir(&self.root.dir, name.as_ref()))?;
            self.persistence(fs::publish(
                &dir,
                "intent.json",
                &bytes,
                fs::Publication::Immutable,
            ))?;
            l.entries.insert(
                name.clone(),
                Entry {
                    inode: dir.metadata()?.ino(),
                    accepted_sha256: files::hash(&bytes),
                    budget,
                    dispatch: None,
                    terminal: None,
                    reconciliations: Vec::new(),
                },
            );
            self.save(l)?;
            self.persistence(self.verify_directory(l, &name, &dir))?;
            Ok(Acceptance {
                record,
                is_new: true,
            })
        })
    }
}
