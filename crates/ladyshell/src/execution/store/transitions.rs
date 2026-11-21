use super::*;

impl Store {
    // Open a separate file description for each participant. All acquisition
    // under the metadata lock is nonblocking, so recovery cannot deadlock a worker.
    pub fn acquire_worker(&self, key: &Key) -> Result<WorkerLease> {
        self.locked(false, |l| {
            let found = self.required(l, key)?;
            ensure!(
                found.record.phase == Phase::Accepted,
                "Only accepted retained work can acquire a worker"
            );
            ensure!(
                fs::lock(&found.dir, true)?,
                "Retained invocation already owned"
            );
            fs::same(&found.dir, &self.directory_for(l, &key.digest()?)?)?;
            Ok(WorkerLease {
                key: key.clone(),
                instance: self.instance.clone(),
                dir: found.dir,
            })
        })
    }
    pub fn worker_present(&self, key: &Key) -> Result<bool> {
        self.locked(false, |l| Ok(!fs::lock(&self.required(l, key)?.dir, true)?))
    }
    fn owned(&self, l: &Ledger, lease: &WorkerLease, expected: Phase) -> Result<Loaded> {
        ensure!(
            Arc::ptr_eq(&lease.instance, &self.instance),
            "Worker belongs to another retained receiver"
        );
        let found = self.required(l, &lease.key)?;
        fs::same(&found.dir, &lease.dir)?;
        ensure!(
            found.record.phase == expected,
            "Retained phase does not permit this transition"
        );
        Ok(found)
    }
    /// Persist the consumed dispatch boundary while rechecking exact host authority.
    pub fn begin(&self, lease: &WorkerLease, now: u64) -> Result<Record> {
        self.begin_with_clock(lease, || Ok(now))
    }
    /// Sample the trusted host clock under the short metadata lock, after fence
    /// validation. The callback must not reenter the store.
    pub fn begin_with_clock(
        &self,
        lease: &WorkerLease,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<Record> {
        self.locked(true, |l| {
            let found = self.owned(l, lease, Phase::Accepted)?;
            let r = &found.record;
            l.authorize(&r.invocation.scope, &r.admission)?;
            let now = clock()?;
            self.clock(l, now)?;
            ensure!(
                now < r.admission.admit_before,
                "Retained dispatch admission expired"
            );
            let name = lease.key.digest()?;
            let e = l
                .entries
                .get_mut(&name)
                .ok_or_else(|| invalid("Missing retained reservation"))?;
            let marker = Dispatch {
                accepted_sha256: e.accepted_sha256.clone(),
                at: now,
            };
            let bytes = seal(&marker, 1024)?;
            self.persistence(fs::publish(
                &lease.dir,
                "dispatch.json",
                &bytes,
                fs::Publication::Immutable,
            ))?;
            e.dispatch = Some(now);
            self.save(l)?;
            self.persistence(self.verify_directory(l, &name, &lease.dir))?;
            let mut record = found.record;
            record.phase = Phase::Dispatching;
            record.dispatched_at = Some(now);
            Ok(record)
        })
    }
    pub fn refuse(&self, lease: &WorkerLease, reason: &str, now: u64) -> Result<Record> {
        text(reason, 1024)?;
        self.locked(true, |l| {
            let found = self.owned(l, lease, Phase::Accepted)?;
            self.finish(l, found, Phase::Refused, Some(reason.into()), None, now)
        })
    }
    /// Consume an interrupted native dispatch while the original worker lease is
    /// held. There is no client observation to store at this boundary.
    pub(in crate::execution) fn uncertain_before_spawn(
        &self,
        lease: &WorkerLease,
        expected: Phase,
        reason: &str,
        now: u64,
    ) -> Result<Record> {
        ensure!(
            matches!(expected, Phase::Accepted | Phase::Dispatching),
            "Cannot change a terminal retained receipt"
        );
        text(reason, 1024)?;
        self.locked(true, |l| {
            let found = self.owned(l, lease, expected)?;
            self.finish(l, found, Phase::Uncertain, Some(reason.into()), None, now)
        })
    }
    /// Preserve loss of worker ownership as uncertainty. No external action is replayed.
    pub fn recover(&self, key: &Key, now: u64) -> Result<Record> {
        self.locked(true, |l| {
            let found = self.required(l, key)?;
            ensure!(
                matches!(found.record.phase, Phase::Accepted | Phase::Dispatching),
                "Retained invocation is already terminal"
            );
            ensure!(
                fs::lock(&found.dir, true)?,
                "Retained worker still owns this invocation"
            );
            self.finish(
                l,
                found,
                Phase::Uncertain,
                Some("Recovered without a live worker".into()),
                None,
                now,
            )
        })
    }
    pub fn complete(
        &self,
        lease: &WorkerLease,
        result: ClientResult,
        outputs: CapturedOutputs,
        now: u64,
    ) -> Result<Record> {
        let phase = result.phase(outputs.stdout.truncated || outputs.stderr.truncated)?;
        self.locked(true, |l| {
            let found = self.owned(l, lease, Phase::Dispatching)?;
            ensure!(
                now >= found
                    .record
                    .dispatched_at
                    .unwrap_or(found.record.accepted_at),
                "Retained completion clock regressed"
            );
            let limit = found.record.definition.output_limit_bytes as usize;
            for stream in [&outputs.stdout, &outputs.stderr] {
                ensure!(
                    stream.bytes.len() <= limit,
                    "Captured output exceeds retained task limit"
                );
            }
            let capture = |stream: Stream, output: &CapturedStream| -> Result<OutputRef> {
                self.persistence(fs::publish(
                    &lease.dir,
                    stream.name(),
                    &output.bytes,
                    fs::Publication::Immutable,
                ))?;
                Ok(OutputRef {
                    stream,
                    length: output.bytes.len() as u32,
                    sha256: files::hash(&output.bytes),
                    truncated: output.truncated,
                })
            };
            let outcome = Outcome {
                provenance: Provenance::OpenshellClient,
                result,
                stdout: capture(Stream::Stdout, &outputs.stdout)?,
                stderr: capture(Stream::Stderr, &outputs.stderr)?,
            };
            self.finish(l, found, phase, None, Some(outcome), now)
        })
    }
    fn finish(
        &self,
        l: &mut Ledger,
        found: Loaded,
        phase: Phase,
        reason: Option<String>,
        outcome: Option<Outcome>,
        now: u64,
    ) -> Result<Record> {
        let mut r = found.record;
        let name = r.invocation.key().digest()?;
        let e = l
            .entries
            .get_mut(&name)
            .ok_or_else(|| invalid("Missing retained reservation"))?;
        let terminal = Terminal {
            accepted_sha256: e.accepted_sha256.clone(),
            finished_at: now,
            phase,
            dispatched_at: r.dispatched_at,
            reason,
            outcome,
        };
        // Half the reservation holds an abandoned worker draft; half remains
        // available for the explicit recovery receipt even at full capacity.
        let bytes = seal(&terminal, RECEIPT_LIMIT / 2)?;
        let kind = if phase == Phase::Uncertain && terminal.outcome.is_none() {
            fs::Publication::Recover
        } else {
            fs::Publication::Immutable
        };
        terminal.apply(&mut r, &found.dir, &e.accepted_sha256)?;
        self.persistence(fs::publish(&found.dir, "receipt.json", &bytes, kind))?;
        e.terminal = Some(files::hash(&bytes));
        e.dispatch = r.dispatched_at;
        // Recovery can encounter a partly written capture. Keep its original
        // reservation until an operator can account for all retained bytes.
        if r.outcome.is_some() || r.phase == Phase::Refused {
            e.budget = fs::regular(&found.dir, "intent.json")?.metadata()?.len()
                + 1024
                + bytes.len() as u64
                + r.outcome.as_ref().map_or(0, |o| {
                    u64::from(o.stdout.length) + u64::from(o.stderr.length)
                });
        }
        self.save(l)?;
        self.persistence(self.verify_directory(l, &name, &found.dir))?;
        Ok(r)
    }
}

impl Store {
    /// Append a trusted host's observation after independent runtime verification.
    /// The original uncertainty, invocation, client receipt and outputs survive.
    pub fn record_reconciliation(
        &self,
        key: &Key,
        reason: &str,
        evidence: &serde_json::Value,
        now: u64,
    ) -> Result<Record> {
        text(reason, 1024)?;
        bounded_value(evidence, 8192)?;
        self.locked(true, |l| {
            let found = self.required(l, key)?;
            let mut r = found.record;
            ensure!(
                r.phase == Phase::Uncertain && r.reconciliations.len() < 16,
                "A bounded terminal uncertainty history is required"
            );
            let previous = r
                .reconciliations
                .last()
                .map(|n| n.at)
                .or(r.finished_at)
                .ok_or_else(|| invalid("Missing terminal timestamp"))?;
            ensure!(now >= previous, "Reconciliation clock regressed");
            let note = Reconciliation {
                at: now,
                reason: reason.into(),
                evidence: evidence.clone(),
            };
            // A replacement index and its predecessor coexist during publication.
            let charge = 2 * (encode(&note)?.len() as u64 + 1);
            self.check_growth(l, charge, false)?;
            let name = key.digest()?;
            let e = l
                .entries
                .get_mut(&name)
                .ok_or_else(|| invalid("Missing retained reservation"))?;
            e.budget += charge;
            e.reconciliations.push(note.clone());
            r.reconciliations.push(note);
            self.save(l)?;
            self.persistence(self.verify_directory(l, &name, &found.dir))?;
            Ok(r)
        })
    }
}
