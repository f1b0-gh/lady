//! Host-owned epochs and crash recovery. Only native resolution decides compatibility.
use super::{
    environment, invalid,
    model::{Acknowledgement, Phase, RefreshOffer, Session},
    worker,
};
use crate::{
    error::{ensure, Result},
    files, plan,
    snapshot::{self, Inventory},
    state::{self, SessionLock, StateLock},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub sandbox_id: String,
    pub owner: String,
    pub runtime: String,
    pub phase: String,
}
pub trait Driver {
    fn observe(&mut self, current: &Value) -> Result<Observation>;
    fn verify(&mut self, current: &Value) -> Result<()>;
    fn export(&mut self, current: &Value, directory: &Path) -> Result<Value>;
    fn stop(&mut self, current: &Value) -> Result<()>;
    fn start(&mut self, current: &Value) -> Result<()>;
    fn apply(&mut self, current: &Value, bundle: &[u8]) -> Result<Acknowledgement>;
    fn inventory(&mut self, current: &Value) -> Result<Inventory>;
    fn can_swap_source(&mut self, current: &Value) -> Result<bool>;
}
pub fn session(current: &Value) -> Result<Option<Session>> {
    let Some(value) = current.get("continuous") else {
        return Ok(None);
    };
    let session: Session = serde_json::from_value(value.clone())?;
    session.validate()?;
    ensure!(
        current["sandbox_id"] == session.sandbox_id && current["owner"] == session.owner,
        "Continuous binding differs from host state"
    );
    Ok(Some(session))
}
fn required(current: &Value) -> Result<Session> {
    session(current)?.ok_or_else(|| invalid("Continuous sandboxing is not initialized"))
}
pub fn ensure_ready(current: &Value) -> Result<()> {
    if let Some(s) = session(current)? {
        ensure!(s.phase==Phase::Ready,"Continuous handoff is pending; inspect cs status and retry the pending handoff before execution, sync or checkout");
    }
    Ok(())
}
pub fn export_binding(current: &Value) -> Result<Value> {
    Ok(match session(current)? {
        None => Value::Null,
        Some(s) => {
            json!({"task":s.task,"sandbox_id":s.sandbox_id,"owner":s.owner,"environment":s.environment,"epoch":s.epoch,"input_tree":s.tree})
        }
    })
}
pub fn verify_export(current: &Value, receipt: &Value) -> Result<()> {
    ensure!(
        receipt["continuous"] == export_binding(current)?,
        "Export belongs to another continuous epoch or incarnation"
    );
    Ok(())
}
fn load(directory: &Path) -> Result<Value> {
    crate::destroy::broker::ensure_available(directory)?;
    state::load(directory)?.ok_or_else(|| invalid("State is missing"))
}
pub(crate) fn save(directory: &Path, current: &Value) -> Result<()> {
    files::publish_json(&directory.join("state.json"), current, true)
}
fn bind(current: &mut Value, s: &Session) -> Result<()> {
    current["continuous"] = serde_json::to_value(s)?;
    Ok(())
}
fn observe(driver: &mut impl Driver, current: &Value) -> Result<Observation> {
    let observed = driver.observe(current)?;
    ensure!(
        current["sandbox_id"] == observed.sandbox_id && current["owner"] == observed.owner,
        "Sandbox ownership changed; no lifecycle action allowed"
    );
    ensure!(
        super::model::token(&observed.runtime),
        "Runtime generation is missing or invalid"
    );
    Ok(observed)
}
fn ready(driver: &mut impl Driver, current: &Value) -> Result<Observation> {
    let o = observe(driver, current)?;
    ensure!(o.phase == "Ready", "Sandbox is not ready");
    driver.verify(current)?;
    Ok(o)
}
pub fn admit(current: &Value, driver: &mut impl Driver) -> Result<()> {
    if let Some(s) = session(current)? {
        ensure_ready(current)?;
        let o = ready(driver, current)?;
        s.admit(&o.sandbox_id, &o.runtime)?;
    }
    Ok(())
}
pub fn initialize_with(directory: &Path, driver: &mut impl Driver, task: &str) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    execution_directory(&lock.directory)?;
    let _lease = SessionLock::acquire(&lock.directory, true)?;
    let mut current = load(&lock.directory)?;
    crate::run::ensure_no_pending(&lock.directory)?;
    ensure!(
        session(&current)?.is_none(),
        "Continuous session already exists"
    );
    ensure!(crate::sync::exclusions(&current)?.is_empty(), "Initial CS profile requires no explicit source exclusions; excluded application data needs a preservation policy");
    let observed = ready(driver, &current)?;
    let inventory = driver.inventory(&current)?;
    ensure!(records(&inventory)==current["host_sources"],"Initial sandbox differs from construction snapshot; preserve/reconcile edits before initialization");
    let s = Session::new(
        task.into(),
        observed.sandbox_id,
        observed.owner,
        observed.runtime,
        environment::identity(&current["desired_inputs"])?,
        plan::digest(&inventory)?,
    )?;
    bind(&mut current, &s)?;
    current
        .as_object_mut()
        .ok_or_else(|| invalid("Invalid state"))?
        .remove("last_sync");
    save(&lock.directory, &current)?;
    Ok(current)
}

pub trait ReplacementDriver: Driver {
    fn create(&mut self, desired: &Value, directory: &Path) -> Result<Value>;
    fn retire(&mut self, previous: &Value) -> Result<()>;
}
/// Activate the verified replacement in the stable host state before retiring the old resource.
pub fn replace_with(directory: &Path, driver: &mut impl ReplacementDriver) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    let _lease = SessionLock::acquire(&lock.directory, true)?;
    let mut current = load(&lock.directory)?;
    let mut old = required(&current)?;
    if current["continuous_replacement"]["stage"] == "retiring" {
        let observed = ready(driver, &current)?;
        ensure!(
            observed.runtime == old.runtime
                && plan::digest(&driver.inventory(&current)?)? == old.tree,
            "Activated replacement changed; old sandbox retained"
        );
        let previous = state::read(Path::new(state::text(
            &current["continuous_replacement"],
            "previous_state",
        )?))?
        .ok_or_else(|| invalid("Retained predecessor missing"))?;
        ensure!(
            previous["sandbox_id"] == current["continuous_replacement"]["previous_id"]
                && previous["owner"] == current["continuous_replacement"]["previous_owner"],
            "Predecessor identity changed"
        );
        driver.retire(&previous)?;
        current["continuous_replacement"]["stage"] = json!("complete");
        old.phase = Phase::Ready;
        bind(&mut current, &old)?;
        save(&lock.directory, &current)?;
        return Ok(current);
    }
    if current["continuous_replacement"]["stage"] == "complete" && old.phase == Phase::Ready {
        return Ok(current);
    }
    ensure!(
        [Phase::ReplacementRequired, Phase::Replacing].contains(&old.phase),
        "No environment replacement is pending"
    );
    let selection = current["continuous_selection"].clone();
    let attempt = state::text(&selection, "attempt")?;
    ensure!(super::model::token(attempt), "Invalid replacement attempt");
    let desired = &selection["desired"];
    ensure!(
        environment::identity(desired)? == state::text(&selection, "environment")?,
        "Retained environment selection changed"
    );
    ensure!(
        plan::digest(&snapshot::inventory(Path::new(state::text(
            desired, "project"
        )?))?)?
            == state::text(&selection, "tree")?,
        "Retained replacement source changed"
    );
    let o = ready(driver, &current)?;
    ensure!(
        o.runtime == old.runtime,
        "Old runtime changed before replacement"
    );
    ensure!(
        plan::digest(&driver.inventory(&current)?)?
            == old
                .checkpoint_tree
                .as_deref()
                .ok_or_else(|| invalid("Checkpoint tree missing"))?,
        "Old sandbox changed after checkpoint; preserve edits before replacing"
    );
    old.phase = Phase::Replacing;
    bind(&mut current, &old)?;
    save(&lock.directory, &current)?;
    let child = lock
        .directory
        .join("continuous")
        .join(attempt)
        .join("replacement");
    state::create_directory(&child)?;
    files::publish_json(
        &child.join("continuous-staging.json"),
        &json!({"parent":lock.directory,"task":old.task}),
        true,
    )?;
    let mut next = driver.create(desired, &child)?;
    ensure!(
        next["sandbox_id"] != current["sandbox_id"],
        "Replacement reused old sandbox identity"
    );
    let observed = ready(driver, &next)?;
    let inventory = driver.inventory(&next)?;
    ensure!(
        plan::digest(&inventory)? == selection["tree"],
        "Replacement source differs from selection"
    );
    ensure!(
        environment::identity(&next["desired_inputs"])? == selection["environment"],
        "Replacement environment differs from selection"
    );
    let epoch = old
        .epoch
        .checked_add(1)
        .ok_or_else(|| invalid("Continuous epoch exhausted"))?;
    let mut fresh = Session::new(
        old.task.clone(),
        observed.sandbox_id,
        observed.owner,
        observed.runtime,
        state::text(&selection, "environment")?.into(),
        state::text(&selection, "tree")?.into(),
    )?;
    // Deliver the explicit continuation context before admitting the new incarnation.
    fresh.epoch = old.epoch;
    fresh.incarnation_epoch = old.epoch;
    fresh.phase = Phase::Checkpointed;
    fresh.checkpoint_tree = Some(fresh.tree.clone());
    let offer = RefreshOffer::new(
        &fresh,
        attempt,
        fresh.tree.clone(),
        plan::digest(&selection["context"])?,
    )?;
    fresh.begin_refresh(&offer)?;
    let bundle = worker::bundle(
        &offer,
        &fresh.runtime,
        &selection["context"],
        Path::new(state::text(desired, "project")?),
    )?;
    let ack = driver.apply(&next, &bundle)?;
    ensure!(
        ready(driver, &next)?.runtime == fresh.runtime && driver.inventory(&next)? == inventory,
        "Replacement changed during context delivery"
    );
    fresh.acknowledge(&offer, &ack)?;
    fresh.resume(&ack)?;
    ensure!(fresh.epoch == epoch, "Replacement epoch mismatch");
    fresh.phase = Phase::Replacing;
    next["desired_inputs"]["project"] = current["desired_inputs"]["project"].clone();
    next["desired_hash"] = json!(plan::digest(&next["desired_inputs"])?);
    next["checkout_base"] = records(&inventory);
    next["continuous_selection"] = selection;
    let archive = child
        .parent()
        .ok_or_else(|| invalid("Replacement parent missing"))?
        .join("previous-state.json");
    if let Some(previous) = state::read(&archive)? {
        ensure!(previous == current, "Retained predecessor differs");
    } else {
        files::publish_json(&archive, &current, false)?;
    }
    next["continuous_replacement"] = json!({"stage":"retiring","previous_state":archive,"previous_id":current["sandbox_id"],"previous_owner":current["owner"],"provisioning_state":child});
    bind(&mut next, &fresh)?;
    save(&lock.directory, &next)?;
    driver.retire(&current)?;
    fresh.phase = Phase::Ready;
    next["continuous_replacement"]["stage"] = json!("complete");
    bind(&mut next, &fresh)?;
    save(&lock.directory, &next)?;
    Ok(next)
}

pub fn execution_directory(directory: &Path) -> Result<()> {
    lifecycle_directory(directory)?;
    crate::destroy::broker::ensure_available(directory)
}

pub(crate) fn lifecycle_directory(directory: &Path) -> Result<()> {
    ensure!(
        !directory.join("continuous-staging.json").try_exists()?,
        "This is a retained provisioning state; use its stable continuous task state"
    );
    Ok(())
}

/// A retry inspects the observed phase and generation before repeating any effect.
pub fn checkpoint_with(
    directory: &Path,
    driver: &mut impl Driver,
    attempt: &str,
    epoch: u64,
) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    let _lease = SessionLock::acquire(&lock.directory, true)
        .map_err(|e| e.context("Finish the active foreground iteration before checkpointing"))?;
    crate::run::ensure_no_pending(&lock.directory)?;
    let mut current = load(&lock.directory)?;
    let mut s = required(&current)?;
    crate::publication_recovery::ensure_available(&lock.directory)?;
    if s.phase == Phase::Checkpointed
        && s.checkpoint_attempt.as_deref() == Some(attempt)
        && s.epoch == epoch
    {
        return Ok(current);
    }
    let initial = s.phase == Phase::Ready;
    s.begin_checkpoint(attempt, epoch)?;
    if initial {
        let o = ready(driver, &current)?;
        ensure!(o.runtime == s.runtime, "Runtime changed before checkpoint");
        let history = lock.directory.join("continuous-checkpoints");
        state::create_directory(&history)?;
        let path = history.join(format!("{attempt}.json"));
        let intent = json!({"schema_version":1,"task":s.task,"sandbox_id":s.sandbox_id,
            "owner":s.owner,"epoch":s.epoch,"runtime":s.runtime,"attempt":attempt});
        if let Some(previous) = state::read(&path)? {
            ensure!(
                previous == intent,
                "Checkpoint attempt already belongs to another epoch or incarnation"
            );
        } else {
            files::publish_json(&path, &intent, false)?;
        }
        current["continuous_checkpoint"] =
            json!({"attempt":attempt,"stage":"exporting","before_runtime":s.runtime});
        bind(&mut current, &s)?;
        save(&lock.directory, &current)?;
    }
    if current["continuous_checkpoint"]["stage"] == "exporting" {
        let o = ready(driver, &current)?;
        ensure!(
            o.runtime == s.runtime,
            "Runtime changed before retained export"
        );
        current = driver.export(&current, &lock.directory)?;
        let path = state::text(&current, "last_sync")?.to_owned();
        current["continuous_checkpoint"]["before_export"] = json!(path);
        current["continuous_checkpoint"]["before_tree"] = json!(plan::digest(
            &snapshot::inventory(&Path::new(&path).join("project"))?
        )?);
        current["continuous_checkpoint"]["stage"] = json!("stopping");
        save(&lock.directory, &current)?;
    }
    if current["continuous_checkpoint"]["stage"] == "stopping" {
        let o = observe(driver, &current)?;
        ensure!(
            o.runtime == s.runtime,
            "Unexpected runtime during stop; inspect checkpoint evidence"
        );
        if o.phase == "Ready" {
            driver.stop(&current)?;
        }
        let o = observe(driver, &current)?;
        ensure!(
            o.phase == "Stopped" && o.runtime == s.runtime,
            "Stop is not confirmed; retry checkpoint after inspection"
        );
        current["continuous_checkpoint"]["stage"] = json!("starting");
        save(&lock.directory, &current)?;
    }
    if current["continuous_checkpoint"]["stage"] == "starting" {
        let o = observe(driver, &current)?;
        if o.phase == "Stopped" {
            ensure!(o.runtime == s.runtime, "Stopped runtime changed");
            driver.start(&current)?;
        }
        let o = ready(driver, &current)?;
        ensure!(
            o.runtime != s.runtime,
            "Restart did not establish a new runtime generation"
        );
        current["continuous_checkpoint"]["after_runtime"] = json!(o.runtime);
        current["continuous_checkpoint"]["stage"] = json!("exporting_after");
        save(&lock.directory, &current)?;
    }
    if current["continuous_checkpoint"]["stage"] == "exporting_after" {
        let o = ready(driver, &current)?;
        ensure!(
            current["continuous_checkpoint"]["after_runtime"] == o.runtime,
            "Runtime changed after restart"
        );
        current = driver.export(&current, &lock.directory)?;
        let path = state::text(&current, "last_sync")?.to_owned();
        let tree = plan::digest(&snapshot::inventory(&Path::new(&path).join("project"))?)?;
        current["continuous_checkpoint"]["after_export"] = json!(path);
        current["continuous_checkpoint"]["after_tree"] = json!(tree);
        current["continuous_checkpoint"]["stage"] = json!("exported");
        save(&lock.directory, &current)?;
    }
    ensure!(
        current["continuous_checkpoint"]["stage"] == "exported",
        "Unknown checkpoint recovery stage"
    );
    ensure!(current["continuous_checkpoint"]["before_tree"]==current["continuous_checkpoint"]["after_tree"],"Source changed across stop/start; both exports are retained. Explicit reconciliation is required");
    let runtime = state::text(&current["continuous_checkpoint"], "after_runtime")?;
    s.finish_checkpoint(
        attempt,
        runtime,
        state::text(&current["continuous_checkpoint"], "after_tree")?.into(),
    )?;
    bind(&mut current, &s)?;
    save(&lock.directory, &current)?;
    Ok(current)
}

pub fn records(inventory: &Inventory) -> Value {
    json!(inventory
        .iter()
        .map(|(p, e)| (
            p.clone(),
            crate::sources::FileRecord {
                sha256: e.sha256.clone(),
                executable: e.executable
            }
        ))
        .collect::<crate::sources::Snapshot>())
}

/// The host explicitly acknowledges both retained sides; it must reconcile their
/// contents when selecting the next candidate. Neither side is deleted or hidden.
pub fn reconcile_checkpoint_with(
    directory: &Path,
    driver: &mut impl Driver,
    before: &str,
    after: &str,
) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    let _lease = SessionLock::acquire(&lock.directory, true)?;
    let mut current = load(&lock.directory)?;
    let mut s = required(&current)?;
    ensure!(
        s.phase == Phase::Checkpointing && current["continuous_checkpoint"]["stage"] == "exported",
        "No exported checkpoint discrepancy is pending"
    );
    ensure!(
        current["continuous_checkpoint"]["before_tree"] == before
            && current["continuous_checkpoint"]["after_tree"] == after,
        "Both exact retained tree identities must be acknowledged"
    );
    for (field, expected) in [("before_export", before), ("after_export", after)] {
        let root =
            Path::new(state::text(&current["continuous_checkpoint"], field)?).join("project");
        ensure!(
            plan::digest(&snapshot::inventory(&root)?)? == expected,
            "Retained checkpoint evidence changed"
        );
    }
    let o = ready(driver, &current)?;
    ensure!(
        current["continuous_checkpoint"]["after_runtime"] == o.runtime
            && plan::digest(&driver.inventory(&current)?)? == after,
        "Sandbox changed after checkpoint; preserve new edits before reconciliation"
    );
    let attempt = s
        .checkpoint_attempt
        .clone()
        .ok_or_else(|| invalid("Checkpoint attempt missing"))?;
    s.finish_checkpoint(&attempt, &o.runtime, after.into())?;
    current["continuous_checkpoint"]["reconciliation"] = json!({"before_tree":before,"after_tree":after,"authority":"explicit_host_selection","candidate_still_required":true});
    bind(&mut current, &s)?;
    save(&lock.directory, &current)?;
    Ok(current)
}
/// Retain exact regular source bytes. Existing attempts are immutable and checked.
pub fn freeze(source: &Path, destination: &Path) -> Result<Inventory> {
    let inventory = snapshot::inventory(source)?;
    if destination.try_exists()? {
        ensure!(
            snapshot::inventory(destination)? == inventory,
            "Retained candidate differs; use a new attempt"
        );
        return Ok(inventory);
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("Candidate parent missing"))?;
    state::create_directory(parent)?;
    let tmp = tempfile::Builder::new()
        .prefix(".candidate-")
        .tempdir_in(parent)?;
    for (path, expected) in &inventory {
        let (actual, bytes) = snapshot::local_bytes(source, path)?;
        ensure!(&actual == expected, "Candidate changed during capture");
        crate::image::write_source(tmp.path(), path, &bytes, actual.executable)?;
        files::open_regular(&tmp.path().join(path))?.sync_all()?;
    }
    ensure!(
        snapshot::inventory(source)? == inventory && snapshot::inventory(tmp.path())? == inventory,
        "Candidate changed during capture"
    );
    worker::sync_tree(tmp.path())?;
    std::fs::rename(tmp.path(), destination)?;
    files::open_directory(parent)?.sync_all()?;
    Ok(inventory)
}

pub fn refresh_with(
    directory: &Path,
    driver: &mut impl Driver,
    desired: &Value,
    attempt: &str,
    context: &Value,
) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    let _lease = SessionLock::acquire(&lock.directory, true)?;
    ensure!(super::model::token(attempt), "Invalid refresh attempt");
    let mut current = load(&lock.directory)?;
    let mut s = required(&current)?;
    ensure!(
        [
            Phase::Checkpointed,
            Phase::Refreshing,
            Phase::Refreshed,
            Phase::ReplacementRequired
        ]
        .contains(&s.phase),
        "Refresh requires checkpointed source"
    );
    let environment = environment::identity(desired)?;
    let exclusions: Vec<String> =
        serde_json::from_value(desired["evaluated"]["config"]["sources"]["exclude"].clone())?;
    ensure!(exclusions.is_empty(), "CS source exclusions need a preservation policy; this profile requires an empty exclusion list");
    let source = Path::new(state::text(desired, "project")?);
    let retained = lock
        .directory
        .join("continuous")
        .join(attempt)
        .join("candidate");
    let inventory = freeze(source, &retained)?;
    ensure!(
        records(&inventory) == desired["sources"],
        "Candidate contains unselected paths or changed bytes; revise source scope explicitly"
    );
    let mut resolved = desired.clone();
    resolved["project"] = json!(retained);
    let selection = json!({"attempt":attempt,"desired":resolved,"context":context,"tree":plan::digest(&inventory)?,"environment":environment});
    let selection_path = lock
        .directory
        .join("continuous")
        .join(attempt)
        .join("selection.json");
    if let Some(previous) = state::read(&selection_path)? {
        ensure!(
            previous == selection,
            "Attempt identifier already belongs to another selection"
        );
    } else {
        files::publish_json(&selection_path, &selection, false)?;
    }
    if s.phase != Phase::Checkpointed {
        ensure!(
            current["continuous_selection"] == selection,
            "Pending selection differs; recover the original attempt"
        );
    } else {
        current["continuous_selection"] = selection;
    }
    if s.phase == Phase::ReplacementRequired {
        return Ok(current);
    }
    let o = ready(driver, &current)?;
    ensure!(o.runtime == s.runtime, "Runtime changed after checkpoint");
    let reason = if environment != s.environment {
        Some("environment_changed")
    } else if s.epoch.saturating_sub(s.incarnation_epoch) >= 32 {
        Some("retained_source_limit")
    } else if s.phase == Phase::Checkpointed
        && s.checkpoint_tree.as_deref() != Some(&plan::digest(&inventory)?)
        && !driver.can_swap_source(&current)?
    {
        Some("source_storage_profile")
    } else {
        None
    };
    if let Some(reason) = reason {
        current["continuous_replacement_reason"] = json!(reason);
        s.phase = Phase::ReplacementRequired;
        bind(&mut current, &s)?;
        save(&lock.directory, &current)?;
        return Ok(current);
    }
    let offer = if s.phase == Phase::Checkpointed {
        RefreshOffer::new(
            &s,
            attempt,
            plan::digest(&inventory)?,
            plan::digest(context)?,
        )?
    } else {
        s.offer
            .clone()
            .ok_or_else(|| invalid("Refresh offer missing"))?
    };
    if s.phase == Phase::Refreshed {
        ensure!(
            plan::digest(&driver.inventory(&current)?)? == offer.tree,
            "Refreshed source changed before resume"
        );
        return Ok(current);
    }
    s.begin_refresh(&offer)?;
    bind(&mut current, &s)?;
    save(&lock.directory, &current)?;
    let bundle = worker::bundle(&offer, &s.runtime, context, &retained)?;
    let ack = driver.apply(&current, &bundle)?;
    let o = ready(driver, &current)?;
    ensure!(o.runtime == s.runtime, "Runtime changed during refresh");
    ensure!(
        plan::digest(&driver.inventory(&current)?)? == offer.tree,
        "Independent source verification differs from worker acknowledgement"
    );
    s.acknowledge(&offer, &ack)?;
    bind(&mut current, &s)?;
    save(&lock.directory, &current)?;
    Ok(current)
}
pub fn resume_with(directory: &Path, driver: &mut impl Driver, epoch: u64) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    let _lease = SessionLock::acquire(&lock.directory, true)?;
    let mut current = load(&lock.directory)?;
    let mut s = required(&current)?;
    ensure!(
        s.phase == Phase::Refreshed,
        "Resume requires an applied refresh"
    );
    let ack = s
        .acknowledgement
        .clone()
        .ok_or_else(|| invalid("Acknowledgement missing"))?;
    ensure!(ack.epoch == epoch, "Selected resume epoch differs");
    let o = ready(driver, &current)?;
    ensure!(o.runtime == s.runtime, "Runtime changed before resume");
    let actual = driver.inventory(&current)?;
    ensure!(
        plan::digest(&actual)? == ack.tree,
        "Source changed before resume"
    );
    let candidate = PathBuf::from(state::text(
        &current["continuous_selection"]["desired"],
        "project",
    )?);
    ensure!(
        snapshot::inventory(&candidate)? == actual,
        "Retained candidate changed"
    );
    let records = records(&actual);
    current["host_sources"] = records.clone();
    current["checkout_base"] = records.clone();
    current["project_snapshot"] = json!(candidate);
    current["desired_inputs"]["sources"] = records;
    current["desired_hash"] = json!(plan::digest(&current["desired_inputs"])?);
    for field in ["last_sync", "last_checkout_export"] {
        current
            .as_object_mut()
            .ok_or_else(|| invalid("Invalid state"))?
            .remove(field);
    }
    s.resume(&ack)?;
    bind(&mut current, &s)?;
    save(&lock.directory, &current)?;
    Ok(current)
}
