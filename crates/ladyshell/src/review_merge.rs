//! Explicit signed fast-forward merge, preserving the reviewed commit identity.
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Error, Result},
    files,
    publication_policy::Policy,
    publish::Git,
    state,
};
use serde_json::{json, Value};
use std::path::Path;
pub struct Options<'a> {
    pub config: &'a Path,
    pub policy: &'a Path,
    pub remote: &'a str,
    pub branch: &'a str,
    pub head: &'a str,
    pub expected: &'a str,
}
pub fn run(directory: &Path, options: &Options<'_>) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    let _parents = crate::stacks::guard(&lock.directory)?;
    let (git, mut receipt) = evaluate_locked(&lock, options)?;
    if let Some(previous) = state::read(&lock.directory.join("merge.json"))? {
        archive(&lock.directory, &previous)?;
    }
    save(&lock.directory, &receipt)?;
    push(&git, &receipt)?;
    receipt["confirmed"] = json!(true);
    save(&lock.directory, &receipt)?;
    Ok(receipt)
}
/// Observe exact current readiness without publishing or retaining approval.
/// Policy loading can invoke its host-owned signing availability probe.
pub fn check(directory: &Path, options: &Options<'_>) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    let _parents = crate::stacks::guard(&lock.directory)?;
    let (_, receipt) = evaluate_locked(&lock, options)?;
    // Public summary: retain identities and a policy binding, not host paths,
    // private check details, signing key material or the private merge receipt.
    Ok(json!({"schema_version":1,"display_state":"ready_to_merge",
        "observation_only":true,"acceptance_authority":false,"merge_performed":false,
        "head":receipt["head"],"expected_target":receipt["expected_target"],
        "reference":receipt["reference"],"repository":receipt["review"]["review"]["repository"],
        "round":receipt["review"]["review"]["patch"],
        "policy_binding_sha256":files::hash(&serde_json::to_vec(&receipt["policy_digests"])?),
        "human_review":receipt["review"]["review"]["human_review"]}))
}
// Both callers hold task, exclusive session and parent guards throughout.
// No archive, receipt, review, Git index/ref or publication write belongs here.
fn evaluate_locked(lock: &state::StateLock, options: &Options<'_>) -> Result<(Git, Value)> {
    crate::publish::oid(options.head)?;
    crate::publish::oid(options.expected)?;
    if let Some(previous) = state::read(&lock.directory.join("merge.json"))? {
        ensure!(
            previous["confirmed"] == true,
            "An uncertain merge must be reconciled before another attempt"
        );
    }
    let admission = crate::tangled_review::merge_admission_locked(
        lock,
        options.config,
        options.head,
        options.expected,
    )?;
    ensure!(
        admission["review"]["target_branch"] == options.branch,
        "Merge branch differs from the reviewed target branch"
    );
    let publication = state::read(&lock.directory.join("publication.json"))?
        .ok_or_else(|| invalid("Publication is missing".into()))?;
    ensure!(
        publication["confirmed"] == true && publication["commit"] == options.head,
        "Merge head is not the confirmed publication"
    );
    let project = Path::new(state::text(&publication, "project")?);
    let export = Path::new(state::text(&publication, "export")?);
    let policy = Policy::load(options.policy, project)?;
    let signing = policy
        .signing
        .as_ref()
        .ok_or_else(|| invalid("Merge requires an explicit trusted signing policy".into()))?;
    let checks = policy
        .checks
        .as_ref()
        .ok_or_else(|| invalid("Merge requires independent checks of the exact export".into()))?;
    crate::publication_checks::revalidate(export, checks)?;
    let mut git = Git::new(project)?;
    git.configure(signing.git_config());
    signing.verify_commit(&git, options.head)?;
    ensure!(
        !options.remote.is_empty() && !options.remote.starts_with('-'),
        "Invalid merge remote"
    );
    git.call(&["check-ref-format", "--branch", options.branch])?;
    git.call(&[
        "merge-base",
        "--is-ancestor",
        options.expected,
        options.head,
    ])
    .map_err(|e| {
        e.context("Reviewed head cannot fast-forward target; restack and renew checks/review")
    })?;
    let destination = git.destination(options.remote)?;
    ensure!(
        !destination.is_empty()
            && !destination.starts_with('-')
            && !destination.contains(['\n', '\r']),
        "Exactly one target destination is required"
    );
    // This command integrates within the published repository; fork merge needs
    // its own explicit repository binding and is not silently inferred here.
    ensure!(
        publication["destination"] == destination,
        "Merge target differs from the bound publication repository"
    );
    let reference = format!("refs/heads/{}", options.branch);
    ensure!(
        git.remote_head(&destination, &reference)? == options.expected,
        "Target advanced; obtain a new exact review/merge decision"
    );
    policy.verify_inputs()?;
    let receipt = json!({"schema_version":1,"project":project,"export":export,"head":options.head,"expected_target":options.expected,"reference":reference,"destination":destination,"policy":std::fs::canonicalize(options.policy)?,"policy_digests":policy.digests,"review_config":std::fs::canonicalize(options.config)?,"review":admission,"confirmed":false,"strategy":"signed_fast_forward"});
    Ok((git, receipt))
}
// Archive before replacing the mutable pointer. The stable key excludes only
// confirmation, so a recovered acknowledgement joins its original intent.
fn archive(directory: &Path, receipt: &Value) -> Result<()> {
    let mut intent = receipt.clone();
    intent["confirmed"] = json!(false);
    let attempt = files::hash(&serde_json::to_vec(&intent)?);
    let dir = directory.join("merge-attempts").join(attempt);
    state::create_directory(&dir)?;
    // Persist both directory entries before the immutable evidence can be
    // followed by a mutable pointer or remote write.
    std::fs::File::open(
        dir.parent()
            .ok_or_else(|| invalid("Merge archive parent is missing".into()))?,
    )?
    .sync_all()?;
    std::fs::File::open(directory)?.sync_all()?;
    let kind = if receipt["confirmed"] == true {
        "confirmed"
    } else {
        "intent"
    };
    let path = dir.join(format!("{kind}.json"));
    if let Some(previous) = state::read(&path)? {
        ensure!(previous == *receipt, "Immutable merge attempt differs");
    } else {
        files::publish_json(&path, receipt, false)?;
    }
    Ok(())
}
fn save(directory: &Path, receipt: &Value) -> Result<()> {
    archive(directory, receipt)?;
    atomic_json(&directory.join("merge.json"), receipt)
}

fn push(git: &Git, receipt: &Value) -> Result<()> {
    let destination = state::text(receipt, "destination")?;
    let reference = state::text(receipt, "reference")?;
    let expected = state::text(receipt, "expected_target")?;
    let head = state::text(receipt, "head")?;
    git.call(&[
        "push",
        "--porcelain",
        &format!("--force-with-lease={reference}:{expected}"),
        destination,
        &format!("{head}:{reference}"),
    ])?;
    ensure!(
        git.remote_head(destination, reference)? == head,
        "Merge readback is unconfirmed; retain receipt and reconcile"
    );
    Ok(())
}
pub fn reconcile(directory: &Path, retry: bool) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    crate::tangled_review::ensure_review_recovery(&lock.directory)?;
    let mut receipt = state::read(&lock.directory.join("merge.json"))?
        .ok_or_else(|| invalid("Merge receipt is missing".into()))?;
    ensure!(receipt["schema_version"] == 1, "Unsupported merge receipt");
    // The retained destination is the publication's source repository. Never
    // label a source-only ref observation as a merge into a different target.
    let review = &receipt["review"]["review"];
    ensure!(
        state::text(review, "repository")? == state::text(review, "source_repository")?,
        "Merge recovery supports only the same repository for source and target"
    );
    let git = Git::new(Path::new(state::text(&receipt, "project")?))?;
    let observed = git.remote_head(
        state::text(&receipt, "destination")?,
        state::text(&receipt, "reference")?,
    )?;
    if observed == state::text(&receipt, "head")? {
        archive(&lock.directory, &receipt)?;
        receipt["confirmed"] = json!(true);
        save(&lock.directory, &receipt)?;
        return Ok(receipt);
    }
    if retry {
        crate::tangled_review::ensure_review_writable(&lock.directory)?;
    }
    archive(&lock.directory, &receipt)?;
    ensure!(
        receipt["confirmed"] != true,
        "Target moved after confirmed merge; receipt is retained"
    );
    ensure!(
        observed == state::text(&receipt, "expected_target")?,
        "Target advanced; refusing merge retry"
    );
    if retry {
        let _parents = crate::stacks::guard(&lock.directory)?;
        let admission = crate::tangled_review::merge_admission_locked(
            &lock,
            Path::new(state::text(&receipt, "review_config")?),
            state::text(&receipt, "head")?,
            state::text(&receipt, "expected_target")?,
        )?;
        ensure!(
            receipt["reference"]
                == format!(
                    "refs/heads/{}",
                    state::text(&admission["review"], "target_branch")?
                )
                && admission["review"]["attempt"] == receipt["review"]["review"]["attempt"]
                && admission["review"]["patch"] == receipt["review"]["review"]["patch"],
            "Review changed; merge retry requires the original current round and target"
        );
        let policy = Policy::load(
            Path::new(state::text(&receipt, "policy")?),
            Path::new(state::text(&receipt, "project")?),
        )?;
        ensure!(
            serde_json::to_value(&policy.digests)? == receipt["policy_digests"],
            "Merge policy changed after intent; retain evidence and request a new merge"
        );
        let signing = policy
            .signing
            .as_ref()
            .ok_or_else(|| invalid("Signing policy is required".into()))?;
        let checks = policy
            .checks
            .as_ref()
            .ok_or_else(|| invalid("Required checks missing".into()))?;
        crate::publication_checks::revalidate(Path::new(state::text(&receipt, "export")?), checks)?;
        let mut verified = git;
        verified.configure(signing.git_config());
        signing.verify_commit(&verified, state::text(&receipt, "head")?)?;
        verified.call(&[
            "merge-base",
            "--is-ancestor",
            state::text(&receipt, "expected_target")?,
            state::text(&receipt, "head")?,
        ])?;
        // The current decision may have changed after this intent. Preserve
        // the old intent, then durably bind this retry to the decision reloaded
        // under the same task/session/parent guards before any remote effect.
        receipt["review"] = admission;
        save(&lock.directory, &receipt)?;
        push(&verified, &receipt)?;
        receipt["confirmed"] = json!(true);
        save(&lock.directory, &receipt)?;
    }
    Ok(receipt)
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
