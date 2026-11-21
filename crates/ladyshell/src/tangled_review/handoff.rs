//! Local, explicit continuation of one logical review in a separately owned task.
use super::*;
use std::collections::BTreeSet;

const PREPARING: &str = "review-handoff-preparing.json";
const OUTGOING: &str = "review-handoff-outgoing.json";
const INCOMING: &str = "review-handoff-incoming.json";
const COMMITTED: &str = "review-handoff-committed.json";
// Match state::read: never commit evidence that recovery cannot read back.
const LOCAL_RECORD_LIMIT: usize = 16 * 1024 * 1024;

/// Host-selected successor, bound to exact immutable publication and prior round.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffInput {
    pub from_state: PathBuf,
    pub from_attempt: String,
    pub head: String,
    pub base: String,
    pub policy: PathBuf,
}

fn retained(directory: &Path, name: &str) -> Result<Option<Value>> {
    crate::state::read(&directory.join(name))
}
fn digest(value: &Value) -> Result<String> {
    Ok(files::hash(&serde_json::to_vec(value)?))
}
fn immutable(directory: &Path, name: &str, value: &Value) -> Result<()> {
    if let Some(old) = retained(directory, name)? {
        ensure!(
            old == *value,
            "Immutable review handoff record differs: {name}"
        );
    } else {
        files::publish_json(&directory.join(name), value, false)?;
    }
    files::open_directory(directory)?.sync_all()?;
    Ok(())
}
// Blocking intent only: this never reserves the predecessor or authorizes review.
fn preparation(directory: &Path) -> Result<Option<Value>> {
    let value = retained(directory, PREPARING)?;
    if let Some(value) = &value {
        ensure!(
            value["schema_version"] == 1 && value["candidate_state"] == json!(directory),
            "Invalid review handoff preparation"
        );
    }
    Ok(value)
}
fn incoming(directory: &Path) -> Result<Option<Value>> {
    let value = retained(directory, INCOMING)?;
    if let Some(value) = &value {
        ensure!(
            value["schema_version"] == 1 && value["candidate_state"] == json!(directory),
            "Invalid incoming review handoff"
        );
    }
    Ok(value)
}
fn credential_continuation(original: &Value, current: &Value) -> Result<()> {
    let mut before = original.clone();
    let mut after = current.clone();
    if original["schema_version"] == 2 {
        let (owner, _) = active_credentials(original)?;
        let (next, _) = active_credentials(current)?;
        ensure!(
            same_authority(owner, next),
            "Credential continuation changed authority"
        );
        let prior = original["credential_history"]
            .as_array()
            .ok_or_else(|| invalid("Missing original credential history".into()))?;
        let history = current["credential_history"]
            .as_array()
            .ok_or_else(|| invalid("Missing current credential history".into()))?;
        ensure!(
            history.starts_with(prior),
            "Credential continuation changed retained history"
        );
        before["credential_history"] = Value::Null;
        after["credential_history"] = Value::Null;
    }
    ensure!(
        before == after,
        "Retained handoff seed or predecessor round changed"
    );
    Ok(())
}
fn committed(directory: &Path, intent: &Value) -> Result<bool> {
    let Some(marker) = retained(directory, COMMITTED)? else {
        return Ok(false);
    };
    ensure!(
        marker == json!({"schema_version":1,"transition_sha256":digest(intent)?}),
        "Review handoff commit marker differs from incoming intent"
    );
    let attempt = text(intent, "from_attempt")?;
    ensure!(
        attempt.len() == 64 && attempt.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid handoff predecessor attempt"
    );
    let confirmed = read(
        &directory
            .join("review-attempts")
            .join(attempt)
            .join("confirmed.json"),
    )?;
    ensure!(
        confirmed == intent["confirmed_archive"],
        "Committed handoff archive differs"
    );
    let current = journal(directory)?
        .ok_or_else(|| invalid("Committed handoff lacks review context".into()))?;
    if current["attempt"] == intent["from_attempt"] {
        credential_continuation(&intent["receipt"], &current)?;
    } else {
        ensure!(
            current["review_predecessor"]["transition_sha256"] == digest(intent)?
                && current["review_predecessor"]["state"] == intent["predecessor_state"]
                && current["review_predecessor"]["attempt"] == intent["from_attempt"],
            "Successor review lacks immutable predecessor linkage"
        );
    }
    Ok(true)
}
/// The caller holds the state lock. A reservation retires writes permanently;
/// malformed or incomplete incoming metadata also fails closed.
pub(super) fn ensure_writable(directory: &Path) -> Result<()> {
    ensure!(
        retained(directory, OUTGOING)?.is_none(),
        "Review writer is retired by an immutable successor reservation"
    );
    ensure_incoming_committed(directory)
}
pub(super) fn ensure_incoming_committed(directory: &Path) -> Result<()> {
    let preparing = preparation(directory)?;
    let incoming = incoming(directory)?;
    if let Some(intent) = &incoming {
        ensure!(
            preparing.as_ref() == Some(intent),
            "Review handoff lacks matching blocking preparation; repeat identical handoff recovery"
        );
        ensure!(
            committed(directory, intent)?,
            "Review handoff is incomplete; repeat the identical handoff command before writes"
        );
    } else {
        ensure!(preparing.is_none(),
            "Review handoff preparation is incomplete; repeat the identical handoff command before writes");
        ensure!(
            retained(directory, COMMITTED)?.is_none(),
            "Review handoff commit lacks incoming intent"
        );
    }
    Ok(())
}
pub(super) fn summary(directory: &Path) -> Result<Value> {
    let preparing = preparation(directory)?;
    let outgoing = retained(directory, OUTGOING)?;
    let incoming = incoming(directory)?;
    if let Some(outgoing) = outgoing {
        ensure!(
            outgoing["schema_version"] == 1 && outgoing["predecessor_state"] == json!(directory),
            "Invalid outgoing review handoff"
        );
        return Ok(
            json!({"role":"predecessor","phase":"reserved","retired_writer":true,
            "candidate_state":outgoing["candidate_state"],"transition_sha256":digest(&outgoing)?,
            "incoming_predecessor":incoming.map(|v| v["predecessor_state"].clone())}),
        );
    }
    if let Some(intent) = incoming {
        ensure!(
            preparing.as_ref() == Some(&intent),
            "Incoming handoff lacks matching preparation"
        );
        let complete = committed(directory, &intent)?;
        return Ok(
            json!({"role":"successor","phase":if complete {"committed"} else {"pending"},
            "writer_blocked":!complete,"retired_writer":false,"predecessor_state":intent["predecessor_state"],
            "predecessor_attempt":intent["from_attempt"],"transition_sha256":digest(&intent)?}),
        );
    }
    if let Some(intent) = preparing {
        ensure!(
            retained(directory, COMMITTED)?.is_none(),
            "Preparation lacks incoming handoff context"
        );
        return Ok(
            json!({"role":"successor","phase":"preparing","writer_blocked":true,
            "retired_writer":false,"predecessor_state":intent["predecessor_state"],
            "predecessor_attempt":intent["from_attempt"],"transition_sha256":digest(&intent)?}),
        );
    }
    ensure!(
        retained(directory, COMMITTED)?.is_none(),
        "Review handoff commit lacks incoming intent"
    );
    Ok(Value::Null)
}
pub(super) fn predecessor(directory: &Path) -> Result<Option<Value>> {
    let Some(v) = incoming(directory)? else {
        return Ok(None);
    };
    Ok(Some(
        json!({"state":v["predecessor_state"],"attempt":v["from_attempt"],
        "receipt_sha256":v["receipt_sha256"],"transition_sha256":digest(&v)?}),
    ))
}
pub(super) fn validate_first_submit(
    directory: &Path,
    old: &Value,
    p: &Value,
    input: &SubmitInput,
) -> Result<()> {
    if let Some(intent) = incoming(directory)? {
        if old["attempt"] == intent["from_attempt"] {
            ensure!(input.resubmit && old["ticket_key"] == input.ticket_key
                && p == &intent["candidate_publication"] && input.target_base == intent["base"],
                "First successor round requires explicit resubmit of the reserved exact publication and base");
        }
    }
    Ok(())
}
// Like stacks::guard, but reuse both already-held endpoint locks. This matters
// when the explicitly selected resolution task directly extends its predecessor.
fn guard_candidate(candidate: &Path, predecessor: &Path) -> Result<Vec<StateLock>> {
    let mut held = BTreeSet::from([candidate.to_path_buf(), predecessor.to_path_buf()]);
    let mut seen = BTreeSet::from([candidate.to_path_buf()]);
    let mut guards = Vec::new();
    let mut cursor = candidate.to_path_buf();
    while let Some(binding) = retained(&cursor, "stack-binding.json")? {
        ensure!(
            binding["schema_version"] == 1 && Path::new(text(&binding, "stack")?).is_absolute(),
            "Unsupported candidate stack binding"
        );
        if binding["parent"].is_null() {
            ensure!(
                binding["parent_head"].is_null(),
                "Root stack binding has a parent revision"
            );
            break;
        }
        let path = Path::new(text(&binding, "parent")?);
        ensure!(
            path.is_absolute(),
            "Stack parent must be an absolute host state path"
        );
        let path = path.canonicalize()?;
        ensure!(seen.insert(path.clone()), "Stack dependency cycle");
        if held.insert(path.clone()) {
            guards.push(StateLock::acquire(&path)?);
        }
        let publication = read(&path.join("publication.json"))?;
        let expected = text(&binding, "parent_head")?;
        crate::publish::oid(expected)?;
        ensure!(
            publication["confirmed"] == true && publication["commit"] == expected,
            "Stack parent checkpoint changed; restack before review handoff"
        );
        cursor = path;
    }
    Ok(guards)
}
fn absent_history(directory: &Path) -> Result<()> {
    for name in [
        "owner-review-decisions",
        "merge.json",
        "merge-attempts",
        "review-feedback.json",
        "review-feedback-owner-context.json",
        "review-feedback-delivery.json",
        OUTGOING,
    ] {
        ensure!(
            !directory.join(name).try_exists()?,
            "Candidate has unrelated review history: {name}"
        );
    }
    Ok(())
}
fn same_repository(left: &Path, right: &Path) -> Result<()> {
    let common = |p: &Path| -> Result<PathBuf> {
        Ok(PathBuf::from(crate::publish::Git::new(p)?.text(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ])?)
        .canonicalize()?)
    };
    ensure!(
        common(left)? == common(right)?,
        "Candidate belongs to a different native repository"
    );
    Ok(())
}
// Restack uses the logical checkpoint base, which survives feedback publications.
// Its parent's historical binding may be stale: repairing that is why this
// candidate exists. Only the candidate's parent chain must still be current.
fn predecessor_checkpoint(
    candidate: &Path,
    predecessor: &Path,
    old: &Value,
    guards: &mut Vec<StateLock>,
) -> Result<Value> {
    let binding = retained(predecessor, "stack-binding.json")?
        .ok_or_else(|| invalid("Native restack predecessor lacks stack binding".into()))?;
    let stack = Path::new(text(&binding, "stack")?);
    ensure!(
        binding["schema_version"] == 1 && stack.is_absolute(),
        "Invalid predecessor stack binding"
    );
    let stack = stack.canonicalize()?;
    if stack != candidate && stack != predecessor && !guards.iter().any(|g| g.directory == stack) {
        guards.push(StateLock::acquire(&stack)?);
    }
    let manifest = retained(&stack, "stack.json")?
        .ok_or_else(|| invalid("Predecessor stack manifest is missing".into()))?;
    ensure!(
        manifest["schema_version"] == 1,
        "Unsupported predecessor stack manifest"
    );
    let entries = manifest["entries"]
        .as_array()
        .ok_or_else(|| invalid("Invalid predecessor stack entries".into()))?;
    let matching: Vec<_> = entries
        .iter()
        .filter(|entry| entry["state"] == json!(predecessor))
        .collect();
    ensure!(
        matching.len() == 1,
        "Predecessor lacks one exact native checkpoint entry"
    );
    let entry = matching[0];
    ensure!(
        entry["head"] == old["commit"]
            && entry["parent"] == binding["parent"]
            && entry["parent_head"] == binding["parent_head"],
        "Predecessor native checkpoint head or parent binding differs"
    );
    crate::publish::oid(text(entry, "base")?)?;
    if entry["parent"].is_null() {
        ensure!(
            entry["parent_head"].is_null(),
            "Root predecessor has a parent revision"
        );
    } else {
        ensure!(
            Path::new(text(entry, "parent")?).is_absolute(),
            "Predecessor parent must be absolute"
        );
        crate::publish::oid(text(entry, "parent_head")?)?;
        ensure!(
            entry["base"] == entry["parent_head"],
            "Predecessor logical base differs from its parent binding"
        );
    }
    Ok(json!({"binding":binding,"entry":entry}))
}
fn native_candidate(
    directory: &Path,
    predecessor: &Path,
    old: &Value,
    publication: &Value,
    branch: &str,
    policy: &crate::publication_policy::Policy,
    guards: &mut Vec<StateLock>,
) -> Result<Value> {
    let native = crate::state::load(directory)?
        .ok_or_else(|| invalid("Candidate native task state is missing".into()))?;
    crate::run::ensure_no_pending(directory)?;
    let parent = directory
        .parent()
        .ok_or_else(|| invalid("Candidate task directory is missing".into()))?;
    let task = read(&parent.join("task.json"))?;
    let project = Path::new(text(publication, "project")?).canonicalize()?;
    ensure!(
        task["schema_version"] == 1
            && matches!(task["phase"].as_str(), Some("prepared" | "active"))
            && task["state"] == json!(directory)
            && task["project"] == json!(project)
            && task["branch"] == branch
            && task["base"] == publication["base"]
            && native["desired_inputs"]["project"] == json!(project),
        "Candidate native task, project, branch or base differs from publication"
    );
    same_repository(&project, Path::new(text(old, "project")?))?;
    same_repository(&project, Path::new(text(&task, "repository")?))?;
    let export = Path::new(text(publication, "export")?).canonicalize()?;
    let destination = Path::new(text(&native["sync"], "destination")?);
    ensure!(
        !destination.as_os_str().is_empty()
            && destination
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
        "Candidate export destination must be a relative owned directory"
    );
    let owned = directory.join(destination).canonicalize()?;
    ensure!(
        owned.starts_with(directory) && export.starts_with(&owned) && export != owned,
        "Candidate publication export is not owned by its state"
    );
    let manifest = read(&export.join("manifest.json"))?;
    ensure!(
        manifest["schema_version"] == 2 && manifest["sandbox_id"] == native["sandbox_id"],
        "Candidate export belongs to another native task"
    );
    let checks = policy
        .checks
        .as_ref()
        .ok_or_else(|| invalid("Review handoff requires independent checks".into()))?;
    ensure!(
        publication["checks"] == *checks,
        "Candidate publication checks differ from trusted policy"
    );
    crate::publication_checks::revalidate(&export, checks)?;
    let signing = policy
        .signing
        .as_ref()
        .ok_or_else(|| invalid("Review handoff requires trusted signing policy".into()))?;
    let mut git = crate::publish::Git::new(&project)?;
    git.configure(signing.git_config());
    let head = text(publication, "commit")?;
    signing.verify_commit(&git, head)?;
    git.call(&[
        "merge-base",
        "--is-ancestor",
        text(publication, "base")?,
        head,
    ])?;
    // Bind the complete exported snapshot to the signed tree, honoring only
    // the native task's retained source exclusions.
    let excluded = &native["desired_inputs"]["evaluated"]["config"]["sources"]["exclude"];
    let excludes: Vec<String> = if excluded.is_null() {
        vec![]
    } else {
        serde_json::from_value(excluded.clone())?
    };
    let spec = crate::config::Sources {
        include: vec![],
        exclude: excludes,
    };
    let mut committed_files = serde_json::Map::new();
    for row in git
        .call(&["ls-tree", "-r", "-z", head])?
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
    {
        let row = std::str::from_utf8(row).map_err(|e| invalid(e.to_string()))?;
        let (meta, path) = row
            .split_once('\t')
            .ok_or_else(|| invalid("Invalid signed tree".into()))?;
        crate::snapshot::validate_path(path)?;
        if crate::sources::excluded(path, &spec) {
            continue;
        }
        let fields: Vec<_> = meta.split_whitespace().collect();
        ensure!(
            fields.len() == 3 && fields[1] == "blob" && ["100644", "100755"].contains(&fields[0]),
            "Candidate signed tree must contain regular files"
        );
        committed_files.insert(path.into(),json!({"sha256":files::hash(&git.call(&["cat-file","blob",fields[2]])?),"executable":fields[0]=="100755"}));
    }
    ensure!(
        manifest["files"] == Value::Object(committed_files),
        "Candidate export differs from signed commit tree"
    );
    let provenance = retained(parent, "restack.json")?;
    ensure!(
        native["kind"] != "host_restack_candidate" || provenance.is_some(),
        "Native restack candidate lacks retained provenance"
    );
    let predecessor_checkpoint = if provenance.is_some() {
        predecessor_checkpoint(directory, predecessor, old, guards)?
    } else {
        Value::Null
    };
    if let Some(p) = &provenance {
        ensure!(
            p["source_state"] == json!(predecessor)
                && p["old_head"] == old["commit"]
                && p["old_base"] == predecessor_checkpoint["entry"]["base"]
                && p["new_base"] == publication["base"]
                && p["candidate"] == task
                && p["export"] == json!(export),
            "Candidate restack provenance conflicts with selected predecessor or native task"
        );
    }
    let binding = retained(directory, "stack-binding.json")?
        .ok_or_else(|| invalid("Candidate requires an exact current stack parent".into()))?;
    ensure!(
        !binding["parent"].is_null() && binding["parent_head"] == publication["base"],
        "Candidate requires an exact current stack parent and base"
    );
    policy.verify_inputs()?;
    Ok(json!({"task":task,"native":native,"manifest":manifest,
        "checks":read(&export.join("checks.json"))?,"provenance":provenance,
        "stack_binding":retained(directory,"stack-binding.json")?,"predecessor_checkpoint":predecessor_checkpoint}))
}

pub(super) fn run(candidate: &Path, config_path: &Path, input: &HandoffInput) -> Result<Value> {
    let candidate = candidate.canonicalize()?;
    let predecessor = input.from_state.canonicalize()?;
    ensure!(
        candidate != predecessor,
        "Review handoff requires distinct canonical states"
    );
    let candidate_lock = StateLock::acquire(&candidate)?;
    let old_lock = StateLock::acquire(&predecessor)?;
    let _candidate_session = SessionLock::acquire(&candidate, true)?;
    let _old_session = SessionLock::acquire(&predecessor, true)?;
    crate::continuous::host::execution_directory(&candidate)?;
    current_publication(&candidate)?;
    // The predecessor is explicitly historical; only the successor must be a
    // current publication. Do not reapply writer guards after reserving a retry.
    let existing_preparation = preparation(&candidate)?;
    if let Some(intent) = &existing_preparation {
        ensure!(
            intent["predecessor_state"] == json!(predecessor)
                && intent["from_attempt"] == input.from_attempt
                && intent["head"] == input.head
                && intent["base"] == input.base
                && intent["config"] == json!(config_path.canonicalize()?)
                && intent["policy"] == json!(input.policy.canonicalize()?),
            "Review handoff preparation belongs to different explicit bindings"
        );
    }
    let mut parents = guard_candidate(&candidate, &predecessor)?;
    ensure_incoming_committed(&predecessor)?;
    ensure!(
        input.from_attempt.len() == 64 && input.from_attempt.bytes().all(|b| b.is_ascii_hexdigit()),
        "Handoff requires an exact prior attempt digest"
    );
    crate::publish::oid(&input.head)?;
    crate::publish::oid(&input.base)?;
    let (config, publication, config_digest, authority) = context(&candidate, config_path)?;
    let (old_config, old_publication, old_digest, old_authority) =
        context(&predecessor, config_path)?;
    let (head, branch) = source(&config, &publication)?;
    let (old_head, old_branch) = source(&old_config, &old_publication)?;
    ensure!(
        head == input.head && publication["base"] == input.base && branch != old_branch,
        "Candidate head, base or distinct source branch differs"
    );
    ensure!(
        config_digest == old_digest && authority == old_authority,
        "Candidate trusted configuration or authority differs from predecessor"
    );
    let existing_outgoing = retained(&predecessor, OUTGOING)?;
    let active_receipt =
        journal(&predecessor)?.ok_or_else(|| invalid("Predecessor review is missing".into()))?;
    if let (Some(outgoing), Some(preparing)) = (&existing_outgoing, &existing_preparation) {
        ensure!(
            outgoing == preparing,
            "Outgoing handoff differs from candidate preparation"
        );
    }
    // Preparation pins the original seed even before the authoritative outgoing
    // reservation, including across explicit same-owner credential renewal.
    let prior_transition = existing_outgoing.as_ref().or(existing_preparation.as_ref());
    let (receipt, retained_digest, retained_authority) = if let Some(reservation) = prior_transition
    {
        let original = &reservation["receipt"];
        let mut original_stable = original.clone();
        let mut current_stable = active_receipt.clone();
        if original["schema_version"] == 2 {
            let (original_owner, _) = active_credentials(original)?;
            let (current_owner, _) = active_credentials(&active_receipt)?;
            ensure!(
                same_authority(original_owner, current_owner),
                "Retired predecessor authority changed"
            );
            original_stable["credential_history"] = Value::Null;
            current_stable["credential_history"] = Value::Null;
            let authority = authority
                .as_ref()
                .ok_or_else(|| invalid("Typed handoff cannot adopt legacy credentials".into()))?;
            ensure!(
                same_authority(original_owner, authority),
                "Handoff authority or policy changed"
            );
            let predecessor_rebound = current_owner == authority
                && bound(&config, &config_digest, &active_receipt).is_ok();
            let successor_rebound = if let Some(intent) = incoming(&candidate)? {
                if committed(&candidate, &intent)? {
                    if let Some(current) = journal(&candidate)? {
                        active_credentials(&current)?.0 == authority
                            && bound(&config, &config_digest, &current).is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            ensure!(predecessor_rebound || successor_rebound,
                "Changed generation requires supported predecessor rebind before pending handoff recovery, or committed successor rebind");
        } else {
            bound(&config, &config_digest, original)?;
            ensure!(
                authority.is_none(),
                "Legacy handoff cannot adopt typed owner identity"
            );
        }
        ensure!(
            original_stable == current_stable,
            "Retired predecessor round differs from immutable handoff snapshot"
        );
        credential_continuation(original, &active_receipt)?;
        (
            original.clone(),
            reservation["config_digest"].clone(),
            reservation["authority"].clone(),
        )
    } else {
        bound(&config, &config_digest, &active_receipt)?;
        if let Some(authority) = &authority {
            ensure!(
                active_credentials(&active_receipt)?.0 == authority,
                "Predecessor credential authority requires supported rebind before handoff"
            );
        }
        (active_receipt, json!(config_digest), json!(authority))
    };
    ensure!(
        receipt["phase"] == "submitted"
            && receipt["attempt"] == input.from_attempt
            && receipt["submitted_head"] == old_head
            && receipt["source_branch"] == old_branch
            && receipt["publication_base"] == old_publication["base"],
        "Predecessor is not the exact confirmed submitted attempt and publication"
    );
    if let Some(merge) = retained(&predecessor, "merge.json")? {
        ensure!(
            merge["confirmed"] == true,
            "Predecessor has a pending merge effect"
        );
    }
    let policy = crate::publication_policy::Policy::load(
        &input.policy,
        Path::new(text(&publication, "project")?),
    )?;
    let old_project = Path::new(text(&old_publication, "project")?).canonicalize()?;
    for path in policy.digests.keys() {
        ensure!(
            !path.canonicalize()?.starts_with(&old_project),
            "Trusted handoff policy must remain outside predecessor project"
        );
    }
    if !publication["policy_digests"].is_null() {
        ensure!(
            publication["policy_digests"] == serde_json::to_value(&policy.digests)?,
            "Candidate publication policy inputs changed"
        );
    }
    let candidate_binding = native_candidate(
        &candidate,
        &predecessor,
        &old_publication,
        &publication,
        &branch,
        &policy,
        &mut parents,
    )?;
    // Provider reads are observations only. No ticket, patch or attestation is
    // dispatched by this local metadata transition.
    if existing_outgoing.is_none() {
        let observed = status_locked(&old_lock, config_path)?;
        ensure!(
            current_round(&observed),
            "Predecessor lacks a current exact open provider round"
        );
    }
    let archive_path = predecessor
        .join("review-attempts")
        .join(text(&receipt, "attempt")?)
        .join("confirmed.json");
    let confirmed = read(&archive_path)?;
    ensure!(
        confirmed["phase"] == "submitted"
            && DecisionRound::from_review(&confirmed)? == DecisionRound::from_review(&receipt)?,
        "Original confirmed review archive differs from retained round"
    );
    credential_continuation(&confirmed, &receipt)?;
    let reservation = json!({"schema_version":1,"predecessor_state":predecessor,"candidate_state":candidate,
        "from_attempt":input.from_attempt,"head":input.head,"base":input.base,
        "config":config_path.canonicalize()?,"config_digest":retained_digest,"authority":retained_authority,
        "policy":input.policy.canonicalize()?,"policy_digests":policy.digests,
        "predecessor_publication":old_publication,"candidate_publication":publication,
        "candidate_binding":candidate_binding,"receipt":receipt,"receipt_sha256":digest(&receipt)?,
        "confirmed_archive":confirmed,"confirmed_archive_sha256":digest(&confirmed)?});
    ensure!(
        // publish_json appends one newline, also counted by state::read.
        serde_json::to_vec_pretty(&reservation)?.len() < LOCAL_RECORD_LIMIT,
        "Review handoff evidence exceeds the local recovery record limit"
    );
    if let Some(old) = &existing_outgoing {
        ensure!(
            *old == reservation,
            "Predecessor already reserved a different successor or binding"
        );
    }
    if let Some(preparing) = &existing_preparation {
        ensure!(
            *preparing == reservation,
            "Immutable review handoff preparation differs"
        );
    }
    if let Some(old) = incoming(&candidate)? {
        ensure!(
            old == reservation && existing_outgoing.is_some(),
            "Incoming handoff differs or lacks predecessor reservation"
        );
        if committed(&candidate, &old)? {
            immutable(&candidate, PREPARING, &reservation)?;
            // In particular, do not put the original round back after resubmit.
            return Ok(
                json!({"schema_version":1,"phase":"committed","transition_sha256":digest(&old)?,"predecessor_state":predecessor,"candidate_state":candidate}),
            );
        }
    } else {
        ensure!(
            journal(&candidate)?.is_none() && retained(&candidate, COMMITTED)?.is_none(),
            "Candidate already owns a review journal"
        );
    }
    absent_history(&candidate)?;
    // Only the exact seed archive is allowed in an interrupted candidate.
    if candidate.join("review-attempts").try_exists()? {
        for entry in candidate.join("review-attempts").read_dir()? {
            let entry = entry?;
            ensure!(
                entry.file_name() == input.from_attempt.as_str(),
                "Candidate has unrelated review attempts"
            );
            for file in entry.path().read_dir()? {
                ensure!(
                    file?.file_name() == "confirmed.json",
                    "Candidate has unrelated review evidence"
                );
            }
        }
    }
    if let Some(current) = journal(&candidate)? {
        ensure!(
            current == receipt,
            "Interrupted candidate journal differs from exact seed"
        );
    }
    // From the first durable preparation, the candidate cannot open an
    // unrelated ticket. Only outgoing is the authoritative successor claim.
    immutable(&candidate, PREPARING, &reservation)?;
    immutable(&predecessor, OUTGOING, &reservation)?;
    immutable(&candidate, INCOMING, &reservation)?;
    archive(&candidate, &confirmed, "confirmed")?;
    if journal(&candidate)?.is_none() {
        immutable(&candidate, "review.json", &receipt)?;
    }
    immutable(
        &candidate,
        COMMITTED,
        &json!({"schema_version":1,"transition_sha256":digest(&reservation)?}),
    )?;
    // Retain both endpoints and every ancestor guard through the final sync.
    drop(candidate_lock);
    Ok(
        json!({"schema_version":1,"phase":"committed","transition_sha256":digest(&reservation)?,"predecessor_state":predecessor,"candidate_state":candidate}),
    )
}
