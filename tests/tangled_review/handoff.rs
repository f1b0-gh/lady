use super::*;
use ladyshell::tangled_review::HandoffInput;
use std::path::{Path, PathBuf};

struct HandoffFixture {
    old: MergeFixture,
    state: PathBuf,
    head: String,
    base: String,
    attempt: String,
}
#[test]
fn continuous_handoff_candidate_refuses_stale_epoch_before_reservation() -> Result {
    use ladyshell::continuous::{
        host,
        model::{Phase, Session},
    };
    let f = HandoffFixture::new(false)?;
    let mut current = ladyshell::state::load(&f.state)?.ok_or("state")?;
    let export = PathBuf::from(current["last_sync"].as_str().ok_or("export")?);
    let mut manifest = ladyshell::state::read(&export.join("manifest.json"))?.ok_or("manifest")?;
    let mut session = Session::new(
        "task".into(),
        "candidate-id".into(),
        "owner".into(),
        "runtime".into(),
        "a".repeat(64),
        "b".repeat(64),
    )?;
    current["continuous"] = serde_json::to_value(&session)?;
    manifest["continuous"] = host::export_binding(&current)?;
    put(&export.join("manifest.json"), &manifest)?;
    for pending in [false, true] {
        session.epoch = if pending { 0 } else { 1 };
        session.phase = if pending {
            Phase::Checkpointed
        } else {
            Phase::Ready
        };
        current["continuous"] = serde_json::to_value(&session)?;
        put(&f.state.join("state.json"), &current)?;
        let requests = f.old.review.data.lock().map_err(|_| "fixture lock")?["requests"].clone();
        let error = f.handoff().err().ok_or("stale handoff admitted")?;
        let expected = if pending {
            "handoff is pending"
        } else {
            "another continuous epoch"
        };
        assert!(error.to_string().contains(expected), "{error}");
        assert!(!f.state.join("review-handoff-preparing.json").exists());
        assert!(!f
            .old
            .review
            .state()
            .join("review-handoff-outgoing.json")
            .exists());
        assert_eq!(
            f.old.review.data.lock().map_err(|_| "fixture lock")?["requests"],
            requests
        );
    }
    Ok(())
}
impl HandoffFixture {
    fn new(typed: bool) -> Result<Self> {
        Self::with_owner_policy(typed, true)
    }
    fn with_owner_policy(typed: bool, required: bool) -> Result<Self> {
        let old = MergeFixture::with_profile(true, required)?;
        if typed {
            // Establish typed authority before the original immutable round.
            fs::remove_file(old.review.state().join("review.json"))?;
            fs::remove_dir_all(old.review.state().join("review-attempts"))?;
            typed_connector(&old.review, false)?;
            let mut input = old.review.input();
            input.target_base = old.base.clone();
            tangled_review::submit(&old.review.state(), &old.config, &input)?;
        }
        let prior = tangled_review::status(&old.review.state(), &old.config)?;
        if required {
            tangled_review::record_owner_decision(
                &old.review.state(),
                &old.config,
                &ladyshell::tangled_review::DecisionInput {
                    decision: ladyshell::tangled_review::OwnerDecision::Approved,
                    head: old.head.clone(),
                    base: old.base.clone(),
                    patch_uri: prior["patch"]["uri"].as_str().ok_or("uri")?.into(),
                    patch_cid: prior["patch"]["cid"].as_str().ok_or("cid")?.into(),
                    explanation: None,
                },
            )?;
        }
        let attempt = prior["attempt"].as_str().ok_or("attempt")?.into();
        let directory = old.review.root.path().join("candidate");
        let task = ladyshell::tasks::prepare(
            &old.review.root.path().join("project"),
            &directory,
            "continued",
            &old.head,
        )?;
        let state = directory.join("state");
        ladyshell::state::create_directory(&state)?;
        let project = Path::new(task["project"].as_str().ok_or("project")?);
        fs::write(project.join("code"), b"continued\n")?;
        fixture_git(project, &["commit", "-S", "-am", "continued"])?;
        let head = fixture_git(project, &["rev-parse", "HEAD"])?;
        let export = state.join("exports/continued");
        fs::create_dir_all(export.join("project"))?;
        fs::write(export.join("project/code"), b"continued\n")?;
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(old.export.join("manifest.json"))?)?;
        manifest["sandbox_id"] = json!("candidate-id");
        manifest["files"]["code"]["sha256"] = json!(ladyshell::files::hash(b"continued\n"));
        put(&export.join("manifest.json"), &manifest)?;
        let mut checks: Value = serde_json::from_slice(&fs::read(old.export.join("checks.json"))?)?;
        checks["snapshot_sha256"] = json!(ladyshell::publication_checks::export_digest(&export)?);
        put(&export.join("checks.json"), &checks)?;
        let policy: Value = serde_json::from_slice(&fs::read(&old.policy)?)?;
        put(
            &state.join("state.json"),
            &json!({"schema_version":2,"sandbox_name":"candidate","sandbox_id":"candidate-id","owner":"owner","policy_hash":"policy","desired_hash":"desired","project_snapshot":export.join("project"),"build_dir":directory,"desired_inputs":{"project":project},"context":{"gateway":"fixture","workspace":"default"},"image_id":"image","codex_binary":"/codex","sync":{"destination":"exports"},"last_sync":export}),
        )?;
        put(
            &state.join("publication.json"),
            &json!({"schema_version":2,"phase":"published","confirmed":true,"project":project,"export":export,"destination":"git@127.0.0.1:did:plc:repo","reference":"refs/heads/continued","branch":"continued","base":old.head,"commit":head,"checks":policy["checks"]}),
        )?;
        put(
            &state.join("stack-binding.json"),
            &json!({"schema_version":1,"stack":old.review.root.path().join("stack"),"parent":old.review.state(),"parent_head":old.head}),
        )?;
        let base = old.head.clone();
        Ok(Self {
            old,
            state,
            head,
            base,
            attempt,
        })
    }
    fn input(&self) -> HandoffInput {
        HandoffInput {
            from_state: self.old.review.state(),
            from_attempt: self.attempt.clone(),
            head: self.head.clone(),
            base: self.base.clone(),
            policy: self.old.policy.clone(),
        }
    }
    fn handoff(&self) -> ladyshell::error::Result<Value> {
        tangled_review::handoff(&self.state, &self.old.config, &self.input())
    }
    fn resubmit(&self) -> ladyshell::error::Result<Value> {
        let mut input = self.old.review.input();
        input.resubmit = true;
        input.ticket_key = "79".into();
        input.target_base = self.base.clone();
        input.created_at = "2026-11-05T00:01:00Z".into();
        tangled_review::submit(&self.state, &self.old.config, &input)
    }
}
fn put(path: &Path, value: &Value) -> Result {
    fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}
fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

#[test]
fn handoff_signed_candidate_reuses_ticket_without_owner_approval_or_old_archive_changes() -> Result
{
    let f = HandoffFixture::new(false)?;
    let old_before = persistent_tree(&f.old.review.state())?;
    let writes = f.old.review.data.lock().unwrap()["writes"].clone();
    let input = f.input();
    let cli = std::process::Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["review", "handoff", "--state"])
        .arg(&f.state)
        .arg("--from-state")
        .arg(&input.from_state)
        .arg("--from-attempt")
        .arg(&input.from_attempt)
        .arg("--head")
        .arg(&input.head)
        .arg("--base")
        .arg(&input.base)
        .arg("--policy")
        .arg(&input.policy)
        .arg("--config")
        .arg(&f.old.config)
        .output()?;
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_result: Value = serde_json::from_slice(&cli.stdout)?;
    assert_eq!(cli_result["phase"], "committed");
    let transition = f.handoff()?;
    assert!(f.state.join("review-handoff-preparing.json").exists());
    assert_eq!(transition["phase"], "committed");
    assert_eq!(f.old.review.data.lock().unwrap()["writes"], writes);
    let old_status = tangled_review::status(&f.old.review.state(), &f.old.config)?;
    assert_eq!(old_status["handoff"]["retired_writer"], true);
    assert_eq!(old_status["superseded"], false);
    let round = f.resubmit()?;
    assert_eq!(round["ticket_key"], "79");
    assert_eq!(round["previous"]["attempt"], f.attempt);
    assert_eq!(round["submitted_head"], f.head);
    assert_eq!(round["submitted_base"], f.base);
    assert_eq!(round["source_branch"], "continued");
    assert!(!f.state.join("owner-review-decisions").exists());
    assert_ne!(
        tangled_review::status(&f.state, &f.old.config)?["human_review"]["status"],
        "current"
    );
    assert!(tangled_review::merge_admission(&f.state, &f.old.config, &f.head, &f.base).is_err());
    tangled_review::record_owner_decision(
        &f.state,
        &f.old.config,
        &ladyshell::tangled_review::DecisionInput {
            decision: ladyshell::tangled_review::OwnerDecision::Approved,
            head: f.head.clone(),
            base: f.base.clone(),
            patch_uri: round["patch"]["uri"].as_str().ok_or("uri")?.into(),
            patch_cid: round["patch"]["cid"].as_str().ok_or("cid")?.into(),
            explanation: None,
        },
    )?;
    let decisions = persistent_tree(&f.state.join("owner-review-decisions"))?;
    f.handoff()?;
    assert_eq!(
        persistent_tree(&f.state.join("owner-review-decisions"))?,
        decisions
    );
    for (path, bytes) in old_before {
        if let Some(bytes) = bytes {
            assert_eq!(fs::read(f.old.review.state().join(path))?, bytes);
        } else {
            assert!(f.old.review.state().join(path).is_dir());
        }
    }
    assert_eq!(f.old.review.data.lock().unwrap()["writes"], 3);
    let current = fs::read(f.state.join("review.json"))?;
    f.handoff()?;
    assert_eq!(fs::read(f.state.join("review.json"))?, current);
    Ok(())
}

#[test]
fn handoff_refuses_binding_changes_before_reserving() -> Result {
    for change in [
        "head",
        "base",
        "attempt",
        "source",
        "target",
        "policy",
        "parent",
        "native",
        "provenance",
        "pending",
        "merge",
        "owner",
        "repository",
        "source_repository",
        "native_repository",
        "export",
        "signature",
        "candidate_review",
        "receipt_tamper",
        "missing_parent",
    ] {
        let f = HandoffFixture::new(change == "owner")?;
        let mut input = f.input();
        match change {
            "head" => input.head = "a".repeat(40),
            "base" => input.base = "b".repeat(40),
            "attempt" => input.from_attempt = "c".repeat(64),
            "repository" | "source_repository" => {
                let mut c = read_json(&f.old.config)?;
                c[change] = json!("did:plc:other");
                put(&f.old.config, &c)?;
            }
            "native_repository" => {
                let path = f.state.parent().ok_or("parent")?.join("task.json");
                let mut t = read_json(&path)?;
                t["repository"] = json!(f.old.review.root.path());
                put(&path, &t)?;
            }
            "export" => {
                fs::write(f.state.join("exports/continued/project/code"), b"tampered")?;
            }
            "signature" => {
                let mut policy = read_json(&f.old.policy)?;
                policy["signing"]["principal"] = json!("other@example.invalid");
                put(&f.old.policy, &policy)?;
            }
            "receipt_tamper" => {
                let path = f.old.review.state().join("review.json");
                let mut r = read_json(&path)?;
                r["change_summary"]["body"] = json!("changed retained receipt");
                put(&path, &r)?;
            }
            "missing_parent" => fs::remove_file(f.state.join("stack-binding.json"))?,
            "candidate_review" => put(
                &f.state.join("review.json"),
                &json!({"schema_version":1,"phase":"submitted"}),
            )?,
            "source" => {
                let mut p = read_json(&f.state.join("publication.json"))?;
                p["destination"] = json!("git@127.0.0.1:did:plc:other");
                put(&f.state.join("publication.json"), &p)?;
            }
            "target" => {
                f.old.review.data.lock().unwrap()["ticket"]["targetBranch"] = json!("other");
            }
            "policy" => {
                let mut p = read_json(&f.old.policy)?;
                p["checks"]["commands"] = json!([["false"]]);
                put(&f.old.policy, &p)?;
            }
            "parent" => {
                let mut p = read_json(&f.state.join("stack-binding.json"))?;
                p["parent_head"] = json!("d".repeat(40));
                put(&f.state.join("stack-binding.json"), &p)?;
            }
            "native" => {
                let path = f.state.parent().ok_or("parent")?.join("task.json");
                let mut t = read_json(&path)?;
                t["branch"] = json!("unrelated");
                put(&path, &t)?;
            }
            "provenance" => {
                put(
                    &f.state.parent().ok_or("parent")?.join("restack.json"),
                    &json!({"source_state":f.old.review.state(),"old_head":"e".repeat(40),"old_base":f.old.base,"new_base":f.base}),
                )?;
            }
            "pending" => {
                let path = f.old.review.state().join("review.json");
                let mut r = read_json(&path)?;
                r["phase"] = json!("patch_pending");
                put(&path, &r)?;
            }
            "merge" => put(
                &f.old.review.state().join("merge.json"),
                &json!({"schema_version":1,"confirmed":false}),
            )?,
            "owner" => {
                let host = f.old.review.root.path().join("host.json");
                let mut p = read_json(&host)?;
                p["account"] = json!("did:plc:other");
                put(&host, &p)?;
            }
            _ => unreachable!(),
        }
        let candidate_before = persistent_tree(&f.state)?;
        assert!(
            tangled_review::handoff(&f.state, &f.old.config, &input).is_err(),
            "{change}"
        );
        assert!(
            !f.old
                .review
                .state()
                .join("review-handoff-outgoing.json")
                .exists(),
            "{change}"
        );
        assert_eq!(persistent_tree(&f.state)?, candidate_before, "{change}");
    }
    Ok(())
}

#[test]
fn handoff_durable_prefixes_resume_only_identical_transition_and_block_writers() -> Result {
    for boundary in 0..6 {
        let f = HandoffFixture::new(false)?;
        handoff_prefix(&f, boundary)?;
        let before = f.old.review.data.lock().unwrap()["writes"].clone();
        if boundary > 0 {
            assert!(tangled_review::submit(
                &f.old.review.state(),
                &f.old.config,
                &f.old.review.input()
            )
            .is_err());
            assert!(tangled_review::merge_admission(
                &f.old.review.state(),
                &f.old.config,
                &f.old.head,
                &f.old.base
            )
            .is_err());
        }
        assert!(tangled_review::reconcile(&f.old.review.state(), &f.old.config).is_ok());
        if boundary < 5 {
            assert!(f.resubmit().is_err());
            let mut fresh = f.old.review.input();
            fresh.target_base = f.base.clone();
            assert!(
                tangled_review::submit(&f.state, &f.old.config, &fresh).is_err(),
                "boundary {boundary}"
            );
            assert_eq!(f.old.review.data.lock().unwrap()["writes"], before);
        }
        let mut wrong = f.input();
        wrong.head = "a".repeat(40);
        assert!(tangled_review::handoff(&f.state, &f.old.config, &wrong).is_err());
        if boundary == 2 {
            for binding in ["attempt", "base", "policy", "config"] {
                let mut mismatched = f.input();
                let mut config = f.old.config.clone();
                match binding {
                    "attempt" => mismatched.from_attempt = "e".repeat(64),
                    "base" => mismatched.base = "e".repeat(40),
                    "policy" => {
                        let path = f.old.review.root.path().join("other-policy.json");
                        fs::copy(&f.old.policy, &path)?;
                        mismatched.policy = path;
                    }
                    _ => {
                        config = f.old.review.root.path().join("other-config.json");
                        fs::copy(&f.old.config, &config)?;
                    }
                }
                assert!(
                    tangled_review::handoff(&f.state, &config, &mismatched).is_err(),
                    "{binding}"
                );
            }
        }
        f.handoff()?;
        let round = f.resubmit()?;
        assert_eq!(round["previous"]["attempt"], f.attempt);
    }
    Ok(())
}

#[test]
fn handoff_lost_patch_acknowledgement_and_typed_rebind_preserve_original_ticket() -> Result {
    let f = HandoffFixture::new(true)?;
    f.handoff()?;
    f.old.review.data.lock().unwrap()["lost"] = json!(true);
    assert!(f.resubmit().is_err());
    let before = f.old.review.data.lock().unwrap()["writes"].clone();
    let round = tangled_review::reconcile(&f.state, &f.old.config)?;
    assert_eq!(round["phase"], "submitted");
    assert_eq!(round["ticket_key"], "79");
    assert_eq!(f.old.review.data.lock().unwrap()["writes"], before);
    for path in [&f.old.config, &f.old.review.root.path().join("host.json")] {
        let mut v = read_json(path)?;
        if v["connector"].is_object() {
            v["connector"]["generation"] = json!(2);
        } else {
            v["generation"] = json!(2);
        }
        put(path, &v)?;
    }
    tangled_review::rebind_credentials(&f.state, &f.old.config)?;
    let current = fs::read(f.state.join("review.json"))?;
    f.handoff()?;
    assert_eq!(fs::read(f.state.join("review.json"))?, current);
    assert_eq!(
        tangled_review::status(&f.state, &f.old.config)?["phase"],
        "submitted"
    );
    tangled_review::rebind_credentials(&f.old.review.state(), &f.old.config)?;
    assert!(
        tangled_review::submit(&f.old.review.state(), &f.old.config, &f.old.review.input())
            .is_err()
    );
    Ok(())
}

fn handoff_contender(f: &HandoffFixture) -> Result<PathBuf> {
    let directory = f.old.review.root.path().join("contender");
    let task = ladyshell::tasks::prepare(
        &f.old.review.root.path().join("project"),
        &directory,
        "contender",
        &f.base,
    )?;
    let project = Path::new(task["project"].as_str().ok_or("project")?);
    fixture_git(project, &["reset", "--hard", &f.head])?;
    let state = directory.join("state");
    ladyshell::state::create_directory(&state)?;
    let export = state.join("exports/continued");
    fs::create_dir_all(export.join("project"))?;
    for path in ["manifest.json", "checks.json", "project/code"] {
        fs::copy(
            f.state.join("exports/continued").join(path),
            export.join(path),
        )?;
    }
    let mut native = read_json(&f.state.join("state.json"))?;
    native["desired_inputs"]["project"] = json!(project);
    native["last_sync"] = json!(export);
    native["project_snapshot"] = json!(export.join("project"));
    native["build_dir"] = json!(directory);
    put(&state.join("state.json"), &native)?;
    let mut publication = read_json(&f.state.join("publication.json"))?;
    publication["project"] = json!(project);
    publication["export"] = json!(export);
    publication["reference"] = json!("refs/heads/contender");
    publication["branch"] = json!("contender");
    put(&state.join("publication.json"), &publication)?;
    fs::copy(
        f.state.join("stack-binding.json"),
        state.join("stack-binding.json"),
    )?;
    Ok(state)
}

#[test]
fn handoff_competing_successors_have_only_one_reserved_writer() -> Result {
    let f = HandoffFixture::new(false)?;
    let state = handoff_contender(&f)?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let results = thread::scope(|scope| {
        let b = barrier.clone();
        let first_fixture = &f;
        let first = scope.spawn(move || {
            b.wait();
            first_fixture.handoff()
        });
        let second = scope.spawn(|| {
            barrier.wait();
            tangled_review::handoff(&state, &f.old.config, &f.input())
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    // Nonblocking contenders can both lose their first lock race; retry only
    // the original exact candidates. A reservation, once present, never changes.
    if results.0.is_err() && results.1.is_err() {
        let _ = f.handoff();
    }
    let outgoing = read_json(&f.old.review.state().join("review-handoff-outgoing.json"))?;
    let winner = outgoing["candidate_state"].as_str().ok_or("winner")?;
    let loser = if Path::new(winner) == f.state {
        &state
    } else {
        &f.state
    };
    assert!(tangled_review::handoff(loser, &f.old.config, &f.input()).is_err());
    tangled_review::handoff(Path::new(winner), &f.old.config, &f.input())?;
    assert!(!loser.join("review.json").exists());
    assert!(!loser.join("review-handoff-preparing.json").exists());
    assert_eq!(
        read_json(&f.old.review.state().join("review-handoff-outgoing.json"))?,
        outgoing
    );
    Ok(())
}

#[test]
fn handoff_pending_generation_change_requires_explicit_predecessor_then_successor_rebind() -> Result
{
    let f = HandoffFixture::new(true)?;
    f.handoff()?;
    fs::remove_file(f.state.join("review-handoff-committed.json"))?;
    for path in [&f.old.config, &f.old.review.root.path().join("host.json")] {
        let mut v = read_json(path)?;
        if v["connector"].is_object() {
            v["connector"]["generation"] = json!(2);
        } else {
            v["generation"] = json!(2);
        }
        put(path, &v)?;
    }
    assert!(f.handoff().is_err());
    assert!(tangled_review::rebind_credentials(&f.state, &f.old.config).is_err());
    tangled_review::rebind_credentials(&f.old.review.state(), &f.old.config)?;
    let before = f.old.review.data.lock().unwrap()["writes"].clone();
    f.handoff()?;
    assert_eq!(f.old.review.data.lock().unwrap()["writes"], before);
    assert!(f.resubmit().is_err());
    tangled_review::rebind_credentials(&f.state, &f.old.config)?;
    let round = f.resubmit()?;
    let current = fs::read(f.state.join("review.json"))?;
    f.handoff()?;
    assert_eq!(fs::read(f.state.join("review.json"))?, current);
    assert_eq!(round["ticket_key"], "79");
    Ok(())
}

#[test]
fn handoff_tampered_local_commit_and_archive_refuse_before_provider_dispatch() -> Result {
    for change in ["preparing", "incoming", "marker", "archive", "journal"] {
        let f = HandoffFixture::new(false)?;
        f.handoff()?;
        let path = match change {
            "preparing" => f.state.join("review-handoff-preparing.json"),
            "incoming" => f.state.join("review-handoff-incoming.json"),
            "marker" => f.state.join("review-handoff-committed.json"),
            "archive" => f
                .state
                .join("review-attempts")
                .join(&f.attempt)
                .join("confirmed.json"),
            _ => f.state.join("review.json"),
        };
        let mut value = read_json(&path)?;
        value["tampered"] = json!(true);
        put(&path, &value)?;
        if change == "archive" || change == "journal" {
            fs::remove_file(f.state.join("review-handoff-committed.json"))?;
        }
        let before = f.old.review.data.lock().unwrap()["writes"].clone();
        assert!(f.handoff().is_err(), "{change}");
        assert!(f.resubmit().is_err(), "{change}");
        assert_eq!(f.old.review.data.lock().unwrap()["writes"], before);
    }
    Ok(())
}

#[test]
fn handoff_native_restack_after_feedback_continues_original_ticket() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    let root = f.review.root.path();
    let project = root.join("project");
    put(
        &f.review.state().join("state.json"),
        &json!({"schema_version":2,"sandbox_name":"original","sandbox_id":"original-id","policy_hash":"policy","codex_binary":"/codex","owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"snapshot","build_dir":"build","context":{"gateway":"fixture","workspace":"default"}}),
    )?;
    let stack = root.join("native-stack");
    ladyshell::stacks::record(&stack, &f.review.state(), None)?;
    // A feedback publication advances its immediate publication base while
    // stacks::record deliberately retains the logical checkpoint base.
    fs::write(project.join("code"), b"reviewed again\n")?;
    fixture_git(&project, &["commit", "-S", "-am", "feedback"])?;
    let feedback_head = fixture_git(&project, &["rev-parse", "HEAD"])?;
    fs::write(f.export.join("project/code"), b"reviewed again\n")?;
    let mut manifest = read_json(&f.export.join("manifest.json"))?;
    manifest["files"]["code"]["sha256"] = json!(ladyshell::files::hash(b"reviewed again\n"));
    put(&f.export.join("manifest.json"), &manifest)?;
    let mut checks = read_json(&f.export.join("checks.json"))?;
    checks["snapshot_sha256"] = json!(ladyshell::publication_checks::export_digest(&f.export)?);
    put(&f.export.join("checks.json"), &checks)?;
    let mut old_publication = read_json(&f.review.state().join("publication.json"))?;
    old_publication["base"] = json!(f.head);
    old_publication["commit"] = json!(feedback_head);
    put(&f.review.state().join("publication.json"), &old_publication)?;
    let mut feedback = f.review.input();
    feedback.ticket_key = "79".into();
    feedback.resubmit = true;
    feedback.target_base = f.base.clone();
    tangled_review::submit(&f.review.state(), &f.config, &feedback)?;
    ladyshell::stacks::record(&stack, &f.review.state(), None)?;
    fixture_git(&project, &["checkout", "-b", "integration", &f.base])?;
    fs::write(project.join("parent"), b"new parent\n")?;
    fixture_git(&project, &["add", "parent"])?;
    fixture_git(&project, &["commit", "-S", "-m", "new parent"])?;
    let new_base = fixture_git(&project, &["rev-parse", "HEAD"])?;
    let parent = root.join("parent-state");
    ladyshell::state::create_directory(&parent)?;
    put(
        &parent.join("publication.json"),
        &json!({"schema_version":2,"phase":"published","confirmed":true,"project":project,"base":f.base,"commit":new_base}),
    )?;
    ladyshell::stacks::record(&stack, &parent, None)?;
    let restack = ladyshell::stacks::restack_onto(&stack, &f.review.state(), Some(&parent))?;
    let candidate = Path::new(restack["candidate"]["state"].as_str().ok_or("state")?);
    let export = Path::new(restack["export"].as_str().ok_or("export")?);
    let policy = read_json(&f.policy)?;
    // Independent check protocol fixture only, as in MergeFixture. No live
    // verifier or credentials are used. Publication/signature are real Git.
    put(
        &export.join("checks.json"),
        &json!({"schema_version":1,"passed":true,
        "snapshot_sha256":ladyshell::publication_checks::export_digest(export)?,
        "policy_sha256":ladyshell::files::hash(&serde_json::to_vec(&policy["checks"])?)}),
    )?;
    let branch = restack["candidate"]["branch"].as_str().ok_or("branch")?;
    let publication = ladyshell::retained_publication::run(
        candidate,
        export,
        &ladyshell::publish::Options {
            remote: "knot".into(),
            branch: branch.into(),
            message: "restacked".into(),
            policy: Some(f.policy.clone()),
        },
    )?;
    let old = read_json(&f.review.state().join("review.json"))?;
    tangled_review::handoff(
        candidate,
        &f.config,
        &HandoffInput {
            from_state: f.review.state(),
            from_attempt: old["attempt"].as_str().ok_or("attempt")?.into(),
            head: publication["commit"].as_str().ok_or("head")?.into(),
            base: new_base.clone(),
            policy: f.policy.clone(),
        },
    )?;
    let mut input = f.review.input();
    input.resubmit = true;
    input.ticket_key = "79".into();
    input.target_base = new_base;
    let round = tangled_review::submit(candidate, &f.config, &input)?;
    assert_eq!(round["submitted_head"], publication["commit"]);
    assert_eq!(round["previous"]["attempt"], old["attempt"]);
    assert_eq!(f.review.data.lock().unwrap()["writes"], 4);
    Ok(())
}

#[test]
fn handoff_retires_owner_and_merge_retry_but_keeps_accepted_historical_readback() -> Result {
    let f = HandoffFixture::new(false)?;
    let before = read_json(&f.old.review.state().join("review.json"))?;
    let admission = tangled_review::merge_admission(
        &f.old.review.state(),
        &f.old.config,
        &f.old.head,
        &f.old.base,
    )?;
    f.handoff()?;
    assert!(tangled_review::record_owner_decision(
        &f.old.review.state(),
        &f.old.config,
        &ladyshell::tangled_review::DecisionInput {
            decision: ladyshell::tangled_review::OwnerDecision::Approved,
            head: f.old.head.clone(),
            base: f.old.base.clone(),
            patch_uri: before["patch"]["uri"].as_str().ok_or("uri")?.into(),
            patch_cid: before["patch"]["cid"].as_str().ok_or("cid")?.into(),
            explanation: None
        }
    )
    .is_err());
    let intent = json!({"schema_version":1,"project":f.old.review.root.path().join("project"),"head":f.old.head,"expected_target":f.old.base,
        "reference":"refs/heads/main","destination":f.old.remote,"confirmed":false,"review":admission});
    put(&f.old.review.state().join("merge.json"), &intent)?;
    assert!(ladyshell::review_merge::reconcile(&f.old.review.state(), true).is_err());
    assert_eq!(
        fixture_git(&f.old.remote, &["rev-parse", "main"])?,
        f.old.base
    );
    fixture_git(
        &f.old.review.root.path().join("project"),
        &[
            "push",
            f.old.remote.to_str().ok_or("remote")?,
            &format!("{}:refs/heads/main", f.old.head),
        ],
    )?;
    assert_eq!(
        ladyshell::review_merge::reconcile(&f.old.review.state(), true)?["confirmed"],
        true
    );
    Ok(())
}

#[test]
fn handoff_preserves_explicit_unsupported_human_review_policy() -> Result {
    let f = HandoffFixture::with_owner_policy(false, false)?;
    f.handoff()?;
    f.resubmit()?;
    let status = tangled_review::status(&f.state, &f.old.config)?;
    assert_eq!(status["human_review"]["status"], "unknown");
    assert_eq!(
        status["human_review"]["reason"],
        "decision_source_unsupported"
    );
    assert!(tangled_review::merge_admission(&f.state, &f.old.config, &f.head, &f.base).is_ok());
    assert!(!f.state.join("owner-review-decisions").exists());
    Ok(())
}

#[test]
fn handoff_oversized_evidence_refuses_before_creating_an_unreadable_reservation() -> Result {
    let f = HandoffFixture::new(false)?;
    let mut native = read_json(&f.state.join("state.json"))?;
    native["fixture_metadata"] = json!("x".repeat(15 * 1024 * 1024));
    put(&f.state.join("state.json"), &native)?;
    let path = f.state.join("exports/continued/checks.json");
    let mut checks = read_json(&path)?;
    checks["fixture_metadata"] = json!("x".repeat(2 * 1024 * 1024));
    put(&path, &checks)?;
    assert!(f.handoff().is_err());
    assert!(!f
        .old
        .review
        .state()
        .join("review-handoff-outgoing.json")
        .exists());
    assert!(!f.state.join("review-handoff-incoming.json").exists());
    Ok(())
}

// Construct exact durable prefixes from the records emitted by native handoff.
fn handoff_prefix(f: &HandoffFixture, boundary: usize) -> Result {
    f.handoff()?;
    let preparing = f.state.join("review-handoff-preparing.json");
    assert!(
        preparing.exists(),
        "Native handoff must publish its blocking preparation"
    );
    let paths = [
        preparing,
        f.old.review.state().join("review-handoff-outgoing.json"),
        f.state.join("review-handoff-incoming.json"),
        f.state
            .join("review-attempts")
            .join(&f.attempt)
            .join("confirmed.json"),
        f.state.join("review.json"),
        f.state.join("review-handoff-committed.json"),
    ];
    for path in &paths[boundary + 1..] {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[test]
fn handoff_fix1_preparation_and_outgoing_prefixes_block_fresh_ticket_writes() -> Result {
    for boundary in 0..2 {
        let f = HandoffFixture::new(false)?;
        handoff_prefix(&f, boundary)?;
        let before = f.old.review.data.lock().unwrap()["writes"].clone();
        let mut fresh = f.old.review.input();
        fresh.target_base = f.base.clone();
        assert!(
            tangled_review::submit(&f.state, &f.old.config, &fresh).is_err(),
            "boundary {boundary}"
        );
        assert_eq!(f.old.review.data.lock().unwrap()["writes"], before);
        assert!(f.resubmit().is_err());
        assert!(tangled_review::reconcile(&f.state, &f.old.config).is_err());
        assert!(
            tangled_review::merge_admission(&f.state, &f.old.config, &f.head, &f.base).is_err()
        );
        let status = tangled_review::status(&f.state, &f.old.config)?;
        assert_eq!(status["handoff"]["phase"], "preparing");
        if boundary == 0 {
            assert!(tangled_review::merge_admission(
                &f.old.review.state(),
                &f.old.config,
                &f.old.head,
                &f.old.base
            )
            .is_ok());
        }
        f.handoff()?;
        assert_eq!(f.resubmit()?["ticket_key"], "79");
    }
    Ok(())
}

fn reset_handoff_records(f: &HandoffFixture) -> Result {
    for path in [
        f.state.join("review-handoff-preparing.json"),
        f.old.review.state().join("review-handoff-outgoing.json"),
        f.state.join("review-handoff-incoming.json"),
        f.state.join("review.json"),
        f.state.join("review-handoff-committed.json"),
    ] {
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    fs::remove_dir_all(f.state.join("review-attempts"))?;
    Ok(())
}

#[test]
fn handoff_fix1_exact_encoded_record_boundary_includes_publisher_newline() -> Result {
    let f = HandoffFixture::new(false)?;
    let native_path = f.state.join("state.json");
    let mut native = read_json(&native_path)?;
    native["fixture_padding"] = json!("");
    put(&native_path, &native)?;
    f.handoff()?;
    let reservation = read_json(&f.old.review.state().join("review-handoff-outgoing.json"))?;
    let unpadded = serde_json::to_vec_pretty(&reservation)?.len();
    reset_handoff_records(&f)?;
    let before = f.old.review.data.lock().unwrap()["writes"].clone();
    let limit = 16 * 1024 * 1024;
    for encoded_length in [limit, limit + 1] {
        native["fixture_padding"] = json!("x".repeat(encoded_length - 1 - unpadded));
        put(&native_path, &native)?;
        let result = f.handoff();
        if encoded_length == limit {
            result?;
            for path in [
                f.state.join("review-handoff-preparing.json"),
                f.old.review.state().join("review-handoff-outgoing.json"),
                f.state.join("review-handoff-incoming.json"),
            ] {
                assert_eq!(fs::metadata(path)?.len() as usize, limit);
            }
            f.handoff()?;
            reset_handoff_records(&f)?;
        } else {
            assert!(
                result.is_err(),
                "{encoded_length} encoded bytes exceed the reader limit"
            );
            assert!(!f.state.join("review-handoff-preparing.json").exists());
            assert!(!f
                .old
                .review
                .state()
                .join("review-handoff-outgoing.json")
                .exists());
            assert!(!f.state.join("review-handoff-incoming.json").exists());
        }
        assert_eq!(f.old.review.data.lock().unwrap()["writes"], before);
    }
    Ok(())
}

#[test]
fn handoff_fix1_preparation_pins_predecessor_and_refuses_before_other_state_writes() -> Result {
    let f = HandoffFixture::new(false)?;
    handoff_prefix(&f, 0)?;
    let other = f.old.review.root.path().join("other-predecessor");
    ladyshell::state::create_directory(&other)?;
    for name in ["publication.json", "review.json"] {
        fs::copy(f.old.review.state().join(name), other.join(name))?;
    }
    let target = other.join("review-attempts").join(&f.attempt);
    fs::create_dir_all(&target)?;
    fs::copy(
        f.old
            .review
            .state()
            .join("review-attempts")
            .join(&f.attempt)
            .join("confirmed.json"),
        target.join("confirmed.json"),
    )?;
    let untouched = persistent_tree(&other)?;
    let mut wrong = f.input();
    wrong.from_state = other.clone();
    assert!(tangled_review::handoff(&f.state, &f.old.config, &wrong).is_err());
    assert_eq!(persistent_tree(&other)?, untouched);
    assert!(!f
        .old
        .review
        .state()
        .join("review-handoff-outgoing.json")
        .exists());
    let preparing = f.state.join("review-handoff-preparing.json");
    let original = fs::read(&preparing)?;
    let mut tampered = read_json(&preparing)?;
    tampered["head"] = json!("e".repeat(40));
    put(&preparing, &tampered)?;
    assert!(f.handoff().is_err());
    assert!(f.resubmit().is_err());
    assert!(!f
        .old
        .review
        .state()
        .join("review-handoff-outgoing.json")
        .exists());
    fs::write(preparing, original)?;
    f.handoff()?;
    Ok(())
}

#[test]
fn handoff_fix1_latch_only_loses_to_separate_authoritative_successor_without_effects() -> Result {
    let f = HandoffFixture::new(false)?;
    let contender = handoff_contender(&f)?;
    handoff_prefix(&f, 0)?;
    let retained = persistent_tree(f.state.parent().ok_or("task")?)?;
    let before = f.old.review.data.lock().unwrap()["writes"].clone();
    tangled_review::handoff(&contender, &f.old.config, &f.input())?;
    let authoritative = fs::read(f.old.review.state().join("review-handoff-outgoing.json"))?;
    assert_eq!(
        read_json(&f.old.review.state().join("review-handoff-outgoing.json"))?["candidate_state"],
        json!(contender)
    );
    assert!(f.handoff().is_err());
    assert!(f.resubmit().is_err());
    let mut fresh = f.old.review.input();
    fresh.target_base = f.base.clone();
    assert!(tangled_review::submit(&f.state, &f.old.config, &fresh).is_err());
    assert_eq!(persistent_tree(f.state.parent().ok_or("task")?)?, retained);
    assert_eq!(
        fs::read(f.old.review.state().join("review-handoff-outgoing.json"))?,
        authoritative
    );
    assert_eq!(f.old.review.data.lock().unwrap()["writes"], before);
    assert!(!f.state.join("review-handoff-incoming.json").exists());
    Ok(())
}

#[test]
fn handoff_fix1_latch_only_generation_recovery_preserves_original_seed() -> Result {
    let f = HandoffFixture::new(true)?;
    handoff_prefix(&f, 0)?;
    let preparing = f.state.join("review-handoff-preparing.json");
    let original = fs::read(&preparing)?;
    let intent = read_json(&preparing)?;
    for path in [&f.old.config, &f.old.review.root.path().join("host.json")] {
        let mut value = read_json(path)?;
        if value["connector"].is_object() {
            value["connector"]["generation"] = json!(2);
        } else {
            value["generation"] = json!(2);
        }
        put(path, &value)?;
    }
    assert!(f.handoff().is_err());
    assert!(tangled_review::rebind_credentials(&f.state, &f.old.config).is_err());
    tangled_review::rebind_credentials(&f.old.review.state(), &f.old.config)?;
    let before = f.old.review.data.lock().unwrap()["writes"].clone();
    f.handoff()?;
    assert_eq!(fs::read(preparing)?, original);
    assert_eq!(read_json(&f.state.join("review.json"))?, intent["receipt"]);
    assert_eq!(
        read_json(&f.old.review.state().join("review-handoff-outgoing.json"))?,
        intent
    );
    assert_eq!(f.old.review.data.lock().unwrap()["writes"], before);
    assert!(f.resubmit().is_err());
    tangled_review::rebind_credentials(&f.state, &f.old.config)?;
    f.resubmit()?;
    let newer = fs::read(f.state.join("review.json"))?;
    f.handoff()?;
    assert_eq!(fs::read(f.state.join("review.json"))?, newer);
    Ok(())
}
