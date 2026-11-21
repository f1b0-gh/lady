use effects::{BookmarkBinding, Journal, Scope};
use ladyhost::effects;
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn directory() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "jjpr-effects-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn scope() -> Scope {
    Scope {
        task: "task-a".into(),
        actor: "worker".into(),
        owner: "owner".into(),
        repository: "repo".into(),
        remote_url: "http://127.0.0.1:34080/owner/repo.git".into(),
        bookmarks: BTreeMap::from([(
            "task-a-parent".into(),
            BookmarkBinding {
                change_id: "change-a".into(),
                oid: "a".repeat(40),
                expected_remote: None,
            },
        )]),
        bases: BTreeMap::from([("main".into(), "b".repeat(40))]),
        reviewers: vec!["reviewer".into()],
        prs: BTreeMap::new(),
        comments: BTreeMap::new(),
    }
}
#[test]
fn scope_refuses_other_repo_branch_and_changed_objects() {
    let s = scope();
    s.validate().unwrap();
    assert!(s.repository("owner", "repo").is_ok());
    assert!(s.repository("owner", "other").is_err());
    assert!(
        s.bookmark("task-a-parent", "change-a", &"a".repeat(40))
            .is_ok()
    );
    assert!(
        s.bookmark("task-a-parent", "change-a", &"c".repeat(40))
            .is_err()
    );
    assert!(s.bookmark("main", "change-a", &"a".repeat(40)).is_err());
}
#[test]
fn uncertain_outcome_blocks_further_effects_and_reopen() {
    let dir = directory();
    let j = Journal::create(&dir, &scope()).unwrap();
    let mut calls = 0;
    let failure: anyhow::Result<()> = j.perform(
        "push",
        json!({"oid":"a".repeat(40)}),
        || {
            calls += 1;
            anyhow::bail!("lost reply")
        },
        |_| json!(null),
    );
    assert!(failure.is_err());
    let retry: anyhow::Result<()> = j.perform(
        "push",
        json!({}),
        || {
            calls += 1;
            Ok(())
        },
        |_| json!(null),
    );
    assert!(retry.is_err());
    assert_eq!(calls, 1);
    assert!(dir.join("000000.intent.json").exists());
    assert!(!dir.join("000000.ok.json").exists());
    assert!(Journal::create(&dir, &scope()).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn journal_intent_precedes_effect_and_records_receipt() {
    let dir = directory();
    let j = Journal::create(&dir, &scope()).unwrap();
    let number = j
        .perform(
            "create_pr",
            json!({"head":"task-a-parent"}),
            || {
                let intent: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(dir.join("000000.intent.json"))?)
                        .unwrap();
                assert_eq!(intent["scope"]["task"], "task-a");
                Ok(7_u64)
            },
            |n| json!({"pr":n}),
        )
        .unwrap();
    assert_eq!(number, 7);
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("000000.ok.json")).unwrap()).unwrap();
    assert_eq!(receipt["result"]["pr"], 7);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn exhaustive_crash_traces_match_independent_terminal_model() {
    // 3^4 complete schedules: acknowledgement, lost provider reply, or failed
    // local receipt write. Reference is the first non-acknowledged position.
    for seed in 0..81_u32 {
        let mut digits = seed;
        let mut schedule = Vec::new();
        for _ in 0..4 {
            schedule.push(digits % 3);
            digits /= 3;
        }
        let stop = schedule.iter().position(|x| *x != 0);
        let dir = directory();
        let j = Journal::create(&dir, &scope()).unwrap();
        let mut actual_calls = 0;
        for (index, fault) in schedule.iter().enumerate() {
            if *fault == 2 && stop.is_none_or(|n| index <= n) {
                std::fs::write(
                    dir.join(format!("{index:06}.ok.json")),
                    b"injected storage failure",
                )
                .unwrap();
            }
            let result = j.perform(
                "publish",
                json!({"revision":index}),
                || {
                    actual_calls += 1;
                    if *fault == 1 {
                        anyhow::bail!("accepted remotely; reply lost");
                    }
                    Ok(())
                },
                |_| json!(null),
            );
            let expected_ok = stop.is_none_or(|n| index < n);
            assert_eq!(result.is_ok(), expected_ok, "seed={seed}, step={index}");
            let expected_calls = stop.map_or(index + 1, |n| (index + 1).min(n + 1));
            assert_eq!(actual_calls, expected_calls, "seed={seed}, step={index}");
        }
        assert!(Journal::create(&dir, &scope()).is_err(), "seed={seed}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

use jjpr::{forge::*, jj::*};
use std::sync::Mutex;
struct Fake {
    bookmarks: Mutex<Vec<Bookmark>>,
    heads: Mutex<BTreeMap<String, String>>,
    calls: AtomicU64,
    pr: Mutex<Option<PullRequest>>,
    resolved: Mutex<Vec<String>>,
}
impl Fake {
    fn new() -> Self {
        Self {
            bookmarks: Mutex::new(vec![Bookmark {
                name: "task-a-parent".into(),
                change_id: "change-a".into(),
                commit_id: "a".repeat(40),
                has_remote: false,
                is_synced: false,
            }]),
            heads: Mutex::new(BTreeMap::from([("main".into(), "b".repeat(40))])),
            calls: AtomicU64::new(0),
            pr: Mutex::new(None),
            resolved: Mutex::new(vec!["a".repeat(40)]),
        }
    }
}
impl Jj for Fake {
    fn git_fetch(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn get_my_bookmarks(&self) -> anyhow::Result<Vec<Bookmark>> {
        Ok(self.bookmarks.lock().unwrap().clone())
    }
    fn get_changes_to_commit(&self, _c: &str) -> anyhow::Result<Vec<LogEntry>> {
        Ok(vec![])
    }
    fn get_git_remotes(&self) -> anyhow::Result<Vec<GitRemote>> {
        Ok(vec![GitRemote {
            name: "origin".into(),
            url: scope().remote_url,
        }])
    }
    fn get_default_branch(&self) -> anyhow::Result<String> {
        Ok("main".into())
    }
    fn push_bookmark(&self, name: &str, _remote: &str) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.heads
            .lock()
            .unwrap()
            .insert(name.into(), "a".repeat(40));
        Ok(())
    }
    fn get_working_copy_commit_id(&self) -> anyhow::Result<String> {
        Ok("a".repeat(40))
    }
    fn rebase_onto(&self, _s: &str, _d: &str) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn merge_into(&self, _b: &str, _d: &str) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn resolve_change_id(&self, _c: &str) -> anyhow::Result<Vec<String>> {
        Ok(self.resolved.lock().unwrap().clone())
    }
    fn is_conflicted(&self, _r: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
}
impl Forge for Fake {
    fn list_open_prs(&self, _o: &str, _r: &str) -> anyhow::Result<Vec<PullRequest>> {
        Ok(vec![])
    }
    fn create_pr(
        &self,
        _o: &str,
        _r: &str,
        _t: &str,
        _b: &str,
        _h: &str,
        _base: &str,
        _d: bool,
    ) -> anyhow::Result<PullRequest> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("not configured")
    }
    fn update_pr_base(&self, _o: &str, _r: &str, _n: u64, _base: &str) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn request_reviewers(
        &self,
        _o: &str,
        _r: &str,
        _n: u64,
        _who: &[String],
    ) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn list_comments(&self, _o: &str, _r: &str, _n: u64) -> anyhow::Result<Vec<IssueComment>> {
        Ok(vec![])
    }
    fn create_comment(
        &self,
        _o: &str,
        _r: &str,
        _n: u64,
        _b: &str,
    ) -> anyhow::Result<IssueComment> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(IssueComment { id: 1, body: None })
    }
    fn update_comment(&self, _o: &str, _r: &str, _id: u64, _b: &str) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn delete_comment(&self, _o: &str, _r: &str, _id: u64) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn update_pr_body(&self, _o: &str, _r: &str, _n: u64, _b: &str) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn mark_pr_ready(&self, _o: &str, _r: &str, _n: u64) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn get_authenticated_user(&self) -> anyhow::Result<String> {
        Ok("worker".into())
    }
    fn find_merged_pr(&self, _o: &str, _r: &str, _h: &str) -> anyhow::Result<Option<PullRequest>> {
        Ok(None)
    }
    fn merge_pr(&self, _o: &str, _r: &str, _n: u64, _m: MergeMethod) -> anyhow::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn get_pr_checks_status(&self, _o: &str, _r: &str, _h: &str) -> anyhow::Result<ChecksStatus> {
        anyhow::bail!("not configured")
    }
    fn get_pr_reviews(&self, _o: &str, _r: &str, _n: u64) -> anyhow::Result<ReviewSummary> {
        anyhow::bail!("not configured")
    }
    fn get_pr_mergeability(&self, _o: &str, _r: &str, _n: u64) -> anyhow::Result<PrMergeability> {
        anyhow::bail!("not configured")
    }
    fn get_pr(&self, _o: &str, _r: &str, _n: u64) -> anyhow::Result<(PullRequest, PrState)> {
        Ok((
            self.pr
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no PR"))?,
            PrState {
                merged: false,
                state: "open".into(),
            },
        ))
    }
    fn get_pr_state(&self, _o: &str, _r: &str, _n: u64) -> anyhow::Result<PrState> {
        anyhow::bail!("not configured")
    }
    fn get_branch_head(&self, _o: &str, _r: &str, b: &str) -> anyhow::Result<Option<String>> {
        Ok(self.heads.lock().unwrap().get(b).cloned())
    }
}
#[test]
fn wrapper_refuses_changed_sources_remote_heads_and_alternate_writes() {
    let fake = Fake::new();
    let dir = directory();
    let session = effects::Session::create(scope(), &dir, &fake, &fake).unwrap();
    fake.bookmarks.lock().unwrap()[0].commit_id = "c".repeat(40);
    assert!(session.push_bookmark("task-a-parent", "origin").is_err());
    fake.bookmarks.lock().unwrap()[0].commit_id = "a".repeat(40);
    fake.heads
        .lock()
        .unwrap()
        .insert("task-a-parent".into(), "d".repeat(40));
    assert!(session.push_bookmark("task-a-parent", "origin").is_err());
    assert!(session.push_bookmark("main", "origin").is_err());
    assert!(
        session
            .merge_pr("owner", "repo", 1, MergeMethod::Merge)
            .is_err()
    );
    assert!(session.close_pr("owner", "repo", 1).is_err());
    assert!(
        session
            .update_comment("owner", "repo", 1, "unowned")
            .is_err()
    );
    assert!(session.rebase_onto("@", "main").is_err());
    assert!(session.restore_operation("old").is_err());
    assert!(session.snapshot().is_err());
    assert_eq!(fake.calls.load(Ordering::Relaxed), 0);
    assert!(session.ensure_complete().is_err());
    fake.heads.lock().unwrap().remove("task-a-parent");
    let second = directory();
    let session = effects::Session::create(scope(), &second, &fake, &fake).unwrap();
    session.push_bookmark("task-a-parent", "origin").unwrap();
    assert_eq!(fake.calls.load(Ordering::Relaxed), 1);
    session.ensure_complete().unwrap();
    assert!(session.push_bookmark("task-a-parent", "origin").is_err());
    assert_eq!(fake.calls.load(Ordering::Relaxed), 1);
    std::fs::remove_dir_all(second).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

fn owned_pr() -> PullRequest {
    serde_json::from_value(json!({"number":7,"html_url":"https://github.com/owner/repo/pull/7","title":"task","body":"planned body","head":{"ref":"task-a-parent","sha":"a".repeat(40),"label":"owner:task-a-parent"},"base":{"ref":"main","sha":"b".repeat(40),"label":"owner:main"},"user":{"login":"worker"}})).unwrap()
}
#[test]
fn stale_body_and_retarget_refused_before_effect() {
    for changed in ["body", "base"] {
        let fake = Fake::new();
        let mut bound = scope();
        let mut pr = owned_pr();
        bound.prs.insert(
            7,
            effects::PrBinding {
                head: "task-a-parent".into(),
                base: "main".into(),
                body: Some("planned body".into()),
            },
        );
        bound.bases.insert("other".into(), "c".repeat(40));
        fake.heads
            .lock()
            .unwrap()
            .insert("other".into(), "c".repeat(40));
        if changed == "body" {
            pr.body = Some("human edit".into());
        } else {
            pr.base.ref_name = "other".into();
        }
        *fake.pr.lock().unwrap() = Some(pr);
        let dir = directory();
        let session = effects::Session::create(bound, &dir, &fake, &fake).unwrap();
        assert!(
            session
                .update_pr_body("owner", "repo", 7, "planned replacement")
                .is_err(),
            "{changed}"
        );
        assert!(session.ensure_complete().is_err(), "{changed}");
        assert_eq!(fake.calls.load(Ordering::Relaxed), 0);
        assert!(!dir.join("000000.intent.json").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn swallowed_comment_refusal_still_fails_session_completion() {
    let fake = Fake::new();
    let dir = directory();
    let session = effects::Session::create(scope(), &dir, &fake, &fake).unwrap();
    // Model upstream's warning-only handling of stack navigation errors.
    let _ignored = session.create_comment("owner", "repo", 999, "navigation");
    assert!(session.ensure_complete().is_err());
    assert_eq!(fake.calls.load(Ordering::Relaxed), 0);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn full_oid_resolution_rejects_ambiguity_mismatch_and_malformed_results() {
    let fake = Fake::new();
    let mut bookmark = fake.get_my_bookmarks().unwrap().remove(0);
    bookmark.commit_id = "a".repeat(12);
    assert_eq!(
        effects::resolve_bookmark_oid(&fake, &bookmark).unwrap(),
        "a".repeat(40)
    );
    for resolved in [
        vec![],
        vec!["a".repeat(40), format!("{}b", "a".repeat(39))],
        vec!["b".repeat(40)],
        vec!["a".repeat(12)],
        vec!["x".repeat(40)],
    ] {
        *fake.resolved.lock().unwrap() = resolved;
        assert!(effects::resolve_bookmark_oid(&fake, &bookmark).is_err());
    }
    *fake.resolved.lock().unwrap() = vec!["a".repeat(40)];
    for display in [
        String::new(),
        "a".into(),
        "z".repeat(12),
        format!("{}b", "a".repeat(39)),
    ] {
        bookmark.commit_id = display;
        assert!(effects::resolve_bookmark_oid(&fake, &bookmark).is_err());
    }
}
#[test]
fn abbreviated_bookmark_dispatch_still_records_exact_full_object() {
    let fake = Fake::new();
    fake.bookmarks.lock().unwrap()[0].commit_id = "a".repeat(12);
    let dir = directory();
    let session = effects::Session::create(scope(), &dir, &fake, &fake).unwrap();
    session.push_bookmark("task-a-parent", "origin").unwrap();
    session.ensure_complete().unwrap();
    let intent: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("000000.intent.json")).unwrap()).unwrap();
    assert_eq!(intent["payload"]["oid"], "a".repeat(40));
    std::fs::remove_dir_all(dir).unwrap();
}
