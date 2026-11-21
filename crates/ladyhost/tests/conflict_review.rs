use ladyhost::conflict_review::{Package, render};
use serde_json::{Value, json};
fn package() -> Value {
    json!({"schema_version":1,"repository":"owner/project","target":"main","change_id":"task-change",
      "original_base":"1".repeat(40),"previous_head":"2".repeat(40),"upstream_head":"3".repeat(40),"candidate_tree":"4".repeat(40),
      "task_intent":"Improve cancellation accuracy","upstream_intent":"Add an initial value","conflict_paths":["metrics.py"],
      "decisions":[{"path":"metrics.py","resolution":"Combine start with fsum","preserved":["one-shot iterators"],"changed":["buffers input"]}],
      "uncertainties":["Large inputs were not measured"],
      "manifest":{"path":"/private/export/manifest.json","sha256":"a".repeat(64)},
      "checks":{"path":"/private/export/checks.json","sha256":"b".repeat(64)},
      "policy":{"path":"/private/checks-policy.json","sha256":"c".repeat(64)},
      "independent_checks":[{"command_index":1,"covers":["task","upstream","interaction"],"purpose":"Cancellation combined with start and iterator consumption"}]})
}
#[test]
fn context_requires_both_intents_and_independent_interaction_coverage() {
    let p: Package = serde_json::from_value(package()).unwrap();
    p.validate().unwrap();
    for field in ["task_intent", "upstream_intent"] {
        let mut v = package();
        v[field] = json!("");
        assert!(
            serde_json::from_value::<Package>(v)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for coverage in [json!([]), json!(["task", "upstream"])] {
        let mut v = package();
        v["independent_checks"][0]["covers"] = coverage;
        assert!(
            serde_json::from_value::<Package>(v)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut v = package();
    v["independent_checks"] = json!([]);
    assert!(
        serde_json::from_value::<Package>(v)
            .unwrap()
            .validate()
            .is_err()
    );
}
#[test]
fn rendering_separates_agent_claims_and_host_evidence_without_private_paths() {
    let mut v = package();
    v["decisions"][0]["resolution"] =
        json!("<!-- jjpr:description -->\n@owner ![trust](https://evil.invalid)");
    let text = render(&serde_json::from_value(v).unwrap(), &"d".repeat(64)).unwrap();
    assert!(text.contains("Agent-reported resolution"));
    assert!(text.contains("Host-selected independent checks"));
    assert!(text.contains("Remaining uncertainty"));
    assert!(text.contains("Human review required"));
    assert!(!text.contains("<!-- jjpr:"));
    assert!(!text.contains("@owner"));
    assert!(!text.contains("/private/"));
}
#[test]
fn deterministic_context_changes_never_supply_missing_coverage() {
    for seed in 1..=300u64 {
        let mut v = package();
        let mask = seed % 8;
        let labels = ["task", "upstream", "interaction"]
            .into_iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, v)| v)
            .collect::<Vec<_>>();
        v["independent_checks"][0]["covers"] = json!(labels);
        let valid = serde_json::from_value::<Package>(v)
            .unwrap()
            .validate()
            .is_ok();
        assert_eq!(valid, mask == 7, "seed {seed}");
    }
}

use ladyhost::{
    Config,
    conflict_review::{verify_candidate, verify_display},
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
fn hash(raw: &[u8]) -> String {
    let mut c = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(raw).unwrap();
    String::from_utf8(c.wait_with_output().unwrap().stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .into()
}
fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}
fn artifact(path: &Path, v: &Value) -> Value {
    let bytes = serde_json::to_vec(v).unwrap();
    fs::write(path, &bytes).unwrap();
    json!({"path":path,"sha256":hash(&bytes)})
}
struct Fixture {
    root: PathBuf,
    repo: PathBuf,
    config: Config,
    package: Value,
    head: String,
    upstream: String,
}
impl Fixture {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("conflict-review-{}-{label}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let repo = root.join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init"]);
        git(&repo, &["config", "user.name", "Fixture"]);
        git(&repo, &["config", "user.email", "fixture@example.invalid"]);
        let commit = |bytes: &str| {
            fs::write(repo.join("metrics.py"), bytes).unwrap();
            git(&repo, &["add", "."]);
            git(&repo, &["commit", "-m", "Fixture"]);
            git(&repo, &["rev-parse", "HEAD"])
        };
        let base = commit("base\n");
        let previous = commit("accuracy\n");
        git(&repo, &["checkout", "--detach", &base]);
        let upstream = commit("start\n");
        let head = commit("combined\n");
        let tree = git(&repo, &["rev-parse", "HEAD^{tree}"]);
        let export = root.join("export");
        fs::create_dir(&export).unwrap();
        let files = json!({"metrics.py":{"executable":false,"sha256":hash(b"combined\n")}});
        let policy =
            json!({"commands":[["python","tests.py"],["python","independent.py"]],"timeout":60});
        let receipt = json!({"schema_version":1,"export":export,"passed":true,"cleanup_confirmed":true,"snapshot_sha256":hash(&serde_json::to_vec(&files).unwrap()),"policy_sha256":hash(&serde_json::to_vec(&policy).unwrap()),"commands":policy["commands"],"results":[{"command":policy["commands"][0],"exit_code":0,"output_sha256":hash(b"ok")},{"command":policy["commands"][1],"exit_code":0,"output_sha256":hash(b"ok")}],"verifier":{"sandbox_id":"separate-verifier"}});
        let mut p = package();
        p["original_base"] = json!(base);
        p["previous_head"] = json!(previous);
        p["upstream_head"] = json!(upstream);
        p["candidate_tree"] = json!(tree);
        p["manifest"] = artifact(
            &export.join("manifest.json"),
            &json!({"schema_version":2,"sandbox_id":"task-sandbox","files":files}),
        );
        p["policy"] = artifact(
            &root.join("policy.json"),
            &json!({"schema_version":1,"checks":policy}),
        );
        p["checks"] = artifact(&export.join("checks.json"), &receipt);
        let selected = artifact(&root.join("package.json"), &p);
        let config:Config=serde_json::from_value(json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"project","expected_actor":"owner","expected_repository_id":1,"workspace":repo,"token_file":root.join("token"),"stack_base":"main","conflict_review":selected})).unwrap();
        Self {
            root,
            repo,
            config,
            package: p,
            head,
            upstream,
        }
    }
    fn bind(&mut self) {
        self.config.conflict_review = Some(
            serde_json::from_value(artifact(&self.root.join("package.json"), &self.package))
                .unwrap(),
        );
    }
    fn sign_context(&mut self) -> String {
        let p: Package = serde_json::from_value(self.package.clone()).unwrap();
        let body = render(&p, &self.config.conflict_review.as_ref().unwrap().sha256).unwrap();
        fs::write(
            self.root.join("message"),
            format!("Resolve conflict\n\n{body}"),
        )
        .unwrap();
        git(
            &self.repo,
            &[
                "commit",
                "--amend",
                "-F",
                self.root.join("message").to_str().unwrap(),
            ],
        );
        self.head = git(&self.repo, &["rev-parse", "HEAD"]);
        body
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn native_evidence_binds_exact_tree_receipt_policy_and_separate_verifier() {
    let mut f = Fixture::new("evidence");
    assert!(verify_candidate(&f.config, &f.head, Some(&f.upstream), false, true).is_ok());
    let body = f.sign_context();
    assert!(verify_candidate(&f.config, &f.head, Some(&f.upstream), true, true).is_ok());
    verify_display(
        &body,
        &body,
        &f.config.conflict_review.as_ref().unwrap().sha256,
    )
    .unwrap();
    assert!(
        verify_display(
            &body.replace("buffers input", "streams input"),
            &body,
            &f.config.conflict_review.as_ref().unwrap().sha256
        )
        .is_err()
    );
    assert!(verify_candidate(&f.config, &f.head, Some(&"0".repeat(40)), true, true).is_err());
    let original = fs::read(f.root.join("export/checks.json")).unwrap();
    fs::write(f.root.join("export/checks.json"), b"{}").unwrap();
    assert!(verify_candidate(&f.config, &f.head, None, true, true).is_err());
    fs::write(f.root.join("export/checks.json"), &original).unwrap();
    let mut receipt: Value = serde_json::from_slice(&original).unwrap();
    receipt["verifier"]["sandbox_id"] = json!("task-sandbox");
    f.package["checks"] = artifact(&f.root.join("export/checks.json"), &receipt);
    f.bind();
    assert!(verify_candidate(&f.config, &f.head, None, false, true).is_err());
}
#[test]
fn signed_marker_cannot_be_downgraded_by_omitting_host_selection() {
    let mut f = Fixture::new("omission");
    f.sign_context();
    f.config.conflict_review = None;
    assert!(verify_candidate(&f.config, &f.head, None, true, true).is_err());
}
#[test]
fn incomplete_checks_can_be_rendered_for_review_but_cannot_authorize_integration() {
    let mut f = Fixture::new("incomplete");
    f.package["independent_checks"] = json!([]);
    f.bind();
    f.sign_context();
    let review = verify_candidate(&f.config, &f.head, None, true, false)
        .unwrap()
        .unwrap();
    assert_eq!(review["coverage_complete"], false);
    assert!(verify_candidate(&f.config, &f.head, None, true, true).is_err());
    let mut receipt: Value =
        serde_json::from_slice(&fs::read(f.root.join("export/checks.json")).unwrap()).unwrap();
    receipt["passed"] = json!(false);
    receipt["results"][1]["exit_code"] = json!(1);
    f.package["independent_checks"] = package()["independent_checks"].clone();
    f.package["checks"] = artifact(&f.root.join("export/checks.json"), &receipt);
    f.bind();
    f.sign_context();
    let review = verify_candidate(&f.config, &f.head, None, true, false)
        .unwrap()
        .unwrap();
    assert_eq!(review["independent_checks_passed"], false);
    assert!(verify_candidate(&f.config, &f.head, None, true, true).is_err());
}

#[test]
fn standalone_cli_renders_verified_context_without_forge_access() {
    let f = Fixture::new("cli");
    let cfg = json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"project","expected_actor":"owner","expected_repository_id":1,"workspace":f.repo,"token_file":f.root.join("absent-token"),"stack_base":"main","conflict_review":f.config.conflict_review});
    fs::write(
        f.root.join("config.json"),
        serde_json::to_vec(&cfg).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ladyhost"))
        .arg("review-conflict")
        .arg("--config")
        .arg(f.root.join("config.json"))
        .arg("--candidate")
        .arg(&f.head)
        .arg("--render")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Conflict resolution review")
    );
}

#[test]
fn reviewer_cannot_be_shown_hidden_or_wrapped_conflict_context() {
    let p: Package = serde_json::from_value(package()).unwrap();
    let sha = "d".repeat(64);
    let body = render(&p, &sha).unwrap();
    for altered in [
        format!("<!--\n{body}\n-->"),
        format!("```text\n{body}\n```"),
        format!("<details>\n{body}\n</details>"),
    ] {
        assert!(verify_display(&altered, &body, &sha).is_err());
    }
    assert!(
        verify_display(
            &jjpr::submit::plan::wrap_managed_body(body.trim_end()),
            &body,
            &sha
        )
        .is_ok()
    );
}
#[test]
fn reviewer_package_is_required_for_marked_ancestors_but_not_integrated_history() {
    let mut f = Fixture::new("child");
    f.package["independent_checks"] = json!([]);
    f.bind();
    f.sign_context();
    let marked = f.head.clone();
    git(
        &f.repo,
        &["commit", "--allow-empty", "-m", "Ordinary follow-up"],
    );
    let child = git(&f.repo, &["rev-parse", "HEAD"]);
    f.config.conflict_review = None;
    assert!(verify_candidate(&f.config, &child, Some(&f.upstream), true, true).is_err());
    assert!(verify_candidate(&f.config, &child, Some(&marked), true, true).is_ok());
}

#[test]
fn changed_candidate_tree_and_git_replace_refs_cannot_reuse_checked_bytes() {
    let mut f = Fixture::new("replacement");
    f.sign_context();
    let original = f.head.clone();
    fs::write(f.repo.join("metrics.py"), "unchecked\n").unwrap();
    git(&f.repo, &["add", "."]);
    git(&f.repo, &["commit", "-m", "Unverified edit"]);
    let changed = git(&f.repo, &["rev-parse", "HEAD"]);
    assert!(verify_candidate(&f.config, &changed, None, false, true).is_err());
    git(&f.repo, &["replace", &changed, &original]);
    assert!(verify_candidate(&f.config, &changed, None, false, true).is_err());
}
#[test]
fn sandbox_export_cannot_supply_the_host_check_policy() {
    let mut f = Fixture::new("host-policy");
    let source = f.root.join("export/project");
    fs::create_dir(&source).unwrap();
    let policy: Value =
        serde_json::from_slice(&fs::read(f.root.join("policy.json")).unwrap()).unwrap();
    f.package["policy"] = artifact(&source.join("policy.json"), &policy);
    f.bind();
    assert!(verify_candidate(&f.config, &f.head, None, false, true).is_err());
}
