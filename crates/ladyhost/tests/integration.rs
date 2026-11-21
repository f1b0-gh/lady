use ladyhost::{Config, integration::IntegrationRequest};
use serde_json::json;

fn config() -> Config {
    serde_json::from_value(json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"repo","workspace":"/tmp/integration-project","stack_base":"app-experiment-base","expected_actor":"publisher[bot]","expected_repository_id":42,"github_app":{"app_id":123,"installation_id":456,"slug":"publisher","private_key":"/tmp/host/key.pem","openssl":"/usr/bin/openssl"}})).unwrap()
}
fn request() -> IntegrationRequest {
    serde_json::from_value(json!({"task":"integrate-parent","pr_number":7,"source":"parent","target":"app-experiment-base","expected_head":"a".repeat(40),"expected_target":"b".repeat(40),"reviewer":{"id":888,"login":"reviewer"},"update_ruleset_id":101,"quality_ruleset_id":102,"allowed_signers":"/tmp/host/allowed_signers","receipt_dir":"/tmp/host/integration-receipt"})).unwrap()
}
#[test]
fn request_refuses_mutable_revisions_and_unselected_target() {
    request().validate(&config()).unwrap();
    let mut r = request();
    r.expected_head = "HEAD".into();
    assert!(r.validate(&config()).is_err());
    let mut r = request();
    r.target = "main".into();
    assert!(r.validate(&config()).is_err());
    let mut r = request();
    r.allowed_signers = "/tmp/integration-project/trust".into();
    assert!(r.validate(&config()).is_err());
}

use anyhow::{Result, bail};
use ladyhost::{
    app::{AppApi, Clock},
    integration::{IntegrationGit, inspect, integrate},
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixed;
impl Clock for Fixed {
    fn now(&self) -> Result<u64> {
        Ok(1234567890)
    }
}
#[derive(Default)]
struct Git {
    verify_calls: usize,
    push_calls: usize,
    fail_verify: bool,
    lose_reply: bool,
    reject: bool,
}
impl IntegrationGit for Git {
    fn verify(&mut self, _: &Config, _: &IntegrationRequest) -> Result<()> {
        self.verify_calls += 1;
        if self.fail_verify {
            bail!("signature or ancestry invalid");
        }
        Ok(())
    }
    fn push(&mut self, _: &Config, _: &IntegrationRequest) -> Result<()> {
        self.push_calls += 1;
        if self.reject {
            return Err(ladyhost::integration::PushRefusal::LocalRejection.into());
        }
        if self.lose_reply {
            bail!("lost reply after server accepted push");
        }
        Ok(())
    }
}
struct Api {
    replies: VecDeque<Value>,
    calls: Vec<String>,
}
impl Api {
    fn new(values: Vec<Value>) -> Self {
        Self {
            replies: values.into(),
            calls: vec![],
        }
    }
}
impl AppApi for Api {
    fn get(&mut self, path: &str) -> Result<Value> {
        assert_ne!(path, "/user");
        self.calls.push(path.into());
        self.replies
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("missing native observation"))
    }
    fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
        panic!("integration must not use provider mutations")
    }
}
fn native_ref(branch: &str, oid: &str) -> Value {
    json!({"ref":format!("refs/heads/{branch}"),"object":{"type":"commit","sha":oid}})
}
fn observations() -> Vec<Value> {
    let r = request();
    let mut update = json!({"id":101,"target":"branch","source_type":"Repository","source":"owner/repo","enforcement":"active","conditions":{"ref_name":{"include":["refs/heads/app-experiment-base"],"exclude":[]}},"bypass_actors":[{"actor_id":123,"actor_type":"Integration","bypass_mode":"always"}],"rules":[{"type":"update","parameters":{"update_allows_fetch_and_merge":false}}]});
    update["source_id"] = json!(42);
    let quality = json!({"id":102,"target":"branch","source_type":"Repository","source":"owner/repo","enforcement":"active","conditions":{"ref_name":{"include":["refs/heads/app-experiment-base"],"exclude":[]}},"bypass_actors":[],"rules":[
        {"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,"require_code_owner_review":false,"require_last_push_approval":false,"required_review_thread_resolution":true}},
        {"type":"required_signatures"},{"type":"required_linear_history"},{"type":"deletion"},{"type":"non_fast_forward"},
        {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,"do_not_enforce_on_create":false,"required_status_checks":[{"context":"fixture/verify","integration_id":123}]}}
    ]});
    let mut effective = vec![];
    for p in [&update, &quality] {
        for rule in p["rules"].as_array().unwrap() {
            let mut rule = rule.clone();
            rule["ruleset_id"] = p["id"].clone();
            rule["ruleset_source_type"] = json!("Repository");
            rule["ruleset_source"] = json!("owner/repo");
            effective.push(rule);
        }
    }
    vec![
        json!({"id":42,"full_name":"owner/repo","private":true}),
        json!({"id":777,"login":"publisher[bot]","type":"Bot"}),
        json!({"number":7,"state":"open","draft":false,"merged":false,"user":{"id":777,"login":"publisher[bot]","type":"Bot"},"head":{"ref":"parent","sha":r.expected_head,"repo":{"id":42}},"base":{"ref":"app-experiment-base","sha":r.expected_target,"repo":{"id":42}}}),
        native_ref(&r.source, &r.expected_head),
        native_ref(&r.target, &r.expected_target),
        update,
        quality,
        json!(effective),
        json!([{"id":900,"user":{"id":888,"login":"reviewer"},"state":"APPROVED","commit_id":r.expected_head,"submitted_at":"2026-11-06T00:00:00Z"}]),
        json!({"sha":r.expected_head,"total_count":1,"statuses":[{"id":901,"context":"fixture/verify","state":"success"}]}),
        json!([{"id":901,"context":"fixture/verify","state":"success","creator":{"id":777,"login":"publisher[bot]","type":"Bot"}}]),
    ]
}
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "jjpr-integration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn request(&self) -> IntegrationRequest {
        let mut r = request();
        r.receipt_dir = self.0.join("receipt");
        r
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn exact_native_observation_is_read_only_and_uses_no_user_token_identity() {
    let mut api = Api::new(observations());
    let observed = inspect(&config(), &request(), &mut api, &mut Git::default(), &Fixed).unwrap();
    assert_eq!(
        observed.evidence["review"]["commit_id"],
        request().expected_head
    );
    assert_eq!(observed.evidence["status"]["sha"], request().expected_head);
    assert_eq!(api.calls.len(), 11);
    assert!(api.replies.is_empty());
}

#[test]
fn rewritten_provider_review_does_not_replace_a_new_human_submission() {
    let temp = Temp::new();
    let mut r = temp.request();
    r.superseded_review_ids = vec![900];
    // GitHub can attach the same ID/time to the new head. Exact commit_id alone
    // must not qualify an earlier approval as a new review of this revision.
    assert!(
        inspect(
            &config(),
            &r,
            &mut Api::new(observations()),
            &mut Git::default(),
            &Fixed
        )
        .is_err()
    );
    let mut git = Git::default();
    assert!(
        integrate(
            &config(),
            &r,
            &mut Api::new(observations()),
            &mut git,
            &Fixed
        )
        .is_err()
    );
    assert_eq!(git.push_calls, 0);
    assert!(!r.receipt_dir.exists());
    let mut fresh = observations();
    let mut approval = fresh[8][0].clone();
    approval["id"] = json!(902);
    approval["submitted_at"] = json!("2026-11-06T01:00:00Z");
    fresh[8].as_array_mut().unwrap().push(approval);
    let value = inspect(
        &config(),
        &r,
        &mut Api::new(fresh),
        &mut Git::default(),
        &Fixed,
    )
    .unwrap();
    assert_eq!(value.evidence["review"]["id"], 902);
    for ids in [vec![0], vec![900, 900], (1..=1001).collect()] {
        r.superseded_review_ids = ids;
        assert!(r.validate(&config()).is_err());
    }
}
#[test]
fn native_refusal_matrix_does_not_dispatch() {
    // Each case changes one independently required native fact. This finite
    // reference model admits exactly the unmodified row, not weakened evidence.
    let cases: Vec<(usize, &str, Value)> = vec![
        (0, "/id", json!(43)),
        (0, "/private", json!(false)),
        (1, "/type", json!("User")),
        (2, "/state", json!("closed")),
        (2, "/draft", json!(true)),
        (2, "/merged", json!(true)),
        (2, "/user/id", json!(999)),
        (2, "/head/repo/id", json!(43)),
        (2, "/base/repo/id", json!(43)),
        (2, "/head/ref", json!("other")),
        (2, "/head/sha", json!("c".repeat(40))),
        (2, "/base/ref", json!("main")),
        (3, "/object/sha", json!("c".repeat(40))),
        (4, "/object/sha", json!("c".repeat(40))),
        (5, "/id", json!(999)),
        (5, "/enforcement", json!("disabled")),
        (5, "/source_id", json!(43)),
        (5, "/conditions/ref_name/include", json!(["~ALL"])),
        (5, "/bypass_actors/0/actor_id", json!(999)),
        (
            5,
            "/rules/0/parameters/update_allows_fetch_and_merge",
            json!(true),
        ),
        (
            6,
            "/bypass_actors",
            json!([{"actor_id":123,"actor_type":"Integration","bypass_mode":"always"}]),
        ),
        (
            6,
            "/rules/0/parameters/required_approving_review_count",
            json!(0),
        ),
        (
            6,
            "/rules/0/parameters/dismiss_stale_reviews_on_push",
            json!(false),
        ),
        (
            6,
            "/rules/0/parameters/required_review_thread_resolution",
            json!(false),
        ),
        (
            6,
            "/rules/5/parameters/required_status_checks/0/integration_id",
            json!(999),
        ),
        (
            6,
            "/rules/5/parameters/strict_required_status_checks_policy",
            json!(false),
        ),
        (
            6,
            "/rules/5/parameters/do_not_enforce_on_create",
            json!(true),
        ),
        (
            6,
            "/rules/0/parameters/require_last_push_approval",
            json!(true),
        ),
        (7, "/0/ruleset_id", json!(999)),
        (7, "/0/ruleset_source", json!("owner/other")),
        (8, "/0/user/id", json!(999)),
        (8, "/0/user/login", json!("impostor")),
        (8, "/0/commit_id", json!("c".repeat(40))),
        (8, "/0/state", json!("DISMISSED")),
        (9, "/sha", json!("c".repeat(40))),
        (9, "/total_count", json!(101)),
        (9, "/statuses/0/state", json!("failure")),
        (10, "/0/creator/id", json!(999)),
        (10, "/0/creator/login", json!("other[bot]")),
        (10, "/0/creator/type", json!("User")),
    ];
    for (seed, (index, pointer, replacement)) in cases.into_iter().enumerate() {
        let mut rows = observations();
        *rows[index].pointer_mut(pointer).unwrap() = replacement;
        let mut git = Git::default();
        assert!(
            inspect(&config(), &request(), &mut Api::new(rows), &mut git, &Fixed).is_err(),
            "seed={seed}, {pointer}"
        );
        assert_eq!(git.push_calls, 0, "seed={seed}");
    }
    for index in [5, 6] {
        let mut rows = observations();
        rows[index].as_object_mut().unwrap().remove("bypass_actors");
        assert!(
            inspect(
                &config(),
                &request(),
                &mut Api::new(rows),
                &mut Git::default(),
                &Fixed
            )
            .is_err()
        );
    }
}
#[test]
fn latest_decisive_review_requires_fresh_approval_and_comments_do_not_approve() {
    for state in ["CHANGES_REQUESTED", "DISMISSED", "APPROVED", "COMMENTED"] {
        let mut rows = observations();
        let mut latest = rows[8][0].clone();
        latest["id"] = json!(950);
        latest["state"] = json!(state);
        latest["submitted_at"] = json!("2026-11-06T01:00:00Z");
        latest["commit_id"] = json!("c".repeat(40));
        rows[8].as_array_mut().unwrap().push(latest);
        let result = inspect(
            &config(),
            &request(),
            &mut Api::new(rows),
            &mut Git::default(),
            &Fixed,
        );
        assert_eq!(result.is_ok(), state == "COMMENTED", "{state}");
    }
}
#[test]
fn integration_journals_exact_request_and_observations_before_one_push() {
    let temp = Temp::new();
    let r = temp.request();
    let mut rows = observations();
    rows.extend(observations());
    rows.push(native_ref(&r.target, &r.expected_head));
    let mut git = Git::default();
    let mut api = Api::new(rows);
    let result = integrate(&config(), &r, &mut api, &mut git, &Fixed).unwrap();
    assert_eq!(result["outcome"], "integrated");
    assert_eq!(git.push_calls, 1);
    let intent: Value =
        serde_json::from_slice(&std::fs::read(r.receipt_dir.join("000000.intent.json")).unwrap())
            .unwrap();
    assert_eq!(intent["operation"], "integrate_signed_object");
    assert_eq!(
        intent["payload"]["request"]["expected_head"],
        r.expected_head
    );
    assert_eq!(
        intent["payload"]["observation"]["evidence"]["review"]["id"],
        900
    );
    assert!(r.receipt_dir.join("000000.ok.json").is_file());
    assert!(integrate(&config(), &r, &mut api, &mut git, &Fixed).is_err());
    assert_eq!(git.push_calls, 1);
}
#[test]
fn changed_provider_facts_between_checks_prevent_dispatch_and_intent() {
    for index in [2, 4, 5, 8, 9] {
        let temp = Temp::new();
        let r = temp.request();
        let mut rows = observations();
        let mut later = observations();
        match index {
            2 => later[2]["head"]["sha"] = json!("c".repeat(40)),
            4 => later[4]["object"]["sha"] = json!("c".repeat(40)),
            5 => later[5]["enforcement"] = json!("disabled"),
            8 => later[8][0]["state"] = json!("DISMISSED"),
            9 => later[9]["statuses"][0]["state"] = json!("failure"),
            _ => unreachable!(),
        }
        rows.extend(later);
        let mut git = Git::default();
        assert!(
            integrate(&config(), &r, &mut Api::new(rows), &mut git, &Fixed).is_err(),
            "seed={index}"
        );
        assert_eq!(git.push_calls, 0);
        assert!(!r.receipt_dir.join("000000.intent.json").exists());
    }
}
#[test]
fn lost_push_reply_and_failed_readback_preserve_unknown_without_replay() {
    for lose_reply in [false, true] {
        let temp = Temp::new();
        let r = temp.request();
        let mut rows = observations();
        rows.extend(observations());
        rows.push(native_ref(&r.target, &r.expected_target));
        let mut git = Git {
            lose_reply,
            ..Git::default()
        };
        let mut api = Api::new(rows);
        assert!(integrate(&config(), &r, &mut api, &mut git, &Fixed).is_err());
        assert_eq!(git.push_calls, 1);
        assert!(r.receipt_dir.join("000000.intent.json").is_file());
        assert!(!r.receipt_dir.join("000000.ok.json").exists());
        assert!(integrate(&config(), &r, &mut api, &mut git, &Fixed).is_err());
        assert_eq!(git.push_calls, 1);
    }
}

#[test]
fn explicit_push_rejection_has_a_durable_refusal_without_readback_or_replay() {
    let temp = Temp::new();
    let r = temp.request();
    let mut rows = observations();
    rows.extend(observations());
    let mut git = Git {
        reject: true,
        ..Git::default()
    };
    let mut api = Api::new(rows);
    let result = integrate(&config(), &r, &mut api, &mut git, &Fixed).unwrap();
    assert_eq!(result["outcome"], "refused");
    assert_eq!(result["push_refusal"], "local_rejection");
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(r.receipt_dir.join("000000.ok.json")).unwrap())
            .unwrap();
    assert_eq!(receipt["result"], result);
    assert_eq!(api.calls.len(), 22);
    assert!(integrate(&config(), &r, &mut api, &mut git, &Fixed).is_err());
    assert_eq!(git.push_calls, 1);
}

#[test]
fn porcelain_rejection_requires_one_exact_ref_and_a_complete_unambiguous_reply() {
    use ladyhost::integration::{PushRefusal, classify_push_result};
    let r = request();
    let line = format!(
        "!\t{}:refs/heads/{}\t[rejected] (stale info)",
        r.expected_head, r.target
    );
    let reply = format!("To https://github.com/owner/repo.git\n{line}\nDone\n");
    let error = classify_push_result(&r, false, reply.as_bytes()).unwrap_err();
    assert_eq!(
        error.downcast_ref::<PushRefusal>(),
        Some(&PushRefusal::LocalRejection)
    );
    let remote = reply.replace("[rejected]", "[remote rejected]");
    let error = classify_push_result(&r, false, remote.as_bytes()).unwrap_err();
    assert_eq!(
        error.downcast_ref::<PushRefusal>(),
        Some(&PushRefusal::RemoteRejection)
    );
    for bad in [
        reply.replace("[rejected]", "[remote failure]"),
        reply.replace(&r.expected_head, &"c".repeat(40)),
        reply.replace("refs/heads/app-experiment-base", "refs/heads/main"),
        reply.replace("Done\n", ""),
        reply.replace("Done\n", &format!("{line}\nDone\n")),
        reply.replace("!\t", "+\t"),
        reply.replace(" (stale info)", "garbage"),
        String::new(),
    ] {
        let error = classify_push_result(&r, false, bad.as_bytes()).unwrap_err();
        assert!(error.downcast_ref::<PushRefusal>().is_none(), "{bad:?}");
    }
}
#[test]
fn missing_signature_or_ancestry_prevents_native_reads_and_push() {
    let mut git = Git {
        fail_verify: true,
        ..Git::default()
    };
    let mut api = Api::new(observations());
    assert!(inspect(&config(), &request(), &mut api, &mut git, &Fixed).is_err());
    assert!(api.calls.is_empty());
    assert_eq!(git.push_calls, 0);
}

fn command(path: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("/usr/bin/git")
        .arg("-C")
        .arg(path)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().into()
}
fn setup_repository(temp: &Temp) -> (Config, IntegrationRequest, PathBuf) {
    let workspace = temp.0.join("repository");
    std::fs::create_dir(&workspace).unwrap();
    command(&workspace, &["init", "-b", "app-experiment-base"]);
    command(&workspace, &["config", "user.name", "Integration Test"]);
    command(
        &workspace,
        &["config", "user.email", "integration@example.invalid"],
    );
    command(&workspace, &["commit", "--allow-empty", "-m", "base"]);
    let base = command(&workspace, &["rev-parse", "HEAD"]);
    let key = temp.0.join("signer");
    let out = std::process::Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success());
    command(&workspace, &["config", "gpg.format", "ssh"]);
    command(
        &workspace,
        &["config", "user.signingkey", key.to_str().unwrap()],
    );
    command(
        &workspace,
        &["commit", "--allow-empty", "-S", "-m", "signed candidate"],
    );
    let head = command(&workspace, &["rev-parse", "HEAD"]);
    command(
        &workspace,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/owner/repo.git",
        ],
    );
    let mut c = config();
    c.workspace = workspace;
    let mut r = temp.request();
    r.expected_head = head;
    r.expected_target = base;
    r.allowed_signers = temp.0.join("allowed_signers");
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    std::fs::write(
        &r.allowed_signers,
        format!("integration@example.invalid {public}"),
    )
    .unwrap();
    let config_path = temp.0.join("config.json");
    std::fs::write(&config_path, "{}").unwrap();
    (c, r, config_path)
}
#[test]
fn real_git_verifies_selected_signer_and_refuses_unsigned_or_nonancestor() {
    let temp = Temp::new();
    let (c, mut r, config_path) = setup_repository(&temp);
    let mut git = ladyhost::integration::NativeGit::new(&config_path).unwrap();
    git.verify(&c, &r).unwrap();
    let signed = r.expected_head.clone();
    command(&c.workspace, &["commit", "--allow-empty", "-m", "unsigned"]);
    r.expected_head = command(&c.workspace, &["rev-parse", "HEAD"]);
    assert!(git.verify(&c, &r).is_err());
    command(&c.workspace, &["reset", "--hard", &signed]);
    r.expected_head = signed;
    let tree = command(&c.workspace, &["rev-parse", "HEAD^{tree}"]);
    r.expected_target = command(
        &c.workspace,
        &["commit-tree", &tree, "-m", "unrelated root"],
    );
    assert!(git.verify(&c, &r).is_err());
}
#[test]
fn real_git_refuses_wrong_trust_and_ambient_configuration() {
    let temp = Temp::new();
    let (c, r, config_path) = setup_repository(&temp);
    let mut git = ladyhost::integration::NativeGit::new(&config_path).unwrap();
    git.verify(&c, &r).unwrap();
    for (key, value) in [
        ("url.https://evil.invalid/.insteadof", "https://github.com/"),
        ("gpg.ssh.program", "/bin/true"),
        ("remote.origin.pushurl", "https://evil.invalid/repo"),
        ("include.path", "/tmp/ambient-config"),
    ] {
        command(&c.workspace, &["config", key, value]);
        assert!(git.verify(&c, &r).is_err(), "accepted {key}");
        command(&c.workspace, &["config", "--unset-all", key]);
    }
    let wrong = temp.0.join("wrong");
    assert!(
        std::process::Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&wrong)
            .status()
            .unwrap()
            .success()
    );
    let public = std::fs::read_to_string(wrong.with_extension("pub")).unwrap();
    std::fs::write(
        &r.allowed_signers,
        format!("integration@example.invalid {public}"),
    )
    .unwrap();
    assert!(git.verify(&c, &r).is_err());
}
#[test]
fn real_git_lease_pushes_unchanged_object_and_rejects_changed_target() {
    let temp = Temp::new();
    let (c, mut r, _) = setup_repository(&temp);
    let bare = temp.0.join("server.git");
    std::fs::create_dir(&bare).unwrap();
    command(&bare, &["init", "--bare"]);
    command(
        &c.workspace,
        &["remote", "set-url", "origin", bare.to_str().unwrap()],
    );
    command(
        &c.workspace,
        &[
            "push",
            "origin",
            &format!("{}:refs/heads/{}", r.expected_target, r.target),
        ],
    );
    let output = std::process::Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&c.workspace)
        .args(r.push_arguments())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(command(&bare, &["rev-parse", &r.target]), r.expected_head);
    // The already advanced target does not match the original lease. Introduce
    // another local commit so an actual update (not Git's up-to-date shortcut)
    // must be refused by the stale expected-target comparison.
    let integrated = r.expected_head.clone();
    command(
        &c.workspace,
        &["commit", "--allow-empty", "-S", "-m", "next candidate"],
    );
    r.expected_head = command(&c.workspace, &["rev-parse", "HEAD"]);
    let output = std::process::Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&c.workspace)
        .args(r.push_arguments())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error =
        ladyhost::integration::classify_push_result(&r, output.status.success(), &output.stdout)
            .unwrap_err();
    assert_eq!(
        error.downcast_ref::<ladyhost::integration::PushRefusal>(),
        Some(&ladyhost::integration::PushRefusal::LocalRejection)
    );
    assert_eq!(command(&bare, &["rev-parse", &r.target]), integrated);
    // With a current lease, a server hook produces a distinct explicit refusal.
    use std::os::unix::fs::PermissionsExt;
    let hook = bare.join("hooks/update");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    r.expected_target = integrated.clone();
    let output = std::process::Command::new("/usr/bin/git")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(&c.workspace)
        .args(r.push_arguments())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = ladyhost::integration::classify_push_result(&r, false, &output.stdout).unwrap_err();
    assert_eq!(
        error.downcast_ref::<ladyhost::integration::PushRefusal>(),
        Some(&ladyhost::integration::PushRefusal::RemoteRejection)
    );
    assert_eq!(command(&bare, &["rev-parse", &r.target]), integrated);
}

#[test]
fn deterministic_push_reply_and_receipt_failures_preserve_three_outcomes() {
    use ladyhost::integration::{classify_push_result, failure_outcome};
    struct Transport {
        success: bool,
        bytes: Vec<u8>,
        block_ack: bool,
    }
    impl IntegrationGit for Transport {
        fn verify(&mut self, _: &Config, _: &IntegrationRequest) -> Result<()> {
            Ok(())
        }
        fn push(&mut self, _: &Config, r: &IntegrationRequest) -> Result<()> {
            if self.block_ack {
                std::fs::create_dir(r.receipt_dir.join("000000.ok.json"))?;
            }
            classify_push_result(r, self.success, &self.bytes)
        }
    }
    let mut counts = [0; 3];
    for (case, (success, summary, known_refusal)) in [
        (true, "", false),
        (false, "[rejected] (stale info)", true),
        (false, "[remote rejected] (hook declined)", true),
        (
            false,
            "[remote failure] (remote failed to report status)",
            false,
        ),
        (false, "unrecognized result", false),
    ]
    .into_iter()
    .enumerate()
    {
        for block_ack in [false, true] {
            for current in [false, true] {
                let temp = Temp::new();
                let r = temp.request();
                let mut rows = observations();
                rows.extend(observations());
                rows.push(native_ref(
                    &r.target,
                    if current {
                        &r.expected_head
                    } else {
                        &r.expected_target
                    },
                ));
                let mut api = Api::new(rows);
                let mut git = Transport { success, block_ack,
                    bytes: format!("To https://github.com/owner/repo.git\n!\t{}:refs/heads/{}\t{summary}\nDone\n", r.expected_head, r.target).into_bytes() };
                let result = integrate(&config(), &r, &mut api, &mut git, &Fixed);
                let expected = if block_ack {
                    "unknown"
                } else if known_refusal {
                    "refused"
                } else if success && current {
                    "integrated"
                } else {
                    "unknown"
                };
                let actual = match &result {
                    Ok(value) => value["outcome"].as_str().unwrap(),
                    Err(error) => failure_outcome(error),
                };
                assert_eq!(
                    actual, expected,
                    "case={case}, block_ack={block_ack}, current={current}"
                );
                assert_eq!(
                    r.receipt_dir.join("000000.ok.json").is_file(),
                    expected != "unknown"
                );
                assert!(r.receipt_dir.join("000000.intent.json").is_file());
                assert!(integrate(&config(), &r, &mut api, &mut git, &Fixed).is_err());
                counts[match expected {
                    "integrated" => 0,
                    "refused" => 1,
                    _ => 2,
                }] += 1;
            }
        }
    }
    assert_eq!(counts, [1, 4, 15]);
}

#[test]
fn deterministic_state_transitions_match_independent_admission_model() {
    let mut accepted = 0;
    let mut refused = 0;
    for seed in 1..=300u64 {
        // This local xorshift uses the complete nonzero seed, without lo_sim's
        // seed|1 mapping. Enumerated streams therefore have distinct states.
        let mut rng = seed;
        let mut valid = [true; 7];
        for step in 0..12 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            if step > 0 {
                valid[(rng % 7) as usize] ^= true;
            }
            let expected = valid.iter().all(|v| *v);
            let mut rows = observations();
            if !valid[0] {
                rows[2]["head"]["sha"] = json!("c".repeat(40));
                rows[3]["object"]["sha"] = json!("c".repeat(40));
            }
            if !valid[1] {
                rows[2]["base"]["sha"] = json!("d".repeat(40));
                rows[4]["object"]["sha"] = json!("d".repeat(40));
            }
            if !valid[2] {
                rows[6]["enforcement"] = json!("disabled");
            }
            if !valid[3] {
                rows[8][0]["state"] = json!("CHANGES_REQUESTED");
            }
            if !valid[4] {
                rows[9]["statuses"][0]["state"] = json!("pending");
            }
            if !valid[5] {
                rows[6].as_object_mut().unwrap().remove("bypass_actors");
            }
            let mut git = Git {
                fail_verify: !valid[6],
                ..Git::default()
            };
            let result = inspect(&config(), &request(), &mut Api::new(rows), &mut git, &Fixed);
            assert_eq!(
                result.is_ok(),
                expected,
                "seed={seed}, step={step}, model={valid:?}"
            );
            assert_eq!(git.push_calls, 0, "seed={seed}, step={step}");
            if expected {
                accepted += 1;
            } else {
                refused += 1;
            }
        }
    }
    assert!(accepted >= 300);
    assert!(refused >= 3000);
}
#[test]
fn pagination_missing_native_evidence_and_provider_failures_refuse() {
    let mut rows = observations();
    let review = rows[8][0].clone();
    rows[8] = json!(vec![review.clone(); 100]);
    rows.truncate(9);
    for _ in 0..9 {
        rows.push(json!(vec![review.clone(); 100]));
    }
    assert!(
        inspect(
            &config(),
            &request(),
            &mut Api::new(rows),
            &mut Git::default(),
            &Fixed
        )
        .is_err()
    );
    for truncate in 0..11 {
        let mut rows = observations();
        rows.truncate(truncate);
        assert!(
            inspect(
                &config(),
                &request(),
                &mut Api::new(rows),
                &mut Git::default(),
                &Fixed
            )
            .is_err(),
            "missing read {truncate}"
        );
    }
}

#[test]
fn hidden_roster_requires_native_caller_evidence_and_limits_claim() {
    let mut rows = observations();
    for (index, bypass) in [(5, "always"), (6, "never")] {
        rows[index].as_object_mut().unwrap().remove("bypass_actors");
        rows[index]["current_user_can_bypass"] = json!(bypass);
    }
    rows[5]["rules"][0]
        .as_object_mut()
        .unwrap()
        .remove("parameters");
    rows[7][0].as_object_mut().unwrap().remove("parameters");
    rows[6]["rules"][0]["parameters"]["required_reviewers"] = json!([]);
    rows[6]["rules"][0]["parameters"]["require_extra_approval_for_unattributed_changes"] =
        json!(true);
    rows[6]["rules"][0]["parameters"]["allowed_merge_methods"] =
        json!(["merge", "squash", "rebase"]);
    rows[7][1]["parameters"] = rows[6]["rules"][0]["parameters"].clone();
    let observed = inspect(
        &config(),
        &request(),
        &mut Api::new(rows.clone()),
        &mut Git::default(),
        &Fixed,
    )
    .unwrap();
    assert_eq!(observed.evidence["bypass_scope"], "current_app_only");
    assert_eq!(observed.evidence["roster_visibility"]["quality"], "hidden");
    for value in [json!("always"), json!("pull_request"), json!(null)] {
        let mut changed = rows.clone();
        changed[6]["current_user_can_bypass"] = value;
        assert!(
            inspect(
                &config(),
                &request(),
                &mut Api::new(changed),
                &mut Git::default(),
                &Fixed
            )
            .is_err()
        );
    }
    for index in [5, 6] {
        let mut changed = rows.clone();
        changed[index]
            .as_object_mut()
            .unwrap()
            .remove("current_user_can_bypass");
        let error = inspect(
            &config(),
            &request(),
            &mut Api::new(changed),
            &mut Git::default(),
            &Fixed,
        )
        .unwrap_err();
        assert_eq!(ladyhost::integration::failure_outcome(&error), "unknown");
    }
}

#[test]
fn cli_accepts_new_operations_and_sanitizes_invalid_host_configuration() {
    let temp = Temp::new();
    let config_path = temp.0.join("invalid-config.json");
    std::fs::write(&config_path, "private-credential-must-not-appear").unwrap();
    for operation in ["inspect-integration", "integrate"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_ladyhost-jjpr"))
            .arg(operation)
            .arg(&config_path)
            .arg(temp.0.join("request.json"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let value: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(value["outcome"], "refused");
        assert!(!stdout.contains("private-credential-must-not-appear"));
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("private-credential-must-not-appear")
        );
    }
}

#[test]
fn combined_status_identity_binds_latest_detailed_status_creator() {
    let mut rows = observations();
    let detail = rows[10][0].clone();
    assert!(rows[9]["statuses"][0].get("creator").is_none());
    let mut api = Api::new(rows.clone());
    inspect(&config(), &request(), &mut api, &mut Git::default(), &Fixed).unwrap();
    assert!(
        api.calls
            .last()
            .unwrap()
            .contains("/statuses?per_page=100&page=1")
    );
    for field in ["id", "state", "creator"] {
        let mut changed = rows.clone();
        changed[10][0][field] = match field {
            "id" => json!(902),
            "state" => json!("pending"),
            _ => json!({"id":999,"login":"other[bot]","type":"Bot"}),
        };
        assert!(
            inspect(
                &config(),
                &request(),
                &mut Api::new(changed),
                &mut Git::default(),
                &Fixed
            )
            .is_err(),
            "changed {field}"
        );
    }
    let mut newer = detail.clone();
    newer["id"] = json!(902);
    newer["state"] = json!("failure");
    rows[10] = json!([newer, detail]);
    assert!(
        inspect(
            &config(),
            &request(),
            &mut Api::new(rows),
            &mut Git::default(),
            &Fixed
        )
        .is_err()
    );
}

#[test]
fn bounded_status_detail_pagination_reports_unknown_without_old_success_fallback() {
    let mut rows = observations();
    let selected = rows[10].clone();
    let other = json!({"id":902,"context":"unrelated","state":"failure"});
    rows[10] = json!(vec![other.clone(); 100]);
    rows.push(selected);
    inspect(
        &config(),
        &request(),
        &mut Api::new(rows),
        &mut Git::default(),
        &Fixed,
    )
    .unwrap();
    let mut rows = observations();
    rows.truncate(10);
    for _ in 0..10 {
        rows.push(json!(vec![other.clone(); 100]));
    }
    let error = inspect(
        &config(),
        &request(),
        &mut Api::new(rows),
        &mut Git::default(),
        &Fixed,
    )
    .unwrap_err();
    assert_eq!(ladyhost::integration::failure_outcome(&error), "unknown");
    let mut rows = observations();
    rows[9]["total_count"] = json!(101);
    let error = inspect(
        &config(),
        &request(),
        &mut Api::new(rows),
        &mut Git::default(),
        &Fixed,
    )
    .unwrap_err();
    assert_eq!(ladyhost::integration::failure_outcome(&error), "unknown");
    let mut rows = observations();
    let review = rows[8][0].clone();
    rows.truncate(8);
    for _ in 0..10 {
        rows.push(json!(vec![review.clone(); 100]));
    }
    let error = inspect(
        &config(),
        &request(),
        &mut Api::new(rows),
        &mut Git::default(),
        &Fixed,
    )
    .unwrap_err();
    assert_eq!(ladyhost::integration::failure_outcome(&error), "unknown");
}

fn ci_request(temp: &Temp) -> IntegrationRequest {
    let mut r = temp.request();
    r.ci=Some(serde_json::from_value(json!({"check_name":"ci/verify","app_id":999,"workflow_path":".github/workflows/ci-verify.yml"})).unwrap());
    r
}
fn ci_observations(attempt: u64) -> Vec<Value> {
    let mut rows = observations();
    let required = json!({"context":"ci/verify","integration_id":999});
    rows[6]["rules"][5]["parameters"]["required_status_checks"]
        .as_array_mut()
        .unwrap()
        .push(required.clone());
    rows[7][6]["parameters"]["required_status_checks"]
        .as_array_mut()
        .unwrap()
        .push(required);
    rows.splice(8..8,[
        json!({"total_count":1,"check_runs":[{"id":11,"name":"ci/verify","head_sha":"a".repeat(40),"status":"completed","conclusion":"success","app":{"id":999,"slug":"github-actions"},"check_suite":{"id":12},"details_url":"https://github.com/owner/repo/actions/runs/13/job/14"}]}),
        json!({"id":13,"head_sha":"a".repeat(40),"head_branch":"parent","event":"push","path":".github/workflows/ci-verify.yml","repository":{"id":42},"head_repository":{"id":42},"check_suite_id":12,"run_attempt":attempt,"status":"completed","conclusion":"success"}),
        json!({"total_count":1,"jobs":[{"id":14,"run_id":13,"name":"ci/verify","head_sha":"a".repeat(40),"head_branch":"parent","status":"completed","conclusion":"success","check_run_url":"https://api.github.com/repos/owner/repo/check-runs/11"}]}),
    ]);
    rows
}
#[test]
fn ci_required_by_policy_is_recorded_before_exact_integration() {
    let temp = Temp::new();
    let r = ci_request(&temp);
    let mut rows = ci_observations(1);
    rows.extend(ci_observations(1));
    rows.push(native_ref(&r.target, &r.expected_head));
    let mut git = Git::default();
    integrate(&config(), &r, &mut Api::new(rows), &mut git, &Fixed).unwrap();
    assert_eq!(git.push_calls, 1);
    let intent: Value =
        serde_json::from_slice(&std::fs::read(r.receipt_dir.join("000000.intent.json")).unwrap())
            .unwrap();
    assert_eq!(
        intent["payload"]["observation"]["evidence"]["ci"]["run_attempt"],
        1
    );
}
#[test]
fn ci_failure_precedes_review_and_changed_attempt_prevents_dispatch() {
    let temp = Temp::new();
    let r = ci_request(&temp);
    let mut rows = ci_observations(1);
    rows[8]["check_runs"][0]["conclusion"] = json!("failure");
    let mut api = Api::new(rows);
    let mut git = Git::default();
    let error = integrate(&config(), &r, &mut api, &mut git, &Fixed).unwrap_err();
    assert!(error.to_string().contains("CI"));
    assert!(!api.calls.iter().any(|p| p.contains("/reviews")));
    assert_eq!(git.push_calls, 0);
    let mut rows = ci_observations(1);
    rows.extend(ci_observations(2));
    assert!(integrate(&config(), &r, &mut Api::new(rows), &mut git, &Fixed).is_err());
    assert_eq!(git.push_calls, 0);
    assert!(!r.receipt_dir.join("000000.intent.json").exists());
}
#[test]
fn ci_policy_cannot_be_dropped_or_rebound_and_native_order_is_not_authority() {
    for mutation in 0..3 {
        let temp = Temp::new();
        let r = ci_request(&temp);
        let mut rows = ci_observations(1);
        match mutation {
            0 => {
                rows[6]["rules"][5]["parameters"]["required_status_checks"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
            }
            1 => {
                rows[6]["rules"][5]["parameters"]["required_status_checks"][1]["integration_id"] =
                    json!(123);
            }
            _ => {
                rows[6]["rules"][5]["parameters"]["required_status_checks"]
                    .as_array_mut()
                    .unwrap()
                    .reverse();
                rows[7][6]["parameters"]["required_status_checks"]
                    .as_array_mut()
                    .unwrap()
                    .reverse();
            }
        }
        assert_eq!(
            inspect(
                &config(),
                &r,
                &mut Api::new(rows),
                &mut Git::default(),
                &Fixed
            )
            .is_ok(),
            mutation == 2
        );
    }
}
