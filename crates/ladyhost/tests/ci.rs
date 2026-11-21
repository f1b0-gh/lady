use anyhow::{Result, bail};
use ladyhost::{Config, app::AppApi, ci, integration::IntegrationRequest};
use serde_json::{Value, json};
use std::collections::VecDeque;

fn config() -> Config {
    serde_json::from_value(json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"repo","workspace":"/tmp/ci-project","stack_base":"base","expected_actor":"publisher[bot]","expected_repository_id":42,"github_app":{"app_id":123,"installation_id":456,"slug":"publisher","private_key":"/tmp/host/key.pem","openssl":"/usr/bin/openssl"}})).unwrap()
}
fn request() -> IntegrationRequest {
    serde_json::from_value(json!({"task":"ci","pr_number":7,"source":"agent/ci/task","target":"base","expected_head":"a".repeat(40),"expected_target":"b".repeat(40),"reviewer":{"id":888,"login":"reviewer"},"update_ruleset_id":101,"quality_ruleset_id":102,"allowed_signers":"/tmp/host/signers","receipt_dir":"/tmp/host/ci-receipt","ci":{"check_name":"ci/verify","app_id":999,"workflow_path":".github/workflows/ci-verify.yml"}})).unwrap()
}
fn evidence() -> Vec<Value> {
    vec![
        json!({"total_count":1,"check_runs":[{"id":11,"name":"ci/verify","head_sha":"a".repeat(40),"status":"completed","conclusion":"success","app":{"id":999,"slug":"github-actions"},"check_suite":{"id":12},"details_url":"https://github.com/owner/repo/actions/runs/13/job/14"}]}),
        json!({"id":13,"head_sha":"a".repeat(40),"head_branch":"agent/ci/task","event":"push","path":".github/workflows/ci-verify.yml","repository":{"id":42},"head_repository":{"id":42},"check_suite_id":12,"run_attempt":2,"status":"completed","conclusion":"success"}),
        json!({"total_count":1,"jobs":[{"id":14,"run_id":13,"name":"ci/verify","head_sha":"a".repeat(40),"head_branch":"agent/ci/task","status":"completed","conclusion":"success","check_run_url":"https://api.github.com/repos/owner/repo/check-runs/11"}]}),
    ]
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
        self.calls.push(path.into());
        self.replies
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("unavailable"))
    }
    fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
        bail!("CI observations must be read-only")
    }
}
#[test]
fn exact_success_binds_current_actions_attempt_and_uses_locally_derived_paths() {
    let mut api = Api::new(evidence());
    let result = ci::inspect(&config(), &request(), &mut api).unwrap();
    assert_eq!(result["run_attempt"], 2);
    assert_eq!(result["check_run_id"], 11);
    assert_eq!(
        api.calls,
        vec![
            format!(
                "/repos/owner/repo/commits/{}/check-runs?check_name=ci%2Fverify&filter=latest&per_page=100&page=1",
                "a".repeat(40)
            ),
            "/repos/owner/repo/actions/runs/13".into(),
            "/repos/owner/repo/actions/runs/13/attempts/2/jobs?per_page=100&page=1".into()
        ]
    );
}
#[test]
fn wrong_source_revision_workflow_or_attempt_cannot_supply_ci() {
    for (index, pointer, value) in [
        (0, "/check_runs/0/head_sha", json!("b".repeat(40))),
        (0, "/check_runs/0/name", json!("other")),
        (0, "/check_runs/0/app/id", json!(123)),
        (0, "/check_runs/0/app/slug", json!("publisher")),
        (
            0,
            "/check_runs/0/details_url",
            json!("https://evil.test/owner/repo/actions/runs/13/job/14"),
        ),
        (
            0,
            "/check_runs/0/details_url",
            json!("https://github.com/owner/repo/actions/runs/13/job/14?redirect=evil"),
        ),
        (0, "/check_runs/0/id", json!(0)),
        (1, "/id", json!(15)),
        (1, "/head_sha", json!("b".repeat(40))),
        (1, "/head_branch", json!("other")),
        (1, "/event", json!("pull_request")),
        (1, "/path", json!(".github/workflows/other.yml")),
        (1, "/repository/id", json!(43)),
        (1, "/head_repository/id", json!(43)),
        (1, "/check_suite_id", json!(15)),
        (1, "/run_attempt", json!(0)),
        (2, "/jobs/0/id", json!(15)),
        (2, "/jobs/0/run_id", json!(15)),
        (2, "/jobs/0/head_sha", json!("b".repeat(40))),
        (2, "/jobs/0/head_branch", json!("other")),
        (
            2,
            "/jobs/0/check_run_url",
            json!("https://api.github.com/repos/owner/repo/check-runs/10"),
        ),
    ] {
        let mut values = evidence();
        *values[index].pointer_mut(pointer).unwrap() = value;
        assert!(
            ci::inspect(&config(), &request(), &mut Api::new(values)).is_err(),
            "{index} {pointer}"
        );
    }
}
#[test]
fn missing_ambiguous_and_truncated_evidence_never_falls_back_to_old_success() {
    for index in [0, 2] {
        for count in [0, 2, 101] {
            let mut values = evidence();
            values[index]["total_count"] = json!(count);
            let error = ci::inspect(&config(), &request(), &mut Api::new(values)).unwrap_err();
            assert_eq!(ladyhost::integration::failure_outcome(&error), "unknown");
        }
        let mut values = evidence();
        values[index]["total_count"] = json!(0);
        values[index][if index == 0 { "check_runs" } else { "jobs" }] = json!([]);
        let error = ci::inspect(&config(), &request(), &mut Api::new(values)).unwrap_err();
        assert_eq!(ladyhost::integration::failure_outcome(&error), "unknown");
    }
    let mut values = evidence();
    let mut newer = values[0]["check_runs"][0].clone();
    newer["id"] = json!(20);
    newer["conclusion"] = json!("failure");
    values[0]["check_runs"].as_array_mut().unwrap().push(newer);
    values[0]["total_count"] = json!(2);
    let error = ci::inspect(&config(), &request(), &mut Api::new(values)).unwrap_err();
    assert_eq!(ladyhost::integration::failure_outcome(&error), "unknown");
    let err = ci::inspect(&config(), &request(), &mut Api::new(vec![])).unwrap_err();
    assert_eq!(ladyhost::integration::failure_outcome(&err), "unknown");
}
#[test]
fn requirement_rejects_policy_aliases_and_unsafe_paths() {
    let mut r = request();
    r.ci.as_mut().unwrap().check_name = "fixture/verify".into();
    assert!(r.validate(&config()).is_err());
    for path in [
        ".github/workflows/../other.yml",
        "evil.yml",
        ".github/workflows/a.yml?ref=x",
    ] {
        let mut r = request();
        r.ci.as_mut().unwrap().workflow_path = path.into();
        assert!(r.validate(&config()).is_err());
    }
}
#[test]
fn deterministic_ci_transitions_match_all_three_layers_success_model() {
    // Exhaustive deterministic transitions over independent check/run/job states.
    let states = [
        ("queued", None),
        ("in_progress", None),
        ("completed", Some("failure")),
        ("completed", Some("cancelled")),
        ("completed", Some("skipped")),
        ("completed", Some("neutral")),
        ("completed", Some("success")),
    ];
    let mut visited = 0;
    for (a, check) in states.iter().enumerate() {
        for (b, run) in states.iter().enumerate() {
            for (c, job) in states.iter().enumerate() {
                let mut values = evidence();
                values[0]["check_runs"][0]["status"] = json!(check.0);
                values[0]["check_runs"][0]["conclusion"] = json!(check.1);
                values[1]["status"] = json!(run.0);
                values[1]["conclusion"] = json!(run.1);
                values[2]["jobs"][0]["status"] = json!(job.0);
                values[2]["jobs"][0]["conclusion"] = json!(job.1);
                let expected = a == 6 && b == 6 && c == 6;
                assert_eq!(
                    ci::inspect(&config(), &request(), &mut Api::new(values)).is_ok(),
                    expected,
                    "case {a}/{b}/{c}"
                );
                visited += 1;
            }
        }
    }
    assert_eq!(visited, 343);
}
