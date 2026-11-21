//! Native Actions evidence for a host-selected exact-commit CI requirement.
//! A missing/ambiguous observation never supplies positive admission.
use crate::{
    Config,
    app::AppApi,
    integration::{IntegrationRequest, Unknown, encode, read},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub check_name: String,
    pub app_id: u64,
    pub workflow_path: String,
}
impl Requirement {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.app_id > 0
                && !self.check_name.is_empty()
                && self.check_name.len() <= 100
                && self.check_name != "fixture/verify"
                && self
                    .check_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_/ .".contains(&b)),
            "invalid or conflicting CI check requirement"
        );
        let file = self
            .workflow_path
            .strip_prefix(".github/workflows/")
            .context("CI workflow must be a repository workflow file")?;
        ensure!(
            !file.starts_with('.')
                && !file.contains("..")
                && (file.ends_with(".yml") || file.ends_with(".yaml"))
                && file
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "invalid CI workflow path"
        );
        Ok(())
    }
}
fn id(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .filter(|n| *n > 0)
        .context("CI numeric identity missing")
}
fn list<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    let count = value["total_count"]
        .as_u64()
        .ok_or(Unknown("CI count unavailable"))?;
    let entries = value[field]
        .as_array()
        .ok_or(Unknown("CI entries unavailable"))?;
    if count > 100 || count != entries.len() as u64 {
        return Err(Unknown("CI list truncated or exceeds bound").into());
    }
    Ok(entries)
}
fn success(value: &Value) -> Result<()> {
    ensure!(
        value["status"] == "completed" && value["conclusion"] == "success",
        "required CI is not completed successfully"
    );
    Ok(())
}
/// Binds the current check to its native Actions run and current-attempt job.
/// Only API paths constructed from pinned repository identity and numeric IDs
/// are fetched; metadata URLs never select a transport authority.
pub fn inspect(
    config: &Config,
    request: &IntegrationRequest,
    api: &mut dyn AppApi,
) -> Result<Value> {
    request.validate(config)?;
    let Some(required) = &request.ci else {
        return Ok(Value::Null);
    };
    inspect_candidate(
        config,
        &request.expected_head,
        &request.source,
        required,
        api,
    )
}

/// The same native CI binding is usable before setup has created PR/ruleset IDs.
pub fn inspect_candidate(
    config: &Config,
    head: &str,
    source: &str,
    required: &Requirement,
    api: &mut dyn AppApi,
) -> Result<Value> {
    config.validate()?;
    required.validate()?;
    ensure!(
        crate::integration::full_oid(head) && crate::integration::branch(source),
        "Invalid CI candidate binding"
    );
    ensure!(
        config
            .github_app
            .as_ref()
            .is_none_or(|app| app.app_id != required.app_id),
        "Publisher cannot supply its own independent CI identity"
    );
    let prefix = format!("/repos/{}/{}", config.owner, config.repository);
    let checks = read(
        api,
        &format!(
            "{prefix}/commits/{}/check-runs?check_name={}&filter=latest&per_page=100&page=1",
            head,
            encode(&required.check_name)
        ),
    )?;
    let entries = list(&checks, "check_runs")?;
    if entries.len() != 1 {
        return Err(Unknown("required CI check missing or ambiguous").into());
    }
    let check = &entries[0];
    let check_id = id(&check["id"])?;
    let suite_id = id(&check["check_suite"]["id"])?;
    ensure!(
        check["name"] == required.check_name
            && check["head_sha"] == head
            && check["app"]["id"] == required.app_id
            && check["app"]["slug"] == "github-actions",
        "CI check name, commit or Actions identity differs from selection"
    );
    success(check)?;
    let url_prefix = format!(
        "https://github.com/{}/{}/actions/runs/",
        config.owner, config.repository
    );
    let detail = check["details_url"]
        .as_str()
        .and_then(|s| s.strip_prefix(&url_prefix))
        .context("CI Actions URL differs from repository")?;
    let (run_text, job_text) = detail
        .split_once("/job/")
        .context("CI Actions job URL missing")?;
    let numeric = |s: &str| -> Result<u64> {
        ensure!(
            !s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()),
            "CI Actions URL contains nonnumeric identity"
        );
        Ok(s.parse()?)
    };
    let run_id = numeric(run_text)?;
    let job_id = numeric(job_text)?;
    let run = read(api, &format!("{prefix}/actions/runs/{run_id}"))?;
    let attempt = id(&run["run_attempt"])?;
    let repository_id = config
        .expected_repository_id
        .context("CI repository ID missing")?;
    ensure!(
        run["id"] == run_id
            && run["head_sha"] == head
            && run["head_branch"] == source
            && run["event"] == "push"
            && run["path"] == required.workflow_path
            && run["repository"]["id"] == repository_id
            && run["head_repository"]["id"] == repository_id
            && run["check_suite_id"] == suite_id,
        "CI workflow run differs from exact push, workflow or repository"
    );
    success(&run)?;
    let jobs = read(
        api,
        &format!("{prefix}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page=1"),
    )?;
    let matches: Vec<_> = list(&jobs, "jobs")?
        .iter()
        .filter(|j| j["name"] == required.check_name)
        .collect();
    if matches.len() != 1 {
        return Err(Unknown("current CI attempt job missing or ambiguous").into());
    }
    let job = matches[0];
    ensure!(
        job["id"] == job_id
            && job["run_id"] == run_id
            && job["head_sha"] == head
            && job["head_branch"] == source
            && job["check_run_url"]
                == format!("https://api.github.com{prefix}/check-runs/{check_id}"),
        "CI job differs from current check or attempt"
    );
    success(job)?;
    Ok(
        json!({"check_run_id":check_id,"check_suite_id":suite_id,"run_id":run_id,
        "run_attempt":attempt,"job_id":job_id,"head_sha":head,
        "requirement":required,"status":"completed","conclusion":"success"}),
    )
}
