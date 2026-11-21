//! Agent-free host setup. Provider effects and owner consent stay outside sandboxes.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub schema_version: u32,
    pub repository: String,
    pub workspace: PathBuf,
    pub target: String,
    pub app_name: String,
    /// Host-selected argv vectors, run in CI rather than by setup on the host.
    #[serde(default)]
    pub checks: Vec<Vec<String>>,
    #[serde(default = "default_check")]
    pub ci_check: String,
    #[serde(default = "default_workflow")]
    pub workflow_path: String,
    #[serde(default)]
    pub adopt_workflow: bool,
    pub gh: PathBuf,
    pub jj: PathBuf,
    #[serde(default)]
    pub signing_key: Option<PathBuf>,
}
fn default_check() -> String {
    "ci/ladyhost".into()
}
fn default_workflow() -> String {
    ".github/workflows/ladyhost.yml".into()
}
impl Spec {
    pub fn parts(&self) -> Result<(&str, &str)> {
        let (owner, repository) = self
            .repository
            .split_once('/')
            .context("Use OWNER/REPOSITORY")?;
        ensure!(
            crate::identifier(owner, false) && crate::identifier(repository, true),
            "Invalid repository identity"
        );
        Ok((owner, repository))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "Unsupported setup schema");
        self.parts()?;
        ensure!(
            crate::integration::branch(&self.target) && !self.target.contains("${{"),
            "Invalid target branch"
        );
        ensure!(
            crate::identifier(&self.app_name, false)
                && self.app_name.len() <= 34
                && self
                    .app_name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "App name must be a lowercase ASCII slug of at most 34 characters"
        );
        ensure!(
            self.workspace.is_absolute()
                && self.gh.is_absolute()
                && self.jj.is_absolute()
                && self.signing_key.as_ref().is_none_or(|p| p.is_absolute()),
            "Host paths must be absolute"
        );
        ensure!(
            (self.adopt_workflow || !self.checks.is_empty()) && self.checks.len() <= 16,
            "Select 1 to 16 project check commands"
        );
        // Only selection syntax is validated here; the real CI App ID is bound from GitHub later.
        crate::ci::Requirement {
            check_name: self.ci_check.clone(),
            workflow_path: self.workflow_path.clone(),
            app_id: 1,
        }
        .validate()?;
        for command in &self.checks {
            ensure!(
                !command.is_empty() && command.len() <= 64,
                "Invalid check argument count"
            );
            for argument in command {
                ensure!(
                    argument.len() <= 4096 && !argument.contains('\0'),
                    "Invalid check argument"
                );
            }
            ensure!(!command[0].is_empty(), "Check executable is empty");
        }
        Ok(())
    }
    pub fn endpoint(&self) -> String {
        format!("/repos/{}", self.repository)
    }
}

/// Split update authority from non-bypassable review, signatures and checks.
pub fn policies(
    spec: &Spec,
    operation: &str,
    app_id: u64,
    ci_app_id: u64,
) -> Result<(Value, Value)> {
    spec.validate()?;
    ensure!(
        crate::identifier(operation, false) && operation.len() <= 32,
        "Invalid setup operation identity"
    );
    ensure!(
        app_id > 0 && ci_app_id > 0 && app_id != ci_app_id,
        "Select distinct publisher and CI identities"
    );
    let conditions =
        json!({"ref_name":{"include":[format!("refs/heads/{}",spec.target)],"exclude":[]}});
    let update = json!({"name":format!("ladyhost-{operation}-updates"),"target":"branch","enforcement":"active",
        "conditions":conditions,"bypass_actors":[{"actor_id":app_id,"actor_type":"Integration","bypass_mode":"always"}],
        "rules":[{"type":"update"}]});
    let quality = json!({"name":format!("ladyhost-{operation}-quality"),"target":"branch","enforcement":"active",
    "conditions":conditions,"bypass_actors":[],"rules":[
        {"type":"deletion"},{"type":"non_fast_forward"},{"type":"required_linear_history"},{"type":"required_signatures"},
        {"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,
            "require_code_owner_review":false,"require_last_push_approval":false,"required_review_thread_resolution":true}},
        {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,
            "do_not_enforce_on_create":false,"required_status_checks":[
                {"context":"fixture/verify","integration_id":app_id},{"context":spec.ci_check,"integration_id":ci_app_id}]}}
    ]});
    Ok((update, quality))
}

mod resources;
mod state;
pub use resources::{Api, ensure_ruleset, policy_view, remove_ruleset};
pub use state::Store;

pub mod native;

pub mod flow;

pub mod workflow;

pub mod bootstrap;

pub mod doctor;

pub mod engine;

pub mod help;
