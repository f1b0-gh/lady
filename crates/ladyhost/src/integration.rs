//! Bounded, conventional host integration of one unchanged signed Git object.
//! Provider observations are not atomic with dispatch. Native quality rules and
//! the target-only Git lease complement them; unknown writes are never retried.
use crate::{
    Config, Provider,
    app::{self, AppApi, Clock},
    effects::{BookmarkBinding, Journal, PrBinding, Scope},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reviewer {
    pub id: u64,
    pub login: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRequest {
    pub task: String,
    pub pr_number: u64,
    pub source: String,
    pub target: String,
    pub expected_head: String,
    pub expected_target: String,
    pub reviewer: Reviewer,
    pub update_ruleset_id: u64,
    pub quality_ruleset_id: u64,
    pub allowed_signers: PathBuf,
    pub receipt_dir: PathBuf,
    /// Retained review IDs from an earlier candidate. GitHub can rebind an old
    /// review's commit_id after a rewrite without a new human submission.
    #[serde(default)]
    pub superseded_review_ids: Vec<u64>,
    #[serde(default)]
    pub ci: Option<crate::ci::Requirement>,
}

pub(crate) fn full_oid(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn branch(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && !value.starts_with('-')
        && value.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(".lock")
                && !part.contains("..")
        })
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_/.".contains(&b))
}
fn host_path(config: &Config, path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| c == std::path::Component::ParentDir),
        "integration path must be absolute without traversal"
    );
    ensure!(
        !crate::resolved(path)?.starts_with(crate::resolved(&config.workspace)?),
        "integration host input or receipt resolves inside workspace"
    );
    Ok(())
}
impl IntegrationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        config.validate_host_paths()?;
        ensure!(
            config.provider == Provider::Github && config.github_app.is_some(),
            "integration requires pinned GitHub App authentication"
        );
        ensure!(
            !self.task.trim().is_empty()
                && self.task.len() <= 512
                && !self.task.chars().any(char::is_control),
            "invalid integration task"
        );
        ensure!(
            self.pr_number > 0
                && self.reviewer.id > 0
                && crate::identifier(&self.reviewer.login, false),
            "invalid PR or reviewer binding"
        );
        ensure!(
            self.superseded_review_ids.len() <= 1000
                && self.superseded_review_ids.iter().all(|id| *id > 0)
                && self
                    .superseded_review_ids
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == self.superseded_review_ids.len(),
            "invalid retained review IDs"
        );
        ensure!(
            branch(&self.source) && branch(&self.target) && self.source != self.target,
            "invalid source or target branch"
        );
        ensure!(
            config.stack_base.as_deref() == Some(self.target.as_str()),
            "target differs from host-selected stack base"
        );
        ensure!(
            full_oid(&self.expected_head)
                && full_oid(&self.expected_target)
                && self.expected_head.len() == self.expected_target.len()
                && self.expected_head != self.expected_target,
            "integration requires distinct full immutable object IDs"
        );
        ensure!(
            self.update_ruleset_id > 0
                && self.quality_ruleset_id > 0
                && self.update_ruleset_id != self.quality_ruleset_id,
            "two distinct numeric ruleset IDs are required"
        );
        host_path(config, &self.allowed_signers)?;
        host_path(config, &self.receipt_dir)?;
        if let Some(ci) = &self.ci {
            ci.validate()?;
        }
        Ok(())
    }
    pub fn load(config: &Config, path: &Path) -> Result<Self> {
        host_path(config, path)?;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(65_537)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65_536, "integration request exceeds limit");
        let request: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid integration request"))?;
        request.validate(config)?;
        Ok(request)
    }
    /// Exact push command; the native dispatcher validates identity, signature
    /// and ancestry before using it. The lease is only a target-ref CAS.
    pub fn push_arguments(&self) -> Vec<String> {
        vec![
            "push".into(),
            "--porcelain".into(),
            format!(
                "--force-with-lease=refs/heads/{}:{}",
                self.target, self.expected_target
            ),
            "origin".into(),
            format!("{}:refs/heads/{}", self.expected_head, self.target),
        ]
    }
    fn scope(&self, config: &Config) -> Result<Scope> {
        Ok(Scope {
            task: self.task.clone(),
            actor: config.expected_actor.clone().context("App actor missing")?,
            owner: config.owner.clone(),
            repository: config.repository.clone(),
            remote_url: remote_url(config),
            bookmarks: BTreeMap::from([(
                self.source.clone(),
                BookmarkBinding {
                    change_id: self.expected_head.clone(),
                    oid: self.expected_head.clone(),
                    expected_remote: Some(self.expected_head.clone()),
                },
            )]),
            bases: BTreeMap::from([(self.target.clone(), self.expected_target.clone())]),
            reviewers: vec![self.reviewer.login.clone()],
            prs: BTreeMap::from([(
                self.pr_number,
                PrBinding {
                    head: self.source.clone(),
                    base: self.target.clone(),
                    body: None,
                },
            )]),
            comments: BTreeMap::new(),
        })
    }
}
fn remote_url(config: &Config) -> String {
    format!(
        "https://github.com/{}/{}.git",
        config.owner, config.repository
    )
}
pub(crate) fn encode(value: &str) -> String {
    let mut result = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            result.push(char::from(b));
        } else {
            result.push_str(&format!("%{b:02X}"));
        }
    }
    result
}
#[derive(Debug)]
pub(crate) struct Unknown(pub(crate) &'static str);
impl std::fmt::Display for Unknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for Unknown {}

/// A single selected ref was explicitly rejected by the native Git transport.
/// This is not inferred from an exit code or a later observation of the ref.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PushRefusal {
    LocalRejection,
    RemoteRejection,
}
impl std::fmt::Display for PushRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native Git explicitly rejected the selected ref")
    }
}
impl std::error::Error for PushRefusal {}

/// Interpret native Git's porcelain result without exposing transport text.
pub fn classify_push_result(
    request: &IntegrationRequest,
    success: bool,
    stdout: &[u8],
) -> Result<()> {
    if success {
        return Ok(());
    }
    let unknown = || Unknown("native Git push has no confirmed outcome");
    if stdout.len() > 65_536 {
        return Err(unknown().into());
    }
    let text = std::str::from_utf8(stdout).map_err(|_| unknown())?;
    let lines: Vec<_> = text.lines().collect();
    // Git's fixed porcelain framing and one exact ref are required. Remote
    // failure, truncated output, extra refs and human stderr prove no refusal.
    if lines.len() != 3 || !lines[0].starts_with("To ") || lines[2] != "Done" {
        return Err(unknown().into());
    }
    let fields: Vec<_> = lines[1].split('\t').collect();
    if fields.len() != 3
        || fields[0] != "!"
        || fields[1] != format!("{}:refs/heads/{}", request.expected_head, request.target)
        || fields[2].chars().any(char::is_control)
    {
        return Err(unknown().into());
    }
    for (prefix, refusal) in [
        ("[rejected]", PushRefusal::LocalRejection),
        ("[remote rejected]", PushRefusal::RemoteRejection),
    ] {
        if let Some(reason) = fields[2].strip_prefix(prefix)
            && (reason.is_empty() || (reason.starts_with(" (") && reason.ends_with(')')))
        {
            return Err(refusal.into());
        }
    }
    Err(unknown().into())
}
/// Unknown evidence or a possibly dispatched effect is never positive admission.
pub fn failure_outcome(error: &anyhow::Error) -> &'static str {
    if error.downcast_ref::<Unknown>().is_some() {
        "unknown"
    } else {
        "refused"
    }
}
pub(crate) fn read(api: &mut dyn AppApi, path: &str) -> Result<Value> {
    api.get(path)
        .map_err(|_| Unknown("native integration observation unavailable; outcome unknown").into())
}
fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| Unknown("native list evidence missing; outcome unknown").into())
}

/// The native Git boundary must independently check object identity, signer,
/// ancestry and exclusive host configuration on every verification and push.
pub trait IntegrationGit {
    fn verify(&mut self, config: &Config, request: &IntegrationRequest) -> Result<()>;
    fn push(&mut self, config: &Config, request: &IntegrationRequest) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Observation {
    pub observed_at: u64,
    pub evidence: Value,
}

fn ruleset(config: &Config, r: &IntegrationRequest, value: &Value, update: bool) -> Result<()> {
    verify_ruleset(
        config,
        &r.target,
        if update {
            r.update_ruleset_id
        } else {
            r.quality_ruleset_id
        },
        r.ci.as_ref(),
        value,
        update,
    )
}

/// Inspect the selected protection independently of any proposed PR merge.
pub fn verify_ruleset(
    config: &Config,
    target: &str,
    id: u64,
    ci: Option<&crate::ci::Requirement>,
    value: &Value,
    update: bool,
) -> Result<()> {
    config.validate()?;
    ensure!(
        branch(target) && id > 0 && config.stack_base.as_deref() == Some(target),
        "Ruleset target binding differs"
    );
    if let Some(required) = ci {
        required.validate()?;
    }
    let app = config.github_app.as_ref().context("App missing")?;
    ensure!(
        value["id"].as_u64() == Some(id)
            && value["target"] == "branch"
            && value["enforcement"] == "active",
        "ruleset identity, target or enforcement changed"
    );
    ensure!(
        value["source_type"] == "Repository"
            && value["source"] == format!("{}/{}", config.owner, config.repository),
        "ruleset source repository mismatch"
    );
    if let Some(source_id) = value.get("source_id") {
        ensure!(
            source_id.as_u64() == config.expected_repository_id,
            "ruleset source numeric ID mismatch"
        );
    }
    ensure!(
        value["conditions"]
            == json!({"ref_name":{"include":[format!("refs/heads/{target}")],"exclude":[]}}),
        "ruleset does not apply exclusively to selected target"
    );
    let bypass = value.get("bypass_actors").map(array).transpose()?;
    let expected_caller = if update { "always" } else { "never" };
    if bypass.is_none() || value.get("current_user_can_bypass").is_some() {
        let caller = value["current_user_can_bypass"].as_str().ok_or(Unknown(
            "native caller bypass evidence unavailable; outcome unknown",
        ))?;
        ensure!(
            caller == expected_caller,
            "current App bypass policy differs from required split"
        );
    }
    if update {
        if let Some(bypass) = bypass {
            ensure!(
                bypass
                    == &vec![
                        json!({"actor_id":app.app_id,"actor_type":"Integration","bypass_mode":"always"})
                    ],
                "update bypass differs from selected App only"
            );
        }
        ensure!(
            value["rules"] == json!([{"type":"update"}])
                || value["rules"]
                    == json!([{"type":"update","parameters":{"update_allows_fetch_and_merge":false}}]),
            "update restriction changed"
        );
    } else {
        if let Some(bypass) = bypass {
            ensure!(
                bypass.is_empty(),
                "quality rules must have no bypass actors"
            );
        }
        let rules = array(&value["rules"])?;
        ensure!(
            rules.len() == 6,
            "quality rule set differs from required profile"
        );
        for kind in [
            "pull_request",
            "required_signatures",
            "required_linear_history",
            "deletion",
            "non_fast_forward",
            "required_status_checks",
        ] {
            let selected: Vec<_> = rules.iter().filter(|rule| rule["type"] == kind).collect();
            ensure!(selected.len() == 1, "quality rule missing or duplicated");
            let rule = selected[0];
            match kind {
                "pull_request" => {
                    let mut p = rule["parameters"].clone();
                    let object = p
                        .as_object_mut()
                        .context("native review parameters missing")?;
                    for (name, expected) in [
                        ("required_reviewers", json!([])),
                        (
                            "require_extra_approval_for_unattributed_changes",
                            json!(true),
                        ),
                        (
                            "allowed_merge_methods",
                            json!(["merge", "squash", "rebase"]),
                        ),
                    ] {
                        if let Some(actual) = object.remove(name) {
                            ensure!(
                                actual == expected,
                                "unsupported expanded native review policy"
                            );
                        }
                    }
                    ensure!(
                        p == json!({"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,"require_code_owner_review":false,"require_last_push_approval":false,"required_review_thread_resolution":true}),
                        "required native review policy changed"
                    );
                }
                "required_status_checks" => {
                    let mut actual = rule["parameters"].clone();
                    let checks = actual
                        .as_object_mut()
                        .context("status policy missing")?
                        .remove("required_status_checks")
                        .context("required status list missing")?;
                    let mut checks = array(&checks)?.clone();
                    let mut expected =
                        vec![json!({"context":"fixture/verify","integration_id":app.app_id})];
                    if let Some(ci) = ci {
                        expected.push(json!({"context":ci.check_name,"integration_id":ci.app_id}));
                    }
                    checks.sort_by_key(Value::to_string);
                    expected.sort_by_key(Value::to_string);
                    ensure!(
                        actual
                            == json!({"strict_required_status_checks_policy":true,"do_not_enforce_on_create":false})
                            && checks == expected,
                        "status requirement lost exact App source or strict policy"
                    );
                }
                _ => ensure!(
                    rule.get("parameters")
                        .is_none_or(|p| p.is_null() || p == &json!({})),
                    "unsupported quality rule parameters"
                ),
            }
        }
    }
    Ok(())
}
fn native_ref(api: &mut dyn AppApi, prefix: &str, name: &str, expected: &str) -> Result<Value> {
    let value = read(api, &format!("{prefix}/git/ref/heads/{}", encode(name)))?;
    ensure!(
        value["ref"] == format!("refs/heads/{name}")
            && value["object"]["type"] == "commit"
            && value["object"]["sha"] == expected,
        "native source or target reference changed"
    );
    Ok(json!({"ref":value["ref"],"sha":value["object"]["sha"]}))
}

/// Read-only native observations plus independent local signature/ancestry checks.
/// Successful inspection is a bounded observation, never permission to retry.
pub fn inspect(
    config: &Config,
    r: &IntegrationRequest,
    api: &mut dyn AppApi,
    git: &mut dyn IntegrationGit,
    clock: &dyn Clock,
) -> Result<Observation> {
    r.validate(config)?;
    git.verify(config, r)?;
    let prefix = format!("/repos/{}/{}", config.owner, config.repository);
    let repo = read(api, &prefix)?;
    config.validate_repository(&repo)?;
    let app = config.github_app.as_ref().context("App missing")?;
    let actor = format!("{}[bot]", app.slug);
    let bot = read(api, &format!("/users/{}", encode(&actor)))?;
    ensure!(
        bot["login"] == actor
            && bot["type"] == "Bot"
            && bot["id"].as_u64().is_some_and(|id| id > 0),
        "native App bot identity missing or changed"
    );
    let pr = read(api, &format!("{prefix}/pulls/{}", r.pr_number))?;
    ensure!(
        pr["number"].as_u64() == Some(r.pr_number)
            && pr["state"] == "open"
            && pr["draft"] == false
            && pr["merged"] == false,
        "PR must be open, unmerged and non-draft"
    );
    ensure!(
        pr["user"]["id"] == bot["id"]
            && pr["user"]["login"] == actor
            && pr["user"]["type"] == "Bot",
        "PR author differs from selected App"
    );
    for side in ["head", "base"] {
        ensure!(
            pr[side]["repo"]["id"].as_u64() == config.expected_repository_id,
            "PR repository identity changed"
        );
    }
    ensure!(
        pr["head"]["ref"] == r.source
            && pr["head"]["sha"] == r.expected_head
            && pr["base"]["ref"] == r.target
            && pr["base"]["sha"] == r.expected_target,
        "PR source, target or exact revision changed"
    );
    let conflict_review = if config.conflict_review.is_some() {
        let evidence = crate::conflict_review::verify_candidate(
            config,
            &r.expected_head,
            Some(&r.expected_target),
            true,
            true,
        )?
        .context("Conflict review evidence missing")?;
        crate::conflict_review::verify_display(
            pr["body"].as_str().context("Conflict PR body missing")?,
            evidence["body"]
                .as_str()
                .context("Conflict display missing")?,
            evidence["sha256"]
                .as_str()
                .context("Conflict digest missing")?,
        )?;
        Some(evidence)
    } else {
        None
    };
    let source = native_ref(api, &prefix, &r.source, &r.expected_head)?;
    let target = native_ref(api, &prefix, &r.target, &r.expected_target)?;
    let update = read(api, &format!("{prefix}/rulesets/{}", r.update_ruleset_id))?;
    let quality = read(api, &format!("{prefix}/rulesets/{}", r.quality_ruleset_id))?;
    ruleset(config, r, &update, true)?;
    ruleset(config, r, &quality, false)?;
    let effective = read(
        api,
        &format!("{prefix}/rules/branches/{}", encode(&r.target)),
    )?;
    let effective_rules = array(&effective)?;
    ensure!(
        effective_rules.len() == 7,
        "effective native rules incomplete or unsupported"
    );
    for policy in [&update, &quality] {
        for rule in array(&policy["rules"])? {
            let matches: Vec<_> = effective_rules
                .iter()
                .filter(|v| v["ruleset_id"] == policy["id"] && v["type"] == rule["type"])
                .collect();
            ensure!(
                matches.len() == 1,
                "pinned rule is not effective for selected branch"
            );
            let actual = matches[0];
            ensure!(
                actual["ruleset_source_type"] == "Repository"
                    && actual["ruleset_source"]
                        == format!("{}/{}", config.owner, config.repository)
                    && actual.get("parameters") == rule.get("parameters"),
                "effective rule source or parameters differ"
            );
        }
    }
    let ci = crate::ci::inspect(config, r, api)?;
    let mut reviews = Vec::new();
    let mut complete = false;
    for page in 1..=10 {
        let list = read(
            api,
            &format!(
                "{prefix}/pulls/{}/reviews?per_page=100&page={page}",
                r.pr_number
            ),
        )?;
        let list = array(&list)?;
        if list.len() > 100 {
            return Err(Unknown("review response exceeds page bound").into());
        }
        reviews.extend(list.iter().cloned());
        if list.len() < 100 {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err(Unknown("review pagination exceeds bound; outcome unknown").into());
    }
    let mut decisive = Vec::new();
    for review in &reviews {
        if review["user"]["id"].as_u64() != Some(r.reviewer.id) {
            continue;
        }
        ensure!(
            review["user"]["login"] == r.reviewer.login,
            "allowed reviewer login changed"
        );
        match review["state"].as_str() {
            Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED") => {
                let time = review["submitted_at"]
                    .as_str()
                    .context("review submission time missing")?;
                ensure!(
                    time.len() == 20 && time.ends_with('Z') && time.is_ascii(),
                    "unsupported review submission time"
                );
                let id = review["id"].as_u64().context("native review ID missing")?;
                decisive.push((time, id, review));
            }
            Some("COMMENTED" | "PENDING") => {}
            _ => bail!("native reviewer state unknown"),
        }
    }
    decisive.sort_by_key(|(time, id, _)| (*time, *id));
    let (_, _, review) = decisive
        .last()
        .context("no native approval from allowed reviewer")?;
    ensure!(
        review["state"] == "APPROVED" && review["commit_id"] == r.expected_head,
        "latest decisive native review does not approve exact candidate"
    );
    ensure!(
        !r.superseded_review_ids
            .contains(&review["id"].as_u64().context("review ID missing")?),
        "native approval was retained from an earlier candidate; a new human review is required"
    );
    let statuses = read(
        api,
        &format!(
            "{prefix}/commits/{}/status?per_page=100&page=1",
            r.expected_head
        ),
    )?;
    ensure!(
        statuses["sha"] == r.expected_head,
        "status commit binding differs from candidate"
    );
    let total = statuses["total_count"]
        .as_u64()
        .ok_or(Unknown("status count evidence missing"))?;
    if total > 100 {
        return Err(Unknown("combined status pagination exceeds bound").into());
    }
    let list = array(&statuses["statuses"])?;
    if total != list.len() as u64 {
        return Err(Unknown("status evidence incomplete").into());
    }
    let matching: Vec<_> = list
        .iter()
        .filter(|s| s["context"] == "fixture/verify")
        .collect();
    ensure!(
        matching.len() == 1,
        "exact required status missing or ambiguous"
    );
    let current_status = matching[0];
    ensure!(
        current_status["id"].as_u64().is_some_and(|id| id > 0),
        "native status identity missing"
    );
    ensure!(
        current_status["state"] == "success",
        "current required status is not successful"
    );
    // Combined statuses bind the current ID and commit but omit creator.
    // Native detailed statuses are newest first; never skip a newer required
    // context to recover an older successful or correctly authored entry.
    let mut detailed = None;
    for page in 1..=10 {
        let response = read(
            api,
            &format!(
                "{prefix}/commits/{}/statuses?per_page=100&page={page}",
                r.expected_head
            ),
        )?;
        let entries = array(&response)?;
        if entries.len() > 100 {
            return Err(Unknown("status detail response exceeds page bound").into());
        }
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry["context"] == "fixture/verify")
        {
            detailed = Some(entry.clone());
            break;
        }
        if entries.len() < 100 {
            break;
        }
    }
    let status = detailed.ok_or(Unknown(
        "current detailed status unavailable within bound; outcome unknown",
    ))?;
    ensure!(
        status["id"] == current_status["id"] && status["state"] == current_status["state"],
        "required status changed between native observations"
    );
    ensure!(
        status["state"] == "success"
            && status["creator"]["id"] == bot["id"]
            && status["creator"]["login"] == actor
            && status["creator"]["type"] == "Bot",
        "required status is not successful from selected App bot"
    );
    Ok(Observation {
        observed_at: clock.now()?,
        evidence: json!({
            "repository_id":repo["id"], "app_id":app.app_id, "bot_id":bot["id"],
            "pr":{"number":r.pr_number,"source":source,"target":target,"author_id":bot["id"]},
            "review":{"id":review["id"],"reviewer":r.reviewer,"commit_id":review["commit_id"],"state":review["state"],"submitted_at":review["submitted_at"]},
            "status":{"id":status["id"],"context":status["context"],"sha":statuses["sha"],"state":status["state"],"creator_id":bot["id"]},
            "ci":ci,"conflict_review":conflict_review,
            "roster_visibility":{"update":if update.get("bypass_actors").is_some() {"visible"} else {"hidden"},"quality":if quality.get("bypass_actors").is_some() {"visible"} else {"hidden"}},
            "bypass_scope":if update.get("bypass_actors").is_some() && quality.get("bypass_actors").is_some() {"all_configured_actors"} else {"current_app_only"},
            "update_ruleset":update,"quality_ruleset":quality,"effective_rules":effective
        }),
    })
}

pub fn integrate(
    config: &Config,
    r: &IntegrationRequest,
    api: &mut dyn AppApi,
    git: &mut dyn IntegrationGit,
    clock: &dyn Clock,
) -> Result<Value> {
    r.validate(config)?;
    ensure!(
        !r.receipt_dir.try_exists()?,
        "integration receipt already exists; reconcile rather than retry"
    );
    let first = inspect(config, r, api, git, clock)?;
    let journal = Journal::create(&r.receipt_dir, &r.scope(config)?)?;
    let final_observation = inspect(config, r, api, git, clock)?;
    ensure!(
        first.evidence == final_observation.evidence,
        "integration observations changed before dispatch"
    );
    ensure!(
        final_observation.observed_at >= first.observed_at,
        "host clock moved backwards"
    );
    let bypass_scope = final_observation.evidence["bypass_scope"].clone();
    let roster_visibility = final_observation.evidence["roster_visibility"].clone();
    journal.perform("integrate_signed_object", json!({"request":r,"observation":final_observation}), || {
        // The native boundary independently repeats identity/ancestry checks.
        // Only a typed, exact-ref rejection can acknowledge non-application.
        // Transport failures and errors writing this acknowledgement stay unknown.
        if let Err(error) = git.push(config, r) {
            if let Some(refusal) = error.downcast_ref::<PushRefusal>() {
                return Ok(json!({"outcome":"refused","pr_number":r.pr_number,"target":r.target,"oid":r.expected_head,"receipt_dir":r.receipt_dir,"push_refusal":refusal,"scope":"native Git explicitly rejected this selected ref update"}));
            }
            return Err(error);
        }
        let prefix = format!("/repos/{}/{}", config.owner, config.repository);
        native_ref(api, &prefix, &r.target, &r.expected_head)?;
        Ok(json!({"outcome":"integrated","pr_number":r.pr_number,"target":r.target,"oid":r.expected_head,"receipt_dir":r.receipt_dir,"scope":"exact signed object; lease guards target only","bypass_scope":bypass_scope,"roster_visibility":roster_visibility}))
    }, Clone::clone).map_err(|_| Unknown("integration effect outcome unknown; inspect the retained journal before any new attempt").into())
}

/// Linux host Git adapter. Repository contents and host trust files must have
/// one exclusive writer for the invocation; this does not establish isolation.
pub struct NativeGit {
    config_path: PathBuf,
}
impl NativeGit {
    pub fn new(config_path: &Path) -> Result<Self> {
        Ok(Self {
            config_path: config_path.canonicalize()?,
        })
    }
    fn command(&self, config: &Config, r: &IntegrationRequest) -> Result<Command> {
        let quote = |p: &Path| -> Result<String> {
            let s = p.to_str().context("host helper path is not UTF-8")?;
            ensure!(!s.chars().any(char::is_control), "invalid host helper path");
            Ok(format!("'{}'", s.replace('\'', "'\\''")))
        };
        let helper = format!(
            "!{} credential {}",
            quote(&std::env::current_exe()?.canonicalize()?)?,
            quote(&self.config_path)?
        );
        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .env("SSH_ASKPASS", "/bin/false")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .arg("-C")
            .arg(&config.workspace)
            .args([
                "-c",
                "credential.helper=",
                "-c",
                &format!("credential.helper={helper}"),
                "-c",
                "credential.useHttpPath=true",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "http.followRedirects=false",
                "-c",
                "http.sslVerify=true",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
                "-c",
                "gpg.format=ssh",
                "-c",
                "gpg.ssh.program=/usr/bin/ssh-keygen",
                "-c",
                "gpg.ssh.revocationFile=",
                "-c",
                "gpg.minTrustLevel=fully",
                "-c",
                &format!("gpg.ssh.allowedSignersFile={}", r.allowed_signers.display()),
                "-c",
                "push.followTags=false",
                "-c",
                "push.recurseSubmodules=no",
            ]);
        Ok(command)
    }
    fn output(&self, config: &Config, r: &IntegrationRequest, args: &[&str]) -> Result<Output> {
        self.command(config, r)?
            .args(args)
            .output()
            .map_err(|_| anyhow::anyhow!("native Git operation unavailable"))
    }
    fn text(&self, config: &Config, r: &IntegrationRequest, args: &[&str]) -> Result<String> {
        let output = self.output(config, r, args)?;
        ensure!(output.status.success(), "native Git verification failed");
        Ok(String::from_utf8(output.stdout)
            .context("invalid Git output encoding")?
            .trim()
            .to_owned())
    }
    fn config_guard(&self, config: &Config, r: &IntegrationRequest) -> Result<()> {
        host_path(config, &self.config_path)?;
        let keys = self.text(
            config,
            r,
            &[
                "config",
                "--local",
                "--no-includes",
                "--name-only",
                "--list",
            ],
        )?;
        for key in keys.lines() {
            let allowed = matches!(
                key,
                "core.repositoryformatversion"
                    | "core.filemode"
                    | "core.bare"
                    | "core.logallrefupdates"
                    | "core.hookspath"
                    | "remote.origin.url"
                    | "remote.origin.fetch"
                    | "credential.helper"
                    | "credential.usehttppath"
                    | "user.name"
                    | "user.email"
                    | "user.signingkey"
                    | "gpg.format"
                    | "gpg.ssh.allowedsignersfile"
                    | "commit.gpgsign"
            ) || key.starts_with("branch.")
                && (key.ends_with(".remote") || key.ends_with(".merge"));
            ensure!(
                allowed,
                "unsupported local Git configuration; no ambient transport or signing fallback allowed"
            );
        }
        ensure!(
            self.text(config, r, &["rev-parse", "--show-toplevel"])?
                == config.workspace.canonicalize()?.to_string_lossy(),
            "Git workspace root mismatch"
        );
        let git_dir = PathBuf::from(self.text(config, r, &["rev-parse", "--absolute-git-dir"])?)
            .canonicalize()?;
        ensure!(
            git_dir.starts_with(config.workspace.canonicalize()?),
            "external Git directory is unsupported"
        );
        for relative in ["shallow", "info/grafts", "config.worktree"] {
            ensure!(
                !git_dir.join(relative).try_exists()?,
                "shallow, grafted or worktree Git metadata is unsupported"
            );
        }
        ensure!(
            self.text(config, r, &["remote"])? == "origin",
            "exactly the selected origin is required"
        );
        ensure!(
            self.text(config, r, &["config", "--get-all", "remote.origin.url"])?
                == remote_url(config),
            "origin differs from pinned repository"
        );
        let trust = std::fs::symlink_metadata(&r.allowed_signers)?;
        ensure!(
            trust.is_file() && trust.len() > 0 && trust.len() <= 16_384,
            "signer trust must be a bounded regular host file"
        );
        let signers = std::fs::read_to_string(&r.allowed_signers)?;
        ensure!(
            signers
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
                .count()
                == 1,
            "select one explicit SSH signer entry"
        );
        Ok(())
    }
}
impl IntegrationGit for NativeGit {
    fn verify(&mut self, config: &Config, r: &IntegrationRequest) -> Result<()> {
        r.validate(config)?;
        self.config_guard(config, r)?;
        crate::conflict_review::verify_candidate(
            config,
            &r.expected_head,
            Some(&r.expected_target),
            true,
            true,
        )?;
        ensure!(
            self.text(config, r, &["rev-parse", "--verify", "HEAD^{commit}"])? == r.expected_head,
            "local HEAD differs from exact candidate"
        );
        ensure!(
            self.text(config, r, &["cat-file", "-t", &r.expected_head])? == "commit",
            "candidate commit is not local"
        );
        ensure!(
            self.output(config, r, &["verify-commit", &r.expected_head])?
                .status
                .success(),
            "candidate SSH signature failed selected signer verification"
        );
        ensure!(
            self.output(
                config,
                r,
                &[
                    "merge-base",
                    "--is-ancestor",
                    &r.expected_target,
                    &r.expected_head
                ]
            )?
            .status
            .success(),
            "expected target is not an ancestor of candidate"
        );
        ensure!(
            self.text(
                config,
                r,
                &[
                    "rev-list",
                    "--merges",
                    &format!("{}..{}", r.expected_target, r.expected_head)
                ]
            )?
            .is_empty(),
            "candidate introduces merge commits"
        );
        Ok(())
    }
    fn push(&mut self, config: &Config, r: &IntegrationRequest) -> Result<()> {
        self.verify(config, r)?;
        let output = self
            .command(config, r)?
            .args(r.push_arguments())
            .output()
            .map_err(|_| anyhow::anyhow!("native Git push unavailable; outcome unknown"))?;
        classify_push_result(r, output.status.success(), &output.stdout)
    }
}

/// CLI output contains only sanitized evidence. Errors never include provider
/// bodies, transport diagnostics, credentials or Git child-process output.
pub fn run(config: &Config, config_path: &Path, request_path: &Path, write: bool) -> Result<Value> {
    let request = IntegrationRequest::load(config, request_path)?;
    let credential = app::mint(config)
        .map_err(|_| Unknown("App authentication unavailable; integration not dispatched"))?;
    let mut client = jjpr::forge::ForgeClient::new(
        &config.endpoint,
        credential.value(&app::SystemClock)?.to_owned(),
        jjpr::forge::AuthScheme::Bearer,
        jjpr::forge::PaginationStyle::LinkHeader,
    );
    let mut git = NativeGit::new(config_path)?;
    if write {
        integrate(config, &request, &mut client, &mut git, &app::SystemClock)
    } else {
        Ok(
            json!({"outcome":"observed","request":request,"observation":inspect(config, &request, &mut client, &mut git, &app::SystemClock)?,"scope":"read-only bounded observation; no atomic provider snapshot"}),
        )
    }
}
