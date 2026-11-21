//! Host-owned configuration and entry points over the pinned jjpr library.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use anyhow::{Context, Result, ensure};
use jjpr::forge::{
    AuthScheme, Forge, ForgeClient, ForgeKind, ForgejoForge, GitHubForge, PaginationStyle,
};
use serde::Deserialize;
use std::{io::Read, path::PathBuf};

pub mod app;
pub mod ci;
pub mod conflict_review;
pub mod effects;
pub mod integration;
pub mod lifecycle;
pub mod setup;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub task: String,
    pub receipt_dir: PathBuf,
    #[serde(default)]
    pub prior_receipts: Vec<PathBuf>,
    #[serde(default)]
    pub bookmarks: std::collections::BTreeMap<String, String>,
    /// A revision-only task binds every candidate to an already existing PR.
    #[serde(default)]
    pub revision_prs: std::collections::BTreeMap<String, u64>,
}

impl Publication {
    pub fn validate_revisions(
        &self,
        observed: &std::collections::BTreeMap<String, u64>,
        creation_count: usize,
    ) -> Result<()> {
        if self.revision_prs.is_empty() {
            return Ok(());
        }
        ensure!(
            self.revision_prs.keys().eq(self.bookmarks.keys())
                && self.revision_prs.values().all(|number| *number > 0)
                && &self.revision_prs == observed
                && creation_count == 0,
            "revision-only publication requires the same existing PRs; replacement creation refused"
        );
        Ok(())
    }

    pub fn validate_candidates(
        &self,
        observed: &std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        ensure!(
            !self.bookmarks.is_empty(),
            "publication requires exact checked bookmark/OID bindings"
        );
        ensure!(
            &self.bookmarks == observed,
            "planned bookmarks differ from the checked host candidates"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    Forgejo,
    Github,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    #[default]
    Private,
    Public,
}

/// Trusted host settings, never read from a sandbox export.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub provider: Provider,
    #[serde(default)]
    pub visibility: Visibility,
    pub endpoint: String,
    pub owner: String,
    pub repository: String,
    pub workspace: PathBuf,
    pub token_file: Option<PathBuf>,
    pub gh_cli: Option<PathBuf>,
    pub github_app: Option<app::GitHubApp>,
    pub expected_actor: Option<String>,
    pub expected_repository_id: Option<u64>,
    pub stack_base: Option<String>,
    pub publication: Option<Publication>,
    /// Host-selected review context for a known conflict resolution.
    #[serde(default)]
    pub conflict_review: Option<conflict_review::Artifact>,
    #[serde(default)]
    pub reviewers: Vec<String>,
}

fn identifier(value: &str, dots: bool) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || (dots && b == b'.'))
}

fn resolved(path: &std::path::Path) -> Result<PathBuf> {
    if path.try_exists()? {
        return Ok(path.canonicalize()?);
    }
    let parent = path.parent().context("path has no existing ancestor")?;
    Ok(resolved(parent)?.join(path.file_name().context("invalid host path")?))
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if let Some(base) = &self.stack_base {
            ensure!(!base.is_empty() && base.len() <= 1024, "invalid stack base");
            let output = std::process::Command::new("git")
                .args(["check-ref-format", &format!("refs/heads/{base}")])
                .output()
                .context("cannot validate Git stack base")?;
            ensure!(
                output.status.success(),
                "stack base must be a Git branch name"
            );
        }
        match self.provider {
            Provider::Github => {
                ensure!(
                    self.endpoint == "https://api.github.com",
                    "GitHub requires the exact HTTPS API origin"
                );
                ensure!(
                    self.expected_actor
                        .as_ref()
                        .is_some_and(|v| match &self.github_app {
                            Some(app) => v == &format!("{}[bot]", app.slug),
                            None => identifier(v, false),
                        }),
                    "GitHub requires an explicit expected actor"
                );
            }
            Provider::Forgejo => {
                let port = self
                    .endpoint
                    .strip_prefix("http://127.0.0.1:")
                    .context("Forgejo is limited to the numeric loopback Docker fixture")?;
                ensure!(
                    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
                    "invalid endpoint port"
                );
                ensure!(port.parse::<u16>()? != 0, "port must be nonzero");
                ensure!(
                    self.gh_cli.is_none() && self.github_app.is_none(),
                    "GitHub login cannot supply Forgejo authentication"
                );
            }
        }
        ensure!(
            identifier(&self.owner, false) && identifier(&self.repository, true),
            "invalid repository identity"
        );
        ensure!(
            self.reviewers.iter().all(|v| identifier(v, false)),
            "invalid reviewer identity"
        );
        ensure!(self.workspace.is_absolute(), "workspace must be absolute");
        ensure!(
            !self
                .workspace
                .components()
                .any(|c| c == std::path::Component::ParentDir),
            "parent path components are forbidden"
        );
        if let Some(publication) = &self.publication {
            ensure!(
                !publication.task.trim().is_empty(),
                "publication task is required"
            );
            for path in std::iter::once(&publication.receipt_dir).chain(&publication.prior_receipts)
            {
                ensure!(
                    path.is_absolute()
                        && !path.starts_with(&self.workspace)
                        && !path
                            .components()
                            .any(|c| c == std::path::Component::ParentDir),
                    "publication receipts must be outside the project without parent traversal"
                );
            }
        }
        ensure!(
            usize::from(self.token_file.is_some())
                + usize::from(self.gh_cli.is_some())
                + usize::from(self.github_app.is_some())
                == 1,
            "select exactly one host authentication source: github_app, token_file or gh_cli"
        );
        for path in self.token_file.iter().chain(self.gh_cli.iter()).chain(
            self.github_app
                .iter()
                .flat_map(|a| [&a.private_key, &a.openssl]),
        ) {
            ensure!(
                path.is_absolute()
                    && !path.starts_with(&self.workspace)
                    && !path
                        .components()
                        .any(|c| c == std::path::Component::ParentDir),
                "authentication source must be absolute and outside the project without parent traversal"
            );
        }
        if let Some(app) = &self.github_app {
            ensure!(
                app.app_id > 0 && app.installation_id > 0 && identifier(&app.slug, false),
                "invalid App identity"
            );
            ensure!(
                self.expected_repository_id.is_some_and(|id| id > 0),
                "App authentication requires the retained numeric repository ID"
            );
        }
        Ok(())
    }

    /// Resolve existing ancestors as well as symlinks, including paths that will
    /// only be created later. This does not reserve paths against another writer.
    pub fn validate_host_paths(&self) -> Result<()> {
        self.validate()?;
        let workspace = resolved(&self.workspace)?;
        for path in self.token_file.iter().chain(self.gh_cli.iter()).chain(
            self.github_app
                .iter()
                .flat_map(|a| [&a.private_key, &a.openssl]),
        ) {
            ensure!(
                !resolved(path)?.starts_with(&workspace),
                "authentication source resolves inside workspace"
            );
        }
        if let Some(review) = &self.conflict_review {
            review.validate(&self.workspace)?;
        }
        if let Some(publication) = &self.publication {
            for path in std::iter::once(&publication.receipt_dir).chain(&publication.prior_receipts)
            {
                ensure!(
                    !resolved(path)?.starts_with(&workspace),
                    "receipt path resolves inside workspace"
                );
            }
        }
        Ok(())
    }

    pub fn validate_repository(&self, repo: &serde_json::Value) -> Result<()> {
        ensure!(
            repo["private"].as_bool() == Some(self.visibility == Visibility::Private),
            "repository visibility differs from the explicit host selection"
        );
        ensure!(
            repo["full_name"].as_str().is_some_and(
                |v| v.eq_ignore_ascii_case(&format!("{}/{}", self.owner, self.repository))
            ),
            "repository response identity mismatch"
        );
        let id = repo["id"].as_u64().context("repository ID missing")?;
        if let Some(expected) = self.expected_repository_id {
            ensure!(
                id == expected,
                "repository was replaced or selected incorrectly"
            );
        }
        Ok(())
    }

    /// Check host-selected API identity and Git destination before fetching.
    pub fn validate_binding(&self, actor: &str, remotes: &[(String, String)]) -> Result<()> {
        self.validate()?;
        if let Some(expected) = &self.expected_actor {
            ensure!(
                actor.eq_ignore_ascii_case(expected),
                "authenticated actor differs from host configuration"
            );
        }
        ensure!(
            remotes.len() == 1 && remotes[0].0 == "origin",
            "exactly one origin remote is required"
        );
        let urls = match self.provider {
            Provider::Github if self.github_app.is_some() => vec![format!(
                "https://github.com/{}/{}.git",
                self.owner, self.repository
            )],
            Provider::Github => vec![
                format!("https://github.com/{}/{}.git", self.owner, self.repository),
                format!("git@github.com:{}/{}.git", self.owner, self.repository),
            ],
            Provider::Forgejo => vec![format!(
                "{}/{}/{}.git",
                self.endpoint, self.owner, self.repository
            )],
        };
        ensure!(
            urls.contains(&remotes[0].1),
            "Git remote differs from host-selected repository"
        );
        Ok(())
    }

    fn token(&self) -> Result<String> {
        self.validate_host_paths()?;
        let token = if let Some(path) = &self.token_file {
            let metadata = std::fs::symlink_metadata(path)?;
            ensure!(
                metadata.is_file() && metadata.len() <= 16_384,
                "token file must be a bounded regular file"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    metadata.permissions().mode() & 0o077 == 0,
                    "token file must be private to the host user"
                );
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(16_385)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 16_384, "token file exceeds limit");
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Secret {
                token: String,
            }
            serde_json::from_slice::<Secret>(&bytes)
                .context("invalid host token file")?
                .token
        } else {
            let gh = self.gh_cli.as_ref().context("missing GitHub CLI")?;
            // Capture stdout privately; never print the token or pass it in argv.
            let output = std::process::Command::new(gh)
                .args(["auth", "token", "--hostname", "github.com"])
                .env_remove("GH_TOKEN")
                .env_remove("GITHUB_TOKEN")
                .output()
                .context("cannot invoke host GitHub CLI")?;
            ensure!(
                output.status.success(),
                "GitHub host login unavailable; run gh auth login --hostname github.com --web"
            );
            String::from_utf8(output.stdout)
                .context("invalid host credential encoding")?
                .trim()
                .to_owned()
        };
        ensure!(
            !token.is_empty() && token.len() <= 16_384 && !token.chars().any(char::is_whitespace),
            "invalid host credential"
        );
        Ok(token)
    }

    fn connect(&self) -> Result<(ForgeClient, Box<dyn Forge>)> {
        let installation = if self.github_app.is_some() {
            Some(app::mint(self)?)
        } else {
            None
        };
        let token = match &installation {
            Some(credential) => credential.value(&app::SystemClock)?.to_owned(),
            None => self.token()?,
        };
        let (base, auth, pagination) = match self.provider {
            Provider::Github => (
                self.endpoint.clone(),
                AuthScheme::Bearer,
                PaginationStyle::LinkHeader,
            ),
            Provider::Forgejo => (
                format!("{}/api/v1", self.endpoint),
                AuthScheme::Token,
                PaginationStyle::PageNumber { limit: 50 },
            ),
        };
        let client = ForgeClient::new(&base, token, auth, pagination);
        let forge: Box<dyn Forge> = match self.provider {
            Provider::Github => {
                let github = Box::new(GitHubForge::new(client.clone()));
                match installation {
                    Some(credential) => Box::new(app::AppForge::new(
                        github,
                        credential,
                        std::sync::Arc::new(app::SystemClock),
                    )),
                    None => github,
                }
            }
            Provider::Forgejo => Box::new(ForgejoForge::new(client.clone())),
        };
        Ok((client, forge))
    }

    fn repository_response(&self, client: &ForgeClient) -> Result<serde_json::Value> {
        let response = client.get(&format!("/repos/{}/{}", self.owner, self.repository));
        if self.github_app.is_some() {
            response.map_err(|_| anyhow::anyhow!("GitHub App repository request failed"))
        } else {
            response
        }
    }

    /// Load a trusted host file, including before the destination exists.
    pub fn load_host(path: &std::path::Path) -> Result<Self> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir),
            "host configuration path must be absolute without parent traversal"
        );
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "host configuration exceeds limit");
        let config: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid host configuration"))?;
        config.validate_host_paths()?;
        ensure!(
            !resolved(path)?.starts_with(resolved(&config.workspace)?),
            "host configuration must remain outside the project"
        );
        Ok(config)
    }

    /// Read-only account/repository check. No repository creation or policy edits.
    pub fn preflight(&self) -> Result<serde_json::Value> {
        let (client, forge) = self.connect()?;
        let actor = forge.get_authenticated_user()?;
        if let Some(expected) = &self.expected_actor {
            ensure!(
                actor.eq_ignore_ascii_case(expected),
                "authenticated actor differs from host configuration"
            );
        }
        let repo = self.repository_response(&client)?;
        self.validate_repository(&repo)?;
        Ok(
            serde_json::json!({"actor":actor,"repository_id":repo["id"],"repository":repo["full_name"],"private":repo["private"],"default_branch":repo["default_branch"],"permissions":repo["permissions"],"scope":"read-only; protections, signing and review remain unqualified"}),
        )
    }

    /// Ordinary host-only publication; never establishes LO task authority.
    pub fn submit(&self, bookmark: &str, dry_run: bool) -> Result<()> {
        use jjpr::{
            config::StackNavMode,
            forge::{RepoInfo, ReviewerScope},
            jj::{Jj, runner::JjRunner},
            submit::{
                analyze::analyze_submission_graph,
                execute::execute_submission_plan,
                plan::{DraftMode, SubmitOptions, create_submission_plan},
                resolve::resolve_bookmark_selections,
            },
        };
        self.validate()?;
        ensure!(
            dry_run || self.publication.is_some(),
            "submit requires an explicit publication task and new receipt directory"
        );
        ensure!(
            dry_run || self.provider != Provider::Github || self.expected_repository_id.is_some(),
            "GitHub submit requires the retained numeric repository ID"
        );
        let (client, forge) = self.connect()?;
        let mut jj = JjRunner::new(self.workspace.clone())?;
        let remotes = jj
            .get_git_remotes()?
            .into_iter()
            .map(|r| (r.name, r.url))
            .collect::<Vec<_>>();
        self.validate_binding(&forge.get_authenticated_user()?, &remotes)?;
        let repository = self.repository_response(&client)?;
        self.validate_repository(&repository)?;
        let default_branch = repository["default_branch"]
            .as_str()
            .context("repository has no default branch")?;
        jj.set_fetch_remote(Some("origin".into()));
        jj.git_fetch()?;
        let graph = jjpr::graph::change_graph::build_change_graph(&jj)?;
        let analysis = analyze_submission_graph(&graph, bookmark)?;
        let segments = resolve_bookmark_selections(&analysis.relevant_segments, false)?;
        let options = SubmitOptions {
            draft_mode: DraftMode::Default,
            reviewers: &self.reviewers,
            reviewer_scope: ReviewerScope::All,
            stack_base: self.stack_base.as_deref(),
            stack_nav: StackNavMode::Comment,
            dry_run,
        };
        let repo = RepoInfo {
            owner: self.owner.clone(),
            repo: self.repository.clone(),
        };
        let kind = match self.provider {
            Provider::Github => ForgeKind::GitHub,
            Provider::Forgejo => ForgeKind::Forgejo,
        };
        let mut plan = create_submission_plan(
            forge.as_ref(),
            &segments,
            "origin",
            &repo,
            kind,
            default_branch,
            &options,
        )?;
        if dry_run {
            execute_submission_plan(&jj, forge.as_ref(), &plan)
        } else {
            let publication = self
                .publication
                .as_ref()
                .context("missing publication binding")?;
            // jjpr's display model abbreviates object IDs. Resolve through jj's
            // unique change lookup before comparing full checked object IDs.
            for bookmark in &mut plan.all_bookmarks {
                bookmark.commit_id = effects::resolve_bookmark_oid(&jj, bookmark)?;
            }
            let candidates = plan
                .all_bookmarks
                .iter()
                .map(|b| (b.name.clone(), b.commit_id.clone()))
                .collect();
            publication.validate_candidates(&candidates)?;
            for (name, head) in &candidates {
                // A child review is scoped to its planned base, not every
                // already-reviewed parent in the stack.
                let base = plan
                    .bookmarks_needing_base_update
                    .iter()
                    .find(|p| p.bookmark.name == *name)
                    .map(|p| p.expected_base.as_str())
                    .or_else(|| {
                        plan.bookmarks_needing_pr
                            .iter()
                            .find(|p| p.bookmark.name == *name)
                            .map(|p| p.base_branch.as_str())
                    })
                    .or_else(|| {
                        plan.existing_prs
                            .get(name)
                            .map(|p| p.base.ref_name.as_str())
                    })
                    .unwrap_or(self.stack_base.as_deref().unwrap_or(default_branch));
                let target_oid = if let Some(oid) = candidates.get(base) {
                    oid.clone()
                } else {
                    setup::native::git(
                        &self.workspace,
                        &["rev-parse", &format!("refs/remotes/origin/{base}")],
                    )?
                };
                if let Some(review) =
                    conflict_review::verify_candidate(self, head, Some(&target_oid), true, false)?
                {
                    let planned_body = plan
                        .bookmarks_needing_pr
                        .iter()
                        .find(|p| p.bookmark.name == *name)
                        .map(|p| p.body.as_str())
                        .or_else(|| {
                            plan.bookmarks_needing_body_update
                                .iter()
                                .find(|p| p.bookmark.name == *name)
                                .map(|p| p.new_body.as_str())
                        })
                        .or_else(|| plan.existing_prs.get(name).and_then(|p| p.body.as_deref()))
                        .context("Conflict PR display is not selected by the publication plan")?;
                    conflict_review::verify_display(
                        planned_body,
                        review["body"].as_str().context("Review body missing")?,
                        review["sha256"].as_str().context("Review digest missing")?,
                    )?;
                }
            }
            let revisions = plan
                .existing_prs
                .iter()
                .filter(|(name, _)| candidates.contains_key(*name))
                .map(|(name, pr)| (name.clone(), pr.number))
                .collect();
            publication.validate_revisions(&revisions, plan.bookmarks_needing_pr.len())?;
            let actor = forge.get_authenticated_user()?;
            let scope = effects::Scope::from_plan(
                &publication.task,
                &actor,
                &remotes[0].1,
                &plan,
                forge.as_ref(),
                &publication.prior_receipts,
            )?;
            let session =
                effects::Session::create(scope, &publication.receipt_dir, &jj, forge.as_ref())?;
            let result = execute_submission_plan(&session, &session, &plan);
            // Upstream can report navigation errors and still return success.
            // The boundary's unresolved/refused outcome must remain observable.
            let complete = session.ensure_complete();
            result.and(complete)
        }
    }
}
