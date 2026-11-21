//! Host-only publication boundary over jjpr's provider-neutral interfaces.
//!
//! This is an experimental conventional dispatcher, not LO/GNAP authority.
//! Remote reads are observations: PR mutations have no atomic revision condition.
//! The caller owns the scope, credentials, exclusive workspace and receipt chain.
use anyhow::{Context, Result, bail, ensure};
use jjpr::{forge::*, jj::*, submit::plan::SubmissionPlan};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BookmarkBinding {
    pub change_id: String,
    pub oid: String,
    pub expected_remote: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrBinding {
    pub head: String,
    pub base: String,
    pub body: Option<String>,
}

/// Constructed from host-selected task inputs, never from agent-authored files.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scope {
    pub task: String,
    pub actor: String,
    pub owner: String,
    pub repository: String,
    pub remote_url: String,
    pub bookmarks: BTreeMap<String, BookmarkBinding>,
    pub bases: BTreeMap<String, String>,
    pub reviewers: Vec<String>,
    /// Existing PR number to owned head bookmark.
    pub prs: BTreeMap<u64, PrBinding>,
    /// Known host-created navigation comment ID to PR number and last body.
    pub comments: BTreeMap<u64, (u64, String)>,
}

impl Scope {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.task.is_empty()
                && !self.actor.is_empty()
                && !self.owner.is_empty()
                && !self.repository.is_empty(),
            "missing scope identity"
        );
        ensure!(
            !self.remote_url.is_empty() && !self.bookmarks.is_empty(),
            "missing remote or bookmarks"
        );
        for (name, b) in &self.bookmarks {
            ensure!(
                !name.is_empty() && !self.bases.contains_key(name),
                "publication bookmark overlaps protected base"
            );
            ensure!(
                !b.change_id.is_empty()
                    && oid(&b.oid)
                    && b.expected_remote.as_deref().is_none_or(oid),
                "invalid frozen bookmark"
            );
        }
        ensure!(self.bases.values().all(|v| oid(v)), "invalid frozen base");
        ensure!(
            self.prs
                .values()
                .all(|v| self.bookmarks.contains_key(&v.head)),
            "PR outside scope"
        );
        ensure!(
            self.comments
                .values()
                .all(|(pr, _)| self.prs.contains_key(pr)),
            "comment outside scope"
        );
        Ok(())
    }
    pub fn repository(&self, owner: &str, repo: &str) -> Result<()> {
        ensure!(
            owner == self.owner && repo == self.repository,
            "repository outside task scope"
        );
        Ok(())
    }
    pub fn bookmark(&self, name: &str, change: &str, commit: &str) -> Result<()> {
        let b = self
            .bookmarks
            .get(name)
            .context("bookmark outside task scope")?;
        ensure!(
            b.change_id == change && b.oid == commit,
            "bookmark content changed after planning"
        );
        Ok(())
    }
    /// Freeze observations after the host has selected a task's stack. Earlier
    /// receipts must be provided in order; missing receipts are not recoverable
    /// from comment markers (the upstream comment model does not expose author).
    pub fn from_plan(
        task: &str,
        actor: &str,
        remote_url: &str,
        plan: &SubmissionPlan,
        forge: &dyn Forge,
        prior: &[PathBuf],
    ) -> Result<Self> {
        ensure!(
            plan.remote_name == "origin",
            "only the explicitly bound origin is supported"
        );
        let owner = &plan.repo_info.owner;
        let repo = &plan.repo_info.repo;
        let mut scope = Self {
            task: task.into(),
            actor: actor.into(),
            owner: owner.clone(),
            repository: repo.clone(),
            remote_url: remote_url.into(),
            bookmarks: BTreeMap::new(),
            bases: BTreeMap::new(),
            reviewers: plan.reviewers.clone(),
            prs: BTreeMap::new(),
            comments: BTreeMap::new(),
        };
        for b in &plan.all_bookmarks {
            scope.bookmarks.insert(
                b.name.clone(),
                BookmarkBinding {
                    change_id: b.change_id.clone(),
                    oid: b.commit_id.clone(),
                    expected_remote: forge.get_branch_head(owner, repo, &b.name)?,
                },
            );
        }
        let mut bases = vec![plan.default_branch.clone()];
        bases.extend(
            plan.bookmarks_needing_pr
                .iter()
                .map(|p| p.base_branch.clone()),
        );
        bases.extend(
            plan.bookmarks_needing_base_update
                .iter()
                .map(|p| p.expected_base.clone()),
        );
        for pr in plan.existing_prs.values() {
            if scope.bookmarks.contains_key(&pr.head.ref_name) {
                ensure!(pr.author == actor, "existing PR belongs to another actor");
                scope.prs.insert(
                    pr.number,
                    PrBinding {
                        head: pr.head.ref_name.clone(),
                        base: pr.base.ref_name.clone(),
                        body: pr.body.clone(),
                    },
                );
                bases.push(pr.base.ref_name.clone());
            }
        }
        for base in bases {
            if !scope.bookmarks.contains_key(&base) {
                let commit = forge
                    .get_branch_head(owner, repo, &base)?
                    .context("base missing")?;
                scope.bases.insert(base, commit);
            }
        }
        for directory in prior {
            let old: Scope = serde_json::from_slice(&fs::read(directory.join("scope.json"))?)?;
            ensure!(
                old.task == scope.task
                    && old.actor == scope.actor
                    && old.owner == scope.owner
                    && old.repository == scope.repository
                    && old.remote_url == scope.remote_url,
                "prior receipt scope mismatch"
            );
            let mut entries = fs::read_dir(directory)?
                .map(|item| item.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            for path in entries {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("invalid receipt name")?;
                if let Some(number) = name.strip_suffix(".intent.json") {
                    let outcome: Value = serde_json::from_slice(
                        &fs::read(directory.join(format!("{number}.ok.json")))
                            .context("prior outcome unknown; reconcile before a new publication")?,
                    )?;
                    if let (Some(id), Some(pr), Some(body)) = (
                        outcome["result"]["comment"].as_u64(),
                        outcome["result"]["pr"].as_u64(),
                        outcome["result"]["body"].as_str(),
                    ) && scope.prs.contains_key(&pr)
                    {
                        scope.comments.insert(id, (pr, body.into()));
                    }
                }
            }
        }
        scope.validate()?;
        Ok(scope)
    }
}
fn oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Resolve jjpr's display abbreviation through the repository's change lookup.
/// A matching prefix alone is never an authorization object: exactly one full
/// object must be returned, and ambiguity/divergence is rejected.
pub fn resolve_bookmark_oid(jj: &dyn Jj, bookmark: &Bookmark) -> Result<String> {
    let displayed = &bookmark.commit_id;
    ensure!(
        (12..=64).contains(&displayed.len()) && displayed.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid jjpr bookmark object display"
    );
    let candidates = jj.resolve_change_id(&bookmark.change_id)?;
    let [full] = candidates.as_slice() else {
        bail!("bookmark change must resolve to exactly one full object");
    };
    ensure!(
        oid(full) && full.starts_with(displayed),
        "resolved object does not match bookmark display"
    );
    Ok(full.clone())
}

/// One create-only publication attempt. Never automatically replays unknowns.
/// A crash before acknowledgement can leave a completed remote effect unknown.
pub struct Journal {
    directory: PathBuf,
    scope: Scope,
    state: Mutex<(u64, bool)>,
}
impl Journal {
    pub fn create(directory: &Path, scope: &Scope) -> Result<Self> {
        scope.validate()?;
        fs::create_dir(directory).context("receipt directory already exists or cannot be created; do not retry an uncertain attempt")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        write_new(&directory.join("scope.json"), &serde_json::to_value(scope)?)?;
        if let Some(parent) = directory.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            directory: directory.into(),
            scope: scope.clone(),
            state: Mutex::new((0, false)),
        })
    }
    pub fn perform<T>(
        &self,
        operation: &str,
        payload: Value,
        effect: impl FnOnce() -> Result<T>,
        receipt: impl FnOnce(&T) -> Value,
    ) -> Result<T> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("publication lock poisoned"))?;
        ensure!(
            !state.1,
            "earlier effect outcome unknown; reconciliation required"
        );
        let number = state.0;
        // Mark unknown before any I/O: even a failed journal write cannot permit
        // another effect to proceed using a damaged attempt.
        state.1 = true;
        write_new(
            &self.directory.join(format!("{number:06}.intent.json")),
            &json!({"scope":self.scope,"operation":operation,"payload":payload}),
        )?;
        let value = effect()?;
        write_new(
            &self.directory.join(format!("{number:06}.ok.json")),
            &json!({"result":receipt(&value)}),
        )?;
        state.0 += 1;
        state.1 = false;
        Ok(value)
    }
}
fn write_new(path: &Path, value: &Value) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    File::open(path.parent().context("receipt parent missing")?)?.sync_all()?;
    Ok(())
}

/// Use the same Session for both arguments to jjpr's execute_submission_plan.
/// The host must prevent other local writers during this bounded invocation.
pub struct Session<'a> {
    scope: Scope,
    journal: Journal,
    jj: &'a dyn Jj,
    forge: &'a dyn Forge,
    prs: Mutex<BTreeMap<u64, PrBinding>>,
    failed: AtomicBool,
    comments: Mutex<BTreeMap<u64, (u64, String)>>,
}
impl<'a> Session<'a> {
    pub fn create(
        scope: Scope,
        directory: &Path,
        jj: &'a dyn Jj,
        forge: &'a dyn Forge,
    ) -> Result<Self> {
        scope.validate()?;
        ensure!(
            forge.get_authenticated_user()? == scope.actor,
            "authenticated actor mismatch"
        );
        let remotes = jj.get_git_remotes()?;
        ensure!(
            remotes.len() == 1 && remotes[0].name == "origin" && remotes[0].url == scope.remote_url,
            "Git remote differs from frozen host scope"
        );
        let journal = Journal::create(directory, &scope)?;
        Ok(Self {
            prs: Mutex::new(scope.prs.clone()),
            failed: AtomicBool::new(false),
            comments: Mutex::new(scope.comments.clone()),
            scope,
            journal,
            jj,
            forge,
        })
    }
    /// Must be called even when upstream reports successful submission: jjpr
    /// treats navigation-comment errors as warnings.
    pub fn ensure_complete(&self) -> Result<()> {
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "publication included a refused or failed operation"
        );
        let state = self
            .journal
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("publication lock poisoned"))?;
        ensure!(!state.1, "publication has an unknown effect outcome");
        Ok(())
    }
    fn checked<T>(&self, call: impl FnOnce() -> Result<T>) -> Result<T> {
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "earlier publication operation failed; replan or reconcile first"
        );
        let result = call();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    fn actor(&self, o: &str, r: &str) -> Result<()> {
        self.scope.repository(o, r)?;
        ensure!(
            self.forge.get_authenticated_user()? == self.scope.actor,
            "authenticated actor changed"
        );
        Ok(())
    }
    fn base(&self, name: &str) -> Result<()> {
        let wanted = self
            .scope
            .bases
            .get(name)
            .or_else(|| self.scope.bookmarks.get(name).map(|b| &b.oid))
            .context("base outside task scope")?;
        ensure!(
            self.forge
                .get_branch_head(&self.scope.owner, &self.scope.repository, name)?
                .as_ref()
                == Some(wanted),
            "base changed after planning"
        );
        Ok(())
    }
    fn pr(&self, o: &str, r: &str, n: u64) -> Result<PullRequest> {
        self.actor(o, r)?;
        let binding = self
            .prs
            .lock()
            .map_err(|_| anyhow::anyhow!("PR map poisoned"))?
            .get(&n)
            .cloned()
            .context("PR outside task scope")?;
        let b = self
            .scope
            .bookmarks
            .get(&binding.head)
            .context("PR bookmark missing")?;
        let (pr, state) = self.forge.get_pr(o, r, n)?;
        ensure!(
            is_open(&state)
                && pr.author == self.scope.actor
                && pr.head.ref_name == binding.head
                && pr.head.sha == b.oid
                && pr.base.ref_name == binding.base
                && pr.body == binding.body,
            "PR revision, owner, body or base changed after planning"
        );
        self.base(&pr.base.ref_name)?;
        Ok(pr)
    }
    fn comment(&self, o: &str, r: &str, id: u64) -> Result<(u64, String)> {
        let known = self
            .comments
            .lock()
            .map_err(|_| anyhow::anyhow!("comment map poisoned"))?
            .get(&id)
            .cloned()
            .context("comment has no retained ownership receipt")?;
        self.pr(o, r, known.0)?;
        let current = self
            .forge
            .list_comments(o, r, known.0)?
            .into_iter()
            .find(|c| c.id == id)
            .context("owned comment missing")?;
        ensure!(
            current.body.as_deref() == Some(known.1.as_str()),
            "owned comment changed externally"
        );
        Ok(known)
    }
}

impl Forge for Session<'_> {
    fn list_open_prs(&self, o: &str, r: &str) -> Result<Vec<PullRequest>> {
        self.scope.repository(o, r)?;
        self.forge.list_open_prs(o, r)
    }
    fn create_pr(
        &self,
        o: &str,
        r: &str,
        title: &str,
        body: &str,
        head: &str,
        base: &str,
        draft: bool,
    ) -> Result<PullRequest> {
        self.checked(|| {
            self.actor(o, r)?;
            self.base(base)?;
            let b = self.scope.bookmarks.get(head).context("PR head outside task scope")?;
            ensure!(self.forge.get_branch_head(o, r, head)?.as_ref() == Some(&b.oid), "published head differs from frozen candidate");
            ensure!(!self.forge.list_open_prs(o, r)?.iter().any(|p| p.head.ref_name == head), "PR already exists; replan instead of creating a duplicate");
            let payload = json!({"head":head,"head_oid":b.oid,"base":base,"title":title,"body":body,"draft":draft});
            let pr = self.journal.perform("create_pr", payload, || {
                let p = self.forge.create_pr(o, r, title, body, head, base, draft)?;
                ensure!(p.head.ref_name == head && p.head.sha == b.oid && p.author == self.scope.actor && p.base.ref_name == base && p.body.as_deref() == Some(body), "created PR returned unexpected identity or content; outcome needs reconciliation");
                Ok(p)
            }, |p| json!({"pr":p.number,"head":p.head.ref_name,"oid":p.head.sha}))?;
            self.prs.lock().map_err(|_| anyhow::anyhow!("PR map poisoned"))?.insert(pr.number, PrBinding {head:head.into(),base:base.into(),body:Some(body.into())});
            Ok(pr)
        })
    }
    fn update_pr_base(&self, o: &str, r: &str, n: u64, base: &str) -> Result<()> {
        self.checked(|| {
            let pr = self.pr(o, r, n)?;
            self.base(base)?;
            self.journal.perform(
                "update_pr_base",
                json!({"pr":n,"head":pr.head.sha,"previous_base":pr.base.ref_name,"base":base}),
                || self.forge.update_pr_base(o, r, n, base),
                |_| Value::Null,
            )?;
            self.prs
                .lock()
                .map_err(|_| anyhow::anyhow!("PR map poisoned"))?
                .get_mut(&n)
                .context("PR binding disappeared")?
                .base = base.into();
            Ok(())
        })
    }
    fn request_reviewers(&self, o: &str, r: &str, n: u64, reviewers: &[String]) -> Result<()> {
        self.checked(|| {
            let pr = self.pr(o, r, n)?;
            ensure!(
                reviewers.iter().all(|x| self.scope.reviewers.contains(x)),
                "reviewer outside host-selected scope"
            );
            self.journal.perform(
                "request_reviewers",
                json!({"pr":n,"head":pr.head.sha,"reviewers":reviewers}),
                || self.forge.request_reviewers(o, r, n, reviewers),
                |_| Value::Null,
            )
        })
    }
    fn list_comments(&self, o: &str, r: &str, n: u64) -> Result<Vec<IssueComment>> {
        self.checked(|| {
            self.pr(o, r, n)?;
            let comments = self.forge.list_comments(o, r, n)?;
            let known = self
                .comments
                .lock()
                .map_err(|_| anyhow::anyhow!("comment map poisoned"))?;
            // Do not adopt unrelated comments merely because they mimic a marker.
            Ok(comments
                .into_iter()
                .filter(|c| known.get(&c.id).is_some_and(|x| x.0 == n))
                .collect())
        })
    }
    fn create_comment(&self, o: &str, r: &str, n: u64, body: &str) -> Result<IssueComment> {
        self.checked(|| {
            let pr = self.pr(o, r, n)?;
            let c = self.journal.perform(
                "create_comment",
                json!({"pr":n,"head":pr.head.sha,"body":body}),
                || self.forge.create_comment(o, r, n, body),
                |c| json!({"comment":c.id,"pr":n,"body":body}),
            )?;
            self.comments
                .lock()
                .map_err(|_| anyhow::anyhow!("comment map poisoned"))?
                .insert(c.id, (n, body.into()));
            Ok(c)
        })
    }
    fn update_comment(&self, o: &str, r: &str, id: u64, body: &str) -> Result<()> {
        self.checked(|| {
            let (pr, old) = self.comment(o, r, id)?;
            self.journal.perform(
                "update_comment",
                json!({"comment":id,"pr":pr,"previous_body":old,"body":body}),
                || self.forge.update_comment(o, r, id, body),
                |_| json!({"comment":id,"pr":pr,"body":body}),
            )?;
            self.comments
                .lock()
                .map_err(|_| anyhow::anyhow!("comment map poisoned"))?
                .insert(id, (pr, body.into()));
            Ok(())
        })
    }
    fn delete_comment(&self, _o: &str, _r: &str, _id: u64) -> Result<()> {
        self.checked(|| bail!("comment deletion is outside publication scope"))
    }
    fn update_pr_body(&self, o: &str, r: &str, n: u64, body: &str) -> Result<()> {
        self.checked(|| {
            let pr = self.pr(o, r, n)?;
            self.journal.perform(
                "update_pr_body",
                json!({"pr":n,"head":pr.head.sha,"previous_body":pr.body,"body":body}),
                || self.forge.update_pr_body(o, r, n, body),
                |_| Value::Null,
            )?;
            self.prs
                .lock()
                .map_err(|_| anyhow::anyhow!("PR map poisoned"))?
                .get_mut(&n)
                .context("PR binding disappeared")?
                .body = Some(body.into());
            Ok(())
        })
    }
    fn mark_pr_ready(&self, _o: &str, _r: &str, _n: u64) -> Result<()> {
        self.checked(|| bail!("ready transition is outside publication scope"))
    }
    fn get_authenticated_user(&self) -> Result<String> {
        self.forge.get_authenticated_user()
    }
    fn get_authenticated_emails(&self) -> Result<Vec<String>> {
        self.forge.get_authenticated_emails()
    }
    fn find_merged_pr(&self, o: &str, r: &str, head: &str) -> Result<Option<PullRequest>> {
        self.scope.repository(o, r)?;
        self.forge.find_merged_pr(o, r, head)
    }
    fn list_recently_merged_prs(&self, o: &str, r: &str) -> Result<Vec<PullRequest>> {
        self.scope.repository(o, r)?;
        self.forge.list_recently_merged_prs(o, r)
    }
    fn merge_pr(&self, _o: &str, _r: &str, _n: u64, _method: MergeMethod) -> Result<()> {
        self.checked(|| bail!("merge is outside publication scope"))
    }
    fn get_pr_checks_status(&self, o: &str, r: &str, head: &str) -> Result<ChecksStatus> {
        self.scope.repository(o, r)?;
        self.forge.get_pr_checks_status(o, r, head)
    }
    fn get_pr_reviews(&self, o: &str, r: &str, n: u64) -> Result<ReviewSummary> {
        self.scope.repository(o, r)?;
        self.forge.get_pr_reviews(o, r, n)
    }
    fn get_pr_mergeability(&self, o: &str, r: &str, n: u64) -> Result<PrMergeability> {
        self.scope.repository(o, r)?;
        self.forge.get_pr_mergeability(o, r, n)
    }
    fn get_pr_state(&self, o: &str, r: &str, n: u64) -> Result<PrState> {
        self.scope.repository(o, r)?;
        self.forge.get_pr_state(o, r, n)
    }
    fn get_pr(&self, o: &str, r: &str, n: u64) -> Result<(PullRequest, PrState)> {
        self.scope.repository(o, r)?;
        self.forge.get_pr(o, r, n)
    }
    fn get_branch_head(&self, o: &str, r: &str, branch: &str) -> Result<Option<String>> {
        self.scope.repository(o, r)?;
        self.forge.get_branch_head(o, r, branch)
    }
    fn base_dismisses_stale_approvals(&self, o: &str, r: &str, base: &str) -> Result<Option<bool>> {
        self.scope.repository(o, r)?;
        self.forge.base_dismisses_stale_approvals(o, r, base)
    }
    // close/reopen/draft/remove-reviewers inherit rejecting trait defaults.
}
impl Jj for Session<'_> {
    fn git_fetch(&self) -> Result<()> {
        bail!("fetch must finish before the publication scope is frozen")
    }
    fn get_user_email(&self) -> Result<String> {
        self.jj.get_user_email()
    }
    fn get_my_bookmarks(&self) -> Result<Vec<Bookmark>> {
        self.jj.get_my_bookmarks()
    }
    fn get_status_bookmarks(&self, all: bool) -> Result<Vec<Bookmark>> {
        self.jj.get_status_bookmarks(all)
    }
    fn get_changes_to_commit(&self, commit: &str) -> Result<Vec<LogEntry>> {
        self.jj.get_changes_to_commit(commit)
    }
    fn get_git_remotes(&self) -> Result<Vec<GitRemote>> {
        self.jj.get_git_remotes()
    }
    fn get_default_branch(&self) -> Result<String> {
        self.jj.get_default_branch()
    }
    fn push_bookmark(&self, name: &str, remote: &str) -> Result<()> {
        self.checked(|| {
            self.actor(&self.scope.owner, &self.scope.repository)?;
            ensure!(remote == "origin", "remote outside task scope");
            let remotes = self.jj.get_git_remotes()?;
            ensure!(remotes.len() == 1 && remotes[0].name == remote && remotes[0].url == self.scope.remote_url, "remote changed after planning");
            let current = self.jj.get_my_bookmarks()?.into_iter().find(|b| b.name == name).context("bookmark missing; deletion is refused")?;
            let current_oid = resolve_bookmark_oid(self.jj, &current)?;
            self.scope.bookmark(name, &current.change_id, &current_oid)?;
            let frozen = self.scope.bookmarks.get(name).context("bookmark outside scope")?;
            ensure!(self.forge.get_branch_head(&self.scope.owner, &self.scope.repository, name)? == frozen.expected_remote, "remote branch changed after planning");
            let payload = json!({"remote":remote,"url":self.scope.remote_url,"bookmark":name,"oid":frozen.oid,"expected_remote":frozen.expected_remote});
            self.journal.perform("push_bookmark", payload, || {
                self.jj.push_bookmark(name, remote)?;
                ensure!(self.forge.get_branch_head(&self.scope.owner, &self.scope.repository, name)?.as_ref() == Some(&frozen.oid), "push readback differs; outcome needs reconciliation");
                Ok(())
            }, |_| json!({"bookmark":name,"oid":frozen.oid}))
        })
    }
    fn get_working_copy_commit_id(&self) -> Result<String> {
        self.jj.get_working_copy_commit_id()
    }
    fn working_copy_view(&self) -> Result<WorkingCopyView> {
        self.jj.working_copy_view()
    }
    fn rebase_onto(&self, _s: &str, _d: &str) -> Result<()> {
        bail!("rebase is outside publication scope")
    }
    fn merge_into(&self, _b: &str, _d: &str) -> Result<()> {
        bail!("local merge is outside publication scope")
    }
    fn is_rooted_in(&self, r: &str, b: &str) -> Result<bool> {
        self.jj.is_rooted_in(r, b)
    }
    fn resolve_change_id(&self, id: &str) -> Result<Vec<String>> {
        self.jj.resolve_change_id(id)
    }
    fn is_conflicted(&self, rev: &str) -> Result<bool> {
        self.jj.is_conflicted(rev)
    }
    fn first_conflict(&self, rev: &str) -> Result<Option<String>> {
        self.jj.first_conflict(rev)
    }
    fn current_operation_id(&self) -> Result<String> {
        self.jj.current_operation_id()
    }
    fn divergent_change_ids(&self) -> Result<Vec<String>> {
        self.jj.divergent_change_ids()
    }
    fn snapshot(&self) -> Result<()> {
        bail!("snapshot is outside publication scope")
    }
    fn snapshot_if_moved_by(&self, _s: &str) -> Result<bool> {
        bail!("snapshot is outside publication scope")
    }
    fn restore_operation(&self, _id: &str) -> Result<()> {
        bail!("undo is outside publication scope")
    }
    fn restore_operation_keeping_working_copy(&self, _id: &str) -> Result<()> {
        bail!("undo is outside publication scope")
    }
    // Other local writes inherit rejecting trait defaults. checkpoint has no
    // effect and no Result in upstream; watch is not an exposed entry point.
}
