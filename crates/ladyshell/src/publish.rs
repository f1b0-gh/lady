//! Host-only publication of an applied, verified export to one explicit Git branch.
use crate::{
    error::{ensure, Error, Result},
    files, snapshot,
    sources::Snapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Options {
    pub remote: String,
    pub branch: String,
    pub message: String,
    pub policy: Option<PathBuf>,
}

pub struct Prepared {
    git: Git,
    base: String,
    reference: String,
    destination: String,
    expected: String,
    options: Options,
    policy: Option<crate::publication_policy::Policy>,
}
pub(crate) struct Git {
    root: PathBuf,
    config: Vec<String>,
    index: Option<PathBuf>,
}
impl Git {
    pub(crate) fn configure(&mut self, config: Vec<String>) {
        self.config.extend(config);
    }
    pub(crate) fn new(root: &Path) -> Result<Self> {
        let mut git = Self {
            root: std::fs::canonicalize(root)?,
            index: None,
            config: vec![
                "core.hooksPath=/dev/null".into(),
                "core.fsmonitor=false".into(),
                "core.fsync=all".into(),
                "core.fsyncMethod=fsync".into(),
                "commit.gpgsign=false".into(),
                "push.gpgSign=false".into(),
                "push.followTags=false".into(),
                "push.recurseSubmodules=no".into(),
                "protocol.allow=never".into(),
                "protocol.file.allow=always".into(),
                "protocol.http.allow=always".into(),
                "protocol.https.allow=always".into(),
                "protocol.ssh.allow=always".into(),
            ],
        };
        // Read only names, never credential/configuration values. Disable every
        // configured external content filter before inspecting project files.
        let keys = match git.call(&[
            "config",
            "--null",
            "--name-only",
            "--get-regexp",
            r"^filter\.",
        ]) {
            Ok(v) => v,
            Err(Error::ProcessExit { status, .. }) if status.code() == Some(1) => Vec::new(),
            Err(e) => return Err(e),
        };
        for key in keys.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let key = String::from_utf8(key.to_vec())?;
            if key.ends_with(".required") {
                git.config.push(format!("{key}=false"));
            } else if [".clean", ".smudge", ".process"]
                .iter()
                .any(|suffix| key.ends_with(suffix))
            {
                git.config.push(format!("{key}="));
            }
        }
        Ok(git)
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new("git");
        c.arg("--literal-pathspecs").arg("-C").arg(&self.root);
        for config in &self.config {
            c.arg("-c").arg(config);
        }
        c.env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_EXTERNAL_DIFF")
            .env_remove("GIT_INDEX_FILE")
            .args(args);
        if let Some(index) = &self.index {
            c.env("GIT_INDEX_FILE", index);
        }
        c
    }
    pub(crate) fn call(&self, args: &[&str]) -> Result<Vec<u8>> {
        if matches!(args.first(), Some(&"push" | &"ls-remote")) {
            return self.transport(args);
        }
        crate::process::capture(
            self.command(args),
            Duration::from_secs(120),
            snapshot::FILE_LIMIT + 1024 * 1024,
        )
    }
    pub(crate) fn text(&self, args: &[&str]) -> Result<String> {
        Ok(String::from_utf8(self.call(args)?)?.trim().to_owned())
    }
    /// Transport uses a private bare repository and a frozen effective config.
    /// URL expansion happens once during preparation; no inherited rewrite or
    /// conditional include can reinterpret the retained destination afterward.
    pub(crate) fn transport(&self, args: &[&str]) -> Result<Vec<u8>> {
        use std::{
            io::Write,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        let effective = self.call(&["config", "--null", "--list", "--includes"])?;
        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut configuration = String::new();
        for row in effective
            .split(|byte| *byte == 0)
            .filter(|row| !row.is_empty())
        {
            let row = String::from_utf8(row.to_vec())?;
            let (name, value) = row.split_once('\n').unwrap_or((&row, "true"));
            let lower = name.to_ascii_lowercase();
            if lower.starts_with("url.")
                || lower.starts_with("remote.")
                || lower.starts_with("include.")
                || lower.starts_with("includeif.")
                || matches!(
                    lower.as_str(),
                    "core.worktree" | "extensions.worktreeconfig"
                )
            {
                continue;
            }
            let (section, tail) = name
                .split_once('.')
                .ok_or_else(|| invalid("Malformed effective Git configuration".into()))?;
            if let Some((subsection, variable)) = tail.rsplit_once('.') {
                configuration.push_str(&format!(
                    "[{section} \"{}\"]\n{variable} = \"{}\"\n",
                    config_quote(subsection),
                    config_quote(value)
                ));
            } else {
                configuration.push_str(&format!(
                    "[{section}]\n{tail} = \"{}\"\n",
                    config_quote(value)
                ));
            }
        }
        std::fs::create_dir(temporary.path().join("objects"))?;
        std::fs::create_dir(temporary.path().join("refs"))?;
        std::fs::write(temporary.path().join("HEAD"), b"ref: refs/heads/unused\n")?;
        let mut config = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temporary.path().join("config"))?;
        config.write_all(configuration.as_bytes())?;
        let objects = self.text(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ])?;
        let mut command = Command::new("git");
        command.current_dir(&self.root);
        command.arg("--git-dir").arg(temporary.path());
        for config in &self.config {
            command.arg("-c").arg(config);
        }
        command.arg("-c").arg("core.bare=true");
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_CONFIG") {
                command.env_remove(key);
            }
        }
        for key in [
            "GIT_DIR",
            "GIT_COMMON_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
            "GIT_SHALLOW_FILE",
            "GIT_QUARANTINE_PATH",
            "GIT_PREFIX",
        ] {
            command.env_remove(key);
        }
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_OBJECT_DIRECTORY", objects)
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(args);
        crate::process::capture(
            command,
            Duration::from_secs(120),
            snapshot::FILE_LIMIT + 1024 * 1024,
        )
    }
    /// Resolve and validate exactly one push destination before pinning it.
    pub(crate) fn destination(&self, remote: &str) -> Result<String> {
        ensure!(
            !remote.is_empty() && !remote.starts_with('-') && !remote.contains(['\0', '\n', '\r']),
            "A remote name is required"
        );
        let mut destination = self.text(&["remote", "get-url", "--push", "--all", remote])?;
        ensure!(
            !destination.is_empty()
                && !destination.starts_with('-')
                && !destination.contains(['\0', '\n', '\r']),
            "Exactly one push destination is required"
        );
        if !destination.contains(':') && !destination.starts_with('-') {
            destination = std::fs::canonicalize(self.root.join(&destination))?
                .to_str()
                .ok_or_else(|| invalid("Git destination is not UTF-8".into()))?
                .to_owned();
        }
        ensure!(
            !destination.is_empty()
                && !destination.starts_with('-')
                && !destination.contains(['\n', '\r']),
            "Exactly one push destination is required"
        );
        if let Ok(url) = url::Url::parse(&destination) {
            ensure!(
                url.password().is_none()
                    && (!matches!(url.scheme(), "http" | "https") || url.username().is_empty()),
                "Keep HTTP credentials in the host credential configuration, not the remote URL"
            );
        }
        Ok(destination)
    }
    pub(crate) fn remote_head(&self, destination: &str, reference: &str) -> Result<String> {
        let output = String::from_utf8(self.transport(&[
            "ls-remote",
            "--refs",
            "--",
            destination,
            reference,
        ])?)?
        .trim()
        .to_owned();
        if output.is_empty() {
            return Ok(String::new());
        }
        let rows: Vec<_> = output.lines().collect();
        ensure!(rows.len() == 1, "Remote ref is ambiguous");
        let fields: Vec<_> = rows[0].split_whitespace().collect();
        ensure!(
            fields.len() == 2 && fields[1] == reference,
            "Remote ref differs from requested branch"
        );
        oid(fields[0])?;
        Ok(fields[0].into())
    }
}
impl Prepared {
    pub fn new(project: &Path, options: &Options) -> Result<Self> {
        Self::prepare(project, options, true)
    }
    pub(crate) fn for_retained(project: &Path, options: &Options) -> Result<Self> {
        Self::prepare(project, options, false)
    }
    fn prepare(project: &Path, options: &Options, require_clean: bool) -> Result<Self> {
        ensure!(
            !options.remote.is_empty()
                && !options.remote.starts_with('-')
                && !options.remote.contains(['\0', '\n', '\r']),
            "A remote name is required"
        );
        ensure!(
            !options.message.trim().is_empty()
                && options.message.len() <= 16384
                && !options.message.contains('\0'),
            "A bounded commit message is required"
        );
        let mut git = Git::new(project)?;
        let policy = options
            .policy
            .as_ref()
            .map(|path| crate::publication_policy::Policy::load(path, &git.root))
            .transpose()?;
        if let Some(signing) = policy.as_ref().and_then(|p| p.signing.as_ref()) {
            git.config.extend(signing.git_config());
        }
        ensure!(
            Path::new(&git.text(&["rev-parse", "--show-toplevel"])?) == git.root,
            "Publication requires the repository root checkout"
        );
        git.call(&["check-ref-format", "--branch", &options.branch])?;
        let base = git.text(&["rev-parse", "HEAD"])?;
        oid(&base)?;
        let reference = format!("refs/heads/{}", options.branch);
        let destination = git.destination(&options.remote)?;
        let prepared = Self {
            git,
            base,
            reference,
            destination,
            expected: String::new(),
            options: options.clone(),
            policy,
        };
        if require_clean {
            prepared.before_apply()?;
        } else {
            prepared.verify_base()?;
            ensure!(
                prepared
                    .git
                    .call(&[
                        "diff",
                        "--cached",
                        "--name-only",
                        "--no-ext-diff",
                        "-z",
                        &prepared.base,
                        "--"
                    ])?
                    .is_empty(),
                "Retained publication refuses unrelated staged work"
            );
            ensure!(
                !prepared
                    .git
                    .call(&["ls-files", "--stage"])?
                    .split(|b| *b == b'\n')
                    .any(|line| line.starts_with(b"160000 ")),
                "Submodule publication is not supported"
            );
        }
        let expected = prepared
            .git
            .remote_head(&prepared.destination, &prepared.reference)?;
        ensure!(
            expected.is_empty() || expected == prepared.base,
            "Remote branch has diverged; fetch and reconcile before running the experiment"
        );
        Ok(Self {
            expected,
            ..prepared
        })
    }
    pub fn policy(&self) -> Option<&crate::publication_policy::Policy> {
        self.policy.as_ref()
    }
    pub(crate) fn before_apply(&self) -> Result<()> {
        self.verify_base()?;
        ensure!(self.git.call(&["status","--porcelain=v1","--untracked-files=all"])?.is_empty(),"Publication requires a clean checkout and index; preserve local work in a separate worktree");
        ensure!(
            !self
                .git
                .call(&["ls-files", "--stage"])?
                .split(|b| *b == b'\n')
                .any(|line| line.starts_with(b"160000 ")),
            "Submodule publication is not supported by this file exporter"
        );
        Ok(())
    }
    fn verify_base(&self) -> Result<()> {
        ensure!(
            self.git
                .text(&["symbolic-ref", "--quiet", "--short", "HEAD"])?
                == self.options.branch,
            "Check out the explicitly selected publication branch first"
        );
        ensure!(
            self.git.text(&["rev-parse", "HEAD"])? == self.base,
            "Checkout HEAD changed during the experiment"
        );
        Ok(())
    }
    /// The caller holds the Ladyshell state lock and supplies its checkout report.
    /// A failed/uncertain push retains the commit and receipt; no write is retried.
    pub fn publish(&self, report: &Value, directory: &Path) -> Result<Value> {
        let directory = files::absolute(directory)?;
        let directory = directory.as_path();
        crate::continuous::host::execution_directory(directory)?;
        crate::publication_recovery::ensure_available(directory)?;
        let _parents = crate::stacks::guard(directory)?;
        self.verify_base()?;
        if let Some(policy) = &self.policy {
            policy.verify_inputs()?;
        }
        ensure!(
            report["applied"] == true && report["conflicts"] == json!([]),
            "Only a successfully applied export can be published"
        );
        ensure!(
            self.git
                .call(&[
                    "diff",
                    "--cached",
                    "--name-only",
                    "--no-ext-diff",
                    "-z",
                    &self.base,
                    "--"
                ])?
                .is_empty(),
            "Index changed during the experiment; refusing to commit unrelated staged work"
        );
        let export = PathBuf::from(crate::state::text(report, "export")?);
        let manifest = crate::json::parse(&files::read_limited(
            &export.join("manifest.json"),
            2 * 1024 * 1024,
        )?)?;
        if let Some(current) = crate::state::load(directory)? {
            crate::continuous::host::ensure_ready(&current)?;
            crate::continuous::host::verify_export(&current, &manifest)?;
        }
        ensure!(
            manifest["schema_version"] == 2,
            "Unsupported export manifest"
        );
        let records: Snapshot = serde_json::from_value(manifest["files"].clone())?;
        let changes = report["changes"]
            .as_array()
            .ok_or_else(|| invalid("Missing export changes".into()))?;
        let mut paths = BTreeSet::new();
        let mut payloads = Vec::new();
        // Validate every selected byte and path before changing the Git index.
        for change in changes {
            let path = crate::state::text(change, "path")?;
            snapshot::validate_path(path)?;
            ensure!(paths.insert(path.to_owned()), "Duplicate changed path");
            if change["action"] == "delete" {
                ensure!(
                    !records.contains_key(path)
                        && matches!(self.git.root.join(path).symlink_metadata(), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                    "Deleted export path still exists on host"
                );
                payloads.push((path.to_owned(), None));
            } else {
                let record = records
                    .get(path)
                    .ok_or_else(|| invalid("Missing exported file".into()))?;
                let (entry, data) = snapshot::local_bytes(&export.join("project"), path)?;
                ensure!(
                    entry.sha256 == record.sha256 && entry.executable == record.executable,
                    "Export was modified"
                );
                let (host, bytes) = snapshot::local_bytes(&self.git.root, path)?;
                ensure!(
                    host == entry && bytes == data,
                    "Host file changed after sync: {path}"
                );
                payloads.push((path.to_owned(), Some((record.executable, data))));
            }
        }
        if let Some(checks) = self.policy.as_ref().and_then(|p| p.checks.as_ref()) {
            crate::publication_checks::revalidate(&export, checks)?;
        }
        let mut receipt = json!({"schema_version":2,"phase":"acquiring","project":self.git.root,"export":export,"base":self.base,"commit":null,"remote":self.options.remote,"destination":self.destination,"reference":self.reference,"branch":self.options.branch,"expected_remote":self.expected,"confirmed":false,"signing":self.policy.as_ref().and_then(|p|p.signing.as_ref()),"checks":self.policy.as_ref().and_then(|p|p.checks.as_ref()),"policy_digests":self.policy.as_ref().map(|p| &p.digests),"checks":self.policy.as_ref().and_then(|p|p.checks.as_ref()),"local":null});
        let mut index_lock = IndexLock::intent(&self.git)?;
        receipt["local"] = serde_json::to_value(index_lock.record()?)?;
        crate::publication_recovery::write(directory, &receipt)?;
        index_lock.claim()?;
        self.verify_base()?;
        ensure!(
            self.git
                .call(&[
                    "diff",
                    "--cached",
                    "--name-only",
                    "--no-ext-diff",
                    "-z",
                    &self.base,
                    "--"
                ])?
                .is_empty(),
            "Index changed before publication acquired its lock"
        );
        receipt["local"] = serde_json::to_value(index_lock.record()?)?;
        receipt["phase"] = json!("exported");
        crate::publication_recovery::write(directory, &receipt)?;
        let temporary = tempfile::tempdir_in(directory)?;
        let mut isolated = Git::new(&self.git.root)?;
        isolated.config = self.git.config.clone();
        isolated.index = Some(temporary.path().join("index"));
        isolated.call(&["read-tree", &self.base])?;
        for (path, payload) in &payloads {
            if let Some((executable, data)) = payload {
                let bytes = crate::process::capture_input(
                    isolated.command(&["hash-object", "-w", "--stdin", "--no-filters"]),
                    data,
                    Duration::from_secs(30),
                    1024,
                )?;
                let hash = String::from_utf8(bytes)?.trim().to_owned();
                oid(&hash)?;
                let mode = if *executable { "100755" } else { "100644" };
                isolated.call(&[
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("{mode},{hash},{path}"),
                ])?;
            } else {
                isolated.call(&["update-index", "--force-remove", "--", path])?;
            }
        }
        verify_paths(
            &isolated,
            &[
                "diff",
                "--cached",
                "--name-only",
                "--no-ext-diff",
                "--no-renames",
                "-z",
                &self.base,
                "--",
            ],
            &paths,
        )?;
        if let Some(checks) = self.policy.as_ref().and_then(|p| p.checks.as_ref()) {
            crate::publication_checks::revalidate(&export, checks)?;
        }
        let tree = isolated.text(&["write-tree"])?;
        let commit = if paths.is_empty() {
            self.base.clone()
        } else {
            let mut args = vec![
                "commit-tree",
                &tree,
                "-p",
                &self.base,
                "-m",
                &self.options.message,
            ];
            if self
                .policy
                .as_ref()
                .and_then(|p| p.signing.as_ref())
                .is_some()
            {
                args.push("-S");
            }
            isolated.text(&args)?
        };
        oid(&commit)?;
        if let Some(policy) = &self.policy {
            policy.verify_inputs()?;
            if let Some(signing) = &policy.signing {
                ensure!(
                    !paths.is_empty(),
                    "Signed publication requires an exported change"
                );
                signing.verify_commit(&isolated, &commit)?;
            }
        }
        self.verify_paths(
            &[
                "diff",
                "--name-only",
                "--no-ext-diff",
                "--no-renames",
                "-z",
                &self.base,
                &commit,
                "--",
            ],
            &paths,
        )?;
        if !paths.is_empty() {
            ensure!(
                self.git.text(&["rev-parse", &format!("{commit}^")])? == self.base,
                "Commit parent changed during publication"
            );
        }
        for (path, payload) in &payloads {
            if let Some((executable, data)) = payload {
                let entry = self.git.text(&["ls-tree", &commit, "--", path])?;
                let mode = if *executable {
                    "100755 blob "
                } else {
                    "100644 blob "
                };
                ensure!(
                    entry.starts_with(mode),
                    "Committed mode differs from the verified export"
                );
                ensure!(
                    self.git.call(&["show", &format!("{commit}:{path}")])? == *data,
                    "Committed bytes differ from the verified export"
                );
            }
        }
        let prepared_index = isolated
            .index
            .as_ref()
            .ok_or_else(|| invalid("Missing isolated index".into()))?;
        let bytes = files::read_limited(prepared_index, 64 * 1024 * 1024)?;
        let digest = files::hash(&bytes);
        let retained_index = directory.join(format!("publication-index-{digest}"));
        retain_index(&retained_index, &bytes)?;
        receipt["local"]["prepared"] = json!(retained_index);
        receipt["local"]["prepared_sha256"] = json!(digest);
        receipt["commit"] = json!(commit);
        receipt["phase"] = json!("committed");
        // Retain the exact signed object durably before any ref or remote mutation.
        crate::publication_recovery::write(directory, &receipt)?;
        self.git.call(&[
            "update-ref",
            &format!("refs/ladyshell/publications/{commit}"),
            &commit,
        ])?;
        self.verify_base()?;
        self.git
            .call(&["update-ref", &self.reference, &commit, &self.base])?;
        index_lock.install(
            isolated
                .index
                .as_ref()
                .ok_or_else(|| invalid("Missing isolated index".into()))?,
        )?;
        receipt["local"]["completed"] = json!(true);
        receipt["phase"] = json!("push_unconfirmed");
        crate::publication_recovery::write(directory, &receipt)?;
        self.git.transport(&["push","--porcelain",&format!("--force-with-lease={}:{}",self.reference,self.expected),&self.destination,&format!("{commit}:{}",self.reference)])
            .map_err(|e|e.context(format!("Push not confirmed; exact commit {commit} and {} are retained. Use publication reconciliation",directory.join("publication.json").display())))?;
        ensure!(
            self.git.remote_head(&self.destination, &self.reference)? == commit,
            "Remote read-back differs; publication is not confirmed"
        );
        receipt["confirmed"] = json!(true);
        receipt["phase"] = json!("published");
        crate::publication_recovery::write(directory, &receipt)?;
        Ok(receipt)
    }
    fn verify_paths(&self, args: &[&str], expected: &BTreeSet<String>) -> Result<()> {
        verify_paths(&self.git, args, expected)
    }
}
fn verify_paths(git: &Git, args: &[&str], expected: &BTreeSet<String>) -> Result<()> {
    let found = git
        .call(args)?
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8(s.to_vec()))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    ensure!(
        &found == expected,
        "Git changes differ from the verified export"
    );
    Ok(())
}
pub(crate) fn oid(value: &str) -> Result<()> {
    ensure!(
        [40, 64].contains(&value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid Git object ID"
    );
    Ok(())
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalIndex {
    index: PathBuf,
    lock: PathBuf,
    original_sha256: String,
    prepared: Option<PathBuf>,
    prepared_sha256: Option<String>,
    device: u64,
    inode: u64,
    completed: bool,
    #[serde(default)]
    owner: Option<PathBuf>,
}
struct IndexLock {
    path: PathBuf,
    destination: PathBuf,
    file: Option<std::fs::File>,
    original_sha256: String,
    owner: Option<PathBuf>,
    claimed: bool,
}
impl IndexLock {
    fn intent(git: &Git) -> Result<Self> {
        let destination = PathBuf::from(git.text(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "index",
        ])?);
        let parent = destination
            .parent()
            .ok_or_else(|| invalid("Missing Git index parent".into()))?;
        let marker = tempfile::Builder::new()
            .prefix("ladyshell-index-owner-")
            .tempfile_in(parent)?;
        let (file, owner) = marker.keep().map_err(|error| error.error)?;
        let lock = Self {
            path: destination.with_file_name("index.lock"),
            destination,
            file: Some(file),
            original_sha256: String::new(),
            owner: Some(owner),
            claimed: false,
        };
        lock.file
            .as_ref()
            .ok_or_else(|| invalid("Missing ownership marker".into()))?
            .sync_all()?;
        std::fs::File::open(
            lock.destination
                .parent()
                .ok_or_else(|| invalid("Missing Git index parent".into()))?,
        )?
        .sync_all()?;
        Ok(lock)
    }
    fn claim(&mut self) -> Result<()> {
        let owner = self
            .owner
            .as_ref()
            .ok_or_else(|| invalid("Missing durable index ownership marker".into()))?;
        std::fs::hard_link(owner, &self.path)?;
        self.claimed = true;
        std::fs::File::open(
            self.path
                .parent()
                .ok_or_else(|| invalid("Missing lock parent".into()))?,
        )?
        .sync_all()?;
        std::fs::remove_file(owner)?;
        self.owner = None;
        self.original_sha256 =
            files::hash(&files::read_limited(&self.destination, 64 * 1024 * 1024)?);
        Ok(())
    }
    fn record(&self) -> Result<LocalIndex> {
        use std::os::unix::fs::MetadataExt;
        let meta = self
            .file
            .as_ref()
            .ok_or_else(|| invalid("Missing index lock".into()))?
            .metadata()?;
        Ok(LocalIndex {
            index: self.destination.clone(),
            lock: self.path.clone(),
            original_sha256: self.original_sha256.clone(),
            prepared: None,
            prepared_sha256: None,
            device: meta.dev(),
            inode: meta.ino(),
            completed: false,
            owner: self.owner.clone(),
        })
    }
    fn install(&mut self, source: &Path) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let bytes = files::read_limited(source, 64 * 1024 * 1024)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| invalid("Index lock already released".into()))?;
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&self.path, &self.destination)?;
        if let Some(parent) = self.destination.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        self.file = None;
        Ok(())
    }
}
impl Drop for IndexLock {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if let Some(file) = &self.file {
            if let Ok(owned) = file.metadata() {
                for path in self.owner.iter().chain(self.claimed.then_some(&self.path)) {
                    if let Ok(current) = std::fs::symlink_metadata(path) {
                        if current.is_file()
                            && current.dev() == owned.dev()
                            && current.ino() == owned.ino()
                        {
                            let _ = std::fs::remove_file(path);
                        }
                    }
                }
            }
        }
    }
}
fn retain_index(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::File::open(
                path.parent()
                    .ok_or_else(|| invalid("Index parent missing".into()))?,
            )?
            .sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => ensure!(
            files::read_limited(path, 64 * 1024 * 1024)? == bytes,
            "Retained publication index was changed"
        ),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
/// Finish only the exact interrupted ref/index installation described by the
/// journal. An unrelated index, branch, or lock is a conflict, never reset.
pub(crate) fn finish_local(directory: &Path, receipt: &mut Value) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut local: LocalIndex = serde_json::from_value(receipt["local"].clone())?;
    if local.completed {
        return Ok(());
    }
    let git = Git::new(Path::new(crate::state::text(receipt, "project")?))?;
    let index =
        PathBuf::from(git.text(&["rev-parse", "--path-format=absolute", "--git-path", "index"])?);
    ensure!(
        local.index == index && local.lock == index.with_file_name("index.lock"),
        "Local recovery index path differs from the bound repository"
    );
    let prepared = local.prepared.clone().ok_or_else(|| {
        invalid("No prepared index was retained; explicitly abandon this incomplete export".into())
    })?;
    let directory = files::absolute(directory)?;
    ensure!(
        prepared.parent() == Some(directory.as_path()),
        "Prepared index is outside retained state"
    );
    let bytes = files::read_limited(&prepared, 64 * 1024 * 1024)?;
    let digest = files::hash(&bytes);
    ensure!(
        local.prepared_sha256.as_deref() == Some(&digest),
        "Prepared publication index was modified"
    );
    let mut lock = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&local.lock)
    {
        Ok(file) => {
            let meta = file.metadata()?;
            ensure!(
                meta.is_file()
                    && meta.dev() == local.device
                    && meta.ino() == local.inode
                    && owned_links(&local, &meta),
                "Index lock belongs to another operation; preserve it"
            );
            let lock_bytes = files::read_limited(&local.lock, 64 * 1024 * 1024)?;
            ensure!(
                bytes.starts_with(&lock_bytes),
                "Owned index lock contains unrelated bytes; preserve it"
            );
            remove_owner(&local)?;
            local.owner = None;
            IndexLock {
                path: local.lock.clone(),
                destination: index.clone(),
                file: Some(file),
                original_sha256: local.original_sha256.clone(),
                owner: None,
                claimed: true,
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut lock = IndexLock::intent(&git)?;
            let intent = lock.record()?;
            local.device = intent.device;
            local.inode = intent.inode;
            local.owner = intent.owner;
            receipt["local"] = serde_json::to_value(&local)?;
            // Identity is durable before linking the already-owned inode into
            // Git's lock namespace, including when reacquiring after an error.
            crate::publication_recovery::write(&directory, receipt)?;
            lock.claim()?;
            local.owner = None;
            lock
        }
        Err(error) => return Err(error.into()),
    };
    // All decisions about shared index/ref state occur while owning index.lock.
    let current_index = files::hash(&files::read_limited(&index, 64 * 1024 * 1024)?);
    ensure!(
        current_index == local.original_sha256 || current_index == digest,
        "Local index changed after interruption; preserve and reconcile host staging explicitly"
    );
    let reference = crate::state::text(receipt, "reference")?;
    ensure!(
        git.text(&["symbolic-ref", "--quiet", "HEAD"])? == reference,
        "Checkout branch changed after interruption"
    );
    let current_ref = git.text(&["rev-parse", reference])?;
    let base = crate::state::text(receipt, "base")?;
    let commit = crate::state::text(receipt, "commit")?;
    ensure!(
        current_ref == base || current_ref == commit,
        "Local branch advanced after interruption"
    );
    receipt["local"] = serde_json::to_value(&local)?;
    crate::publication_recovery::write(&directory, receipt)?;
    let reference = crate::state::text(receipt, "reference")?;
    let commit = crate::state::text(receipt, "commit")?;
    git.call(&["cat-file", "-e", &format!("{commit}^{{commit}}")])?;
    git.call(&[
        "update-ref",
        &format!("refs/ladyshell/publications/{commit}"),
        commit,
    ])?;
    // CAS is required even when the observed ref already equals the commit.
    git.call(&["update-ref", reference, commit, &current_ref])?;
    ensure!(
        git.text(&["symbolic-ref", "--quiet", "HEAD"])? == reference,
        "Checkout branch changed during recovery"
    );
    if current_index != digest {
        lock.install(&prepared)?;
    } else {
        drop(lock);
    }
    receipt["local"]["completed"] = json!(true);
    crate::publication_recovery::write(&directory, receipt)?;
    Ok(())
}
fn owned_links(local: &LocalIndex, metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() == 1
        || (metadata.nlink() == 2
            && local.owner.as_ref().is_some_and(|path| {
                path.parent() == local.index.parent()
                    && path.file_name().is_some_and(|name| {
                        name.to_string_lossy().starts_with("ladyshell-index-owner-")
                    })
                    && std::fs::symlink_metadata(path).is_ok_and(|meta| {
                        meta.is_file() && meta.dev() == local.device && meta.ino() == local.inode
                    })
            }))
}
fn remove_owner(local: &LocalIndex) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if let Some(owner) = &local.owner {
        ensure!(
            owner.parent() == local.index.parent()
                && owner.file_name().is_some_and(|name| name
                    .to_string_lossy()
                    .starts_with("ladyshell-index-owner-")),
            "Invalid owned index marker path"
        );
        match std::fs::symlink_metadata(owner) {
            Ok(meta)
                if meta.is_file() && meta.dev() == local.device && meta.ino() == local.inode =>
            {
                std::fs::remove_file(owner)?
            }
            Ok(_) => return Err(invalid("Index ownership marker was replaced".into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Release only a provably retained publication lock during explicit abandonment.
/// A foreign lock is left intact; host files, index contents and refs are untouched.
pub(crate) fn release_owned_index_lock(receipt: &Value) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    if receipt["schema_version"] != 2 {
        return Ok(false);
    }
    let local: LocalIndex = serde_json::from_value(receipt["local"].clone())?;
    if local.completed {
        return Ok(false);
    }
    let git = Git::new(Path::new(crate::state::text(receipt, "project")?))?;
    let index =
        PathBuf::from(git.text(&["rev-parse", "--path-format=absolute", "--git-path", "index"])?);
    ensure!(
        local.index == index && local.lock == index.with_file_name("index.lock"),
        "Abandonment index path differs from the bound repository"
    );
    let file = match files::open_regular(&local.lock) {
        Ok(file) => file,
        Err(error) if missing(&error) => {
            remove_owner(&local)?;
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if meta.dev() != local.device || meta.ino() != local.inode || !owned_links(&local, &meta) {
        return Ok(false);
    }
    let lock_bytes = files::read_file(file, 64 * 1024 * 1024)?;
    if let Some(prepared) = &local.prepared {
        let bytes = files::read_limited(prepared, 64 * 1024 * 1024)?;
        ensure!(
            local.prepared_sha256.as_deref() == Some(&files::hash(&bytes))
                && bytes.starts_with(&lock_bytes),
            "Owned lock bytes do not match the retained publication index"
        );
    } else {
        ensure!(
            lock_bytes.is_empty(),
            "Incomplete publication lock contains unrelated bytes"
        );
    }
    std::fs::remove_file(&local.lock)?;
    remove_owner(&local)?;
    std::fs::File::open(
        local
            .lock
            .parent()
            .ok_or_else(|| invalid("Missing index lock parent".into()))?,
    )?
    .sync_all()?;
    Ok(true)
}
fn missing(error: &Error) -> bool {
    match error {
        Error::Io(e) | Error::PathIo { source: e, .. } => e.kind() == std::io::ErrorKind::NotFound,
        Error::Context { source, .. } => missing(source),
        _ => false,
    }
}

fn config_quote(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
        .replace('\u{8}', "\\b")
}
