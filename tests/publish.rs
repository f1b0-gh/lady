use ladyshell::{
    publish::{Options, Prepared},
    snapshot,
    sources::{FileRecord, Snapshot},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn git(root: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).into_owned().into());
    }
    Ok(String::from_utf8(o.stdout)?.trim().into())
}
struct Fixture {
    root: tempfile::TempDir,
    project: PathBuf,
    remote: PathBuf,
    options: Options,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let project = root.path().join("project");
        let remote = root.path().join("remote.git");
        fs::create_dir(&project)?;
        fs::create_dir(&remote)?;
        git(&remote, &["init", "--bare"])?;
        git(&project, &["init", "--initial-branch=agent/test"])?;
        git(&project, &["config", "user.name", "Export test"])?;
        git(&project, &["config", "user.email", "test@example.invalid"])?;
        fs::write(project.join("code.py"), b"print(1)\n")?;
        fs::write(project.join(".gitattributes"), b"*.py filter=trap\n")?;
        git(&project, &["add", "code.py", ".gitattributes"])?;
        git(&project, &["commit", "-m", "Initial code"])?;
        git(
            &project,
            &["remote", "add", "knot", remote.to_str().ok_or("path")?],
        )?;
        Ok(Self {
            root,
            project,
            remote,
            options: Options {
                remote: "knot".into(),
                branch: "agent/test".into(),
                message: "Export sandbox experiment".into(),
                policy: None,
            },
        })
    }
    fn export(&self) -> Result<Value> {
        export_fixture(self.root.path(), &self.project)
    }
}
fn export_fixture(root: &Path, project: &Path) -> Result<Value> {
    let export = root.join("export");
    fs::create_dir_all(export.join("project"))?;
    fs::write(export.join("project/code.py"), b"print(2)\r\n")?;
    fs::write(project.join("code.py"), b"print(2)\r\n")?;
    let files: Snapshot = snapshot::inventory(&export.join("project"))?
        .into_iter()
        .map(|(p, e)| {
            (
                p,
                FileRecord {
                    sha256: e.sha256,
                    executable: e.executable,
                },
            )
        })
        .collect();
    fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(&json!({"schema_version":2,"sandbox_id":"test","files":files}))?,
    )?;
    Ok(
        json!({"export":export,"applied":true,"conflicts":[],"changes":[{"path":"code.py","action":"modify"}]}),
    )
}

#[test]
fn exact_export_is_committed_and_pushed_without_running_hooks_or_filters() -> Result {
    let f = Fixture::new()?;
    let sentinel = f.root.path().join("HOST_CODE_RAN");
    let hook = f.project.join(".git/hooks/pre-commit");
    fs::write(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\n", sentinel.display()),
    )?;
    fs::set_permissions(hook, fs::Permissions::from_mode(0o700))?;
    git(
        &f.project,
        &[
            "config",
            "filter.trap.clean",
            &format!("touch '{}'", sentinel.display()),
        ],
    )?;
    git(&f.project, &["config", "core.autocrlf", "true"])?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let report = f.export()?;
    fs::write(f.root.path().join("continuous-staging.json"), b"{}")?;
    let fenced = prepared
        .publish(&report, f.root.path())
        .err()
        .ok_or("provisioning publication admitted")?;
    assert!(fenced.to_string().contains("provisioning state"));
    assert!(!f.root.path().join("publication.json").exists());
    fs::remove_file(f.root.path().join("continuous-staging.json"))?;
    let receipt = prepared.publish(&report, f.root.path())?;
    assert_eq!(receipt["confirmed"], true);
    let commit = receipt["commit"].as_str().ok_or("commit")?;
    assert_eq!(
        git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?,
        commit
    );
    let bytes = Command::new("git")
        .arg("-C")
        .arg(&f.remote)
        .args(["show", &format!("{commit}:code.py")])
        .output()?;
    assert_eq!(bytes.stdout, b"print(2)\r\n");
    assert!(!sentinel.exists());
    Ok(())
}
#[test]
fn dirty_checkout_and_wrong_branch_are_refused() -> Result {
    let f = Fixture::new()?;
    fs::write(f.project.join("code.py"), b"local work\n")?;
    assert!(Prepared::new(&f.project, &f.options).is_err());
    let f = Fixture::new()?;
    let mut options = f.options.clone();
    options.branch = "main".into();
    assert!(Prepared::new(&f.project, &options).is_err());
    Ok(())
}
#[test]
fn concurrent_remote_update_is_not_overwritten_and_commit_is_retained() -> Result {
    let f = Fixture::new()?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    git(&f.project, &["push", "knot", "HEAD:refs/heads/agent/test"])?;
    let moved = git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?;
    assert!(prepared.publish(&f.export()?, f.root.path()).is_err());
    assert_eq!(
        git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?,
        moved
    );
    let receipt: Value =
        serde_json::from_slice(&fs::read(f.root.path().join("publication.json"))?)?;
    assert_eq!(receipt["confirmed"], false);
    assert!(receipt["commit"].is_string());
    assert_ne!(receipt["commit"].as_str().ok_or("commit")?, moved);
    Ok(())
}
#[test]
fn host_tampering_and_unrelated_staging_prevent_publication() -> Result {
    let f = Fixture::new()?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let report = f.export()?;
    fs::write(f.project.join("code.py"), b"concurrent host edit\n")?;
    assert!(prepared.publish(&report, f.root.path()).is_err());
    assert!(!f.root.path().join("publication.json").exists());
    let f = Fixture::new()?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let report = f.export()?;
    fs::write(f.project.join("unrelated"), b"keep local\n")?;
    git(&f.project, &["add", "unrelated"])?;
    assert!(prepared.publish(&report, f.root.path()).is_err());
    assert_eq!(
        git(&f.project, &["diff", "--cached", "--name-only"])?,
        "unrelated"
    );
    Ok(())
}

#[test]
fn host_follow_tags_never_publishes_an_unrequested_ref() -> Result {
    let f = Fixture::new()?;
    git(
        &f.project,
        &["tag", "-a", "private-note", "-m", "Host-only annotation"],
    )?;
    git(&f.project, &["config", "push.followTags", "true"])?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    prepared.publish(&f.export()?, f.root.path())?;
    assert_eq!(
        git(&f.remote, &["for-each-ref", "--format=%(refname)"])?,
        "refs/heads/agent/test"
    );
    Ok(())
}

fn publication_ignores_push_default(key: &str, value: &str) -> Result {
    let f = Fixture::new()?;
    git(&f.project, &["config", key, value])?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let receipt = prepared.publish(&f.export()?, f.root.path())?;
    assert_eq!(receipt["confirmed"], true, "{key}");
    assert_eq!(
        git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?,
        receipt["commit"].as_str().ok_or("commit")?
    );
    Ok(())
}
#[test]
fn host_push_signing_does_not_change_publication() -> Result {
    publication_ignores_push_default("push.gpgSign", "true")
}
#[test]
fn host_submodule_only_push_does_not_skip_publication() -> Result {
    publication_ignores_push_default("push.recurseSubmodules", "only")
}

#[test]
fn explicit_ssh_policy_signs_and_retains_signing_evidence() -> Result {
    let mut f = Fixture::new()?;
    let key = f.root.path().join("signing-key");
    let output = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()?;
    assert!(output.status.success());
    let allowed = f.root.path().join("allowed-signers");
    fs::write(
        &allowed,
        format!("host@* {}", fs::read_to_string(key.with_extension("pub"))?),
    )?;
    let policy = f.root.path().join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec(
            &json!({"schema_version":1,"signing":{"key":key,"allowed_signers":allowed,"principal":"host@example.invalid","program":"/usr/bin/ssh-keygen"}}),
        )?,
    )?;
    f.options.policy = Some(policy);
    let prepared = Prepared::new(&f.project, &f.options)?;
    assert!(prepared.policy().is_some());
    let receipt = prepared.publish(&f.export()?, f.root.path())?;
    assert_eq!(receipt["phase"], "published");
    assert_eq!(receipt["signing"]["principal"], "host@example.invalid");
    let raw = git(
        &f.project,
        &[
            "cat-file",
            "commit",
            receipt["commit"].as_str().ok_or("commit")?,
        ],
    )?;
    assert!(raw.contains("gpgsig -----BEGIN SSH SIGNATURE-----"));
    Ok(())
}

#[test]
fn explicit_signer_preflight_refuses_wrong_principal_and_unavailable_program() -> Result {
    let mut f = Fixture::new()?;
    let key = f.root.path().join("key");
    assert!(Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()?
        .status
        .success());
    let allowed = f.root.path().join("allowed");
    fs::write(
        &allowed,
        format!(
            "other@example.invalid {}",
            fs::read_to_string(key.with_extension("pub"))?
        ),
    )?;
    let policy = f.root.path().join("policy.json");
    let mut value = json!({"schema_version":1,"signing":{"key":key,"allowed_signers":allowed,"principal":"host@example.invalid","program":"/usr/bin/ssh-keygen"}});
    fs::write(&policy, serde_json::to_vec(&value)?)?;
    f.options.policy = Some(policy.clone());
    assert!(Prepared::new(&f.project, &f.options).is_err());
    value["signing"]["program"] = json!("/nonexistent/ssh-keygen");
    fs::write(policy, serde_json::to_vec(&value)?)?;
    assert!(Prepared::new(&f.project, &f.options).is_err());
    Ok(())
}

#[test]
fn default_publication_stays_unsigned_even_with_broken_global_signing() -> Result {
    let f = Fixture::new()?;
    git(&f.project, &["config", "commit.gpgsign", "true"])?;
    git(
        &f.project,
        &["config", "gpg.program", "/nonexistent/signer"],
    )?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let receipt = prepared.publish(&f.export()?, f.root.path())?;
    let commit = receipt["commit"].as_str().ok_or("commit")?;
    assert!(!git(&f.project, &["cat-file", "commit", commit])?.contains("gpgsig "));
    assert!(git(&f.project, &["status", "--porcelain"])?.is_empty());
    Ok(())
}

#[test]
fn pending_export_journal_blocks_republication_and_mutated_export_is_refused() -> Result {
    let f = Fixture::new()?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let report = f.export()?;
    fs::write(f.root.path().join("export/project/code.py"), "tampered")?;
    assert!(prepared.publish(&report, f.root.path()).is_err());
    assert!(!f.root.path().join("publication.json").exists());
    Ok(())
}

#[test]
fn policy_is_explicit_strict_and_frozen_before_publication() -> Result {
    let mut f = Fixture::new()?;
    let policy = f.root.path().join("policy.json");
    for bytes in [
        r#"{"schema_version":1,"schema_version":1}"#,
        r#"{"schema_version":1,"unknown":true}"#,
    ] {
        fs::write(&policy, bytes)?;
        f.options.policy = Some(policy.clone());
        assert!(Prepared::new(&f.project, &f.options).is_err());
    }
    fs::write(&policy, r#"{"schema_version":1}"#)?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let report = f.export()?;
    fs::write(&policy, r#"{"schema_version":1,"checks":null}"#)?;
    assert!(prepared.publish(&report, f.root.path()).is_err());
    assert!(!f.root.path().join("publication.json").exists());
    Ok(())
}

#[test]
fn revoked_signer_is_refused_before_any_export() -> Result {
    let mut f = Fixture::new()?;
    let key = f.root.path().join("key");
    assert!(Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()?
        .status
        .success());
    let public = fs::read_to_string(key.with_extension("pub"))?;
    let allowed = f.root.path().join("allowed");
    fs::write(&allowed, format!("host@example.invalid {public}"))?;
    let revoked = f.root.path().join("revoked");
    fs::write(&revoked, public)?;
    let policy = f.root.path().join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec(
            &json!({"schema_version":1,"signing":{"key":key,"allowed_signers":allowed,"revocation_file":revoked,"principal":"host@example.invalid","program":"/usr/bin/ssh-keygen"}}),
        )?,
    )?;
    f.options.policy = Some(policy);
    assert!(Prepared::new(&f.project, &f.options).is_err());
    assert!(!f.root.path().join("export").exists());
    Ok(())
}

#[test]
fn refused_push_retry_uses_the_retained_object_and_preserves_unrelated_host_edits() -> Result {
    let f = Fixture::new()?;
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let hook = f.remote.join("hooks/pre-receive");
    fs::write(&hook, "#!/bin/sh\nexit 1\n")?;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let report = f.export()?;
    assert!(prepared.publish(&report, &state).is_err());
    let receipt: Value = serde_json::from_slice(&fs::read(state.join("publication.json"))?)?;
    let commit = receipt["commit"].as_str().ok_or("commit")?;
    assert_eq!(receipt["phase"], "push_unconfirmed");
    assert!(ladyshell::publication_recovery::ensure_available(&state).is_err());
    assert!(prepared.publish(&report, &state).is_err());
    fs::write(f.project.join("unrelated"), "preserve")?;
    git(&f.project, &["add", "unrelated"])?;
    fs::remove_file(hook)?;
    let recovered = ladyshell::publication_recovery::reconcile(&state, true, false)?;
    assert_eq!(recovered["commit"], commit);
    assert_eq!(recovered["phase"], "published");
    assert_eq!(
        git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?,
        commit
    );
    assert_eq!(
        git(&f.project, &["diff", "--cached", "--name-only"])?,
        "unrelated"
    );
    assert_eq!(
        ladyshell::publication_recovery::reconcile(&state, true, false)?,
        recovered
    );
    Ok(())
}

#[test]
fn remote_race_and_unavailable_remote_preserve_evidence_until_explicit_abandonment() -> Result {
    let f = Fixture::new()?;
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    git(&f.project, &["push", "knot", "HEAD:refs/heads/agent/test"])?;
    let report = f.export()?;
    assert!(prepared.publish(&report, &state).is_err());
    let retained = fs::read(state.join("publication.json"))?;
    assert_eq!(
        ladyshell::publication_recovery::status(&state)?["remote_status"],
        "advanced"
    );
    assert!(ladyshell::publication_recovery::reconcile(&state, true, false).is_err());
    let moved = f.root.path().join("unavailable.git");
    fs::rename(&f.remote, &moved)?;
    assert_eq!(
        ladyshell::publication_recovery::status(&state)?["remote_status"],
        "unavailable"
    );
    assert!(ladyshell::publication_recovery::reconcile(&state, true, false).is_err());
    assert_eq!(fs::read(state.join("publication.json"))?, retained);
    let before = git(&f.project, &["rev-parse", "HEAD"])?;
    let abandoned = ladyshell::publication_recovery::reconcile(&state, false, true)?;
    assert_eq!(abandoned["phase"], "abandoned");
    assert_eq!(
        fs::read(abandoned["archive"].as_str().ok_or("archive")?)?,
        retained
    );
    assert_eq!(git(&f.project, &["rev-parse", "HEAD"])?, before);
    assert!(f.root.path().join("export/project/code.py").exists());
    ladyshell::publication_recovery::ensure_available(&state)?;
    Ok(())
}

#[test]
fn accepted_push_with_transport_failure_is_confirmed_without_retrying_the_push() -> Result {
    let f = Fixture::new()?;
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let ssh = f.root.path().join("ssh-transport");
    fs::write(&ssh,format!("#!/bin/sh\ncase \"$*\" in\n *git-upload-pack*) exec git-upload-pack '{}' ;;\n *git-receive-pack*) git-receive-pack '{}'; exit 1 ;;\n *) exit 2 ;;\nesac\n",f.remote.display(),f.remote.display()))?;
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700))?;
    git(
        &f.project,
        &["config", "core.sshCommand", ssh.to_str().ok_or("ssh path")?],
    )?;
    git(&f.project, &["config", "ssh.variant", "ssh"])?;
    git(
        &f.project,
        &[
            "remote",
            "set-url",
            "knot",
            "ssh://fixture.invalid/remote.git",
        ],
    )?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    assert!(prepared.publish(&f.export()?, &state).is_err());
    let receipt: Value = serde_json::from_slice(&fs::read(state.join("publication.json"))?)?;
    assert_eq!(receipt["phase"], "push_unconfirmed");
    assert_eq!(
        git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?,
        receipt["commit"].as_str().ok_or("commit")?
    );
    let reconciled = ladyshell::publication_recovery::reconcile(&state, false, false)?;
    assert_eq!(reconciled["phase"], "published");
    assert_eq!(reconciled["commit"], receipt["commit"]);
    Ok(())
}

#[test]
fn publication_crash_worker() -> Result {
    let Some(root) = std::env::var_os("LADYSHELL_PUBLICATION_CRASH_ROOT") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let project = root.join("project");
    let state = root.join("state");
    let _state = ladyshell::state::StateLock::acquire(&state)?;
    let _session = ladyshell::state::SessionLock::acquire(&state, true)?;
    let prepared = Prepared::new(
        &project,
        &Options {
            remote: "knot".into(),
            branch: "agent/test".into(),
            message: "Crash recovery export".into(),
            policy: std::env::var_os("LADYSHELL_PUBLICATION_CRASH_POLICY").map(PathBuf::from),
        },
    )?;
    let report = export_fixture(&root, &project)?;
    prepared.publish(&report, &state)?;
    Ok(())
}

#[test]
fn killed_after_committed_journal_recovers_exact_ref_and_index_without_manual_state_edits() -> Result
{
    let f = Fixture::new()?;
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    git(&f.project, &["config", "core.filesRefLockTimeout", "10000"])?;
    let ref_lock = f.project.join(".git/refs/heads/agent/test.lock");
    fs::write(&ref_lock, "test-owned branch lock")?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", "publication_crash_worker", "--nocapture"])
        .env("LADYSHELL_PUBLICATION_CRASH_ROOT", f.root.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let started = std::time::Instant::now();
    let receipt = loop {
        if let Ok(bytes) = fs::read(state.join("publication.json")) {
            if let Ok(receipt) = serde_json::from_slice::<Value>(&bytes) {
                if receipt["phase"] == "committed" {
                    break receipt;
                }
            }
        }
        if let Some(exit) = child.try_wait()? {
            return Err(format!("worker exited before committed journal: {exit}").into());
        }
        if started.elapsed() > std::time::Duration::from_secs(8) {
            child.kill()?;
            child.wait()?;
            return Err("worker did not reach committed journal".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    child.kill()?;
    child.wait()?;
    fs::remove_file(ref_lock)?;
    assert_eq!(receipt["local"]["completed"], false);
    assert_eq!(
        git(&f.project, &["rev-parse", "HEAD"])?,
        receipt["base"].as_str().ok_or("base")?
    );
    assert!(f.project.join(".git/index.lock").exists());
    // A different operation's lock must remain untouched and block recovery.
    let index_lock = f.project.join(".git/index.lock");
    let owned_lock = f.root.path().join("owned-index-lock");
    fs::rename(&index_lock, &owned_lock)?;
    fs::write(&index_lock, "unrelated lock")?;
    assert!(ladyshell::publication_recovery::reconcile(&state, true, false).is_err());
    assert_eq!(fs::read(&index_lock)?, b"unrelated lock");
    fs::remove_file(&index_lock)?;
    fs::rename(owned_lock, &index_lock)?;
    // Concurrent host staging is also preserved rather than reset.
    let index = f.project.join(".git/index");
    let original = fs::read(&index)?;
    let staged_index = f.root.path().join("unrelated-index");
    fs::write(&staged_index, &original)?;
    fs::write(f.project.join("unrelated"), "preserve host staging")?;
    let staged = Command::new("git")
        .arg("-C")
        .arg(&f.project)
        .env("GIT_INDEX_FILE", &staged_index)
        .args(["add", "unrelated"])
        .output()?;
    assert!(staged.status.success());
    let unrelated = fs::read(&staged_index)?;
    fs::write(&index, &unrelated)?;
    assert!(ladyshell::publication_recovery::reconcile(&state, true, false).is_err());
    assert_eq!(fs::read(&index)?, unrelated);
    fs::write(&index, original)?;
    fs::remove_file(f.project.join("unrelated"))?;
    let recovered = ladyshell::publication_recovery::reconcile(&state, true, false)?;
    assert_eq!(recovered["phase"], "published");
    assert_eq!(recovered["commit"], receipt["commit"]);
    assert_eq!(
        git(&f.project, &["rev-parse", "HEAD"])?,
        receipt["commit"].as_str().ok_or("commit")?
    );
    assert!(git(&f.project, &["status", "--porcelain"])?.is_empty());
    assert!(!f.project.join(".git/index.lock").exists());
    Ok(())
}

#[test]
fn ref_updated_before_index_install_is_recovered_from_the_exact_retained_index() -> Result {
    let f = Fixture::new()?;
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let bin = f.root.path().join("bin");
    fs::create_dir(&bin)?;
    let wrapper = bin.join("git");
    let ready = f.root.path().join("ref-updated");
    let release = f.root.path().join("release-git");
    let git_program = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v git"])
            .output()?
            .stdout,
    )?
    .trim()
    .to_owned();
    fs::write(
        &wrapper,
        format!(
            r#"#!/bin/sh
'{}' "$@"
result=$?
case " $* " in
 *' update-ref refs/heads/agent/test '*)
 touch '{}'
 while [ ! -f '{}' ]; do sleep 0.01; done
 ;;
esac
exit "$result"
"#,
            git_program,
            ready.display(),
            release.display()
        ),
    )?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
    let paths = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").ok_or("PATH")?,
    )))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", "publication_crash_worker", "--nocapture"])
        .env("LADYSHELL_PUBLICATION_CRASH_ROOT", f.root.path())
        .env("PATH", paths)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let started = std::time::Instant::now();
    while !ready.exists() {
        if let Some(exit) = child.try_wait()? {
            return Err(format!("worker exited before ref checkpoint: {exit}").into());
        }
        if started.elapsed() > std::time::Duration::from_secs(8) {
            child.kill()?;
            child.wait()?;
            fs::write(&release, "release")?;
            return Err("worker did not reach ref checkpoint".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    child.kill()?;
    child.wait()?;
    fs::write(&release, "release")?;
    let receipt: Value = serde_json::from_slice(&fs::read(state.join("publication.json"))?)?;
    assert_eq!(receipt["phase"], "committed");
    assert_eq!(receipt["local"]["completed"], false);
    assert_eq!(
        git(&f.project, &["rev-parse", "HEAD"])?,
        receipt["commit"].as_str().ok_or("commit")?
    );
    assert!(f.project.join(".git/index.lock").exists());
    let recovered = ladyshell::publication_recovery::reconcile(&state, true, false)?;
    assert_eq!(recovered["phase"], "published");
    assert_eq!(recovered["commit"], receipt["commit"]);
    assert!(git(&f.project, &["status", "--porcelain"])?.is_empty());
    assert!(!f.project.join(".git/index.lock").exists());
    Ok(())
}

#[test]
fn abandonment_releases_only_the_owned_lock_and_preserves_ref_index_and_export() -> Result {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new()?;
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let hook = f.remote.join("hooks/pre-receive");
    fs::write(&hook, "#!/bin/sh\nexit 1\n")?;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    assert!(prepared.publish(&f.export()?, &state).is_err());
    let mut receipt: Value = serde_json::from_slice(&fs::read(state.join("publication.json"))?)?;
    // Materialize the on-disk state of an interrupted local installation.
    let lock = f.project.join(".git/index.lock");
    fs::write(&lock, [])?;
    let meta = fs::metadata(&lock)?;
    receipt["phase"] = json!("committed");
    receipt["local"]["completed"] = json!(false);
    receipt["local"]["device"] = json!(meta.dev());
    receipt["local"]["inode"] = json!(meta.ino());
    fs::write(
        state.join("publication.json"),
        serde_json::to_vec(&receipt)?,
    )?;
    let index = fs::read(f.project.join(".git/index"))?;
    let head = git(&f.project, &["rev-parse", "HEAD"])?;
    let export = fs::read(f.root.path().join("export/project/code.py"))?;
    let abandoned = ladyshell::publication_recovery::reconcile(&state, false, true)?;
    assert_eq!(abandoned["owned_index_lock_released"], true);
    assert!(!lock.exists());
    assert_eq!(fs::read(f.project.join(".git/index"))?, index);
    assert_eq!(git(&f.project, &["rev-parse", "HEAD"])?, head);
    assert_eq!(
        fs::read(f.root.path().join("export/project/code.py"))?,
        export
    );
    Ok(())
}

#[test]
fn retained_transport_destination_is_not_redirected_by_later_url_rewrites() -> Result {
    for rewrite in ["insteadOf", "pushInsteadOf"] {
        let f = Fixture::new()?;
        let state = f.root.path().join("state");
        ladyshell::state::create_directory(&state)?;
        let other = f.root.path().join("other.git");
        fs::create_dir(&other)?;
        git(&other, &["init", "--bare"])?;
        let hook = f.remote.join("hooks/pre-receive");
        fs::write(&hook, "#!/bin/sh\nexit 1\n")?;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
        let prepared = Prepared::new(&f.project, &f.options)?;
        assert!(prepared.publish(&f.export()?, &state).is_err());
        fs::remove_file(hook)?;
        git(
            &f.project,
            &[
                "config",
                &format!("url.{}.{rewrite}", other.display()),
                f.remote.to_str().ok_or("remote")?,
            ],
        )?;
        let recovered = ladyshell::publication_recovery::reconcile(&state, true, false)?;
        assert_eq!(recovered["phase"], "published");
        assert_eq!(
            git(&other, &["for-each-ref", "--format=%(refname)"])?,
            "",
            "{rewrite}"
        );
        assert_eq!(
            git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?,
            recovered["commit"].as_str().ok_or("commit")?
        );
    }
    Ok(())
}

fn materialize_interrupted_before_ref(f: &Fixture) -> Result<(PathBuf, Value)> {
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let original = fs::read(f.project.join(".git/index"))?;
    let base = git(&f.project, &["rev-parse", "HEAD"])?;
    let hook = f.remote.join("hooks/pre-receive");
    fs::write(&hook, "#!/bin/sh\nexit 1\n")?;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    assert!(prepared.publish(&f.export()?, &state).is_err());
    fs::remove_file(hook)?;
    let mut receipt: Value = serde_json::from_slice(&fs::read(state.join("publication.json"))?)?;
    git(
        &f.project,
        &[
            "update-ref",
            "refs/heads/agent/test",
            &base,
            receipt["commit"].as_str().ok_or("commit")?,
        ],
    )?;
    fs::write(f.project.join(".git/index"), original)?;
    receipt["phase"] = json!("committed");
    receipt["local"]["completed"] = json!(false);
    fs::write(
        state.join("publication.json"),
        serde_json::to_vec(&receipt)?,
    )?;
    Ok((state, receipt))
}

#[test]
fn changed_policy_refuses_both_recovery_modes_before_any_local_effect() -> Result {
    for retry in [false, true] {
        let mut f = Fixture::new()?;
        let key = f.root.path().join("key");
        assert!(Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()?
            .status
            .success());
        let allowed = f.root.path().join("allowed");
        fs::write(
            &allowed,
            format!(
                "host@example.invalid {}",
                fs::read_to_string(key.with_extension("pub"))?
            ),
        )?;
        let policy = f.root.path().join("policy.json");
        fs::write(
            &policy,
            serde_json::to_vec(
                &json!({"schema_version":1,"signing":{"key":key,"allowed_signers":allowed,"principal":"host@example.invalid","program":"/usr/bin/ssh-keygen"}}),
            )?,
        )?;
        f.options.policy = Some(policy);
        let (state, receipt) = materialize_interrupted_before_ref(&f)?;
        let index = fs::read(f.project.join(".git/index"))?;
        let primary = fs::read(state.join("publication.json"))?;
        fs::write(&allowed, "revoked authorization\n")?;
        let result = ladyshell::publication_recovery::reconcile(&state, retry, false);
        assert!(
            result.is_err(),
            "changed policy accepted with retry={retry}"
        );
        assert_eq!(
            git(&f.project, &["rev-parse", "HEAD"])?,
            receipt["base"].as_str().ok_or("base")?
        );
        assert_eq!(fs::read(f.project.join(".git/index"))?, index);
        assert_eq!(fs::read(state.join("publication.json"))?, primary);
        assert!(ladyshell::publication_recovery::reconcile(&state, false, true).is_ok());
    }
    Ok(())
}

#[test]
fn kill_after_lock_claim_has_durable_owned_intent_and_supported_abandonment() -> Result {
    let f = Fixture::new()?;
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let bin = f.root.path().join("bin");
    fs::create_dir(&bin)?;
    let ready = f.root.path().join("lock-claimed");
    let release = f.root.path().join("release-diff");
    let real = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v git"])
            .output()?
            .stdout,
    )?
    .trim()
    .to_owned();
    fs::write(
        bin.join("git"),
        format!(
            r#"#!/bin/sh
'{}' "$@"
result=$?
case " $* " in
 *' diff --cached --name-only --no-ext-diff -z '*)
 if [ -f '{}' ]; then
  touch '{}'
  while [ ! -f '{}' ]; do sleep 0.01; done
 fi
 ;;
esac
exit "$result"
"#,
            real,
            f.project.join(".git/index.lock").display(),
            ready.display(),
            release.display()
        ),
    )?;
    fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o700))?;
    let paths = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").ok_or("PATH")?,
    )))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--exact", "publication_crash_worker", "--nocapture"])
        .env("LADYSHELL_PUBLICATION_CRASH_ROOT", f.root.path())
        .env("PATH", paths)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let started = std::time::Instant::now();
    while !ready.exists() {
        if let Some(exit) = child.try_wait()? {
            return Err(format!("worker exited before lock checkpoint: {exit}").into());
        }
        if started.elapsed() > std::time::Duration::from_secs(8) {
            child.kill()?;
            child.wait()?;
            fs::write(&release, "release")?;
            return Err("lock checkpoint timed out".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    child.kill()?;
    child.wait()?;
    fs::write(release, "release")?;
    assert!(f.project.join(".git/index.lock").exists());
    let status = ladyshell::publication_recovery::status(&state)?;
    assert_eq!(status["phase"], "acquiring");
    let index = fs::read(f.project.join(".git/index"))?;
    let head = git(&f.project, &["rev-parse", "HEAD"])?;
    let abandoned = ladyshell::publication_recovery::reconcile(&state, false, true)?;
    assert_eq!(abandoned["owned_index_lock_released"], true);
    assert!(!f.project.join(".git/index.lock").exists());
    assert_eq!(fs::read(f.project.join(".git/index"))?, index);
    assert_eq!(git(&f.project, &["rev-parse", "HEAD"])?, head);
    Ok(())
}

#[test]
fn recovery_interleaving_worker() -> Result {
    let Some(root) = std::env::var_os("LADYSHELL_RECOVERY_INTERLEAVING_ROOT") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let result = ladyshell::publication_recovery::reconcile(&root.join("state"), true, false);
    fs::write(
        root.join("recovery-outcome.json"),
        serde_json::to_vec(&match result {
            Ok(receipt) => json!({"ok":true,"receipt":receipt}),
            Err(error) => json!({"ok":false,"error":error.to_string()}),
        })?,
    )?;
    Ok(())
}

#[test]
fn recovery_serializes_staging_and_preserves_staging_completed_before_lock_claim() -> Result {
    for command in [
        "symbolic-ref --quiet HEAD",
        "--path-format=absolute --git-path index",
    ] {
        let f = Fixture::new()?;
        let (_state, _receipt) = materialize_interrupted_before_ref(&f)?;
        fs::write(f.project.join("unrelated"), "concurrent staging")?;
        let bin = f.root.path().join("bin");
        fs::create_dir(&bin)?;
        let marker = f.root.path().join("staging-attempted");
        let staging = f.root.path().join("staging-result");
        let real = String::from_utf8(
            Command::new("sh")
                .args(["-c", "command -v git"])
                .output()?
                .stdout,
        )?
        .trim()
        .to_owned();
        fs::write(
            bin.join("git"),
            format!(
                r#"#!/bin/sh
case " $* " in
 *' {} '*)
 if [ ! -f '{}' ]; then
  touch '{}'
  '{}' -C '{}' add unrelated 2>'{}.stderr'
  echo "$?" > '{}'
 fi
 ;;
esac
exec '{}' "$@"
"#,
                command,
                marker.display(),
                marker.display(),
                real,
                f.project.display(),
                staging.display(),
                staging.display(),
                real
            ),
        )?;
        fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o700))?;
        let paths = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
            &std::env::var_os("PATH").ok_or("PATH")?,
        )))?;
        let worker = Command::new(std::env::current_exe()?)
            .args(["--exact", "recovery_interleaving_worker", "--nocapture"])
            .env("LADYSHELL_RECOVERY_INTERLEAVING_ROOT", f.root.path())
            .env("PATH", paths)
            .output()?;
        assert!(
            worker.status.success(),
            "{}",
            String::from_utf8_lossy(&worker.stderr)
        );
        let result: Value =
            serde_json::from_slice(&fs::read(f.root.path().join("recovery-outcome.json"))?)?;
        let staged = fs::read_to_string(&staging)?.trim() == "0";
        if staged {
            assert_eq!(
                result["ok"], false,
                "recovery overwrote staging completed at {command}"
            );
            assert_eq!(
                git(&f.project, &["diff", "--cached", "--name-only"])?,
                "unrelated"
            );
            assert_eq!(
                git(&f.remote, &["for-each-ref", "--format=%(refname)"])?,
                ""
            );
        } else {
            assert!(
                fs::read_to_string(format!("{}.stderr", staging.display()))?.contains("index.lock")
            );
            assert_eq!(result["ok"], true, "{}", result);
        }
    }
    Ok(())
}

#[test]
fn already_at_commit_recovery_cas_refuses_an_interleaved_branch_update() -> Result {
    let f = Fixture::new()?;
    let (_state, receipt) = materialize_interrupted_before_ref(&f)?;
    let base = receipt["base"].as_str().ok_or("base")?;
    let commit = receipt["commit"].as_str().ok_or("commit")?;
    git(
        &f.project,
        &["update-ref", "refs/heads/agent/test", commit, base],
    )?;
    let index = fs::read(f.project.join(".git/index"))?;
    let bin = f.root.path().join("bin");
    fs::create_dir(&bin)?;
    let marker = f.root.path().join("branch-raced");
    let real = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v git"])
            .output()?
            .stdout,
    )?
    .trim()
    .to_owned();
    fs::write(
        bin.join("git"),
        format!(
            r#"#!/bin/sh
case " $* " in
 *' update-ref refs/ladyshell/publications/'*)
 if [ ! -f '{}' ]; then
  touch '{}'
  '{}' -C '{}' update-ref refs/heads/agent/test '{}' '{}' || exit 9
 fi
 ;;
esac
exec '{}' "$@"
"#,
            marker.display(),
            marker.display(),
            real,
            f.project.display(),
            base,
            commit,
            real
        ),
    )?;
    fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o700))?;
    let paths = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").ok_or("PATH")?,
    )))?;
    let worker = Command::new(std::env::current_exe()?)
        .args(["--exact", "recovery_interleaving_worker", "--nocapture"])
        .env("LADYSHELL_RECOVERY_INTERLEAVING_ROOT", f.root.path())
        .env("PATH", paths)
        .output()?;
    assert!(worker.status.success());
    let outcome: Value =
        serde_json::from_slice(&fs::read(f.root.path().join("recovery-outcome.json"))?)?;
    assert!(
        marker.exists(),
        "Recovery stopped before the injected branch race: {outcome}"
    );
    assert_eq!(outcome["ok"], false, "{}", outcome);
    assert_eq!(git(&f.project, &["rev-parse", "HEAD"])?, base, "{outcome}");
    assert_eq!(fs::read(f.project.join(".git/index"))?, index);
    assert_eq!(
        git(&f.remote, &["for-each-ref", "--format=%(refname)"])?,
        ""
    );
    Ok(())
}

#[test]
fn preparation_resolves_selected_alias_once_without_rejecting_unrelated_rewrites() -> Result {
    let f = Fixture::new()?;
    git(
        &f.project,
        &["remote", "set-url", "knot", "publication-alias:repo"],
    )?;
    git(
        &f.project,
        &[
            "config",
            &format!("url.{}.insteadOf", f.remote.display()),
            "publication-alias:repo",
        ],
    )?;
    git(
        &f.project,
        &[
            "config",
            "url./nonexistent/unrelated.insteadOf",
            "unused-alias:",
        ],
    )?;
    let prepared = Prepared::new(&f.project, &f.options)?;
    let receipt = prepared.publish(&f.export()?, f.root.path())?;
    assert_eq!(receipt["destination"], f.remote.to_str().ok_or("remote")?);
    assert_eq!(receipt["phase"], "published");
    git(&f.project, &["remote", "set-url", "knot", ""])?;
    assert!(Prepared::new(&f.project, &f.options).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
struct SigningCrashGroup {
    child: std::process::Child,
    reaped: bool,
}
#[cfg(target_os = "linux")]
impl SigningCrashGroup {
    fn kill_and_reap(&mut self) -> Result<bool> {
        use std::os::unix::process::ExitStatusExt;
        let group = self.child.id() as i32;
        // This isolated exact-test process is a subreaper. nickel-util starts
        // nested process groups, so kill/reap adopted children as well as the
        // worker group. Every child of this supervisor belongs to this case.
        if self.child.try_wait()?.is_none() {
            unsafe { libc::kill(-group, libc::SIGKILL) };
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut worker_reaped = false;
        let mut helpers_reaped = 0;
        loop {
            for task in fs::read_dir("/proc/self/task")? {
                let children = match fs::read_to_string(task?.path().join("children")) {
                    Ok(children) => children,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                };
                for pid in children.split_whitespace() {
                    let pid: i32 = pid.parse()?;
                    // SAFETY: only direct owned children of the isolated
                    // supervisor are selected. Include all supervisor threads:
                    // test workers and adopted descendants can have different
                    // parent threads. New adoptees appear on the next pass.
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
            }
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid == group {
                worker_reaped = std::process::ExitStatus::from_raw(status).signal() == Some(9);
            } else if pid > 0 {
                helpers_reaped += 1;
            } else if pid == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.reaped = true;
                    eprintln!("Signing cleanup reaped {helpers_reaped} adopted helpers; no children remain");
                    return Ok(worker_reaped);
                }
                return Err(error.into());
            }
            if std::time::Instant::now() >= deadline {
                return Err("signing process group did not reap within five seconds".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}
#[cfg(target_os = "linux")]
impl Drop for SigningCrashGroup {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_and_reap();
        }
    }
}

#[cfg(target_os = "linux")]
fn signing_crash_supervisor(test: &str) -> Result<bool> {
    use std::os::unix::process::CommandExt;
    // The manager never executes scenario code. It remains alive to own the
    // watchdog and reap descendants if the separately grouped scenario hangs.
    let mode = std::env::var("LADYSHELL_SIGNING_CRASH_SUPERVISED").ok();
    if mode.is_none() {
        // This wait is bounded by the manager's sixty-second watchdog and
        // bounded cleanup; the harness never kills the cleanup owner.
        let status = Command::new(std::env::current_exe()?)
            .args(["--exact", test, "--nocapture"])
            .env("LADYSHELL_SIGNING_CRASH_SUPERVISED", "manager")
            .status()?;
        assert!(status.success(), "signing interruption manager: {status}");
        return Ok(false);
    }
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    if mode.as_deref() == Some("scenario") {
        return Ok(true);
    }
    assert_eq!(mode.as_deref(), Some("manager"));
    let mut scenario = SigningCrashGroup {
        child: Command::new(std::env::current_exe()?)
            .args(["--exact", test, "--nocapture"])
            .env("LADYSHELL_SIGNING_CRASH_SUPERVISED", "scenario")
            .process_group(0)
            .spawn()?,
        reaped: false,
    };
    let forced_root = std::env::var_os("LADYSHELL_SIGNING_WATCHDOG_ROOT").map(PathBuf::from);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(status) = scenario.child.try_wait()? {
            // Reap any unexpected adopted descendants even on normal exit.
            scenario.kill_and_reap()?;
            assert!(status.success(), "signing interruption scenario: {status}");
            return Ok(false);
        }
        let forced = forced_root.as_ref().is_some_and(|root| {
            fs::read(root.join("watchdog-ready")).is_ok_and(|bytes| bytes == b"nested-ready")
        });
        if forced || std::time::Instant::now() >= deadline {
            assert!(scenario.kill_and_reap()?, "watchdog must kill its scenario");
            if let Some(root) = &forced_root {
                fs::write(
                    root.join("watchdog-cleaned"),
                    b"timeout-cleaned-no-children",
                )?;
                return Ok(false);
            }
            return Err(
                "signing interruption timed out; owned descendants killed and reaped".into(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(target_os = "linux")]
fn signing_interruption(boundary: &str, test: &str) -> Result {
    use std::os::unix::process::CommandExt;
    if !signing_crash_supervisor(test)? {
        return Ok(());
    }
    let f = Fixture::new()?;
    let state = f.root.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let key = f.root.path().join("signing-key");
    assert!(Command::new("/usr/bin/ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()?
        .status
        .success());
    let allowed = f.root.path().join("allowed-signers");
    fs::write(
        &allowed,
        format!(
            "host@example.invalid {}",
            fs::read_to_string(key.with_extension("pub"))?
        ),
    )?;
    let wrapper = f.root.path().join("ssh-signing-wrapper");
    // The wrapper finishes/reaps real ssh-keygen before either post-sign gate.
    // Preflight has its own exact payload; Git's actual commit is different.
    fs::write(
        &wrapper,
        format!(
            r#"#!/usr/bin/python3
import os, pathlib, subprocess, sys, time
root = pathlib.Path(__file__).parent
boundary = {boundary:?}
args = sys.argv[1:]
operation = args[args.index('-Y') + 1] if '-Y' in args else ''
is_sign = operation == 'sign'
is_preflight = is_sign and pathlib.Path(args[-1]).read_bytes() == b'Ladyshell explicit host signing preflight\n'
is_commit_verify = operation == 'verify' and pathlib.Path(args[args.index('-s') + 1]).name == 'commit.sig'
def event(name):
    with (root / 'signer-events').open('a') as log:
        log.write(name + '\n')
def gate(name):
    if boundary == name:
        marker = root / 'signing-boundary'
        temporary = marker.with_suffix('.tmp')
        if os.environ.get('LADYSHELL_SIGNING_CRASH_SPLIT_MARKER') == '1':
            with temporary.open('w') as stream:
                stream.write(name[:1])
                stream.flush()
                (root / 'marker-staged').write_text('staged')
                deadline = time.monotonic() + 8
                while not (root / 'marker-release').exists():
                    if time.monotonic() >= deadline:
                        sys.exit(93)
                    time.sleep(0.005)
                stream.write(name[1:])
        else:
            temporary.write_text(name)
        temporary.replace(marker)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            time.sleep(0.005)
        sys.exit(91)
if is_preflight:
    event('preflight-sign')
if is_sign and not is_preflight:
    event('commit-sign-start')
    gate('before-sign')
result = subprocess.run(['/usr/bin/ssh-keygen'] + args)
if result.returncode != 0:
    sys.exit(result.returncode)
if is_sign and not is_preflight:
    event('commit-sign-complete')
    gate('after-sign')
if is_commit_verify:
    event('commit-verify-complete')
    gate('after-object')
sys.exit(0)
"#
        ),
    )?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
    let policy = f.root.path().join("policy.json");
    fs::write(
        &policy,
        serde_json::to_vec(
            &json!({"schema_version":1,"signing":{"key":key,"allowed_signers":allowed,"principal":"host@example.invalid","program":wrapper}}),
        )?,
    )?;
    let head = git(&f.project, &["rev-parse", "HEAD"])?;
    let index = fs::read(f.project.join(".git/index"))?;
    let remote = git(
        &f.remote,
        &["for-each-ref", "--format=%(refname):%(objectname)"],
    )?;
    let pending_prepared = Prepared::new(&f.project, &f.options)?;
    let split_marker = test == "signing_marker_publication_waits_for_complete_payload";
    let mut group = SigningCrashGroup {
        child: Command::new(std::env::current_exe()?)
            .args(["--exact", "publication_crash_worker", "--nocapture"])
            .env("LADYSHELL_PUBLICATION_CRASH_ROOT", f.root.path())
            .env("LADYSHELL_PUBLICATION_CRASH_POLICY", &policy)
            .env(
                "LADYSHELL_SIGNING_CRASH_SPLIT_MARKER",
                if split_marker { "1" } else { "0" },
            )
            .process_group(0)
            .spawn()?,
        reaped: false,
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while !f.root.path().join("signing-boundary").exists() {
        if split_marker
            && fs::read(f.root.path().join("marker-staged")).is_ok_and(|bytes| bytes == b"staged")
            && !f.root.path().join("marker-release").exists()
        {
            assert!(!f.root.path().join("signing-boundary").exists());
            assert_eq!(
                fs::read(f.root.path().join("signing-boundary.tmp"))?,
                &boundary.as_bytes()[..1]
            );
            fs::write(f.root.path().join("marker-release"), b"release")?;
        }

        if let Some(status) = group.child.try_wait()? {
            return Err(format!("worker exited before {boundary}: {status}").into());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("worker never reached {boundary}").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if split_marker {
        assert!(f.root.path().join("marker-release").exists());
    }
    assert_eq!(
        fs::read_to_string(f.root.path().join("signing-boundary"))?,
        boundary
    );
    let journal = fs::read(state.join("publication.json"))?;
    let manifest = fs::read(f.root.path().join("export/manifest.json"))?;
    let receipt: Value = serde_json::from_slice(&journal)?;
    assert_eq!(receipt["phase"], "exported");
    assert!(receipt["commit"].is_null());
    assert!(
        group.kill_and_reap()?,
        "publication worker must be killed by SIGKILL"
    );
    let events = fs::read_to_string(f.root.path().join("signer-events"))?;
    assert_eq!(events.matches("preflight-sign\n").count(), 1);
    assert_eq!(events.matches("commit-sign-start\n").count(), 1);
    assert_eq!(
        events.matches("commit-sign-complete\n").count(),
        usize::from(boundary != "before-sign")
    );
    assert_eq!(
        events.matches("commit-verify-complete\n").count(),
        usize::from(boundary == "after-object")
    );
    let objects = git(&f.project, &["fsck", "--unreachable", "--no-reflogs"])?;
    let commits: Vec<_> = objects
        .lines()
        .filter_map(|line| line.strip_prefix("unreachable commit "))
        .collect();
    assert_eq!(commits.len(), usize::from(boundary == "after-object"));
    let retained = commits
        .first()
        .map(|oid| git(&f.project, &["cat-file", "commit", oid]))
        .transpose()?;
    if let Some(commit) = commits.first() {
        assert_eq!(
            git(&f.project, &["rev-parse", &format!("{commit}^")])?,
            head
        );
        assert!(retained
            .as_ref()
            .ok_or("retained commit")?
            .contains("gpgsig -----BEGIN SSH SIGNATURE-----"));
        let output = Command::new("git")
            .arg("-C")
            .arg(&f.project)
            .args([
                "-c",
                "gpg.format=ssh",
                "-c",
                "gpg.ssh.program=/usr/bin/ssh-keygen",
                "-c",
            ])
            .arg(format!("gpg.ssh.allowedSignersFile={}", allowed.display()))
            .args(["verify-commit", commit])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new("git")
            .arg("-C")
            .arg(&f.project)
            .args(["show", &format!("{commit}:code.py")])
            .output()?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"print(2)\r\n");
    }
    let assert_preserved = || -> Result {
        assert_eq!(git(&f.project, &["rev-parse", "HEAD"])?, head);
        assert_eq!(fs::read(f.project.join(".git/index"))?, index);
        assert_eq!(
            git(
                &f.remote,
                &["for-each-ref", "--format=%(refname):%(objectname)"]
            )?,
            remote
        );
        assert_eq!(fs::read(f.project.join("code.py"))?, b"print(2)\r\n");
        assert_eq!(
            fs::read(f.root.path().join("export/project/code.py"))?,
            b"print(2)\r\n"
        );
        Ok(())
    };
    assert_preserved()?;
    assert!(ladyshell::publication_recovery::ensure_available(&state).is_err());
    let pending_report = json!({"export":f.root.path().join("export"),"applied":true,"conflicts":[],"changes":[{"path":"code.py","action":"modify"}]});
    assert!(pending_prepared.publish(&pending_report, &state).is_err());
    if boundary == "before-sign" {
        // Losing the old credential/trust does not authorize a replacement
        // signature, and must not prevent evidence-preserving abandonment.
        fs::remove_file(&key)?;
        fs::remove_file(key.with_extension("pub"))?;
        fs::remove_file(&allowed)?;
    }
    assert!(ladyshell::publication_recovery::reconcile(&state, true, false).is_err());
    assert_eq!(fs::read(state.join("publication.json"))?, journal);
    assert_eq!(
        fs::read_to_string(f.root.path().join("signer-events"))?,
        events
    );
    // Abandonment records success while leaving another operation's lock in
    // place. Other boundaries exercise release of the original owned lock.
    let lock = f.project.join(".git/index.lock");
    let owned = f.root.path().join("owned-lock");
    if boundary == "after-sign" {
        fs::rename(&lock, &owned)?;
        fs::write(&lock, b"unrelated lock")?;
    }
    let abandoned = ladyshell::publication_recovery::reconcile(&state, false, true)?;
    assert_eq!(abandoned["phase"], "abandoned");
    assert_eq!(abandoned["confirmed"], false);
    assert!(abandoned["commit"].is_null());
    assert_eq!(
        abandoned["owned_index_lock_released"],
        boundary != "after-sign"
    );
    if boundary == "after-sign" {
        assert_eq!(fs::read(&lock)?, b"unrelated lock");
        assert_eq!(fs::read(&owned)?, b"");
    } else {
        assert!(!lock.exists());
    }
    assert_eq!(
        fs::read(abandoned["archive"].as_str().ok_or("archive")?)?,
        journal
    );
    assert_eq!(
        fs::read(f.root.path().join("export/publication.json"))?,
        journal
    );
    assert_eq!(
        fs::read_to_string(f.root.path().join("signer-events"))?,
        events
    );
    assert_preserved()?;
    assert_eq!(
        fs::read(f.root.path().join("export/manifest.json"))?,
        manifest
    );
    if let Some(commit) = commits.first() {
        assert_eq!(
            Some(git(&f.project, &["cat-file", "commit", commit])?),
            retained
        );
    }
    ladyshell::publication_recovery::ensure_available(&state)?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn killed_before_actual_commit_signing_preserves_export_until_abandonment() -> Result {
    signing_interruption(
        "before-sign",
        "killed_before_actual_commit_signing_preserves_export_until_abandonment",
    )
}

#[test]
#[cfg(target_os = "linux")]
fn killed_after_actual_commit_signing_preserves_export_until_abandonment() -> Result {
    signing_interruption(
        "after-sign",
        "killed_after_actual_commit_signing_preserves_export_until_abandonment",
    )
}

#[test]
#[cfg(target_os = "linux")]
fn killed_after_signed_object_before_receipt_retains_unrecorded_object() -> Result {
    signing_interruption(
        "after-object",
        "killed_after_signed_object_before_receipt_retains_unrecorded_object",
    )
}

#[test]
#[cfg(target_os = "linux")]
fn killed_during_recovery_preserves_signed_object_lease_host_edits_and_lock_ownership() -> Result {
    use std::os::unix::process::CommandExt;
    if !signing_crash_supervisor(
        "killed_during_recovery_preserves_signed_object_lease_host_edits_and_lock_ownership",
    )? {
        return Ok(());
    }
    for abandon in [false, true] {
        let f = Fixture::new()?;
        let state = f.root.path().join("state");
        ladyshell::state::create_directory(&state)?;
        git(&f.project, &["push", "knot", "HEAD:refs/heads/agent/test"])?;
        let base = git(&f.project, &["rev-parse", "HEAD"])?;
        let index = fs::read(f.project.join(".git/index"))?;
        let key = f.root.path().join("recovery-signing-key");
        assert!(Command::new("/usr/bin/ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()?
            .status
            .success());
        let allowed = f.root.path().join("recovery-allowed-signers");
        fs::write(
            &allowed,
            format!(
                "host@example.invalid {}",
                fs::read_to_string(key.with_extension("pub"))?
            ),
        )?;
        let policy = f.root.path().join("recovery-policy.json");
        fs::write(
            &policy,
            serde_json::to_vec(
                &json!({"schema_version":1,"signing":{"key":key,"allowed_signers":allowed,"principal":"host@example.invalid","program":"/usr/bin/ssh-keygen"}}),
            )?,
        )?;
        // First obtain a real interrupted signed publication with its exact
        // commit durably recorded. No receipt or ref/index state is fabricated.
        git(&f.project, &["config", "core.filesRefLockTimeout", "10000"])?;
        let ref_lock = f.project.join(".git/refs/heads/agent/test.lock");
        fs::write(&ref_lock, b"fixture-owned branch lock")?;
        let mut publication = SigningCrashGroup {
            child: Command::new(std::env::current_exe()?)
                .args(["--exact", "publication_crash_worker", "--nocapture"])
                .env("LADYSHELL_PUBLICATION_CRASH_ROOT", f.root.path())
                .env("LADYSHELL_PUBLICATION_CRASH_POLICY", &policy)
                .process_group(0)
                .spawn()?,
            reaped: false,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        let receipt: Value = loop {
            if let Ok(bytes) = fs::read(state.join("publication.json")) {
                if let Ok(receipt) = serde_json::from_slice::<Value>(&bytes) {
                    if receipt["phase"] == "committed" {
                        break receipt;
                    }
                }
            }
            if publication.child.try_wait()?.is_some() || std::time::Instant::now() >= deadline {
                return Err("publication did not reach committed journal".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert!(publication.kill_and_reap()?);
        fs::remove_file(&ref_lock)?;
        let commit = receipt["commit"].as_str().ok_or("commit")?;
        assert_eq!(receipt["expected_remote"], base);
        let object = git(&f.project, &["cat-file", "commit", commit])?;
        assert!(object.contains("gpgsig -----BEGIN SSH SIGNATURE-----"));
        let prepared_index = fs::read(
            receipt["local"]["prepared"]
                .as_str()
                .ok_or("prepared index")?,
        )?;
        let manifest = fs::read(f.root.path().join("export/manifest.json"))?;
        fs::write(
            f.project.join("unrelated-host-file"),
            b"preserve unrelated host edit",
        )?;
        fs::write(f.project.join("code.py"), b"preserve later host edit\n")?;
        // finish_local asks symbolic-ref only after it owns the index lock.
        // The controlled Git helper blocks there before either ref/index changes.
        let bin = f.root.path().join("recovery-bin");
        fs::create_dir(&bin)?;
        fs::write(
            bin.join("git"),
            r#"#!/usr/bin/python3
import os, pathlib, sys, time
root = pathlib.Path(__file__).parent.parent
if sys.argv[-3:] == ['symbolic-ref', '--quiet', 'HEAD']:
    marker = root / 'recovery-boundary'
    temporary = marker.with_suffix('.tmp')
    temporary.write_text('owned-lock-before-ref')
    temporary.replace(marker)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        time.sleep(0.005)
    sys.exit(92)
os.execv('/usr/bin/git', ['/usr/bin/git'] + sys.argv[1:])
"#,
        )?;
        fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o700))?;
        let paths = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
            &std::env::var_os("PATH").ok_or("PATH")?,
        )))?;
        let mut recovery = SigningCrashGroup {
            child: Command::new(std::env::current_exe()?)
                .args(["--exact", "recovery_interleaving_worker", "--nocapture"])
                .env("LADYSHELL_RECOVERY_INTERLEAVING_ROOT", f.root.path())
                .env("PATH", paths)
                .process_group(0)
                .spawn()?,
            reaped: false,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        while !f.root.path().join("recovery-boundary").exists() {
            if recovery.child.try_wait()?.is_some() || std::time::Instant::now() >= deadline {
                return Err("recovery did not reach owned-lock handshake".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            fs::read_to_string(f.root.path().join("recovery-boundary"))?,
            "owned-lock-before-ref"
        );
        assert!(recovery.kill_and_reap()?);
        assert!(!f.root.path().join("recovery-outcome.json").exists());
        let interrupted = fs::read(state.join("publication.json"))?;
        assert_eq!(
            serde_json::from_slice::<Value>(&interrupted)?["commit"],
            commit
        );
        let assert_preserved = || -> Result {
            assert_eq!(git(&f.project, &["rev-parse", "HEAD"])?, base);
            assert_eq!(fs::read(f.project.join(".git/index"))?, index);
            assert_eq!(
                git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?,
                base
            );
            assert_eq!(
                fs::read(f.project.join("code.py"))?,
                b"preserve later host edit\n"
            );
            assert_eq!(
                fs::read(f.project.join("unrelated-host-file"))?,
                b"preserve unrelated host edit"
            );
            assert_eq!(
                fs::read(f.root.path().join("export/project/code.py"))?,
                b"print(2)\r\n"
            );
            assert_eq!(
                fs::read(f.root.path().join("export/manifest.json"))?,
                manifest
            );
            assert_eq!(git(&f.project, &["cat-file", "commit", commit])?, object);
            Ok(())
        };
        assert_preserved()?;
        assert!(ladyshell::publication_recovery::ensure_available(&state).is_err());
        let lock = f.project.join(".git/index.lock");
        let owned = f.root.path().join("recovery-owned-lock");
        fs::rename(&lock, &owned)?;
        fs::write(&lock, b"foreign recovery lock")?;
        assert!(ladyshell::publication_recovery::reconcile(&state, true, false).is_err());
        assert_eq!(fs::read(&lock)?, b"foreign recovery lock");
        assert_eq!(fs::read(state.join("publication.json"))?, interrupted);
        assert_preserved()?;
        if abandon {
            let abandoned = ladyshell::publication_recovery::reconcile(&state, false, true)?;
            assert_eq!(abandoned["phase"], "abandoned");
            assert_eq!(abandoned["commit"], commit);
            assert_eq!(abandoned["owned_index_lock_released"], false);
            assert_eq!(fs::read(&lock)?, b"foreign recovery lock");
            assert_eq!(
                fs::read(abandoned["archive"].as_str().ok_or("archive")?)?,
                interrupted
            );
            assert_preserved()?;
        } else {
            fs::remove_file(&lock)?;
            fs::rename(&owned, &lock)?;
            let recovered = ladyshell::publication_recovery::reconcile(&state, true, false)?;
            assert_eq!(recovered["phase"], "published");
            assert_eq!(recovered["commit"], commit);
            assert_eq!(recovered["expected_remote"], base);
            assert_eq!(git(&f.project, &["rev-parse", "HEAD"])?, commit);
            assert_eq!(
                git(&f.remote, &["rev-parse", "refs/heads/agent/test"])?,
                commit
            );
            assert_eq!(fs::read(f.project.join(".git/index"))?, prepared_index);
            assert!(!lock.exists());
            assert_eq!(
                fs::read(f.project.join("code.py"))?,
                b"preserve later host edit\n"
            );
            assert_eq!(
                fs::read(f.project.join("unrelated-host-file"))?,
                b"preserve unrelated host edit"
            );
            assert_eq!(git(&f.project, &["cat-file", "commit", commit])?, object);
            assert_eq!(
                ladyshell::publication_recovery::reconcile(&state, true, false)?,
                recovered
            );
        }
        ladyshell::publication_recovery::ensure_available(&state)?;
    }
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn signing_marker_publication_waits_for_complete_payload() -> Result {
    signing_interruption(
        "before-sign",
        "signing_marker_publication_waits_for_complete_payload",
    )
}

#[test]
#[cfg(target_os = "linux")]
fn signing_watchdog_reaps_separately_grouped_nested_helpers() -> Result {
    use std::os::unix::process::CommandExt;
    let Some(root) = std::env::var_os("LADYSHELL_SIGNING_WATCHDOG_ROOT") else {
        let root = tempfile::tempdir()?;
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "signing_watchdog_reaps_separately_grouped_nested_helpers",
                "--nocapture",
            ])
            .env("LADYSHELL_SIGNING_CRASH_SUPERVISED", "manager")
            .env("LADYSHELL_SIGNING_WATCHDOG_ROOT", root.path())
            .status()?;
        assert!(status.success());
        assert_eq!(
            fs::read(root.path().join("watchdog-cleaned"))?,
            b"timeout-cleaned-no-children"
        );
        let helpers: Vec<Value> =
            serde_json::from_slice(&fs::read(root.path().join("watchdog-helpers.json"))?)?;
        assert_eq!(helpers.len(), 2);
        assert_ne!(helpers[0]["group"], helpers[1]["group"]);
        for helper in helpers {
            let pid = helper["pid"].as_u64().ok_or("helper pid")?;
            if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
                let start = stat
                    .rsplit_once(") ")
                    .ok_or("process stat")?
                    .1
                    .split_whitespace()
                    .nth(19)
                    .ok_or("process start time")?;
                assert_ne!(
                    Some(start),
                    helper["start"].as_str(),
                    "owned watchdog helper survived manager exit"
                );
            }
        }
        return Ok(());
    };
    if !signing_crash_supervisor("signing_watchdog_reaps_separately_grouped_nested_helpers")? {
        return Ok(());
    }
    // The manager triggers its watchdog only after two separately grouped
    // Python helpers exist. Their thirty-second fallback bounds this intentional
    // hang even if the watchdog regression breaks.
    let script = PathBuf::from(root).join("watchdog-helper.py");
    fs::write(
        &script,
        r#"import json, os, pathlib, subprocess, sys, time
root = pathlib.Path(__file__).parent
child = subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(30)'], start_new_session=True)
def identity(pid):
    start = pathlib.Path('/proc/' + str(pid) + '/stat').read_text().rsplit(') ', 1)[1].split()[19]
    return {'pid': pid, 'group': os.getpgid(pid), 'start': start}
(root / 'watchdog-helpers.json').write_text(json.dumps([identity(os.getpid()), identity(child.pid)]))
marker = root / 'watchdog-ready'
temporary = marker.with_suffix('.tmp')
temporary.write_text('nested-ready')
temporary.replace(marker)
try:
    time.sleep(30)
finally:
    child.kill()
    child.wait(timeout=5)
"#,
    )?;
    let mut child = Command::new("/usr/bin/python3")
        .arg(script)
        .process_group(0)
        .spawn()?;
    child.wait()?;
    Err("watchdog did not interrupt the deliberately blocked scenario".into())
}
