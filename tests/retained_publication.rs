use ladyshell::{publish::Options, retained_publication, snapshot};
use serde_json::{json, Value};
use std::{path::Path, process::Command};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn git(p: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git").arg("-C").arg(p).args(args).output()?;
    if !o.status.success() {
        return Err(String::from_utf8(o.stderr)?.into());
    }
    Ok(String::from_utf8(o.stdout)?.trim().into())
}
fn records(path: &Path) -> Result<Value> {
    Ok(Value::Object(
        snapshot::inventory(path)?
            .iter()
            .map(|(p, e)| {
                (
                    p.clone(),
                    json!({"sha256":e.sha256,"executable":e.executable}),
                )
            })
            .collect(),
    ))
}
#[test]
fn retained_export_publishes_clean_or_already_applied_without_agent() -> Result {
    for already_applied in [false, true] {
        let t = tempfile::tempdir()?;
        let project = t.path().join("project");
        let remote = t.path().join("remote.git");
        let state = t.path().join("state");
        let export = state.join("exports/saved");
        std::fs::create_dir(&project)?;
        std::fs::create_dir(&remote)?;
        ladyshell::state::create_directory(&state)?;
        std::fs::create_dir_all(export.join("project"))?;
        git(&project, &["init", "-b", "agent/test"])?;
        git(&remote, &["init", "--bare"])?;
        git(&project, &["config", "user.name", "Fixture"])?;
        git(&project, &["config", "user.email", "test@example.invalid"])?;
        git(
            &project,
            &["remote", "add", "knot", remote.to_str().ok_or("remote")?],
        )?;
        std::fs::write(project.join("code"), "before")?;
        std::fs::write(project.join("obsolete"), "obsolete")?;
        git(&project, &["add", "."])?;
        git(&project, &["commit", "-m", "base"])?;
        let original = records(&project)?;
        std::fs::write(export.join("project/code"), "after")?;
        std::fs::write(export.join("project/new"), "new")?;
        let exported = records(&export.join("project"))?;
        std::fs::write(
            export.join("manifest.json"),
            serde_json::to_vec(
                &json!({"schema_version":2,"sandbox_id":"deleted-agent","files":exported}),
            )?,
        )?;
        if already_applied {
            std::fs::write(project.join("code"), "after")?;
            std::fs::write(project.join("new"), "new")?;
            std::fs::remove_file(project.join("obsolete"))?;
        }
        std::fs::write(
            state.join("state.json"),
            serde_json::to_vec(
                &json!({"schema_version":2,"sandbox_name":"deleted-agent","sandbox_id":"deleted-agent","owner":"fixture","policy_hash":"fixture","codex_binary":"fixture","desired_hash":"fixture","image_id":"fixture","project_snapshot":export.join("project"),"build_dir":t.path(),"context":{"gateway":"fixture","workspace":"default"},"desired_inputs":{"project":project},"host_sources":original,"checkout_base":if already_applied{exported.clone()}else{original.clone()},"sync":{"destination":"exports"},"last_sync":export}),
            )?,
        )?;
        let receipt = retained_publication::run(
            &state,
            &export,
            &Options {
                remote: "knot".into(),
                branch: "agent/test".into(),
                message: "Preserved experiment".into(),
                policy: None,
            },
        )?;
        assert_eq!(receipt["confirmed"], true);
        assert_eq!(git(&remote, &["show", "agent/test:code"])?, "after");
        assert!(git(&project, &["status", "--porcelain"])?.is_empty());
        assert!(!project.join("obsolete").exists());
    }
    Ok(())
}

#[test]
fn lost_pending_key_can_be_explicitly_replaced_from_the_same_retained_export() -> Result {
    use ladyshell::publication_recovery;
    use std::{fs, os::unix::fs::PermissionsExt};

    let t = tempfile::tempdir()?;
    let project = t.path().join("project");
    let remote = t.path().join("remote.git");
    let state = t.path().join("state");
    let export = state.join("exports/saved");
    fs::create_dir(&project)?;
    fs::create_dir(&remote)?;
    ladyshell::state::create_directory(&state)?;
    fs::create_dir_all(export.join("project"))?;
    git(&project, &["init", "-b", "agent/test"])?;
    git(&remote, &["init", "--bare"])?;
    git(&project, &["config", "user.name", "Fixture"])?;
    git(&project, &["config", "user.email", "test@example.invalid"])?;
    git(
        &project,
        &["remote", "add", "knot", remote.to_str().ok_or("remote")?],
    )?;
    fs::write(project.join("code"), "before\n")?;
    fs::write(project.join("obsolete"), "obsolete\n")?;
    git(&project, &["add", "."])?;
    git(&project, &["commit", "-m", "base"])?;
    git(&project, &["push", "knot", "HEAD:refs/heads/agent/test"])?;
    let base = git(&project, &["rev-parse", "HEAD"])?;
    let original = records(&project)?;
    fs::write(export.join("project/code"), "after\n")?;
    fs::write(
        export.join("project/new"),
        "#!/bin/sh\nprintf retained\\n\n",
    )?;
    fs::set_permissions(
        export.join("project/new"),
        fs::Permissions::from_mode(0o755),
    )?;
    let exported = records(&export.join("project"))?;
    fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_id":"deleted-agent","files":exported}),
        )?,
    )?;
    fs::write(
        state.join("state.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_name":"deleted-agent","sandbox_id":"deleted-agent","owner":"fixture","policy_hash":"fixture","codex_binary":"fixture","desired_hash":"fixture","image_id":"fixture","project_snapshot":export.join("project"),"build_dir":t.path(),"context":{"gateway":"fixture","workspace":"default"},"desired_inputs":{"project":project},"host_sources":original,"checkout_base":original,"sync":{"destination":"exports"},"last_sync":export}),
        )?,
    )?;
    let manifest_bytes = fs::read(export.join("manifest.json"))?;
    let mut keys = Vec::new();
    let mut trusts = Vec::new();
    let mut policies = Vec::new();
    let wrapper = t.path().join("fail-actual-signing");
    // Preflight really signs and verifies. Only Git's actual commit signing fails.
    fs::write(
        &wrapper,
        r#"#!/usr/bin/python3
import pathlib, subprocess, sys
args = sys.argv[1:]
signing = args[:2] == ['-Y', 'sign']
preflight = signing and pathlib.Path(args[-1]).read_bytes() == b'Ladyshell explicit host signing preflight\n'
if signing:
    with pathlib.Path(__file__).with_suffix('.events').open('a') as log:
        log.write('preflight-sign\n' if preflight else 'actual-sign-refused\n')
if signing and not preflight:
    sys.stderr.write('Fixture refuses actual commit signing after genuine preflight\n')
    sys.exit(73)
sys.exit(subprocess.run(['/usr/bin/ssh-keygen'] + args).returncode)
"#,
    )?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
    for name in ["old", "new"] {
        let key = t.path().join(format!("{name}-key"));
        assert!(Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()?
            .success());
        let trust = t.path().join(format!("{name}-allowed"));
        fs::write(
            &trust,
            format!(
                "host@example.invalid {}",
                fs::read_to_string(key.with_extension("pub"))?
            ),
        )?;
        let policy = t.path().join(format!("{name}-policy.json"));
        fs::write(
            &policy,
            serde_json::to_vec(
                &json!({"schema_version":1,"signing":{"key":key,"allowed_signers":trust,"principal":"host@example.invalid","program":if name == "old" {wrapper.clone()} else {"/usr/bin/ssh-keygen".into()}}}),
            )?,
        )?;
        keys.push(key);
        trusts.push(trust);
        policies.push(policy);
    }
    let old_trust = fs::read(&trusts[0])?;
    let mut options = Options {
        remote: "knot".into(),
        branch: "agent/test".into(),
        message: "Old pending attempt".into(),
        policy: Some(policies[0].clone()),
    };
    let failure = retained_publication::run(&state, &export, &options)
        .err()
        .ok_or("actual signing unexpectedly succeeded")?;
    assert!(failure
        .to_string()
        .contains("Fixture refuses actual commit signing"));
    assert_eq!(
        fs::read_to_string(wrapper.with_extension("events"))?,
        "preflight-sign\nactual-sign-refused\n"
    );
    let pending_bytes = fs::read(state.join("publication.json"))?;
    let pending: Value = serde_json::from_slice(&pending_bytes)?;
    assert_eq!(pending["phase"], "exported");
    assert!(pending["commit"].is_null());
    assert_eq!(pending["expected_remote"], base);
    assert_eq!(pending["base"], base);
    assert_eq!(pending["export"], json!(export));
    assert_eq!(pending["signing"]["key"], json!(keys[0]));
    assert_eq!(fs::read(export.join("publication.json"))?, pending_bytes);
    assert_eq!(records(&project)?, exported);
    assert_eq!(git(&project, &["rev-parse", "HEAD"])?, base);
    assert_eq!(git(&remote, &["rev-parse", "refs/heads/agent/test"])?, base);
    let index_bytes = fs::read(project.join(".git/index"))?;
    let state_after_apply = fs::read(state.join("state.json"))?;
    fs::remove_file(&keys[0])?;
    fs::remove_file(&trusts[0])?;
    for retry in [false, true] {
        assert!(publication_recovery::reconcile(&state, retry, false).is_err());
        assert_eq!(fs::read(state.join("publication.json"))?, pending_bytes);
        assert_eq!(fs::read(export.join("publication.json"))?, pending_bytes);
    }
    assert!(retained_publication::run(&state, &export, &options).is_err());
    let abandoned = publication_recovery::reconcile(&state, false, true)?;
    assert_eq!(abandoned["phase"], "abandoned");
    assert_eq!(abandoned["confirmed"], false);
    assert!(abandoned["commit"].is_null());
    let archive = Path::new(abandoned["archive"].as_str().ok_or("archive")?);
    let archive_bytes = fs::read(archive)?;
    assert_eq!(archive_bytes, pending_bytes);
    assert_eq!(serde_json::from_slice::<Value>(&archive_bytes)?, pending);
    assert_eq!(fs::read(export.join("manifest.json"))?, manifest_bytes);
    assert_eq!(records(&project)?, exported);
    assert_eq!(records(&export.join("project"))?, exported);
    assert_eq!(fs::read(state.join("state.json"))?, state_after_apply);
    assert_eq!(fs::read(project.join(".git/index"))?, index_bytes);
    assert_eq!(git(&project, &["rev-parse", "HEAD"])?, base);
    assert_eq!(git(&remote, &["rev-parse", "refs/heads/agent/test"])?, base);

    // No state/source repair: ordinary retained publication selects fresh authority.
    options.policy = Some(policies[1].clone());
    options.message = "Explicit replacement-key publication".into();
    let receipt = retained_publication::run(&state, &export, &options)?;
    let commit = receipt["commit"].as_str().ok_or("new commit")?;
    assert_ne!(commit, base);
    assert_eq!(receipt["phase"], "published");
    assert_eq!(receipt["confirmed"], true);
    assert_eq!(receipt["base"], pending["base"]);
    assert_eq!(receipt["expected_remote"], pending["expected_remote"]);
    assert_eq!(receipt["destination"], pending["destination"]);
    assert_eq!(receipt["reference"], pending["reference"]);
    assert_eq!(receipt["export"], pending["export"]);
    assert_eq!(receipt["signing"]["key"], json!(keys[1]));
    assert_ne!(receipt["policy_digests"], pending["policy_digests"]);
    assert!(receipt.get("archive").is_none());
    assert_eq!(git(&project, &["rev-parse", "HEAD"])?, commit);
    assert_eq!(
        git(&remote, &["rev-parse", "refs/heads/agent/test"])?,
        commit
    );
    assert_eq!(
        git(&project, &["rev-list", "--parents", "-n", "1", commit])?,
        format!("{commit} {base}")
    );
    assert_eq!(
        git(&project, &["show", "-s", "--format=%B", commit])?,
        options.message
    );
    assert_eq!(
        git(&project, &["ls-tree", "--name-only", "-r", commit])?,
        "code\nnew"
    );
    for (name, mode) in [("code", "100644"), ("new", "100755")] {
        let payload = fs::read(export.join("project").join(name))?;
        let object = git(
            &project,
            &[
                "hash-object",
                export
                    .join("project")
                    .join(name)
                    .to_str()
                    .ok_or("payload")?,
            ],
        )?;
        assert_eq!(
            git(&project, &["ls-tree", commit, "--", name])?,
            format!("{mode} blob {object}\t{name}")
        );
        let shown = Command::new("git")
            .arg("-C")
            .arg(&project)
            .args(["show", &format!("{commit}:{name}")])
            .output()?;
        assert!(shown.status.success());
        assert_eq!(shown.stdout, payload);
    }
    let independent_old_trust = t.path().join("independent-old-trust");
    fs::write(&independent_old_trust, old_trust)?;
    for (trust, accepted) in [(&trusts[1], true), (&independent_old_trust, false)] {
        let verified = Command::new("git")
            .arg("-C")
            .arg(&project)
            .args([
                "-c",
                "gpg.format=ssh",
                "-c",
                "gpg.ssh.program=/usr/bin/ssh-keygen",
                "-c",
            ])
            .arg(format!("gpg.ssh.allowedSignersFile={}", trust.display()))
            .args(["-c", "gpg.ssh.revocationFile=", "verify-commit", commit])
            .output()?;
        assert_eq!(verified.status.success(), accepted);
    }
    for retry in [false, true, true] {
        let recovered = publication_recovery::reconcile(&state, retry, false)?;
        assert_eq!(recovered["commit"], commit);
        assert_eq!(recovered["confirmed"], true);
        assert_eq!(
            git(&remote, &["rev-parse", "refs/heads/agent/test"])?,
            commit
        );
    }
    assert_eq!(fs::read(archive)?, archive_bytes);
    assert_eq!(fs::read(export.join("manifest.json"))?, manifest_bytes);
    assert_eq!(records(&project)?, exported);
    assert_eq!(records(&export.join("project"))?, exported);
    assert_eq!(
        fs::read_to_string(wrapper.with_extension("events"))?,
        "preflight-sign\nactual-sign-refused\n"
    );
    assert!(!keys[0].exists());
    assert!(!trusts[0].exists());
    assert!(git(&project, &["status", "--porcelain"])?.is_empty());
    Ok(())
}
