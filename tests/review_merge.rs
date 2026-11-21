use ladyshell::review_merge;
use serde_json::{json, Value};
use std::{path::Path, process::Command};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn git(p: &Path, a: &[&str]) -> Result<String> {
    let o = Command::new("git").arg("-C").arg(p).args(a).output()?;
    if !o.status.success() {
        return Err(String::from_utf8(o.stderr)?.into());
    }
    Ok(String::from_utf8(o.stdout)?.trim().into())
}
#[test]
fn merge_recovery_confirms_exact_head_and_refuses_advanced_target() -> Result {
    let t = tempfile::tempdir()?;
    let repo = t.path().join("repo");
    let remote = t.path().join("remote.git");
    let state = t.path().join("state");
    std::fs::create_dir(&repo)?;
    std::fs::create_dir(&remote)?;
    ladyshell::state::create_directory(&state)?;
    git(&repo, &["init", "-b", "main"])?;
    git(&remote, &["init", "--bare"])?;
    git(&repo, &["config", "user.name", "Fixture"])?;
    git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
    std::fs::write(repo.join("code"), "base")?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-m", "base"])?;
    let base = git(&repo, &["rev-parse", "HEAD"])?;
    std::fs::write(repo.join("code"), "head")?;
    git(&repo, &["commit", "-am", "head"])?;
    let head = git(&repo, &["rev-parse", "HEAD"])?;
    git(
        &repo,
        &[
            "push",
            remote.to_str().ok_or("path")?,
            "HEAD:refs/heads/main",
        ],
    )?;
    let receipt = json!({"schema_version":1,"project":repo,"head":head,"expected_target":base,"reference":"refs/heads/main","destination":remote,"confirmed":false,"review":{"review":{"repository":"did:plc:repo","source_repository":"did:plc:repo"}}});
    std::fs::write(state.join("merge.json"), serde_json::to_vec(&receipt)?)?;
    assert_eq!(review_merge::reconcile(&state, false)?["confirmed"], true);
    let first_archives = std::fs::read_dir(state.join("merge-attempts"))?
        .map(|entry| entry.map(|e| e.path().join("confirmed.json")))
        .collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(first_archives.len(), 1);
    let first_intent: Value = serde_json::from_slice(&std::fs::read(
        first_archives[0].with_file_name("intent.json"),
    )?)?;
    assert_eq!(first_intent, receipt);
    let first_archive = std::fs::read(&first_archives[0])?;
    let first: Value = serde_json::from_slice(&first_archive)?;
    assert_eq!(first["head"], head);
    assert_eq!(first["confirmed"], true);
    assert_eq!(review_merge::reconcile(&state, false)?["confirmed"], true);
    assert_eq!(std::fs::read(&first_archives[0])?, first_archive);

    std::fs::write(repo.join("code"), "later work")?;
    git(&repo, &["commit", "-am", "later"])?;
    let later = git(&repo, &["rev-parse", "HEAD"])?;
    git(
        &repo,
        &[
            "push",
            remote.to_str().ok_or("path")?,
            "HEAD:refs/heads/main",
        ],
    )?;
    std::fs::write(state.join("merge.json"), serde_json::to_vec(&receipt)?)?;
    assert!(review_merge::reconcile(&state, true).is_err());
    assert_eq!(git(&remote, &["rev-parse", "main"])?, later);
    let retained: Value = serde_json::from_slice(&std::fs::read(state.join("merge.json"))?)?;
    assert_eq!(retained, receipt);
    // A later confirmed operation retains the first receipt after the mutable
    // merge pointer is replaced, without executing another remote write.
    let next = json!({"schema_version":1,"project":repo,"head":later,"expected_target":head,"reference":"refs/heads/main","destination":remote,"confirmed":false,"review":{"review":{"repository":"did:plc:repo","source_repository":"did:plc:repo"}}});
    std::fs::write(state.join("merge.json"), serde_json::to_vec(&next)?)?;
    assert_eq!(review_merge::reconcile(&state, false)?["confirmed"], true);
    assert_eq!(std::fs::read_dir(state.join("merge-attempts"))?.count(), 2);
    assert_eq!(std::fs::read(&first_archives[0])?, first_archive);

    Ok(())
}

#[test]
fn integration_cross_repository_merge_never_confirms_source_as_target_or_retries() -> Result {
    let t = tempfile::tempdir()?;
    let repo = t.path().join("repo");
    let source = t.path().join("source.git");
    let target = t.path().join("target.git");
    let state = t.path().join("state");
    for p in [&repo, &source, &target] {
        std::fs::create_dir(p)?;
    }
    ladyshell::state::create_directory(&state)?;
    git(&repo, &["init", "-b", "main"])?;
    git(&repo, &["config", "user.name", "Fixture"])?;
    git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
    for p in [&source, &target] {
        git(p, &["init", "--bare"])?;
    }
    std::fs::write(repo.join("code"), "base")?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-m", "base"])?;
    let base = git(&repo, &["rev-parse", "HEAD"])?;
    for p in [&source, &target] {
        git(
            &repo,
            &["push", p.to_str().ok_or("path")?, "HEAD:refs/heads/main"],
        )?;
    }
    std::fs::write(repo.join("code"), "head")?;
    git(&repo, &["commit", "-am", "head"])?;
    let head = git(&repo, &["rev-parse", "HEAD"])?;
    let receipt = json!({"schema_version":1,"project":repo,"head":head,"expected_target":base,"reference":"refs/heads/main","destination":source,"confirmed":false,"review":{"review":{"repository":"did:plc:target","source_repository":"did:plc:source"}}});
    for source_advanced in [false, true] {
        if source_advanced {
            git(
                &repo,
                &[
                    "push",
                    source.to_str().ok_or("path")?,
                    "HEAD:refs/heads/main",
                ],
            )?;
        }
        for retry in [false, true] {
            std::fs::write(state.join("merge.json"), serde_json::to_vec(&receipt)?)?;
            assert!(
                review_merge::reconcile(&state, retry).is_err(),
                "source_advanced={source_advanced}, retry={retry}"
            );
            assert_eq!(git(&target, &["rev-parse", "main"])?, base);
            assert_eq!(
                git(&source, &["rev-parse", "main"])?,
                if source_advanced {
                    head.as_str()
                } else {
                    base.as_str()
                }
            );
            let saved: Value = serde_json::from_slice(&std::fs::read(state.join("merge.json"))?)?;
            assert_eq!(saved, receipt);
        }
    }
    assert!(!state.join("merge-attempts").exists());
    Ok(())
}
