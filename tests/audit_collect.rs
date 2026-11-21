use ladyshell::audit::collect::retain_agent;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn root() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
}

#[test]
fn retains_transcript_with_hash_command_and_exclusive_private_publication() -> TestResult {
    let directory = root()?;
    let command = vec!["codex".to_owned(), "exec".to_owned()];
    let receipt = retain_agent(
        directory.path(),
        "hunter",
        b"synthetic transcript\n",
        &command,
    )?;
    assert_eq!(receipt.id, "hunter-transcript");
    assert_eq!(receipt.path, "agents/hunter/artifacts/transcript.jsonl");
    assert_eq!(receipt.command, command);
    assert_eq!(receipt.producer, "hunter");
    assert_eq!(receipt.size, 21);
    assert_eq!(
        receipt.sha256,
        ladyshell::files::hash(b"synthetic transcript\n")
    );
    let path = directory.path().join(&receipt.path);
    assert_eq!(fs::read(&path)?, b"synthetic transcript\n");
    assert_eq!(fs::metadata(&path)?.mode() & 0o077, 0);
    assert!(retain_agent(directory.path(), "hunter", b"replacement", &command).is_err());
    assert_eq!(fs::read(&path)?, b"synthetic transcript\n");
    Ok(())
}

#[test]
fn rejects_unbounded_transcripts_invalid_identity_and_commands_without_writing() -> TestResult {
    let directory = root()?;
    assert!(retain_agent(
        directory.path(),
        "hunter",
        &vec![0; 4 * 1024 * 1024 + 1],
        &["codex".into()]
    )
    .is_err());
    assert!(retain_agent(directory.path(), "../hunter", b"x", &["codex".into()]).is_err());
    assert!(retain_agent(directory.path(), "hunter", b"x", &[]).is_err());
    assert!(retain_agent(directory.path(), "hunter", b"x", &["codex\0".into()]).is_err());
    assert_eq!(fs::read_dir(directory.path())?.count(), 0);
    Ok(())
}

#[test]
fn refuses_linked_transcript_destinations_and_shared_directories() -> TestResult {
    let directory = root()?;
    let external = root()?;
    symlink(external.path(), directory.path().join("agents"))?;
    assert!(retain_agent(directory.path(), "hunter", b"x", &["codex".into()]).is_err());
    assert_eq!(fs::read_dir(external.path())?.count(), 0);
    let directory = root()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))?;
    assert!(retain_agent(directory.path(), "hunter", b"x", &["codex".into()]).is_err());
    assert!(!directory.path().join("agents").exists());
    Ok(())
}

#[test]
fn transcript_publication_preserves_symlink_and_hardlink_destinations() -> TestResult {
    for hardlink in [false, true] {
        let directory = root()?;
        let artifact = retain_agent(directory.path(), "hunter", b"original", ["codex".into()])?;
        let target = directory.path().join(artifact.path);
        let outside = directory.path().join("outside");
        fs::rename(&target, &outside)?;
        if hardlink {
            fs::hard_link(&outside, &target)?;
        } else {
            symlink(&outside, &target)?;
        }
        assert!(
            retain_agent(directory.path(), "hunter", b"replacement", ["codex".into()]).is_err()
        );
        assert_eq!(fs::read(&outside)?, b"original");
    }
    Ok(())
}
