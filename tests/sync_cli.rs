use std::process::Command;
#[test]
fn sync_dispatches_and_accepts_preview_and_apply() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    for flag in ["--dry-run", "--apply"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .args(["sync", "--state"])
            .arg(temp.path().join("state"))
            .arg(flag)
            .output()?;
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains("État absent"), "{error}");
    }
    Ok(())
}
#[test]
fn worker_protocol_is_registered() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["snapshot-list", "--help"])
        .output()?;
    assert!(output.status.success());
    Ok(())
}
#[test]
fn sync_accepts_project_discovery_and_explicit_export() -> Result<(), Box<dyn std::error::Error>> {
    for args in [
        vec!["ladyshell", "sync"],
        vec!["ladyshell", "sync", "--export"],
        vec!["ladyshell", "sync", "--json"],
    ] {
        assert!(ladyshell_cli::cli::validate_args(&args).is_ok(), "{args:?}");
    }
    assert!(
        ladyshell_cli::cli::validate_args(&["ladyshell", "sync", "--export", "--dry-run"]).is_err()
    );
    Ok(())
}
#[test]
fn missing_association_refuses_before_contacting_backend() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .arg("sync")
        .current_dir(temp.path())
        .env("XDG_STATE_HOME", temp.path().join("xdg"))
        .env("PATH", "")
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr)?.contains("Aucune sandbox associée"));
    Ok(())
}
#[test]
fn default_is_apply_and_export_and_preview_are_readonly() -> Result<(), Box<dyn std::error::Error>>
{
    use clap::Parser;
    for (flags, applies) in [
        (vec![], true),
        (vec!["--apply"], true),
        (vec!["--export"], false),
        (vec!["--dry-run"], false),
    ] {
        let mut argv = vec!["ladyshell", "sync"];
        argv.extend(flags);
        match ladyshell_cli::cli::Cli::try_parse_from(argv)?.command {
            ladyshell_cli::cli::Command::Sync(args) => assert_eq!(args.applies(), applies),
            _ => return Err("incorrect command".into()),
        }
    }
    Ok(())
}
