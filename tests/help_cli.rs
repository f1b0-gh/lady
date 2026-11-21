use clap::{CommandFactory, Parser};
use ladyshell_cli::cli::Cli;
use std::{error::Error, process::Command};

fn help(arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(arguments)
        .current_dir(temp.path())
        .env_clear()
        .env("HOME", temp.path())
        .env("XDG_STATE_HOME", temp.path())
        .env("PATH", temp.path())
        .output()?;
    assert!(output.status.success(), "{arguments:?}: {output:?}");
    assert!(output.stderr.is_empty(), "{arguments:?}: {output:?}");
    assert_eq!(std::fs::read_dir(temp.path())?.count(), 0);
    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn help_explains_commands_and_nested_required_inputs_without_a_runtime(
) -> Result<(), Box<dyn Error>> {
    let overview = help(&["help"])?;
    assert!(overview.contains("Examples:"), "{overview}");
    assert!(overview.contains("ladyshell help <COMMAND>"));
    assert_eq!(overview, help(&["--help"])?);
    for (path, required, example) in [
        (vec!["run"], "--state <STATE>", "-- cargo test"),
        (vec!["cs", "checkpoint"], "--attempt <ATTEMPT>", "--epoch 1"),
        (
            vec!["review", "merge-check"],
            "--expected-target <EXPECTED_TARGET>",
            "--policy",
        ),
        (
            vec!["deps", "prune", "validate"],
            "--plan <PLAN>",
            "--state",
        ),
    ] {
        let mut request = vec!["help"];
        request.extend(&path);
        let text = help(&request)?;
        assert!(text.contains(required), "{text}");
        assert!(text.contains("Examples:"), "{text}");
        assert!(text.contains(example), "{text}");
        let mut flag = path;
        flag.push("--help");
        assert_eq!(text, help(&flag)?);
    }
    Ok(())
}

fn public_paths(command: &clap::Command, path: Vec<String>, paths: &mut Vec<Vec<String>>) {
    for child in command
        .get_subcommands()
        .filter(|child| !child.is_hide_set())
    {
        if child.get_name() == "help" || child.get_name() == "artifact" {
            continue;
        }
        let mut next = path.clone();
        next.push(child.get_name().to_owned());
        paths.push(next.clone());
        public_paths(child, next, paths);
    }
}

#[test]
fn every_public_command_has_descriptive_help_without_credentials_or_state(
) -> Result<(), Box<dyn Error>> {
    let mut command = Cli::command();
    command.build();
    let mut paths = vec![];
    public_paths(&command, vec![], &mut paths);
    for path in paths {
        let mut request = vec!["help"];
        request.extend(path.iter().map(String::as_str));
        let text = help(&request)?;
        assert!(text.contains("Usage:"), "{request:?}: {text}");
        assert!(
            !text.starts_with("Usage:"),
            "Missing description: {request:?}"
        );
        let mut flags: Vec<_> = path.iter().map(String::as_str).collect();
        flags.push("--help");
        assert_eq!(text, help(&flags)?, "{path:?}");
    }
    Ok(())
}

#[test]
fn unknown_help_topics_are_errors_without_creating_state() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    for arguments in [
        vec!["help", "unknown-command"],
        vec!["help", "cs", "unknown-command"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .args(&arguments)
            .env_clear()
            .env("HOME", temp.path())
            .env("PATH", temp.path())
            .current_dir(temp.path())
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)?.contains("unrecognized subcommand"));
    }
    assert_eq!(std::fs::read_dir(temp.path())?.count(), 0);
    Ok(())
}

#[test]
fn artifact_local_help_explains_the_retired_command() -> Result<(), Box<dyn Error>> {
    let text = help(&["help", "artifact"])?;
    assert!(text.contains("retired"), "{text}");
    assert!(text.contains("ladyboot directly"), "{text}");
    Ok(())
}

#[test]
fn retained_execution_help_is_local_and_hides_worker() -> Result<(), Box<dyn Error>> {
    let overview = help(&["help", "execution"])?;
    for command in [
        "install",
        "submit",
        "status",
        "output",
        "fence",
        "recover",
        "reconcile",
    ] {
        assert!(overview.contains(command), "{overview}");
        assert_eq!(
            help(&["help", "execution", command])?,
            help(&["execution", command, "--help"])?
        );
    }
    assert!(!overview.contains("worker"), "{overview}");
    Ok(())
}

#[test]
fn operational_examples_satisfy_the_actual_parser() -> Result<(), Box<dyn Error>> {
    for arguments in [
        vec![
            "ladyshell",
            "run",
            "--state",
            "/path/to/state",
            "--",
            "cargo",
            "test",
        ],
        vec![
            "ladyshell",
            "cs",
            "checkpoint",
            "--state",
            "/path/to/state",
            "--attempt",
            "checkpoint-1",
            "--epoch",
            "1",
        ],
        vec![
            "ladyshell",
            "publication",
            "publish",
            "--state",
            "/path/to/state",
            "--export",
            "/path/to/export",
            "--remote",
            "origin",
            "--branch",
            "task-1",
            "--message",
            "Publish task work",
        ],
        vec![
            "ladyshell",
            "deps",
            "prune",
            "validate",
            "--state",
            "/path/to/state",
            "--plan",
            "/path/to/plan.json",
            "--output",
            "/path/to/receipt.json",
        ],
        vec![
            "ladyshell",
            "review",
            "merge-check",
            "--state",
            "/path/to/state",
            "--config",
            "review.json",
            "--policy",
            "/path/to/policy.json",
            "--remote",
            "origin",
            "--branch",
            "main",
            "--head",
            "HEAD_COMMIT",
            "--expected-target",
            "TARGET_COMMIT",
        ],
    ] {
        Cli::try_parse_from(arguments)?;
    }
    Ok(())
}
