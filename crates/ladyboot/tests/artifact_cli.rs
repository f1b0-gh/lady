#![cfg(feature = "cli")]

use clap::Parser;
use ladyboot::cli::Cli;

#[test]
fn artifact_commands_require_explicit_inputs_and_lock_for_builds() {
    for operation in [
        "check", "render", "lock", "plan", "build", "inspect", "test",
    ] {
        assert!(Cli::try_parse_from(["ladyboot", operation, "--help"])
            .is_err_and(|e| e.kind() == clap::error::ErrorKind::DisplayHelp));
    }
    let base = [
        "ladyboot",
        "build",
        "--config",
        "profile.ncl",
        "--resources",
        "recipes",
    ];
    assert!(Cli::try_parse_from(base).is_err());
    let mut valid = base.to_vec();
    valid.extend(["--lock", "profile.lock.json", "--receipt", "receipt.json"]);
    assert!(Cli::try_parse_from(&valid).is_ok());
    valid.extend(["--target", "unknown"]);
    assert!(Cli::try_parse_from(&valid).is_err());
    assert!(Cli::try_parse_from([
        "ladyboot",
        "render",
        "--config",
        "profile.ncl",
        "--resources",
        "recipes",
        "--replace"
    ])
    .is_err());
}

#[test]
fn explanation_and_comparison_have_explicit_inputs() {
    assert!(Cli::try_parse_from([
        "ladyboot",
        "explain",
        "--config",
        "base.ncl",
        "--resources",
        "recipes"
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "ladyboot",
        "diff",
        "--config",
        "base.ncl",
        "--other",
        "vm.ncl",
        "--resources",
        "recipes"
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "ladyboot",
        "diff",
        "--config",
        "base.ncl",
        "--resources",
        "recipes"
    ])
    .is_err());
}
