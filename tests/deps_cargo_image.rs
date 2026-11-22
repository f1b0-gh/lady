//! Native qualification of trusted Cargo configuration with a legacy alias file.
use ladyshell::{config::Tool, deps, files, sources};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

#[test]
#[ignore = "requires Nix sandbox and an approved fixed-output Cargo fixture download"]
fn nix_vendoring_coexists_with_legacy_cargo_aliases_without_running_project_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let resources = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir()?;
    let project = temp.path().join("project");
    fs::create_dir_all(project.join("src"))?;
    fs::create_dir(project.join(".cargo"))?;
    for name in ["Cargo.toml", "Cargo.lock"] {
        fs::copy(
            resources.join("tests/fixtures/deps/rust").join(name),
            project.join(name),
        )?;
    }
    fs::write(
        project.join("src/main.rs"),
        "compile_error!(\"preparation must not compile project targets\");\n",
    )?;
    fs::write(
        project.join("build.rs"),
        "compile_error!(\"preparation must not run project build scripts\");\n",
    )?;
    fs::write(
        project.join(".cargo/config"),
        "[alias]\nfixture-check=['check','--offline']\n",
    )?;
    let snapshot = sources::snapshot(&project, &deps::project_sources(&project)?, None)?;
    let preparation = deps::prepare::plan(
        &project,
        &snapshot,
        &deps::DependencyConfig {
            projects: vec!["Cargo.toml".into()],
            allowed_hosts: vec!["static.crates.io".into()],
        },
        &BTreeMap::from([(
            "rust".into(),
            Tool {
                version: "1.99.1".into(),
                phase: "runtime".into(),
            },
        )]),
    )?;
    let input = temp.path().join("preparation.json");
    files::publish_json(&input, &preparation, false)?;
    let mut command = Command::new("nix");
    command.args([
        "--extra-experimental-features",
        "nix-command flakes",
        "build",
        "--impure",
        "--no-link",
        "--expr",
        r#"
      { flakePath, sourcePath, preparationPath }:
      let flake = builtins.getFlake ("path:" + flakePath);
          pkgs = import flake.inputs.nixpkgs { system = "x86_64-linux"; };
      in (import (flakePath + "/dependencies.nix") {
        inherit pkgs;
        sourcePath = builtins.toPath sourcePath;
        python = pkgs.python313;
        preparation = builtins.fromJSON (builtins.readFile preparationPath);
      }).bundle
    "#,
    ]);
    for (name, value) in [
        ("flakePath", resources.join("nix")),
        ("sourcePath", project.clone()),
        ("preparationPath", input),
    ] {
        command.arg("--argstr").arg(name).arg(value);
    }
    ladyshell::process::capture(
        command,
        std::time::Duration::from_secs(180),
        2 * 1024 * 1024,
    )?;
    assert_eq!(
        snapshot,
        sources::snapshot(&project, &deps::project_sources(&project)?, None)?
    );
    assert!(!project.join(".cargo/config.toml").exists());
    assert!(!project.join("target").exists());
    Ok(())
}
