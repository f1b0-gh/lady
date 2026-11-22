//! Explicit native qualification: downloads fixed-output artifacts and loads a new Docker image.
use ladyshell::{
    config::{ResolvedConfig, Sources},
    deps, environment_lock, files, image, sources,
};
use serde_json::json;
use std::{collections::BTreeMap, path::Path, process::Command};

#[test]
#[ignore = "requires Nix sandbox and approved npm fixture downloads"]
fn nix_workspace_preserves_nested_dependencies_and_local_links_without_scripts(
) -> Result<(), Box<dyn std::error::Error>> {
    let resources = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir()?;
    let project = temp.path().join("project");
    std::fs::create_dir_all(project.join("packages/member"))?;
    let root_manifest = json!({"name":"workspace-fixture","version":"1.0.0","workspaces":["packages/member"],
        "dependencies":{"is-number":"7.0.0","@fixture/member":"*"},"scripts":{"preinstall":"exit 97"}});
    let member_manifest = json!({"name":"@fixture/member","version":"1.0.0","dependencies":{"is-number":"6.0.0"},
        "scripts":{"install":"exit 98"}});
    let existing: serde_json::Value = serde_json::from_slice(&std::fs::read(
        resources.join("tests/fixtures/deps/web/package-lock.json"),
    )?)?;
    let lock = json!({"lockfileVersion":3,"packages":{
        "":{"name":"workspace-fixture","version":"1.0.0","workspaces":["packages/member"],"dependencies":{"is-number":"7.0.0","@fixture/member":"*"},"hasInstallScript":true},
        "packages/member":{"name":"@fixture/member","version":"1.0.0","dependencies":{"is-number":"6.0.0"},"hasInstallScript":true},
        "node_modules/@fixture/member":{"resolved":"packages/member","link":true},
        "node_modules/is-number":existing["packages"]["node_modules/is-number"],
        "packages/member/node_modules/is-number":{"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz",
            "integrity":"sha512-Wu1VHeILBK8KAWJUAiSZQX94GmOE45Rg6/538fKwiloUu21KncEkYGPqob2oSZ5mUT73vLGrHQjKw3KMPwfDzg=="}
    }});
    for (name, value) in [
        ("package.json", root_manifest),
        ("packages/member/package.json", member_manifest),
        ("package-lock.json", lock),
    ] {
        std::fs::write(project.join(name), value.to_string())?;
    }
    let snapshot = sources::snapshot(&project, &deps::project_sources(&project)?, None)?;
    let tools = BTreeMap::from([(
        "node".into(),
        ladyshell::config::Tool {
            version: "24.22.2".into(),
            phase: "runtime".into(),
        },
    )]);
    let preparation = deps::prepare::plan(
        &project,
        &snapshot,
        &deps::DependencyConfig {
            projects: vec!["package.json".into()],
            allowed_hosts: vec!["registry.npmjs.org".into()],
        },
        &tools,
    )?;
    let input = temp.path().join("preparation.json");
    files::publish_json(&input, &preparation, false)?;
    let mut command = Command::new("nix");
    command.args(["--extra-experimental-features", "nix-command flakes", "build", "--impure", "--no-link", "--expr", r#"
      { flakePath, sourcePath, preparationPath }:
      let flake = builtins.getFlake ("path:" + flakePath);
          pkgs = import flake.inputs.nixpkgs { system = "x86_64-linux"; };
          source = builtins.path { path = builtins.toPath sourcePath; name = "workspace-fixture-source"; };
          dependencies = import (flakePath + "/dependencies.nix") {
            inherit pkgs; sourcePath = builtins.toPath sourcePath; python = pkgs.python313;
            preparation = builtins.fromJSON (builtins.readFile preparationPath);
          };
      in pkgs.runCommand "ladyshell-workspace-layout-check" { nativeBuildInputs = [ pkgs.nodejs ]; } ''
        mkdir -p sandbox/workspace
        cp -r ${source} sandbox/workspace/project
        chmod -R u+w sandbox/workspace/project
        ${dependencies.install}
        cd sandbox/workspace/project
        test -L node_modules/@fixture/member
        test "$(readlink -f node_modules/@fixture/member)" = "$PWD/packages/member"
        node -e 'const assert = require("node:assert/strict"); assert.equal(require("./node_modules/is-number/package.json").version, "7.0.0"); assert.equal(require("./packages/member/node_modules/is-number/package.json").version, "6.0.0");'
        touch "$out"
      ''
    "#]);
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
    Ok(())
}

#[test]
#[ignore = "requires Nix and an approved npm fixture download"]
fn nix_refuses_dependency_bytes_with_a_corrupted_lock_hash(
) -> Result<(), Box<dyn std::error::Error>> {
    let resources = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir()?;
    let project = temp.path().join("project");
    std::fs::create_dir(&project)?;
    for name in ["package.json", "package-lock.json"] {
        std::fs::copy(
            resources.join("tests/fixtures/deps/web").join(name),
            project.join(name),
        )?;
    }
    let lock_path = project.join("package-lock.json");
    let mut lock: serde_json::Value = serde_json::from_slice(&std::fs::read(&lock_path)?)?;
    lock["packages"]["node_modules/is-number"]["integrity"] =
        json!(format!("sha512-{}==", "A".repeat(86)));
    std::fs::write(lock_path, lock.to_string())?;
    let snapshot = sources::snapshot(&project, &deps::project_sources(&project)?, None)?;
    let config = deps::DependencyConfig {
        projects: vec!["package.json".into()],
        allowed_hosts: vec!["registry.npmjs.org".into()],
    };
    let tools = BTreeMap::from([(
        "node".into(),
        ladyshell::config::Tool {
            version: "24.22.2".into(),
            phase: "runtime".into(),
        },
    )]);
    let preparation = deps::prepare::plan(&project, &snapshot, &config, &tools)?;
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
        ("sourcePath", project),
        ("preparationPath", input),
    ] {
        command.arg("--argstr").arg(name).arg(value);
    }
    let result = ladyshell::process::capture(
        command,
        std::time::Duration::from_secs(180),
        2 * 1024 * 1024,
    );
    match result {
        Err(ladyshell::error::Error::ProcessExit { stderr, .. }) => {
            assert!(stderr.contains("hash mismatch"), "{stderr}")
        }
        other => return Err(format!("Expected Nix integrity refusal, got {other:?}").into()),
    }
    Ok(())
}

#[test]
#[ignore = "requires Nix sandbox, approved fixture downloads and a local Docker daemon"]
fn nix_image_contains_python_rust_and_typescript_dependencies_offline(
) -> Result<(), Box<dyn std::error::Error>> {
    let resources = Path::new(env!("CARGO_MANIFEST_DIR"));
    let project = resources.join("tests/fixtures/deps");
    let directory = tempfile::tempdir()?;
    let config: ResolvedConfig = serde_json::from_value(json!({
        "schema_version":1, "name":"deps-fixture", "mission":"dev",
        "sources":{"include":["python","rust","web"],"exclude":[]},
        "tools":{"python":{"version":"3.13.18"},"rust":{"version":"1.99.1"},"node":{"version":"24.22.2"}},
        "checks":[], "sandbox":{"gateway":"fixture","workspace":"deps-fixture","provider":"fixture"},
        "resolved_missions":["dev"],"permissions":{"network":[],"filesystem":[]},
        "image":{"backend":"nix","profile":"openshell-native","platform":"x86_64-linux"},
        "sync":{"mode":"files","destination":"exports"},
        "dependencies":{"projects":["python/pyproject.toml","rust/Cargo.toml","web/package.json"],
            "allowed_hosts":["files.pythonhosted.org","static.crates.io","registry.npmjs.org"]}
    }))?;
    let snapshot = sources::snapshot(&project, &config.sources, None)?;
    let inventory = deps::scan_snapshot(&project, &snapshot)?;
    let preparation = deps::prepare::plan(
        &project,
        &snapshot,
        config.dependencies.as_ref().ok_or("config")?,
        &config.tools,
    )?;
    // The image's Codex paths are synthetic ELF fixtures; no provider or sandbox is created.
    let runtime = Path::new(env!("CARGO_BIN_EXE_ladyshell"));
    let artifacts: BTreeMap<_, _> = ["codex", "codex-code-mode-host", "ladyshell"]
        .into_iter()
        .map(|name| {
            Ok((
                name,
                json!({"path":runtime,"sha256":environment_lock::artifact_hash(runtime)?}),
            ))
        })
        .collect::<Result<_, ladyshell::error::Error>>()?;
    let desired = json!({"project":project,"resources":resources,"evaluated":{"config":config},
        "sources":snapshot,"dependency_inventory":inventory,"dependency_preparation":preparation,"artifacts":artifacts});
    let receipt = image::build(&desired, directory.path(), None)?;
    let image_id = receipt["image_id"].as_str().ok_or("image id")?;
    for (directory, command) in [
        ("python", ".venv/bin/python check.py"),
        ("rust", "cargo run --frozen --offline"),
        ("web", "node_modules/.bin/tsc check.ts --strict --target es2020 --module commonjs && node check.js"),
    ] {
        let output = Command::new("docker").args(["run","--rm","--network","none","--workdir",
            &format!("/sandbox/workspace/project/{directory}"), image_id, "/bin/bash","-eu","-c",command]).output()?;
        assert!(output.status.success(), "{directory}: {} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("dependencies OK"));
    }
    assert!(receipt["dependencies"]["preparation_sha256"].is_string());
    // Neither source preparation nor image construction mutates the fixture tree.
    assert_eq!(
        snapshot,
        sources::snapshot(
            &project,
            &Sources {
                include: vec!["python".into(), "rust".into(), "web".into()],
                exclude: vec![]
            },
            None
        )?
    );
    let report = resources.join("docs/validation/dependency-image-native.json");
    files::publish_json(
        &report,
        &json!({"schema_version":1, "image_id": image_id,
        "network":"none", "uid":10001,"checks":["python import/runtime/extras/dev", "cargo run --frozen --offline", "tsc and node"],
        "dependencies":receipt["dependencies"]}),
        true,
    )?;
    Ok(())
}
