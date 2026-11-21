use serde_json::Value;
use std::{os::unix::fs::PermissionsExt, process::Command};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn offline_bundle_preserves_private_permissions_and_refuses_replacement() -> Result {
    let temp = tempfile::tempdir()?;
    let input = temp.path().join("input.json");
    std::fs::write(&input, include_bytes!("fixtures/report-v2.json"))?;
    let output = temp.path().join("bundle");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ladybom"))
            .env_clear()
            .env("PATH", "")
            .args(["interop", "bundle", "--report"])
            .arg(&input)
            .args([
                "--repository",
                "fixture",
                "--revision",
                "commit-1",
                "--target-profile",
                "all-platforms",
                "--output",
            ])
            .arg(&output)
            .output()
    };
    let result = run()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest = std::fs::read(output.join("manifest.json"))?;
    let value: Value = serde_json::from_slice(&manifest)?;
    assert_eq!(
        std::fs::metadata(output.join("private"))?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for artifact in value["private_artifacts"]
        .as_array()
        .ok_or("private artifacts")?
    {
        let path = artifact["path"].as_str().ok_or("path")?;
        assert_eq!(
            std::fs::metadata(output.join(path))?.permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(!run()?.status.success());
    assert_eq!(manifest, std::fs::read(output.join("manifest.json"))?);
    Ok(())
}
#[test]
fn ambiguous_input_fails_before_creating_output_and_symlinks_are_refused() -> Result {
    let temp = tempfile::tempdir()?;
    let mut input: Value = serde_json::from_slice(include_bytes!("fixtures/report-v2.json"))?;
    let mut duplicate = input["projects"][1]["components"][0].clone();
    duplicate["context"] = serde_json::json!("different-context");
    input["projects"][1]["components"]
        .as_array_mut()
        .ok_or("components")?
        .push(duplicate);
    let input_path = temp.path().join("input.json");
    std::fs::write(&input_path, serde_json::to_vec(&input)?)?;
    let output = temp.path().join("bundle");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ladybom"))
            .args(["interop", "bundle", "--report"])
            .arg(&input_path)
            .args([
                "--repository",
                "fixture",
                "--revision",
                "commit-1",
                "--target-profile",
                "all",
                "--output",
            ])
            .arg(&output)
            .output()
    };
    assert!(!run()?.status.success());
    assert!(!output.exists());
    std::fs::write(&input_path, include_bytes!("fixtures/report-v2.json"))?;
    std::os::unix::fs::symlink(temp.path(), &output)?;
    assert!(!run()?.status.success());
    assert!(!temp.path().join("manifest.json").exists());
    Ok(())
}

#[test]
fn output_ancestor_symlink_is_refused_before_writing() -> Result {
    let temp = tempfile::tempdir()?;
    let target = temp.path().join("target");
    std::fs::create_dir(&target)?;
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&target, &alias)?;
    let input = temp.path().join("input.json");
    std::fs::write(&input, include_bytes!("fixtures/report-v2.json"))?;
    let result = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["interop", "bundle", "--report"])
        .arg(&input)
        .args([
            "--repository",
            "fixture",
            "--revision",
            "rev",
            "--target-profile",
            "all",
            "--output",
        ])
        .arg(alias.join("bundle"))
        .output()?;
    assert!(!result.status.success());
    assert!(!target.join("bundle").exists());
    Ok(())
}
