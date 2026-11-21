use serde_json::Value;
use std::{fs, path::Path, process::Command};

fn scan(root: &Path) -> std::io::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["scan", "--project"])
        .arg(root)
        .arg("--json")
        .output()
}

#[test]
fn python_contexts_are_visible_in_deterministic_cli_reports(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("pyproject.toml"),
        "[project]\nname='demo'\nversion='1.0.0'\ndependencies=['idna==3.10']\n",
    )?;
    fs::write(root.path().join("requirements.txt"), "idna==3.11\n")?;
    fs::write(
        root.path().join("requirements-set.txt"),
        "pyarrow==23.0.1\n",
    )?;
    let first = scan(root.path())?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: Value = serde_json::from_slice(&first.stdout)?;
    let projects = report["projects"].as_array().ok_or("projects missing")?;
    assert_eq!(projects.len(), 3);
    assert_eq!(
        projects
            .iter()
            .map(|p| p["manifest"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["pyproject.toml", "requirements-set.txt", "requirements.txt"]
    );
    assert!(projects.iter().all(|p| p["locked"] == false));
    assert_eq!(projects[1]["requirements"][0]["name"], "pyarrow");
    assert_eq!(projects[1]["requirements"][0]["constraint"], "==23.0.1");
    assert_eq!(
        report["inputs"].as_object().ok_or("inputs missing")?.len(),
        3
    );
    let second = scan(root.path())?;
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    Ok(())
}

#[test]
fn unsupported_directives_in_custom_filenames_make_the_cli_fail(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("requirements-dev.in"),
        "-r absent.txt\npyarrow==23.0.1\n",
    )?;
    let output = scan(root.path())?;
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["projects"][0]["requirements"][0]["name"], "pyarrow");
    assert!(report["diagnostics"]
        .as_array()
        .ok_or("diagnostics missing")?
        .iter()
        .any(|d| d["code"] == "unsupported_requirement_option" && d["blocking"] == true));
    assert!(!root.path().join("absent.txt").exists());
    Ok(())
}
