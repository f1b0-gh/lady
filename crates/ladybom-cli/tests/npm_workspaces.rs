use serde_json::{json, Value};
use std::{fs, process::Command};

#[test]
fn npm_workspace_members_inherit_only_the_declared_root_lock_and_stay_local(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("packages/member"))?;
    fs::create_dir_all(root.path().join("unrelated"))?;
    fs::write(
        root.path().join("package.json"),
        json!({"name":"root","version":"1.0.0","workspaces":["packages/member"]}).to_string(),
    )?;
    fs::write(
        root.path().join("packages/member/package.json"),
        json!({"name":"@fixture/member","version":"1.0.0","dependencies":{"is-number":"^6"}})
            .to_string(),
    )?;
    fs::write(
        root.path().join("unrelated/package.json"),
        json!({"name":"unrelated","version":"1.0.0"}).to_string(),
    )?;
    fs::write(root.path().join("package-lock.json"), json!({"lockfileVersion":3,"packages":{
        "":{"name":"root","version":"1.0.0","workspaces":["packages/member"]},
        "packages/member":{"name":"@fixture/member","version":"1.0.0","dependencies":{"is-number":"^6"}},
        "node_modules/@fixture/member":{"resolved":"packages/member","link":true},
        "node_modules/is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"},
        "packages/member/node_modules/is-number":{"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz"}
    }}).to_string())?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["scan", "--project"])
        .arg(root.path())
        .arg("--json")
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    let projects = report["projects"].as_array().ok_or("projects")?;
    let member = projects
        .iter()
        .find(|p| p["manifest"] == "packages/member/package.json")
        .ok_or("member")?;
    assert_eq!(member["locked"], true);
    assert_eq!(member["lockfile"], "package-lock.json");
    let parent = projects
        .iter()
        .find(|p| p["manifest"] == "package.json")
        .ok_or("root")?;
    let local = parent["components"]
        .as_array()
        .ok_or("components")?
        .iter()
        .filter(|c| {
            c["context"] == "packages/member" || c["context"] == "node_modules/@fixture/member"
        })
        .collect::<Vec<_>>();
    assert_eq!(local.len(), 2);
    assert!(local.iter().all(|c| c["purl"].is_null()));
    let missing = report["diagnostics"]
        .as_array()
        .ok_or("diagnostics")?
        .iter()
        .filter(|d| d["code"] == "missing_lockfile")
        .collect::<Vec<_>>();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0]["file"], "unrelated/package.json");
    let graph = ladybom::deps::graph::project(serde_json::from_value(report)?)?;
    let member_roots = graph
        .roots
        .iter()
        .filter(|r| r.manifest == "packages/member/package.json")
        .collect::<Vec<_>>();
    assert_eq!(member_roots.len(), 1);
    assert_eq!(member_roots[0].to.purl, "pkg:npm/is-number@6.0.0");
    assert_eq!(
        graph.components.len(),
        4,
        "shared root lock must not duplicate component contexts"
    );
    Ok(())
}
