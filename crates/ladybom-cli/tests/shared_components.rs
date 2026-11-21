use ladybom::deps::{self, graph, Report};
use serde_json::{json, Value};
use std::fs;

fn workspace() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("Cargo.toml"),
        "[workspace]\nmembers=['a','b']\nresolver='2'\n",
    )?;
    for (member, dependency) in [("a", "itoa"), ("b", "ryu")] {
        fs::create_dir(root.path().join(member))?;
        fs::write(
            root.path().join(member).join("Cargo.toml"),
            format!(
                "[package]\nname='{member}'\nversion='1.0.0'\n[dependencies]\n{dependency}='1'\n"
            ),
        )?;
    }
    fs::write(root.path().join("Cargo.lock"), "version=4\n[[package]]\nname='itoa'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n[[package]]\nname='ryu'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n")?;
    Ok(root)
}

#[test]
fn shared_cargo_lock_is_serialized_once_and_keeps_each_members_graph_roots(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace()?;
    let report = deps::scan_project(root.path())?;
    let value = serde_json::to_value(&report)?;
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["projects"][0]["manifest"], "Cargo.toml");
    assert_eq!(
        value["projects"][0]["components"]
            .as_array()
            .ok_or("components")?
            .len(),
        2
    );
    for member in [1, 2] {
        assert_eq!(value["projects"][member]["components"], json!([]));
        assert_eq!(value["projects"][member]["components_from"], "Cargo.toml");
    }
    let graph = graph::project(serde_json::from_value(value)?)?;
    assert_eq!(graph.components.len(), 2);
    assert_eq!(graph.contexts.len(), 1);
    assert_eq!(graph.roots.len(), 2);
    for (manifest, purl) in [
        ("a/Cargo.toml", "pkg:cargo/itoa@1.0.0"),
        ("b/Cargo.toml", "pkg:cargo/ryu@1.0.0"),
    ] {
        assert!(graph
            .roots
            .iter()
            .any(|r| r.manifest == manifest && r.to.purl == purl));
    }
    let temporary = tempfile::tempdir()?;
    let destination = temporary.path().join("graph");
    graph::write_snapshot(&graph, &destination)?;
    let loaded = graph::read_snapshot(&destination)?;
    assert_eq!(serde_json::to_value(loaded)?, serde_json::to_value(graph)?);
    Ok(())
}

fn rejected(value: Value) -> bool {
    match serde_json::from_value::<Report>(value) {
        Ok(report) => graph::project(report).is_err(),
        Err(_) => true,
    }
}

#[test]
fn malformed_shared_lock_references_are_rejected_without_silent_empty_components(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace()?;
    let value = serde_json::to_value(deps::scan_project(root.path())?)?;
    for target in [
        "missing/Cargo.toml",
        "../Cargo.toml",
        "/Cargo.toml",
        "a/Cargo.toml",
    ] {
        let mut changed = value.clone();
        changed["projects"][1]["components_from"] = json!(target);
        assert!(rejected(changed), "{target}");
    }
    for mutation in 0..8 {
        let mut changed = value.clone();
        match mutation {
            0 => {
                changed["projects"][1]["components"] = changed["projects"][0]["components"].clone()
            }
            1 => changed["projects"][1]["lockfile"] = json!("other/Cargo.lock"),
            2 => changed["projects"][1]["ecosystem"] = json!("npm"),
            3 => changed["projects"][1]["locked"] = json!(false),
            4 => changed["projects"][1]["components_from"] = Value::Null,
            5 => changed["projects"][0]["components_from"] = json!("a/Cargo.toml"),
            6 => {
                changed["projects"][1]["components_from"] = json!("b/Cargo.toml");
                changed["projects"][2]["components_from"] = json!("a/Cargo.toml");
            }
            _ => changed["projects"][2]["manifest"] = json!("a/Cargo.toml"),
        }
        assert!(rejected(changed), "mutation {mutation}");
    }
    Ok(())
}

#[test]
fn a_shared_lock_reference_cannot_silently_expand_an_old_inventory_version(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace()?;
    let mut value = serde_json::to_value(deps::scan_project(root.path())?)?;
    value["schema_version"] = json!(1);
    assert!(rejected(value));
    Ok(())
}

#[test]
fn component_lookup_rejects_a_project_with_a_different_resolution_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace()?;
    let report = deps::scan_project(root.path())?;
    assert_eq!(report.components_for(&report.projects[1])?.len(), 2);
    for mutation in 0..5 {
        let mut project = report.projects[1].clone();
        match mutation {
            0 => project.lockfile = Some("other/Cargo.lock".into()),
            1 => project.ecosystem = "npm".into(),
            2 => project.components_from = Some("b/Cargo.toml".into()),
            3 => project.locked = false,
            _ => project.components = report.projects[0].components.clone(),
        }
        assert!(
            report.components_for(&project).is_err(),
            "mutation {mutation}"
        );
    }
    Ok(())
}

#[test]
fn inventory_rejects_more_projects_than_the_source_snapshot_can_contain(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace()?;
    let mut report = deps::scan_project(root.path())?;
    let mut project = report.projects[0].clone();
    project.locked = false;
    project.lockfile = None;
    project.components.clear();
    report.projects = (0..5000)
        .map(|index| {
            let mut project = project.clone();
            project.manifest = format!("p{index}/Cargo.toml");
            project.root = format!("p{index}");
            project
        })
        .collect();
    report.validate()?;
    project.manifest = "one-too-many/Cargo.toml".into();
    report.projects.push(project);
    let error = report
        .validate()
        .err()
        .ok_or("oversized inventory accepted")?;
    assert!(error.to_string().contains("5000"), "{error}");
    Ok(())
}

#[test]
fn inventory_rejects_more_inputs_than_the_source_snapshot_can_contain(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace()?;
    let mut report = deps::scan_project(root.path())?;
    report.inputs = (0..5000)
        .map(|index| (format!("p{index}/Cargo.toml"), "0".repeat(64)))
        .collect();
    report.validate()?;
    report
        .inputs
        .insert("one-too-many/Cargo.toml".into(), "0".repeat(64));
    let error = report
        .validate()
        .err()
        .ok_or("oversized inventory accepted")?;
    assert!(error.to_string().contains("5000"), "{error}");
    Ok(())
}

#[test]
fn component_lookup_validates_its_requested_reference_without_revalidating_unrelated_projects(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace()?;
    let mut report = deps::scan_project(root.path())?;
    report.projects[2].components_from = Some("absent/Cargo.toml".into());
    assert!(report.validate().is_err());
    assert_eq!(report.components_for(&report.projects[1])?.len(), 2);
    assert!(report.components_for(&report.projects[2]).is_err());
    Ok(())
}

#[test]
fn standalone_component_lookup_rejects_cycles_cross_locks_and_inline_references(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace()?;
    let original = deps::scan_project(root.path())?;
    for mutation in 0..9 {
        let mut report = original.clone();
        match mutation {
            0 => report.projects[0].components_from = Some("a/Cargo.toml".into()),
            1 => report.projects[1].components_from = Some("a/Cargo.toml".into()),
            2 => report.projects[1].components_from = Some("absent/Cargo.toml".into()),
            3 => report.projects[0].ecosystem = "npm".into(),
            4 => report.projects[0].lockfile = Some("other/Cargo.lock".into()),
            5 => report.projects[1].locked = false,
            6 => report.projects[1].components = report.projects[0].components.clone(),
            7 => report.schema_version = 1,
            _ => report.projects[1].components_from = None,
        }
        assert!(
            report.components_for(&report.projects[1]).is_err(),
            "mutation {mutation}"
        );
    }
    Ok(())
}
