use ladybom::{deps, sources, vuln};
use serde_json::json;
use std::{fs, path::Path};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn write(root: &Path, name: &str, content: &str) -> std::io::Result<()> {
    let path = root.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

fn hash(character: char, length: usize) -> String {
    let algorithm = match length {
        96 => "sha384",
        128 => "sha512",
        _ => "sha256",
    };
    format!("{algorithm}:{}", character.to_string().repeat(length))
}

fn record(name: &str, version: &str) -> String {
    format!("{name}=={version} --hash={}\n", hash('a', 64))
}

#[test]
fn hash_lock_records_versions_hashes_and_keeps_adjacent_declarations() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "requirements.in", "idna>=3\n")?;
    write(root.path(), "requirements.lock", &format!(
        "# Generated for Python 3.12; this comment is not evidence\nIdNA==3.10 \\\n    --hash={} \\\n    --hash {}\n    # via imaginary-parent\n", hash('a', 64), hash('B', 96)))?;
    let report = deps::scan_project(root.path())?;
    assert_eq!(report.projects.len(), 2);
    assert_eq!(report.inputs.len(), 2);
    assert!(!report.complete);
    let declaration = report
        .projects
        .iter()
        .find(|p| p.manifest == "requirements.in")
        .ok_or("declaration")?;
    assert!(!declaration.locked);
    assert_eq!(declaration.requirements[0].constraint, ">=3");
    let lock = report
        .projects
        .iter()
        .find(|p| p.manifest == "requirements.lock")
        .ok_or("lock")?;
    assert!(lock.locked);
    assert_eq!(lock.lockfile.as_deref(), Some("requirements.lock"));
    assert!(lock.requirements.is_empty());
    assert!(lock.tools.is_empty());
    assert_eq!(lock.components.len(), 1);
    let component = &lock.components[0];
    assert_eq!(component.name, "idna");
    assert_eq!(component.version, "3.10");
    assert_eq!(component.purl.as_deref(), Some("pkg:pypi/idna@3.10"));
    assert_eq!(component.source, json!({"pip-index":"unverified"}));
    assert!(component.artifacts.is_empty());
    assert!(component.metadata.get("dependencies").is_none());
    assert_eq!(component.metadata["pip"]["records"][0]["line"], 2);
    assert_eq!(
        component.metadata["pip"]["records"][0]["hashes"],
        json!([hash('a', 64), hash('b', 96)])
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "pip_inventory_incomplete" && d.blocking));
    report.validate()?;
    Ok(())
}

#[test]
fn conventional_lock_names_and_inline_hashes_are_discovered() -> TestResult {
    for name in [
        "requirements.lock",
        "requirements-prod.lock",
        "python-requirements.lock",
        "requirements/build.lock",
        "requirements.txt",
        "requirements.in",
    ] {
        let root = tempfile::tempdir()?;
        write(root.path(), name, &record("idna", "3.10"))?;
        let report = deps::scan_project(root.path())?;
        assert_eq!(report.projects.len(), 1, "{name}");
        assert_eq!(report.projects[0].components.len(), 1, "{name}");
        assert_eq!(report.projects[0].lockfile.as_deref(), Some(name));
        assert!(!report.complete);
    }
    Ok(())
}

#[test]
fn comments_do_not_create_hash_options_or_hide_the_following_entry() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "requirements.in",
        "# --hash=bad\nidna==3.10 ; sys_platform == '--hash=literal'\n",
    )?;
    write(
        root.path(),
        "requirements.lock",
        &format!(
            "# --hash=bad \\\n{}# via hidden==9.9 --hash=bad\n",
            record("idna", "3.10")
        ),
    )?;
    let report = deps::scan_project(root.path())?;
    let declaration = report
        .projects
        .iter()
        .find(|p| p.manifest == "requirements.in")
        .ok_or("declaration")?;
    assert!(!declaration.locked);
    assert_eq!(declaration.requirements.len(), 1);
    let lock = report
        .projects
        .iter()
        .find(|p| p.manifest == "requirements.lock")
        .ok_or("lock")?;
    assert_eq!(lock.components.len(), 1);
    assert_eq!(lock.components[0].name, "idna");
    Ok(())
}

#[test]
fn markers_and_duplicate_records_preserve_distinct_hash_lists() -> TestResult {
    let root = tempfile::tempdir()?;
    let content = format!(
        "idna[security]==3.10 ; sys_platform == 'win32' --hash={}\nidna==3.10 ; sys_platform == 'win32' --hash={}\nidna==3.10 ; sys_platform == 'linux' --hash={}\nidna==3.11 --hash={}\n",
        hash('a', 64), hash('b', 64), hash('c', 128), hash('d', 64));
    write(root.path(), "requirements.lock", &content)?;
    let report = deps::scan_project(root.path())?;
    assert_eq!(report.projects.len(), 1);
    let components = &report.projects[0].components;
    assert_eq!(components.len(), 3);
    let repeated = components
        .iter()
        .find(|c| {
            c.metadata["pip"]["records"]
                .as_array()
                .is_some_and(|a| a.len() == 2)
        })
        .ok_or("repeated record")?;
    assert_eq!(
        repeated.metadata["pip"]["records"][0]["hashes"],
        json!([hash('a', 64)])
    );
    assert_eq!(
        repeated.metadata["pip"]["records"][1]["hashes"],
        json!([hash('b', 64)])
    );
    assert_eq!(
        repeated.metadata["pip"]["records"][0]["extras"],
        json!(["security"])
    );
    assert!(repeated.metadata["resolution-markers"]
        .as_array()
        .is_some_and(|m| m.len() == 1));
    assert!(components.iter().any(|c| c.version == "3.11"));
    assert!(!report.complete);
    #[cfg(feature = "graph")]
    {
        let graph = deps::graph::project(report)?;
        assert_eq!(graph.components.len(), 3);
        assert!(graph.dependencies.is_empty());
        assert!(graph.roots.is_empty());
        assert!(!graph.complete());
    }
    Ok(())
}

#[test]
fn invalid_entries_do_not_become_components_or_hide_valid_records() -> TestResult {
    for invalid in [
        format!("bad>=1 --hash={}", hash('b', 64)),
        format!("bad==1.* --hash={}", hash('b', 64)),
        format!("bad===1.0 --hash={}", hash('b', 64)),
        format!(
            "bad @ https://example.invalid/bad.whl --hash={}",
            hash('b', 64)
        ),
        "bad==1.0".into(),
        "bad==1.0 --hash=md5:00000000000000000000000000000000".into(),
        "bad==1.0 --hash=sha256:short".into(),
        format!("bad==1.0 --hash=sha256:{}", "g".repeat(64)),
        format!("bad==1.0 --hash={} --hash=sha256:short", hash('b', 64)),
        "bad==1.0 --hash".into(),
        format!(
            "bad==1.0 --hash={} --config-settings secret=value",
            hash('b', 64)
        ),
    ] {
        let root = tempfile::tempdir()?;
        write(
            root.path(),
            "requirements.lock",
            &(invalid.clone() + "\n" + &record("idna", "3.10")),
        )?;
        let report = deps::scan_project(root.path())?;
        assert_eq!(report.projects.len(), 1, "{invalid}");
        assert_eq!(report.projects[0].components.len(), 1, "{invalid}");
        assert_eq!(report.projects[0].components[0].name, "idna", "{invalid}");
        assert!(!report.complete);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.blocking && d.code != "pip_inventory_incomplete"),
            "{invalid}"
        );
    }
    Ok(())
}

#[test]
fn directives_and_environment_substitutions_never_follow_excluded_sources() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "excluded/requirements.lock",
        "SECRET_SENTINEL\n",
    )?;
    write(root.path(), "requirements.lock", &format!(
        "--require-hashes\n-r excluded/requirements.lock\n-c excluded/requirements.lock\n--index-url https://private.invalid/simple\nbad==${{SECRET_SENTINEL}} --hash={}\n{}", hash('a', 64), record("idna", "3.10")))?;
    let spec = sources::Sources {
        include: vec!["requirements.lock".into()],
        exclude: vec![],
    };
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    let report = deps::scan_snapshot(root.path(), &snapshot)?;
    assert_eq!(report.inputs.len(), 1);
    assert_eq!(report.projects.len(), 1);
    assert_eq!(report.projects[0].components.len(), 1);
    assert_eq!(
        report.projects[0].components[0].source,
        json!({"pip-index":"unverified"})
    );
    assert!(!report.complete);
    assert!(!serde_json::to_string(&report)?.contains("SECRET_SENTINEL"));
    assert!(
        report
            .diagnostics
            .iter()
            .filter(|d| d.code == "unsupported_requirement_option")
            .count()
            >= 3
    );
    Ok(())
}

#[test]
fn nominal_pypi_identity_does_not_claim_public_advisory_coverage() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "requirements.lock", &record("idna", "3.10"))?;
    let report = deps::scan_project(root.path())?;
    let snapshot = vuln::Snapshot {
        schema_version: 1,
        source: "https://osv.dev/test-fixture".into(),
        fetched_at: "2026-11-07T00:00:00Z".into(),
        complete: true,
        ecosystems: vec!["PyPI".into()],
        advisories: vec![],
    };
    let assessment = vuln::assess(&report, &snapshot, "2026-11-07T01:00:00Z", 86400)?;
    assert_eq!(assessment.coverage.components, 1);
    assert_eq!(assessment.coverage.assessed_components, 0);
    assert!(!assessment.coverage.identities_complete);
    assert!(!assessment.complete);
    Ok(())
}

#[test]
fn lock_files_obey_snapshot_exclusions_mutation_and_size_guards() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "requirements.lock", &record("idna", "3.10"))?;
    write(root.path(), "excluded/requirements.lock", "bad [\n")?;
    let spec = sources::Sources {
        include: vec!["requirements.lock".into()],
        exclude: vec![],
    };
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    let report = deps::scan_snapshot(root.path(), &snapshot)?;
    assert_eq!(report.inputs.len(), 1);
    assert_eq!(report.projects[0].components.len(), 1);
    write(root.path(), "requirements.lock", &record("idna", "3.11"))?;
    assert!(deps::scan_snapshot(root.path(), &snapshot).is_err());
    write(
        root.path(),
        "requirements.lock",
        &"#".repeat(8 * 1024 * 1024 + 1),
    )?;
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    let report = deps::scan_snapshot(root.path(), &snapshot)?;
    assert!(!report.complete);
    assert!(report.inputs.contains_key("requirements.lock"));
    assert!(report.diagnostics.iter().any(|d| d.code == "file_limit"));
    Ok(())
}

#[test]
fn lock_replaced_by_symlink_after_snapshot_is_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    write(root.path(), "requirements.lock", &record("idna", "3.10"))?;
    write(outside.path(), "private", "SECRET_SENTINEL\n")?;
    let spec = sources::Sources {
        include: vec!["requirements.lock".into()],
        exclude: vec![],
    };
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    fs::remove_file(root.path().join("requirements.lock"))?;
    std::os::unix::fs::symlink(
        outside.path().join("private"),
        root.path().join("requirements.lock"),
    )?;
    assert!(deps::scan_snapshot(root.path(), &snapshot).is_err());
    Ok(())
}

#[test]
fn empty_or_unsupported_inventory_is_never_complete() -> TestResult {
    for content in [
        String::new(),
        "# generator and via comments do not prove a dependency graph\n".into(),
        "--require-hashes\n".into(),
        format!("bad==1.0 --hash='{}'\n", hash('a', 64)),
        format!("bad==1.0 \\\\\n --hash={}\n", hash('a', 64)),
    ] {
        let root = tempfile::tempdir()?;
        write(root.path(), "requirements.lock", &content)?;
        let report = deps::scan_project(root.path())?;
        assert_eq!(report.projects.len(), 1);
        assert!(report.projects[0].components.is_empty());
        assert!(report.projects[0].requirements.is_empty());
        assert!(!report.complete);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.code == "pip_inventory_incomplete" && d.blocking));
    }
    Ok(())
}
