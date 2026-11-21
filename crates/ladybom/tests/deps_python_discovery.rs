use ladybom::{deps, sources};
use std::{fs, path::Path};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn write(root: &Path, name: &str, content: &str) -> std::io::Result<()> {
    let path = root.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

#[test]
fn conventional_requirement_files_are_inventoried_without_claiming_resolution() -> TestResult {
    for name in [
        "requirements.txt",
        "requirements.in",
        "demos/soc/requirements-set.txt",
        "requirements_dev.in",
        "requirements.test.txt",
        "python-requirements.txt",
        "dev_requirements.in",
        "build.requirements.txt",
        "app/requirements/base.txt",
        "requirements/dev.in",
    ] {
        let root = tempfile::tempdir()?;
        write(root.path(), name, "pyarrow==23.0.1\n")?;
        let report = deps::scan_project(root.path())?;
        assert_eq!(report.projects.len(), 1, "{name}");
        assert_eq!(report.inputs.len(), 1, "{name}");
        assert!(report.inputs.contains_key(name), "{name}");
        let project = &report.projects[0];
        assert_eq!(project.manifest, name);
        assert_eq!(project.manager, "pip");
        assert_eq!(project.ecosystem, "python");
        assert!(!project.locked);
        assert!(project.lockfile.is_none());
        assert!(project.components.is_empty());
        assert_eq!(project.requirements.len(), 1);
        assert_eq!(project.requirements[0].name, "pyarrow");
        assert_eq!(project.requirements[0].constraint, "==23.0.1");
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.code == "missing_lockfile" && d.file == name));
        report.validate()?;
    }
    Ok(())
}

#[test]
fn unrelated_text_and_near_match_names_are_not_python_manifests() -> TestResult {
    let root = tempfile::tempdir()?;
    for name in [
        "notes.txt",
        "prerequirements.txt",
        "requirementsword.txt",
        "requirements-dev.txt.bak",
        "requirements.md",
        "requirements-.txt",
        "-requirements.in",
        "requirements/.txt",
        "Requirements.txt",
        "requirements/base.md",
        "notrequirements/base.txt",
        "requirements/docs/readme.txt",
    ] {
        write(
            root.path(),
            name,
            "ordinary prose, not a PEP 508 declaration\n",
        )?;
    }
    let report = deps::scan_project(root.path())?;
    assert!(report.complete);
    assert!(report.inputs.is_empty());
    assert!(report.projects.is_empty());
    assert!(report.diagnostics.is_empty());
    Ok(())
}

#[test]
fn adjacent_pip_contexts_do_not_disappear_or_inherit_the_uv_lock() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "pyproject.toml",
        "[project]\nname='demo'\nversion='1.0.0'\ndependencies=['idna==3.10']\n",
    )?;
    write(root.path(), "uv.lock", "version=1\n[[package]]\nname='idna'\nversion='3.10'\nsource={registry='https://pypi.org/simple'}\n")?;
    write(root.path(), "requirements.txt", "idna==3.11\n")?;
    write(root.path(), "requirements-dev.in", "pytest>=8\n")?;
    let report = deps::scan_project(root.path())?;
    assert_eq!(report.projects.len(), 3);
    let uv = report
        .projects
        .iter()
        .find(|p| p.manifest == "pyproject.toml")
        .ok_or("pyproject missing")?;
    assert!(uv.locked);
    for (manifest, name, constraint) in [
        ("requirements.txt", "idna", "==3.11"),
        ("requirements-dev.in", "pytest", ">=8"),
    ] {
        let pip = report
            .projects
            .iter()
            .find(|p| p.manifest == manifest)
            .ok_or("pip context missing")?;
        assert!(!pip.locked);
        assert!(pip.lockfile.is_none());
        assert!(pip.components.is_empty());
        assert_eq!(pip.requirements[0].name, name);
        assert_eq!(pip.requirements[0].constraint, constraint);
    }
    report.validate()?;
    Ok(())
}

#[test]
fn pip_directives_remain_blocking_and_do_not_follow_excluded_files() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "requirements-set.txt", "-r hidden.txt\n-c constraints.txt\n--index-url https://example.invalid/simple\npyarrow==23.0.1\n")?;
    write(root.path(), "hidden.txt", "SECRET_SENTINEL\n")?;
    let spec = sources::Sources {
        include: vec!["requirements-set.txt".into()],
        exclude: vec![],
    };
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    let report = deps::scan_snapshot(root.path(), &snapshot)?;
    assert!(!report.complete);
    assert_eq!(report.inputs.len(), 1);
    assert_eq!(report.projects.len(), 1);
    assert_eq!(report.projects[0].requirements[0].name, "pyarrow");
    assert_eq!(
        report
            .diagnostics
            .iter()
            .filter(|d| d.code == "unsupported_requirement_option" && d.blocking)
            .count(),
        3
    );
    assert!(!serde_json::to_string(&report)?.contains("SECRET_SENTINEL"));
    Ok(())
}

#[test]
fn excluded_custom_requirements_are_not_scanned() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "project/active/requirements-prod.txt",
        "idna==3.10\n",
    )?;
    write(
        root.path(),
        "project/experimental/requirements-dev.txt",
        "invalid declaration [\n",
    )?;
    let spec = sources::Sources {
        include: vec!["project".into()],
        exclude: vec!["project/experimental".into()],
    };
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    let report = deps::scan_snapshot(root.path(), &snapshot)?;
    assert!(report.complete);
    assert_eq!(report.projects.len(), 1);
    assert_eq!(
        report.projects[0].manifest,
        "project/active/requirements-prod.txt"
    );
    assert_eq!(report.inputs.len(), 1);
    Ok(())
}

#[test]
fn custom_requirements_changed_after_snapshot_are_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "requirements-set.txt", "idna==3.10\n")?;
    let spec = sources::Sources {
        include: vec!["requirements-set.txt".into()],
        exclude: vec![],
    };
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    write(root.path(), "requirements-set.txt", "idna==3.11\n")?;
    assert!(deps::scan_snapshot(root.path(), &snapshot).is_err());
    Ok(())
}

#[test]
fn oversized_custom_requirements_are_reported_as_blocking() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "requirements-set.txt",
        &"#".repeat(8 * 1024 * 1024 + 1),
    )?;
    let report = deps::scan_project(root.path())?;
    assert!(!report.complete);
    assert!(report.projects.is_empty());
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "file_limit" && d.blocking));
    assert!(report.inputs.contains_key("requirements-set.txt"));
    Ok(())
}

#[test]
fn symlink_replacing_custom_requirements_after_snapshot_is_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    write(root.path(), "requirements-set.txt", "idna==3.10\n")?;
    write(outside.path(), "private", "SECRET_SENTINEL\n")?;
    let spec = sources::Sources {
        include: vec!["requirements-set.txt".into()],
        exclude: vec![],
    };
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    fs::remove_file(root.path().join("requirements-set.txt"))?;
    std::os::unix::fs::symlink(
        outside.path().join("private"),
        root.path().join("requirements-set.txt"),
    )?;
    let result = deps::scan_snapshot(root.path(), &snapshot);
    assert!(result.is_err());
    assert!(!format!("{result:?}").contains("SECRET_SENTINEL"));
    Ok(())
}
