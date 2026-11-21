use ladyshell::{config::Tool, deps, sources};
use std::{collections::BTreeMap, fs, path::Path};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn write(root: &Path, name: &str, content: &str) -> std::io::Result<()> {
    let path = root.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers=['members/app']\nexclude=['vendor']\n",
    )?;
    write(root.path(), "members/app/Cargo.toml", "[package]\nname='app'\nversion='1.0.0'\n[dependencies]\nlocal={package='vendor-lib',path='../../vendor/dependency'}\n")?;
    write(
        root.path(),
        "members/app/src/lib.rs",
        "compile_error!(\"planning must not compile project sources\");\n",
    )?;
    write(
        root.path(),
        "vendor/Cargo.toml",
        "[workspace]\nmembers=['dependency']\n",
    )?;
    write(
        root.path(),
        "vendor/dependency/Cargo.toml",
        "[package]\nname='vendor-lib'\nversion='1.0.0'\n",
    )?;
    write(
        root.path(),
        "vendor/dependency/src/lib.rs",
        "compile_error!(\"planning must not compile dependency sources\");\n",
    )?;
    write(root.path(), "Cargo.lock", "version=4\n[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['vendor-lib']\n[[package]]\nname='vendor-lib'\nversion='1.0.0'\n")?;
    Ok(root)
}

fn snapshot(root: &Path) -> ladyshell::error::Result<sources::Snapshot> {
    sources::snapshot(root, &deps::project_sources(root)?, None)
}

fn plan(root: &Path, snapshot: &sources::Snapshot) -> ladyshell::error::Result<deps::Preparation> {
    plan_projects(root, snapshot, &["Cargo.toml"])
}

fn plan_projects(
    root: &Path,
    snapshot: &sources::Snapshot,
    projects: &[&str],
) -> ladyshell::error::Result<deps::Preparation> {
    deps::prepare::plan(
        root,
        snapshot,
        &deps::DependencyConfig {
            projects: projects.iter().map(|name| (*name).into()).collect(),
            allowed_hosts: vec![],
        },
        &BTreeMap::from([(
            "rust".into(),
            Tool {
                version: "1.98.1".into(),
                phase: "runtime".into(),
            },
        )]),
    )
}

fn append(root: &Path, name: &str, extra: &str) -> std::io::Result<()> {
    let previous = fs::read_to_string(root.join(name))?;
    write(root, name, &(previous + extra))
}

fn sibling_fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = fixture()?;
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nmembers=['members/app','members/sibling']\nexclude=['vendor']\n",
    )?;
    append(
        root.path(),
        "members/app/Cargo.toml",
        "sibling={path='../sibling'}\n",
    )?;
    write(
        root.path(),
        "members/sibling/Cargo.toml",
        "[package]\nname='sibling'\nversion='1.0.0'\n",
    )?;
    write(
        root.path(),
        "members/sibling/src/lib.rs",
        "compile_error!(\"planning must not compile workspace dependencies\");\n",
    )?;
    write(root.path(), "Cargo.lock", "version=4\n[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['vendor-lib','sibling']\n[[package]]\nname='sibling'\nversion='1.0.0'\n[[package]]\nname='vendor-lib'\nversion='1.0.0'\n")?;
    Ok(root)
}

#[test]
fn explicit_member_omits_sibling_targets_but_keeps_the_full_lock() -> TestResult {
    for target in ["bin", "test", "example", "bench"] {
        let root = sibling_fixture()?;
        append(
            root.path(),
            "members/sibling/Cargo.toml",
            &format!("\n[[{target}]]\nname='unselected'\npath='omitted.rs'\n"),
        )?;
        let before = snapshot(root.path())?;
        let prepared = plan_projects(root.path(), &before, &["members/app/Cargo.toml"])?;
        assert_eq!(prepared.projects.len(), 1);
        assert_eq!(prepared.projects[0].manifest, "members/app/Cargo.toml");
        assert_eq!(prepared.projects[0].lockfile.as_deref(), Some("Cargo.lock"));
        let names: std::collections::BTreeSet<_> = prepared.projects[0]
            .components
            .iter()
            .map(|component| component.name.as_str())
            .collect();
        assert_eq!(names, ["app", "sibling", "vendor-lib"].into());
        assert_eq!(snapshot(root.path())?, before);
        assert!(!root.path().join("target").exists());
        for selected in [
            vec!["Cargo.toml"],
            vec!["members/sibling/Cargo.toml"],
            vec!["members/app/Cargo.toml", "members/sibling/Cargo.toml"],
        ] {
            let error = plan_projects(root.path(), &before, &selected)
                .err()
                .ok_or("selected workspace target unexpectedly accepted")?;
            assert!(error.to_string().contains("members/sibling/omitted.rs"));
        }
    }
    Ok(())
}

#[test]
fn explicit_member_still_requires_sibling_library_and_build_inputs() -> TestResult {
    for extra in [
        "\n[lib]\npath='missing-lib.rs'\n",
        "\n[package]\nname='sibling'\nversion='1.0.0'\nbuild='missing-build.rs'\n",
        "\n[package]\nname='sibling'\nversion='1.0.0'\nautolib=false\n",
    ] {
        let root = sibling_fixture()?;
        plan_projects(
            root.path(),
            &snapshot(root.path())?,
            &["members/app/Cargo.toml"],
        )?;
        if extra.contains("[package]") {
            write(root.path(), "members/sibling/Cargo.toml", extra)?;
        } else {
            append(root.path(), "members/sibling/Cargo.toml", extra)?;
        }
        assert!(plan_projects(
            root.path(),
            &snapshot(root.path())?,
            &["members/app/Cargo.toml"]
        )
        .is_err());
    }
    let root = sibling_fixture()?;
    fs::remove_file(root.path().join("members/sibling/src/lib.rs"))?;
    assert!(plan_projects(
        root.path(),
        &snapshot(root.path())?,
        &["members/app/Cargo.toml"]
    )
    .is_err());

    let root = sibling_fixture()?;
    write(
        root.path(),
        "members/sibling/build.rs",
        "compile_error!(\"must not run\");\n",
    )?;
    let mut selected = snapshot(root.path())?;
    selected.remove("members/sibling/build.rs");
    assert!(plan_projects(root.path(), &selected, &["members/app/Cargo.toml"]).is_err());
    Ok(())
}

#[test]
fn unselected_sibling_targets_still_reject_unsafe_paths() -> TestResult {
    for path in [
        "../../../outside.rs",
        "/etc/outside.rs",
        "..\\..\\outside.rs",
        "",
    ] {
        let root = sibling_fixture()?;
        append(
            root.path(),
            "members/sibling/Cargo.toml",
            &format!("\n[[example]]\nname='unselected'\npath='{path}'\n"),
        )?;
        assert!(
            plan_projects(
                root.path(),
                &snapshot(root.path())?,
                &["members/app/Cargo.toml"]
            )
            .is_err(),
            "{path}"
        );
    }
    Ok(())
}

#[test]
fn explicit_member_retains_workspace_dev_but_not_external_library_dev_requirements() -> TestResult {
    let root = sibling_fixture()?;
    append(
        root.path(),
        "vendor/dependency/Cargo.toml",
        "\n[dev-dependencies]\nupstream-test-helper='1'\n",
    )?;
    plan_projects(
        root.path(),
        &snapshot(root.path())?,
        &["members/app/Cargo.toml"],
    )?;
    append(
        root.path(),
        "members/sibling/Cargo.toml",
        "\n[dev-dependencies]\nworkspace-test-helper='1'\n",
    )?;
    let error = plan_projects(
        root.path(),
        &snapshot(root.path())?,
        &["members/app/Cargo.toml"],
    )
    .err()
    .ok_or("workspace development requirement unexpectedly ignored")?;
    assert!(error.to_string().contains("workspace-test-helper"));
    Ok(())
}

#[test]
fn explicit_member_retains_workspace_inheritance_and_root_patch_inputs() -> TestResult {
    let root = sibling_fixture()?;
    write(
        root.path(),
        "members/app/Cargo.toml",
        "[package]\nname='app'\nversion='1.0.0'\n[dependencies]\nsibling={workspace=true}\n",
    )?;
    append(root.path(), "Cargo.toml", "\n[workspace.dependencies]\nsibling={path='members/sibling'}\n[patch.crates-io]\npatched-lib={path='vendor/patch'}\n")?;
    write(
        root.path(),
        "vendor/patch/Cargo.toml",
        "[package]\nname='patched-lib'\nversion='1.0.0'\n",
    )?;
    write(
        root.path(),
        "vendor/patch/src/lib.rs",
        "compile_error!(\"must not run\");\n",
    )?;
    append(
        root.path(),
        "Cargo.lock",
        "\n[[package]]\nname='patched-lib'\nversion='1.0.0'\n",
    )?;
    plan_projects(
        root.path(),
        &snapshot(root.path())?,
        &["members/app/Cargo.toml"],
    )?;
    fs::remove_file(root.path().join("vendor/patch/src/lib.rs"))?;
    let error = plan_projects(
        root.path(),
        &snapshot(root.path())?,
        &["members/app/Cargo.toml"],
    )
    .err()
    .ok_or("root patch library unexpectedly ignored")?;
    assert!(error.to_string().contains("vendor/patch/src/lib.rs"));
    Ok(())
}

#[test]
fn unused_vendored_targets_need_no_sources_or_project_execution() -> TestResult {
    for target in ["bin", "test", "example", "bench"] {
        let root = fixture()?;
        append(
            root.path(),
            "vendor/dependency/Cargo.toml",
            &format!("\n[[{target}]]\nname='upstream'\npath='omitted/upstream.rs'\n"),
        )?;
        write(
            root.path(),
            "vendor/dependency/build.rs",
            "compile_error!(\"build scripts must not run during planning\");\n",
        )?;
        let before = snapshot(root.path())?;
        let prepared = plan(root.path(), &before)?;
        assert_eq!(prepared.projects.len(), 1);
        assert_eq!(snapshot(root.path())?, before);
        assert!(!root.path().join("target").exists());
    }
    Ok(())
}

#[test]
fn workspace_targets_still_require_selected_sources() -> TestResult {
    for target in ["bin", "test", "example", "bench"] {
        let root = fixture()?;
        append(
            root.path(),
            "members/app/Cargo.toml",
            &format!("\n[[{target}]]\nname='active'\npath='missing.rs'\n"),
        )?;
        assert!(
            plan(root.path(), &snapshot(root.path())?).is_err(),
            "{target}"
        );
    }
    Ok(())
}

#[test]
fn unused_vendor_targets_cannot_escape_the_selected_project() -> TestResult {
    for path in [
        "../../../outside.rs",
        "/etc/outside.rs",
        "..\\..\\outside.rs",
    ] {
        let root = fixture()?;
        append(
            root.path(),
            "vendor/dependency/Cargo.toml",
            &format!("\n[[test]]\nname='upstream'\npath='{path}'\n"),
        )?;
        assert!(
            plan(root.path(), &snapshot(root.path())?).is_err(),
            "{path}"
        );
    }
    Ok(())
}

#[test]
fn active_library_and_build_script_inputs_cannot_be_missing() -> TestResult {
    for manifest in ["members/app/Cargo.toml", "vendor/dependency/Cargo.toml"] {
        for extra in [
            "\n[lib]\npath='missing-lib.rs'\n",
            "\n[package]\nname='replacement'\nversion='1.0.0'\nbuild='missing-build.rs'\n",
        ] {
            let root = fixture()?;
            if extra.contains("[package]") {
                let previous = fs::read_to_string(root.path().join(manifest))?;
                write(
                    root.path(),
                    manifest,
                    &previous.replacen(
                        "version='1.0.0'",
                        "version='1.0.0'\nbuild='missing-build.rs'",
                        1,
                    ),
                )?;
            } else {
                append(root.path(), manifest, extra)?;
            }
            assert!(
                plan(root.path(), &snapshot(root.path())?).is_err(),
                "{manifest}: {extra}"
            );
        }
    }
    let root = fixture()?;
    fs::remove_file(root.path().join("vendor/dependency/src/lib.rs"))?;
    assert!(
        plan(root.path(), &snapshot(root.path())?).is_err(),
        "a path dependency requires its implicit library"
    );
    Ok(())
}

#[test]
fn an_automatic_build_script_on_disk_cannot_be_omitted_from_selected_sources() -> TestResult {
    let root = fixture()?;
    write(
        root.path(),
        "vendor/dependency/build.rs",
        "compile_error!(\"must not run\");\n",
    )?;
    let mut selected = snapshot(root.path())?;
    selected.remove("vendor/dependency/build.rs");
    assert!(plan(root.path(), &selected).is_err());
    Ok(())
}

#[test]
fn vendored_dev_and_inactive_optional_dependencies_do_not_constrain_the_root_lock() -> TestResult {
    for declarations in [
        "\n[dev-dependencies]\nupstream-test-helper='1'\n",
        "\n[dependencies.optional-alias]\npackage='unused-optional'\nversion='1'\noptional=true\n",
    ] {
        let root = fixture()?;
        append(root.path(), "vendor/dependency/Cargo.toml", declarations)?;
        plan(root.path(), &snapshot(root.path())?)?;
    }
    Ok(())
}

#[test]
fn required_runtime_and_workspace_dev_dependencies_still_constrain_the_root_lock() -> TestResult {
    for (manifest, declarations) in [
        (
            "vendor/dependency/Cargo.toml",
            "\n[dependencies]\nrequired-runtime='1'\n",
        ),
        (
            "members/app/Cargo.toml",
            "\n[dev-dependencies]\nrequired-test-helper='1'\n",
        ),
    ] {
        let root = fixture()?;
        append(root.path(), manifest, declarations)?;
        assert!(plan(root.path(), &snapshot(root.path())?).is_err());
    }
    Ok(())
}

#[test]
fn a_locked_optional_dependency_cannot_hide_an_incompatible_version() -> TestResult {
    let root = fixture()?;
    append(
        root.path(),
        "vendor/dependency/Cargo.toml",
        "\n[dependencies.optional-alias]\npackage='optional-lib'\nversion='1'\noptional=true\n",
    )?;
    append(
        root.path(),
        "Cargo.lock",
        "dependencies=['optional-lib']\n[[package]]\nname='optional-lib'\nversion='2.0.0'\n",
    )?;
    assert!(plan(root.path(), &snapshot(root.path())?).is_err());
    Ok(())
}

#[test]
fn an_unrelated_package_name_does_not_create_workspace_membership() -> TestResult {
    let root = fixture()?;
    write(root.path(), "unrelated/Cargo.toml", "[package]\nname='vendor-lib'\nversion='1.0.0'\nrust-version='99.0'\n[[test]]\nname='unselected'\npath='missing.rs'\n")?;
    plan(root.path(), &snapshot(root.path())?)?;
    Ok(())
}
