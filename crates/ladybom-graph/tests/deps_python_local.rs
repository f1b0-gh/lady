use ladybom::deps;
use ladybom::sources;
use ladybom_graph as graph;
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

fn root_fixture(root: &Path, mode: &str) -> TestResult {
    write(
        root,
        "pyproject.toml",
        "[project]\nname='Local_Project'\nversion='1.0'\ndependencies=['idna==3.10']\n",
    )?;
    write(
        root,
        "uv.lock",
        &format!(
            "version=1\n[[package]]\nname='local-project'\nversion='1.0.0'\nsource={{{mode}='.'}}\ndependencies=[{{name='idna'}}]\n\
             [[package]]\nname='idna'\nversion='3.10'\nsource={{registry='https://pypi.org/simple'}}\n"
        ),
    )?;
    Ok(())
}

// Dropping a qualified local root must not erase its native dependency edge.
#[test]
fn local_root_modes_keep_identity_edges_and_alignment_evidence() -> TestResult {
    for mode in ["editable", "directory", "virtual"] {
        let root = tempfile::tempdir()?;
        root_fixture(root.path(), mode)?;
        let report = deps::scan_project(root.path())?;
        let graph = graph::project(report)?;
        let alignment = graph::alignment(&graph)?;
        assert_eq!(alignment.coverage.unidentified_components, 0);
        assert_eq!(alignment.coverage.unprojected_components, 0);
        assert_eq!(alignment.coverage.unmapped_nodes, 0);
        let group = alignment
            .groups
            .iter()
            .find(|g| g.identity == "pkg:generic/python-local/local-project")
            .ok_or("local alignment evidence absent")?;
        assert_eq!(group.source, json!({"local": "."}));
    }
    Ok(())
}

#[test]
fn internal_sibling_paths_keep_native_local_dependency_edges() -> TestResult {
    for mode in ["editable", "directory", "virtual"] {
        let root = tempfile::tempdir()?;
        write(
            root.path(),
            "app/pyproject.toml",
            "[project]\nname='consumer'\nversion='1.0.0'\ndependencies=['local-lib']\n\
             [tool.uv.sources]\nlocal-lib={path='../library'}\n",
        )?;
        write(
            root.path(),
            "library/pyproject.toml",
            "[project]\nname='local_lib'\nversion='1.0.0'\ndependencies=[]\n",
        )?;
        write(
            root.path(),
            "app/uv.lock",
            &format!(
                "version=1\n[[package]]\nname='consumer'\nversion='1.0.0'\nsource={{virtual='.'}}\ndependencies=[{{name='local-lib'}}]\n\
                 [[package]]\nname='local-lib'\nversion='1.0.0'\nsource={{{mode}='../library'}}\n"
            ),
        )?;
        let graph = graph::project(deps::scan_project(root.path())?)?;
        let alignment = graph::alignment(&graph)?;
        assert_eq!(alignment.coverage.unidentified_components, 0);
        assert_eq!(alignment.coverage.unmapped_nodes, 0);
        let local = alignment
            .groups
            .iter()
            .find(|g| g.identity == "pkg:generic/python-local/local-lib")
            .ok_or("local library absent")?;
        assert_eq!(local.source, json!({"local": "library"}));
    }
    Ok(())
}

#[test]
fn missing_or_conflicting_manifest_evidence_cannot_qualify_a_local_root() -> TestResult {
    let root = tempfile::tempdir()?;
    root_fixture(root.path(), "editable")?;
    let original = deps::scan_project(root.path())?;
    for case in [
        "manifest-input",
        "lock-input",
        "old-report",
        "name",
        "version",
        "metadata",
        "purl",
        "mixed-source",
        "artifact",
    ] {
        let mut report = original.clone();
        let project = &mut report.projects[0];
        let component = project
            .components
            .iter_mut()
            .find(|c| c.name == "local-project")
            .ok_or("local")?;
        match case {
            "manifest-input" => {
                report.inputs.remove("pyproject.toml");
            }
            "lock-input" => {
                report.inputs.remove("uv.lock");
            }
            "old-report" => {
                project.manifest_package = None;
            }
            "name" => {
                project.manifest_package.as_mut().ok_or("package")?.name = "other".into();
            }
            "version" => {
                project.manifest_package.as_mut().ok_or("package")?.version = "2.0".into();
            }
            "metadata" => {
                component.metadata["source"] = json!({"editable":"other"});
            }
            "purl" => {
                component.purl = Some("pkg:generic/python-local/local-project@1.0.0".into());
            }
            "mixed-source" => {
                component.source = json!({"editable":".","registry":"https://pypi.org/simple"});
                component.context = component.source.to_string();
                component.metadata["source"] = component.source.clone();
            }
            "artifact" => {
                component.artifacts.push(deps::Artifact {
                    url: "https://example.invalid/package.whl".into(),
                    hash: None,
                });
            }
            _ => unreachable!(),
        }
        let graph = graph::project(report)?;
        let coverage = graph::alignment(&graph)?.coverage;
        assert_eq!(coverage.unidentified_components, 1, "{case}");
        assert_eq!(coverage.unprojected_components, 1, "{case}");
        assert!(!coverage.versions_complete, "{case}");
    }
    Ok(())
}

#[test]
fn dynamic_or_malformed_identity_declarations_stay_unknown() -> TestResult {
    for extra in [
        "dynamic=['version']",
        "dynamic=['name']",
        "dynamic='version'",
        "dynamic=[42]",
    ] {
        let root = tempfile::tempdir()?;
        root_fixture(root.path(), "editable")?;
        let manifest = root.path().join("pyproject.toml");
        fs::write(
            &manifest,
            format!("{}\n{extra}\n", fs::read_to_string(&manifest)?),
        )?;
        let graph = graph::project(deps::scan_project(root.path())?)?;
        assert_eq!(
            graph::alignment(&graph)?.coverage.unidentified_components,
            1
        );
    }
    Ok(())
}

#[test]
fn unselected_and_escaping_local_paths_stay_unknown() -> TestResult {
    for path in [
        "..",
        "../../outside",
        "/absolute",
        "C:\\outside",
        "https://example.invalid/x",
        "%2e%2e",
        "absent",
        "",
    ] {
        let root = tempfile::tempdir()?;
        root_fixture(root.path(), "editable")?;
        let mut report = deps::scan_project(root.path())?;
        let c = report.projects[0]
            .components
            .iter_mut()
            .find(|c| c.name == "local-project")
            .ok_or("local")?;
        c.source = json!({"editable":path});
        c.context = c.source.to_string();
        c.metadata["source"] = c.source.clone();
        let graph = graph::project(report)?;
        assert_eq!(
            graph::alignment(&graph)?.coverage.unidentified_components,
            1
        );
    }
    Ok(())
}

#[test]
fn duplicate_local_evidence_is_not_selected_arbitrarily() -> TestResult {
    let root = tempfile::tempdir()?;
    root_fixture(root.path(), "editable")?;
    let mut report = deps::scan_project(root.path())?;
    let duplicate = report.projects[0]
        .components
        .iter()
        .find(|c| c.name == "local-project")
        .ok_or("local")?
        .clone();
    report.projects[0].components.push(duplicate);
    let graph = graph::project(report)?;
    let coverage = graph::alignment(&graph)?.coverage;
    assert_eq!(coverage.unidentified_components, 2);
    assert_eq!(coverage.unprojected_components, 2);
    Ok(())
}

#[test]
fn local_identities_do_not_claim_public_pypi_advisory_coverage() -> TestResult {
    let root = tempfile::tempdir()?;
    root_fixture(root.path(), "editable")?;
    let report = deps::scan_project(root.path())?;
    let graph = graph::project(report)?;
    assert_eq!(
        graph::alignment(&graph)?.coverage.unidentified_components,
        0
    );
    Ok(())
}

#[test]
fn identical_names_keep_directory_and_registry_sources_distinct() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "pyproject.toml",
        "[project]\nname='consumer'\nversion='1.0.0'\ndependencies=[]\n",
    )?;
    for directory in ["a", "b"] {
        write(
            root.path(),
            &format!("{directory}/pyproject.toml"),
            "[project]\nname='shared'\nversion='1.0.0'\ndependencies=[]\n",
        )?;
    }
    write(root.path(), "uv.lock", "version=1\n\
        [[package]]\nname='consumer'\nversion='1.0.0'\nsource={virtual='.'}\n\
        dependencies=[{name='shared',version='1.0.0',source={directory='a'}},{name='shared',version='1.0.0',source={directory='b'}},{name='shared',version='1.0.0',source={registry='https://pypi.org/simple'}}]\n\
        [[package]]\nname='shared'\nversion='1.0.0'\nsource={directory='a'}\n\
        [[package]]\nname='shared'\nversion='1.0.0'\nsource={directory='b'}\n\
        [[package]]\nname='shared'\nversion='1.0.0'\nsource={registry='https://pypi.org/simple'}\n")?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let alignment = graph::alignment(&graph)?;
    assert_eq!(alignment.coverage.unmapped_nodes, 0);
    let groups: Vec<_> = alignment
        .groups
        .iter()
        .filter(|g| g.identity == "pkg:generic/python-local/shared")
        .collect();
    assert_eq!(groups.len(), 2);
    assert!(groups.iter().any(|g| g.source == json!({"local":"a"})));
    assert!(groups.iter().any(|g| g.source == json!({"local":"b"})));
    assert!(alignment
        .groups
        .iter()
        .any(|g| g.identity == "pkg:pypi/shared"));
    let plan = graph::plan_alignment(&graph)?;
    assert!(!plan.remediation_approved);
    Ok(())
}

fn contradictory_local_reports() -> Result<Vec<(String, deps::Report)>, Box<dyn std::error::Error>>
{
    let mut reports = Vec::new();
    for mode in ["editable", "directory", "virtual"] {
        let root = tempfile::tempdir()?;
        root_fixture(root.path(), mode)?;
        let original = deps::scan_project(root.path())?;
        for evidence in ["both", "metadata", "context"] {
            let mut report = original.clone();
            let local = report.projects[0]
                .components
                .iter_mut()
                .find(|c| c.name == "local-project")
                .ok_or("local root absent")?;
            local.source = json!({"registry":"https://pypi.org/simple"});
            local.purl = Some("pkg:pypi/local-project@1.0.0".into());
            if evidence == "metadata" {
                local.context = local.source.to_string();
            } else if evidence == "context" {
                local.metadata["source"] = local.source.clone();
            }
            // Import the contradiction through the same JSON boundary as a consumer.
            let imported = serde_json::from_slice(&serde_json::to_vec(&report)?)?;
            reports.push((format!("{mode}/{evidence}"), imported));
        }
    }
    Ok(reports)
}

#[test]
fn contradictory_local_reports_cannot_claim_public_graph_identities() -> TestResult {
    for (case, report) in contradictory_local_reports()? {
        let graph = graph::project(report)?;
        let alignment = graph::alignment(&graph)?;
        assert_eq!(alignment.coverage.unidentified_components, 1, "{case}");
        assert_eq!(alignment.coverage.unprojected_components, 1, "{case}");
        assert!(!alignment.coverage.versions_complete, "{case}");
    }
    Ok(())
}

#[test]
fn native_markers_and_local_context_survive_snapshot_round_trip() -> TestResult {
    let root = tempfile::tempdir()?;
    root_fixture(root.path(), "virtual")?;
    let mut report = deps::scan_project(root.path())?;
    let local = report.projects[0]
        .components
        .iter_mut()
        .find(|c| c.name == "local-project")
        .ok_or("local")?;
    local.metadata["resolution-markers"] = json!(["sys_platform == 'win32'"]);
    local.metadata["dev-dependencies"] =
        json!({"test":[{"name":"idna","marker":"python_version >= '3.12'"}]});
    let graph = graph::project(report)?;
    assert!(!graph::alignment(&graph)?.coverage.activation_known);
    let output = tempfile::tempdir()?;
    let path = output.path().join("snapshot");
    graph::write_snapshot(&graph, &path)?;
    let restored = graph::read_snapshot(&path)?;
    assert_eq!(
        serde_json::to_value(&graph)?,
        serde_json::to_value(&restored)?
    );
    assert_eq!(graph::alignment(&restored)?.coverage.unmapped_nodes, 0);
    let manifest = path.join("manifest.json");
    fs::write(&manifest, "{}\n")?;
    assert!(graph::read_snapshot(&path).is_err());
    Ok(())
}

#[test]
fn excluded_local_manifest_is_not_read_to_fill_identity() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "app/pyproject.toml",
        "[project]\nname='consumer'\nversion='1.0.0'\ndependencies=[]\n",
    )?;
    write(
        root.path(),
        "library/pyproject.toml",
        "[project]\nname='library'\nversion='1.0.0'\ndependencies=[]\n",
    )?;
    write(root.path(), "app/uv.lock", "version=1\n\
        [[package]]\nname='consumer'\nversion='1.0.0'\nsource={virtual='.'}\ndependencies=[{name='library'}]\n\
        [[package]]\nname='library'\nversion='1.0.0'\nsource={directory='../library'}\n")?;
    let spec = sources::Sources {
        include: vec!["app".into(), "library".into()],
        exclude: vec!["library/pyproject.toml".into()],
    };
    let snapshot = sources::snapshot(root.path(), &spec, None)?;
    let report = deps::scan_snapshot(root.path(), &snapshot)?;
    let graph = graph::project(report)?;
    assert_eq!(
        graph::alignment(&graph)?.coverage.unidentified_components,
        1
    );
    Ok(())
}
