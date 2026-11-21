use ladybom::deps::{interop, Report};
use serde_json::Value;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn report() -> Result<Report> {
    Ok(serde_json::from_str(include_str!(
        "fixtures/report-v2.json"
    ))?)
}
fn scope() -> interop::Scope<'static> {
    interop::Scope {
        repository: "fixture-repository",
        revision: "commit-1",
        target_profile: "all-platforms",
    }
}
#[test]
fn independent_locks_get_stable_separate_projects_and_private_reports() -> Result {
    let report = report()?;
    let bundle = interop::bundle(&report, &scope())?;
    assert_eq!(
        bundle.manifest["partitions"]
            .as_array()
            .ok_or("partitions")?
            .len(),
        3
    );
    assert_eq!(
        serde_json::to_value(&bundle)?,
        serde_json::to_value(interop::bundle(&report, &scope())?)?
    );
    let mut ids = std::collections::BTreeSet::new();
    for partition in bundle.manifest["partitions"]
        .as_array()
        .ok_or("partitions")?
    {
        assert!(ids.insert(partition["project_name"].as_str().ok_or("project name")?));
        let path = partition["native_report"]["path"]
            .as_str()
            .ok_or("native path")?;
        assert!(path.starts_with("private/"));
        let native: Report = serde_json::from_slice(bundle.artifacts.get(path).ok_or("artifact")?)?;
        native.validate()?;
        assert_eq!(native.projects.len(), 1);
        assert_eq!(native.inputs, report.inputs);
        let public = partition["sbom"]["path"].as_str().ok_or("sbom path")?;
        assert!(public.starts_with("public/"));
        assert_eq!(
            ladybom::files::hash(bundle.artifacts.get(public).ok_or("sbom")?),
            partition["sbom"]["sha256"]
        );
    }
    let revised = interop::bundle(
        &report,
        &interop::Scope {
            revision: "commit-2",
            ..scope()
        },
    )?;
    for (a, b) in bundle.manifest["partitions"]
        .as_array()
        .ok_or("partitions")?
        .iter()
        .zip(
            revised.manifest["partitions"]
                .as_array()
                .ok_or("partitions")?,
        )
    {
        assert_eq!(a["project_name"], b["project_name"]);
        assert_ne!(a["project_version"], b["project_version"]);
    }
    Ok(())
}
#[test]
fn shared_locks_stay_together_and_ambiguous_occurrences_are_refused() -> Result {
    let mut report = report()?;
    report.projects.retain(|p| p.ecosystem == "rust");
    let mut member = report.projects[0].clone();
    member.manifest = "rust/member/Cargo.toml".into();
    member.root = "rust/member".into();
    member.components.clear();
    member.components_from = Some(report.projects[0].manifest.clone());
    report.projects.push(member);
    let bundle = interop::bundle(&report, &scope())?;
    assert_eq!(
        bundle.manifest["partitions"]
            .as_array()
            .ok_or("partitions")?
            .len(),
        1
    );
    let path = bundle.manifest["partitions"][0]["native_report"]["path"]
        .as_str()
        .ok_or("path")?;
    let native: Report = serde_json::from_slice(bundle.artifacts.get(path).ok_or("native")?)?;
    assert_eq!(native.projects.len(), 2);
    native.validate()?;
    let mut duplicate = report.projects[0]
        .components
        .iter()
        .find(|c| c.purl.is_some())
        .ok_or("component")?
        .clone();
    duplicate.context = "different-context".into();
    report.projects[0].components.push(duplicate);
    assert!(interop::bundle(&report, &scope()).is_err());
    Ok(())
}
#[test]
fn public_manifest_never_copies_scope_paths_or_diagnostics() -> Result {
    let mut report = report()?;
    report.complete = false;
    report.diagnostics.push(ladybom::deps::Diagnostic {
        code: "SECRET-code".into(),
        file: "SECRET-file".into(),
        message: "SECRET-message".into(),
        blocking: true,
    });
    let bundle = interop::bundle(
        &report,
        &interop::Scope {
            repository: "https://user:SECRET@example.invalid",
            revision: "SECRET-revision",
            target_profile: "SECRET-profile",
        },
    )?;
    assert!(!bundle.manifest.to_string().contains("SECRET"));
    assert_eq!(bundle.manifest["source_complete"], false);
    for (path, bytes) in &bundle.artifacts {
        if path.ends_with("coverage.json") {
            let value: Value = serde_json::from_slice(bytes)?;
            assert_eq!(value["source_complete"], false);
            assert!(!value.to_string().contains("SECRET"));
        }
    }
    Ok(())
}

#[test]
fn normalized_pypi_aliases_cannot_hide_a_collision() -> Result {
    let mut report = report()?;
    report.projects.retain(|p| p.ecosystem == "python");
    let mut duplicate = report.projects[0]
        .components
        .iter()
        .find(|c| c.name == "idna")
        .ok_or("idna")?
        .clone();
    duplicate.name = "IDNA".into();
    duplicate.purl = Some("pkg:pypi/IDNA@3.10".into());
    duplicate.context = "other-installation".into();
    report.projects[0].components.push(duplicate);
    assert!(interop::bundle(&report, &scope()).is_err());
    Ok(())
}

#[test]
fn independent_cargo_workspaces_keep_shared_members_in_their_own_partition() -> Result {
    let mut report = report()?;
    report.projects.retain(|p| p.ecosystem == "rust");
    let mut second = report.projects[0].clone();
    second.root = "other".into();
    second.manifest = "other/Cargo.toml".into();
    second.lockfile = Some("other/Cargo.lock".into());
    report.projects.push(second);
    for index in 0..2 {
        let mut member = report.projects[index].clone();
        member.components_from = Some(member.manifest.clone());
        member.manifest = format!("{}/member/Cargo.toml", member.root);
        member.root = format!("{}/member", member.root);
        member.components.clear();
        report.projects.push(member);
    }
    let bundle = interop::bundle(&report, &scope())?;
    let partitions = bundle.manifest["partitions"]
        .as_array()
        .ok_or("partitions")?;
    assert_eq!(partitions.len(), 2);
    let mut references = std::collections::BTreeSet::new();
    for partition in partitions {
        let path = partition["native_report"]["path"]
            .as_str()
            .ok_or("native path")?;
        let native: Report = serde_json::from_slice(bundle.artifacts.get(path).ok_or("native")?)?;
        native.validate()?;
        assert_eq!(native.projects.len(), 2);
        assert_eq!(
            native.projects[1].components_from.as_deref(),
            Some(native.projects[0].manifest.as_str())
        );
        assert_eq!(
            native.components_for(&native.projects[1])?,
            native.projects[0].components
        );
        let path = partition["sbom"]["path"].as_str().ok_or("sbom path")?;
        let bom: Value = serde_json::from_slice(bundle.artifacts.get(path).ok_or("sbom")?)?;
        for component in bom["components"].as_array().ok_or("components")? {
            assert!(references.insert(component["bom-ref"].as_str().ok_or("ref")?.to_owned()));
        }
    }
    Ok(())
}
