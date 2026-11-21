use cyclonedx_bom::{models::bom::Bom, prelude::Validate};
use ladybom::{cyclonedx, Report};
use serde_json::{json, Value};
use std::{collections::BTreeSet, io};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn report() -> std::result::Result<Report, serde_json::Error> {
    serde_json::from_str(include_str!("fixtures/report-v2.json"))
}

fn exported(report: &Report) -> std::result::Result<Value, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    cyclonedx::write_json_with_profile(
        report,
        cyclonedx::ExportProfile::PrivateDetailed,
        &mut bytes,
    )?;
    let parsed = Bom::parse_from_json(bytes.as_slice())?;
    assert!(parsed.validate_version(parsed.spec_version).passed());
    Ok(serde_json::from_slice(&bytes)?)
}

fn property<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value["properties"]
        .as_array()?
        .iter()
        .find(|property| property["name"] == name)?["value"]
        .as_str()
}

#[test]
fn output_is_valid_and_preserves_component_evidence_without_claiming_a_complete_graph() -> Result {
    let report = report()?;
    let bom = exported(&report)?;
    assert_eq!(bom["specVersion"], "1.5");
    assert_eq!(bom["metadata"]["tools"][0]["name"], "ladybom");
    assert!(bom.get("dependencies").is_some());
    assert!(bom["serialNumber"]
        .as_str()
        .is_some_and(|s| s.starts_with("urn:uuid:")));
    assert_eq!(bom["compositions"][0]["aggregate"], "unknown");
    let components = bom["components"].as_array().ok_or("components")?;
    for project in &report.projects {
        for original in &project.components {
            let component = components
                .iter()
                .find(|component| component["name"] == original.name)
                .ok_or("component")?;
            assert_eq!(component["version"], original.version);
            assert_eq!(
                component.get("purl").and_then(Value::as_str),
                original.purl.as_deref()
            );
            assert_eq!(
                property(component, "ladybom:context"),
                Some(original.context.as_str())
            );
            assert_eq!(
                property(component, "ladybom:lockfile"),
                project.lockfile.as_deref()
            );
            for (key, expected) in [
                (
                    "ladybom:artifacts",
                    serde_json::to_value(&original.artifacts)?,
                ),
                ("ladybom:source", original.source.clone()),
                ("ladybom:metadata", original.metadata.clone()),
            ] {
                assert_eq!(
                    serde_json::from_str::<Value>(property(component, key).ok_or("evidence")?)?,
                    expected
                );
            }
        }
    }
    assert_eq!(exported(&report)?, bom);
    Ok(())
}

#[test]
fn shared_locks_are_exported_once_and_distinct_contexts_keep_unique_references() -> Result {
    let mut report = report()?;
    let original_count: usize = report.projects.iter().map(|p| p.components.len()).sum();
    let mut member = report.projects[0].clone();
    member.manifest = "python/member/pyproject.toml".into();
    member.root = "python/member".into();
    member.components.clear();
    member.components_from = Some(report.projects[0].manifest.clone());
    report.projects.push(member);
    let shared = exported(&report)?;
    assert_eq!(
        shared["components"].as_array().ok_or("components")?.len(),
        original_count
    );
    let projects: Value =
        serde_json::from_str(property(&shared, "ladybom:projects").ok_or("projects")?)?;
    assert_eq!(projects[3]["components_from"], "python/pyproject.toml");
    assert!(projects[3].get("components").is_none());

    let mut other_lock = report.projects[2].clone();
    other_lock.manifest = "other/package.json".into();
    other_lock.root = "other".into();
    other_lock.lockfile = Some("other/package-lock.json".into());
    let mut nested = other_lock.components[0].clone();
    nested.context = "node_modules/parent/node_modules/is-number".into();
    other_lock.components.push(nested);
    report.projects.push(other_lock);
    let bom = exported(&report)?;
    let components = bom["components"].as_array().ok_or("components")?;
    assert_eq!(components.len(), original_count + 3);
    let refs: BTreeSet<_> = components
        .iter()
        .filter_map(|c| c["bom-ref"].as_str())
        .collect();
    assert_eq!(refs.len(), components.len());
    assert_eq!(
        components
            .iter()
            .filter(|c| c["purl"] == "pkg:npm/is-number@7.0.0")
            .count(),
        3
    );
    Ok(())
}

#[test]
fn empty_unlocked_and_partial_reports_never_invent_versions() -> Result {
    let root = tempfile::tempdir()?;
    let empty = exported(&ladybom::scan_project(root.path())?)?;
    assert_eq!(empty["components"], json!([]));
    std::fs::write(
        root.path().join("package.json"),
        r#"{"name":"app","dependencies":{"missing":"^1.0"}}"#,
    )?;
    let report = ladybom::scan_project(root.path())?;
    let bom = exported(&report)?;
    assert_eq!(bom["components"], json!([]));
    assert_eq!(property(&bom, "ladybom:complete"), Some("true"));
    assert_eq!(bom["compositions"][0]["aggregate"], "unknown");
    let projects: Value =
        serde_json::from_str(property(&bom, "ladybom:projects").ok_or("projects")?)?;
    assert_eq!(projects[0]["requirements"][0]["constraint"], "^1.0");
    std::fs::write(root.path().join("Cargo.toml"), "[invalid")?;
    let partial = exported(&ladybom::scan_project(root.path())?)?;
    assert_eq!(property(&partial, "ladybom:complete"), Some("false"));
    assert_eq!(partial["compositions"][0]["aggregate"], "incomplete");
    Ok(())
}

#[test]
fn invalid_reports_and_purls_fail_before_writing() -> Result {
    let original = report()?;
    for mutation in 0..4 {
        let mut report = original.clone();
        match mutation {
            0 => report.schema_version = 1,
            1 => report.projects[0].components_from = Some("missing/pyproject.toml".into()),
            2 => report.projects[0].components[0].purl = Some("not-a-purl".into()),
            _ => report.projects[0].manifest = "../pyproject.toml".into(),
        }
        let mut output = Vec::new();
        assert!(
            cyclonedx::write_json(&report, &mut output).is_err(),
            "mutation {mutation}"
        );
        assert!(output.is_empty());
    }
    Ok(())
}

#[test]
fn normalized_strings_cannot_silently_change_component_identity() -> Result {
    for mutation in 0..4 {
        let mut report = report()?;
        match mutation {
            0 => report.projects[0].components[0].name = "package\tname".into(),
            1 => report.projects[0].components[0].version = "1.\n0.0".into(),
            2 => report.projects[0].components[0].context = "path\rname".into(),
            _ => report.projects[0].ecosystem = "py\nthon".into(),
        }
        let mut output = Vec::new();
        assert!(
            cyclonedx::write_json(&report, &mut output).is_err(),
            "mutation {mutation}"
        );
        assert!(output.is_empty());
    }
    Ok(())
}

#[test]
fn unknown_versions_and_identical_records_do_not_create_false_identities() -> Result {
    let mut report = report()?;
    let mut component = report.projects[0].components[0].clone();
    component.name = "local-unversioned".into();
    component.version.clear();
    component.purl = None;
    report.projects[0].components.push(component.clone());
    report.projects[0].components.push(component);
    let bom = exported(&report)?;
    let matching = bom["components"]
        .as_array()
        .ok_or("components")?
        .iter()
        .filter(|c| c["name"] == "local-unversioned")
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    assert!(matching[0].get("version").is_none());
    assert!(matching[0].get("purl").is_none());
    Ok(())
}

#[test]
fn write_errors_are_operational_failures() -> Result {
    struct BrokenWriter;
    impl io::Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = cyclonedx::write_json(&report()?, BrokenWriter)
        .err()
        .ok_or("write succeeded")?;
    assert_eq!(ladybom::error::exit_code(&error), 1);
    Ok(())
}

fn diamond() -> std::result::Result<Report, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("package.json"),
        r#"{"name":"app","dependencies":{"a":"1.0.0"}}"#,
    )?;
    std::fs::write(
        root.path().join("package-lock.json"),
        serde_json::to_vec(&json!({
            "lockfileVersion":3, "packages": {
                "":{"name":"app","dependencies":{"a":"1.0.0"}},
                "node_modules/a":{"version":"1.0.0","dependencies":{"b":"1.0.0","c":"1.0.0"}},
                "node_modules/b":{"version":"1.0.0","dependencies":{"d":"1.0.0"}},
                "node_modules/c":{"version":"1.0.0","optionalDependencies":{"d":"1.0.0"}},
                "node_modules/d":{"version":"1.0.0"}
            }
        }))?,
    )?;
    Ok(ladybom::scan_project(root.path())?)
}

#[test]
fn root_and_transitive_diamond_retain_conditional_evidence() -> Result {
    let bom = exported(&diamond()?)?;
    let root = &bom["metadata"]["component"];
    assert_eq!(root["type"], "application");
    let root_ref = root["bom-ref"].as_str().ok_or("root ref")?;
    let components = bom["components"].as_array().ok_or("components")?;
    let reference = |name: &str| -> std::result::Result<&str, Box<dyn std::error::Error>> {
        components
            .iter()
            .find(|c| c["name"] == name)
            .and_then(|c| c["bom-ref"].as_str())
            .ok_or("component reference".into())
    };
    let dependencies = bom["dependencies"].as_array().ok_or("dependencies")?;
    for (from, to) in [
        (root_ref, reference("a")?),
        (reference("a")?, reference("b")?),
        (reference("a")?, reference("c")?),
        (reference("b")?, reference("d")?),
        (reference("c")?, reference("d")?),
    ] {
        assert!(dependencies.iter().any(|edge| edge["ref"] == from
            && edge["dependsOn"]
                .as_array()
                .is_some_and(|targets| targets.contains(&json!(to)))));
    }
    let evidence: Value =
        serde_json::from_str(property(&bom, "ladybom:graph:evidence").ok_or("graph evidence")?)?;
    assert!(evidence["dependencies"]
        .as_array()
        .ok_or("evidence dependencies")?
        .iter()
        .any(|edge| edge["kind"] == "optional" && edge["condition"]["optional"] == true));
    assert_eq!(bom["compositions"][0]["aggregate"], "unknown");
    assert!(property(&bom, "ladybom:graph:semantics").is_some());
    Ok(())
}

#[test]
fn serial_commits_to_exported_content_not_only_native_report() -> Result {
    let report = diamond()?;
    let mut bom = exported(&report)?;
    let serial = bom
        .as_object_mut()
        .ok_or("BOM")?
        .remove("serialNumber")
        .ok_or("serial")?;
    assert_eq!(
        serial,
        cyclonedx::document_serial_with_profile(
            &report,
            cyclonedx::ExportProfile::PrivateDetailed
        )?
    );
    assert_eq!(
        serial,
        cyclonedx::serial_from_digest(&ladybom::files::hash(&serde_json::to_vec(&bom)?))?
    );
    bom["metadata"]["tools"][0]["version"] = json!("changed-exporter");
    assert_ne!(
        serial,
        cyclonedx::serial_from_digest(&ladybom::files::hash(&serde_json::to_vec(&bom)?))?
    );
    Ok(())
}

#[test]
fn artifact_hashes_are_scoped_to_distribution_urls() -> Result {
    let report = report()?;
    let bom = exported(&report)?;
    let idna = bom["components"]
        .as_array()
        .ok_or("components")?
        .iter()
        .find(|c| c["name"] == "idna")
        .ok_or("idna")?;
    assert!(idna.get("hashes").is_none());
    let references = idna["externalReferences"]
        .as_array()
        .ok_or("distribution references")?;
    assert_eq!(references.len(), 2);
    assert_eq!(references[0]["type"], "distribution");
    assert_eq!(references[0]["hashes"][0]["alg"], "SHA-256");
    assert_eq!(
        references[0]["hashes"][0]["content"],
        "12f65c9b470abda6dc35cf8e63cc574b1c52b11df2c86030af0ac09b01b13ea9"
    );
    Ok(())
}

#[test]
fn only_explicit_valid_npm_license_expressions_become_standard_licenses() -> Result {
    let mut report = diamond()?;
    report.projects[0].components[0].metadata["license"] = json!("MIT OR Apache-2.0");
    report.projects[0].components[1].metadata["license"] = json!("SEE LICENSE IN LICENSE.txt");
    let bom = exported(&report)?;
    let components = bom["components"].as_array().ok_or("components")?;
    let a = components.iter().find(|c| c["name"] == "a").ok_or("a")?;
    let b = components.iter().find(|c| c["name"] == "b").ok_or("b")?;
    assert_eq!(a["licenses"][0]["expression"], "MIT OR Apache-2.0");
    assert!(b.get("licenses").is_none());
    assert!(components
        .iter()
        .filter(|c| c["name"] != "a")
        .all(|c| c.get("licenses").is_none()));
    Ok(())
}

#[test]
fn independent_locks_and_nested_occurrences_never_cross_dependency_edges() -> Result {
    let mut report = diamond()?;
    let mut second = report.projects[0].clone();
    second.root = "other".into();
    second.manifest = "other/package.json".into();
    second.lockfile = Some("other/package-lock.json".into());
    let mut nested = second
        .components
        .iter()
        .find(|c| c.name == "d")
        .ok_or("d")?
        .clone();
    nested.context = "node_modules/b/node_modules/d".into();
    second.components.push(nested);
    report.projects.push(second);
    let bom = exported(&report)?;
    let components = bom["components"].as_array().ok_or("components")?;
    let by_ref = |reference: &Value| components.iter().find(|c| c["bom-ref"] == *reference);
    for dependency in bom["dependencies"].as_array().ok_or("dependencies")? {
        let Some(from) = by_ref(&dependency["ref"]) else {
            continue;
        };
        for target in dependency["dependsOn"].as_array().ok_or("targets")? {
            let to = by_ref(target).ok_or("target")?;
            assert_eq!(
                property(from, "ladybom:lockfile"),
                property(to, "ladybom:lockfile")
            );
            if from["name"] == "b"
                && property(from, "ladybom:lockfile") == Some("other/package-lock.json")
            {
                assert_eq!(
                    property(to, "ladybom:context"),
                    Some("node_modules/b/node_modules/d")
                );
            }
        }
    }
    Ok(())
}

#[test]
fn local_cargo_edges_keep_inventory_identity_without_fabricated_purls() -> Result {
    let root = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("local"))?;
    std::fs::write(root.path().join("Cargo.toml"), "[package]\nname='app'\nversion='1.0.0'\n[workspace]\nmembers=['local']\n[dependencies]\nlocal={path='local'}\n")?;
    std::fs::write(
        root.path().join("local/Cargo.toml"),
        "[package]\nname='local'\nversion='1.0.0'\n",
    )?;
    std::fs::write(root.path().join("Cargo.lock"), "version=4\n[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['local']\n[[package]]\nname='local'\nversion='1.0.0'\n")?;
    let report = ladybom::scan_project(root.path())?;
    let bom = exported(&report)?;
    let components = bom["components"].as_array().ok_or("components")?;
    let local = components
        .iter()
        .find(|c| c["name"] == "local")
        .ok_or("local")?;
    assert!(local.get("purl").is_none());
    assert!(components.iter().all(|c| c.get("purl").is_none()));
    let original_project = report
        .projects
        .iter()
        .find(|p| !p.components.is_empty())
        .ok_or("owner")?;
    let original_local = original_project
        .components
        .iter()
        .find(|c| c.name == "local")
        .ok_or("local inventory")?;
    assert_eq!(
        local["bom-ref"],
        cyclonedx::component_reference(original_project, original_local)?
    );
    let application = &bom["metadata"]["component"]["bom-ref"];
    assert!(bom["dependencies"]
        .as_array()
        .ok_or("dependencies")?
        .iter()
        .any(|d| d["ref"] == *application
            && d["dependsOn"]
                .as_array()
                .is_some_and(|targets| targets.contains(&local["bom-ref"]))));
    Ok(())
}

#[test]
fn graph_projection_failure_keeps_distinct_inventory_with_explicit_unknown_relations() -> Result {
    let mut report = report()?;
    let owner = report
        .projects
        .iter_mut()
        .find(|p| p.ecosystem == "rust")
        .ok_or("rust")?;
    let mut duplicate = owner
        .components
        .iter()
        .find(|c| c.purl.is_some())
        .ok_or("registry component")?
        .clone();
    duplicate.context = "second occurrence".into();
    owner.components.push(duplicate);
    let expected: usize = report.projects.iter().map(|p| p.components.len()).sum();
    let bom = exported(&report)?;
    assert_eq!(
        bom["components"].as_array().ok_or("components")?.len(),
        expected
    );
    assert_eq!(bom["metadata"]["component"]["type"], "application");
    assert_eq!(bom["dependencies"], json!([]));
    assert_eq!(bom["compositions"][0]["aggregate"], "unknown");
    let limitations: Vec<String> =
        serde_json::from_str(property(&bom, "ladybom:graph:limitations").ok_or("limitations")?)?;
    assert!(limitations.iter().any(|limit| limit.contains("Projection")));
    Ok(())
}

#[test]
fn sensitive_distribution_urls_are_not_promoted_to_standard_references() -> Result {
    let mut report = diamond()?;
    report.projects[0].components[0].artifacts = [
        "https://user:password@example.test/archive",
        "https://example.test/archive?token=secret",
        "https://example.test/archive#secret",
    ]
    .into_iter()
    .map(|url| ladybom::Artifact {
        url: url.into(),
        hash: None,
    })
    .collect();
    let bom = exported(&report)?;
    let a = bom["components"]
        .as_array()
        .ok_or("components")?
        .iter()
        .find(|c| c["name"] == "a")
        .ok_or("a")?;
    assert!(a.get("externalReferences").is_none());
    assert!(property(a, "ladybom:artifacts").is_some());
    Ok(())
}

#[test]
fn default_public_projection_omits_opaque_evidence_and_fingerprints_it_per_component() -> Result {
    let mut report = report()?;
    let component = &mut report.projects[0].components[1];
    component.context = "SECRET_CONTEXT".into();
    component.source = json!({"registry":"https://pypi.org/simple","credential":"SECRET_SOURCE"});
    component.metadata["secret"] = json!({"nested":["SECRET_METADATA"]});
    component.artifacts[0].url = "https://example.test/SECRET_URL".into();
    component.purl = Some("pkg:pypi/idna@3.10?repository_url=SECRET_PURL".into());
    report.projects[0].workspace = json!({"secret":"SECRET_WORKSPACE"});
    report.diagnostics.push(ladybom::Diagnostic {
        code: "test".into(),
        file: "private/SECRET_PATH".into(),
        message: "SECRET_DIAGNOSTIC".into(),
        blocking: false,
    });
    let mut bytes = Vec::new();
    cyclonedx::write_json(&report, &mut bytes)?;
    assert!(!String::from_utf8_lossy(&bytes).contains("SECRET_"));
    let public: Value = serde_json::from_slice(&bytes)?;
    let idna = public["components"]
        .as_array()
        .ok_or("components")?
        .iter()
        .find(|c| c["name"] == "idna")
        .ok_or("idna")?;
    assert!(idna.get("purl").is_none());
    assert!(idna.get("externalReferences").is_none());
    assert_eq!(
        idna["bom-ref"],
        cyclonedx::component_reference(&report.projects[0], &report.projects[0].components[1])?
    );
    assert_eq!(
        property(idna, "ladybom:coverage:composition"),
        Some("unknown")
    );
    assert_eq!(property(idna, "ladybom:export_profile"), Some("public"));
    assert!(property(idna, "ladybom:provenance:component_sha256").is_some_and(|s| s.len() == 64));
    assert!(property(idna, "ladybom:coverage:sha256").is_some_and(|s| s.len() == 64));
    report.projects[0].components[1].metadata["secret"] = json!("SECRET_CHANGED");
    let mut changed = Vec::new();
    cyclonedx::write_json(&report, &mut changed)?;
    assert_ne!(
        public["serialNumber"],
        serde_json::from_slice::<Value>(&changed)?["serialNumber"]
    );
    Ok(())
}

#[test]
fn public_identity_is_not_silently_sanitized() -> Result {
    let mut report = report()?;
    report.projects[0].components[1].name = "https://user:SECRET@example.test/package".into();
    report.projects[0].components[1].purl = None;
    let mut bytes = Vec::new();
    assert!(cyclonedx::write_json(&report, &mut bytes).is_err());
    assert!(bytes.is_empty());
    Ok(())
}

#[test]
fn detailed_profile_is_explicit_and_has_a_distinct_content_bound_serial() -> Result {
    let mut report = report()?;
    report.projects[0].components[1].metadata["secret"] = json!("PRIVATE_REVIEW");
    let private = exported(&report)?;
    let mut bytes = Vec::new();
    cyclonedx::write_json(&report, &mut bytes)?;
    let public: Value = serde_json::from_slice(&bytes)?;
    assert!(serde_json::to_string(&private)?.contains("PRIVATE_REVIEW"));
    assert!(!serde_json::to_string(&public)?.contains("PRIVATE_REVIEW"));
    assert_ne!(public["serialNumber"], private["serialNumber"]);
    assert_eq!(public["serialNumber"], cyclonedx::document_serial(&report)?);
    assert_eq!(
        private["serialNumber"],
        cyclonedx::document_serial_with_profile(
            &report,
            cyclonedx::ExportProfile::PrivateDetailed
        )?
    );
    assert_eq!(
        public["components"]
            .as_array()
            .ok_or("public")?
            .iter()
            .map(|c| &c["bom-ref"])
            .collect::<Vec<_>>(),
        private["components"]
            .as_array()
            .ok_or("private")?
            .iter()
            .map(|c| &c["bom-ref"])
            .collect::<Vec<_>>()
    );
    Ok(())
}
