use ladyshell::{deps, files, sources};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture {
    temp: tempfile::TempDir,
    project: PathBuf,
    report: PathBuf,
    selection: sources::Sources,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let project = temp.path().join("project");
        fs::create_dir(&project)?;
        fs::create_dir(project.join("nested"))?;
        fs::write(project.join("package.json"), br#"{"name":"fixture","version":"1.0.0","scripts":{"install":"touch NEVER_EXECUTE"},"dependencies":{"left-pad":"1.3.0"}}"#)?;
        let report = temp.path().join("ladybom.json");
        let selection = sources::Sources {
            include: vec!["package.json".into(), "nested".into()],
            exclude: vec![],
        };
        let snapshot = sources::snapshot(&project, &selection, None)?;
        let value = deps::scan_snapshot(&project, &snapshot)?;
        files::publish_json(&report, &value, false)?;
        Ok(Self {
            temp,
            project,
            report,
            selection,
        })
    }
    fn admit(
        &self,
        path: Option<&Path>,
    ) -> ladyshell::error::Result<(deps::Report, Option<String>)> {
        let snapshot = sources::snapshot(&self.project, &self.selection, None)?;
        deps::input::verified_report(&self.project, &self.selection, &snapshot, path)
    }
    fn replace(&self, change: impl FnOnce(&mut Value)) -> TestResult {
        let mut value: Value = serde_json::from_slice(&fs::read(&self.report)?)?;
        change(&mut value);
        fs::write(&self.report, serde_json::to_vec(&value)?)?;
        Ok(())
    }
}
#[test]
fn live_and_external_reports_share_the_canonical_model_without_running_code() -> TestResult {
    let f = Fixture::new()?;
    let (live, digest) = f.admit(None)?;
    assert!(digest.is_none());
    let (external, digest) = f.admit(Some(&f.report))?;
    assert_eq!(
        serde_json::to_value(live)?,
        serde_json::to_value(&external)?
    );
    assert_eq!(digest, Some(files::hash(&serde_json::to_vec(&external)?)));
    assert!(!f.project.join("NEVER_EXECUTE").exists());
    Ok(())
}
#[test]
fn stale_reports_and_new_manifests_cannot_self_attest_coverage() -> TestResult {
    let f = Fixture::new()?;
    fs::write(
        f.project.join("nested/package.json"),
        br#"{"name":"omitted","version":"1.0.0"}"#,
    )?;
    assert!(f.admit(Some(&f.report)).is_err());
    fs::remove_file(f.project.join("nested/package.json"))?;
    fs::write(
        f.project.join("package.json"),
        br#"{"name":"changed","version":"2.0.0"}"#,
    )?;
    assert!(f.admit(Some(&f.report)).is_err());
    Ok(())
}
#[test]
fn authentic_hashes_do_not_authorize_forged_packages_flags_or_paths() -> TestResult {
    for change in 0..7 {
        let f = Fixture::new()?;
        f.replace(|v| match change {
            0 => v["projects"] = json!([]),
            1 => v["complete"] = json!(false),
            2 => v["projects"][0]["requirements"][0]["name"] = json!("forged"),
            3 => v["projects"][0]["manifest"] = json!("../outside/package.json"),
            4 => v["inputs"] = json!({}),
            5 => v["schema_version"] = json!(999),
            _ => v["allowed_hosts"] = json!(["attacker.invalid"]),
        })?;
        assert!(f.admit(Some(&f.report)).is_err(), "mutation {change}");
    }
    Ok(())
}
#[test]
fn report_symlinks_duplicate_keys_and_oversized_documents_are_rejected() -> TestResult {
    let f = Fixture::new()?;
    let link = f.temp.path().join("linked.json");
    std::os::unix::fs::symlink(&f.report, &link)?;
    assert!(f.admit(Some(&link)).is_err());
    fs::write(&f.report, br#"{"schema_version":1,"schema_version":1,"complete":true,"inputs":{},"projects":[],"diagnostics":[]}"#)?;
    assert!(f.admit(Some(&f.report)).is_err());
    fs::File::create(&f.report)?.set_len(32 * 1024 * 1024 + 1)?;
    assert!(f.admit(Some(&f.report)).is_err());
    Ok(())
}
#[test]
fn a_changed_source_selection_is_rejected_even_for_the_live_mode() -> TestResult {
    let f = Fixture::new()?;
    let snapshot = sources::snapshot(&f.project, &f.selection, None)?;
    fs::write(f.project.join("nested/package.json"), b"{}")?;
    assert!(deps::input::verified_report(&f.project, &f.selection, &snapshot, None).is_err());
    Ok(())
}

#[test]
fn old_report_versions_require_explicit_regeneration() -> TestResult {
    let f = Fixture::new()?;
    f.replace(|v| v["schema_version"] = json!(1))?;
    let error = f
        .admit(Some(&f.report))
        .err()
        .ok_or("old report accepted")?;
    assert!(error.to_string().contains("régénérer"), "{error}");
    Ok(())
}
