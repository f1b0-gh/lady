use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Command, Output},
};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;
const DATE: &str = "2026-11-04T12:00:00Z";

fn cli(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ladybom"));
    command
        .env_clear()
        .env("PATH", "")
        .args(["vuln"])
        .args(args);
    command
}
fn json_output(
    output: &Output,
    code: i32,
) -> std::result::Result<Value, Box<dyn std::error::Error>> {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn advisory(id: &str, version: &str) -> Value {
    json!({"schema_version":"1.6.0","id":id,"modified":DATE,"published":DATE,"affected":[{"package":{"ecosystem":"npm","name":"is-number"},"versions":[version]}]})
}
fn report(path: &Path) -> Result {
    let project = tempfile::tempdir()?;
    std::fs::write(project.path().join("package.json"), json!({"name":"synthetic","version":"1.0.0","dependencies":{"is-number":"7.0.0"},"scripts":{"preinstall":"touch PROJECT_EXECUTED"}}).to_string())?;
    std::fs::write(project.path().join("package-lock.json"), json!({"name":"synthetic","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"synthetic","version":"1.0.0","dependencies":{"is-number":"7.0.0"}},"node_modules/is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"}}}).to_string())?;
    let report = ladybom::scan_project(project.path())?;
    assert!(report.complete);
    std::fs::write(path, serde_json::to_vec(&report)?)?;
    assert!(!project.path().join("PROJECT_EXECUTED").exists());
    Ok(())
}
fn import(input: &Path, output: &Path, complete: bool) -> std::io::Result<Output> {
    let mut command = cli(&[
        "import",
        "--source",
        "synthetic-local",
        "--fetched-at",
        DATE,
        "--ecosystem",
        "npm",
    ]);
    command
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output);
    if complete {
        command.arg("--complete");
    }
    command.output()
}
fn assess(command: &str, report: &Path, snapshot: &Path) -> Command {
    let mut command = cli(&[command, "--as-of", DATE]);
    command
        .arg("--report")
        .arg(report)
        .arg("--snapshot")
        .arg(snapshot);
    command
}

#[test]
fn offline_import_assess_check_and_vex_recompute_from_inputs() -> Result {
    let dir = tempfile::tempdir()?;
    let report_path = dir.path().join("report.json");
    let input = dir.path().join("advisories.json");
    let snapshot = dir.path().join("snapshot.json");
    report(&report_path)?;
    std::fs::write(
        &input,
        json!([advisory("OSV-Z", "7.0.0"), advisory("OSV-A", "8.0.0")]).to_string(),
    )?;
    let imported = import(&input, &snapshot, true)?;
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    assert!(imported.stdout.is_empty());
    let extra = dir.path().join("extra.json");
    std::fs::write(&extra, advisory("OSV-EXTRA", "9.0.0").to_string())?;
    let combined = dir.path().join("combined.json");
    let combined_result = cli(&[
        "import",
        "--source",
        "local",
        "--fetched-at",
        DATE,
        "--ecosystem",
        "npm",
    ])
    .arg("--input")
    .arg(&input)
    .arg("--input")
    .arg(&extra)
    .arg("--output")
    .arg(&combined)
    .output()?;
    assert!(combined_result.status.success());
    let combined_json: Value = serde_json::from_slice(&std::fs::read(&combined)?)?;
    assert_eq!(
        combined_json["advisories"]
            .as_array()
            .ok_or("advisories")?
            .len(),
        3
    );
    let stored: Value = serde_json::from_slice(&std::fs::read(&snapshot)?)?;
    assert_eq!(stored["schema_version"], 1);
    assert_eq!(stored["advisories"][0]["id"], "OSV-A");
    let assessment = json_output(&assess("assess", &report_path, &snapshot).output()?, 0)?;
    assert_eq!(assessment["complete"], true);
    assert_eq!(
        assessment["findings"].as_array().ok_or("findings")?.len(),
        1
    );
    let rejected = json_output(&assess("check", &report_path, &snapshot).output()?, 2)?;
    assert_eq!(rejected["allowed"], false);
    let vex = json_output(&assess("vex", &report_path, &snapshot).output()?, 0)?;
    assert_eq!(vex["bomFormat"], "CycloneDX");
    assert_eq!(vex["specVersion"], "1.5");
    assert_eq!(vex["vulnerabilities"][0]["analysis"]["state"], "in_triage");
    assert!(vex["vulnerabilities"][0]["affects"][0]["ref"]
        .as_str()
        .ok_or("BOM-Link")?
        .starts_with("urn:cdx:"));
    let again = assess("assess", &report_path, &snapshot).output()?;
    assert_eq!(serde_json::from_slice::<Value>(&again.stdout)?, assessment);
    Ok(())
}

#[test]
fn incomplete_empty_or_stale_sources_do_not_pass_policy() -> Result {
    let dir = tempfile::tempdir()?;
    let report_path = dir.path().join("report.json");
    let input = dir.path().join("advisories.json");
    let snapshot = dir.path().join("snapshot.json");
    report(&report_path)?;
    std::fs::write(&input, "[]")?;
    assert!(import(&input, &snapshot, false)?.status.success());
    let assessment = json_output(&assess("assess", &report_path, &snapshot).output()?, 2)?;
    assert_eq!(assessment["complete"], false);
    assert_eq!(
        json_output(&assess("check", &report_path, &snapshot).output()?, 2)?["allowed"],
        false
    );
    let complete = dir.path().join("complete.json");
    assert!(import(&input, &complete, true)?.status.success());
    let allowed = json_output(&assess("check", &report_path, &complete).output()?, 0)?;
    assert_eq!(allowed["allowed"], true);
    let stale = cli(&["assess", "--as-of", "2026-12-04T12:00:00Z"])
        .arg("--report")
        .arg(&report_path)
        .arg("--snapshot")
        .arg(&complete)
        .output()?;
    assert_eq!(json_output(&stale, 2)?["complete"], false);
    Ok(())
}

#[test]
fn imports_are_local_bounded_and_published_without_overwrite() -> Result {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("advisory.json");
    let output = dir.path().join("snapshot.json");
    std::fs::write(&input, advisory("OSV-ONE", "7.0.0").to_string())?;
    assert!(import(&input, &output, true)?.status.success());
    let bytes = std::fs::read(&output)?;
    assert!(!import(&input, &output, true)?.status.success());
    assert_eq!(std::fs::read(&output)?, bytes);
    let duplicate = dir.path().join("duplicate.json");
    let result = cli(&[
        "import",
        "--source",
        "local",
        "--fetched-at",
        DATE,
        "--ecosystem",
        "npm",
    ])
    .arg("--input")
    .arg(&input)
    .arg("--input")
    .arg(&input)
    .arg("--output")
    .arg(&duplicate)
    .output()?;
    assert!(!result.status.success());
    assert!(!duplicate.exists());
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&input, &link)?;
    assert!(
        !import(&link, &dir.path().join("linked-output.json"), true)?
            .status
            .success()
    );
    let link_dir = dir.path().join("linked-dir");
    std::os::unix::fs::symlink(dir.path(), &link_dir)?;
    assert!(!import(
        &link_dir.join("advisory.json"),
        &dir.path().join("ancestor-output.json"),
        true
    )?
    .status
    .success());
    assert!(!import(&input, &link_dir.join("new.json"), true)?
        .status
        .success());
    std::fs::create_dir(dir.path().join("child"))?;
    assert!(!import(
        &dir.path().join("child/../advisory.json"),
        &dir.path().join("traversal.json"),
        true
    )?
    .status
    .success());
    let final_link = dir.path().join("output-link.json");
    std::os::unix::fs::symlink(&input, &final_link)?;
    let original = std::fs::read(&input)?;
    assert!(!import(&input, &final_link, true)?.status.success());
    assert_eq!(std::fs::read(&input)?, original);
    let huge = dir.path().join("huge.json");
    std::fs::File::create(&huge)?.set_len(64 * 1024 * 1024 + 1)?;
    assert!(!import(&huge, &dir.path().join("huge-output.json"), true)?
        .status
        .success());
    let result = cli(&[
        "import",
        "--input",
        "https://example.invalid/osv.json",
        "--source",
        "local",
        "--fetched-at",
        DATE,
        "--ecosystem",
        "npm",
    ])
    .arg("--output")
    .arg(dir.path().join("remote.json"))
    .output()?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    Ok(())
}

#[test]
fn explicit_evaluation_date_is_required_and_assess_does_not_clobber() -> Result {
    for command in ["assess", "check", "vex"] {
        let output = cli(&[command, "--report", "missing", "--snapshot", "missing"]).output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--as-of"));
        assert!(output.stdout.is_empty());
    }
    let dir = tempfile::tempdir()?;
    let report_path = dir.path().join("report.json");
    let input = dir.path().join("advisory.json");
    let snapshot = dir.path().join("snapshot.json");
    report(&report_path)?;
    std::fs::write(&input, "[]")?;
    assert!(import(&input, &snapshot, true)?.status.success());
    let output = dir.path().join("assessment.json");
    let emitted = assess("assess", &report_path, &snapshot)
        .arg("--output")
        .arg(&output)
        .output()?;
    assert!(emitted.status.success());
    assert!(emitted.stdout.is_empty());
    let bytes = std::fs::read(&output)?;
    assert!(!assess("assess", &report_path, &snapshot)
        .arg("--output")
        .arg(&output)
        .output()?
        .status
        .success());
    assert_eq!(std::fs::read(&output)?, bytes);
    Ok(())
}

#[test]
fn decisions_and_risk_acceptances_are_bound_and_expire() -> Result {
    let dir = tempfile::tempdir()?;
    let report_path = dir.path().join("report.json");
    let input = dir.path().join("advisory.json");
    let snapshot = dir.path().join("snapshot.json");
    report(&report_path)?;
    std::fs::write(&input, advisory("OSV-ONE", "7.0.0").to_string())?;
    assert!(import(&input, &snapshot, true)?.status.success());
    let assessment = json_output(&assess("assess", &report_path, &snapshot).output()?, 0)?;
    let decisions_path = dir.path().join("decisions.json");
    let decisions = json!({"schema_version":1,"report_digest":assessment["report_digest"],"snapshot_digest":assessment["snapshot_digest"],"decisions":[{"finding_id":assessment["findings"][0]["id"],"state":"false_positive","justification":null,"detail":"Synthetic qualification with independently reviewed evidence","author":"fixture-reviewer","evidence":["fixture:test-proof"],"issued_at":"2026-11-04T11:00:00Z","expires_at":"2026-11-05T12:00:00Z"}]});
    std::fs::write(&decisions_path, decisions.to_string())?;
    assert_eq!(
        json_output(
            &assess("check", &report_path, &snapshot)
                .arg("--decisions")
                .arg(&decisions_path)
                .output()?,
            0
        )?["allowed"],
        true
    );
    let duplicate = decisions.to_string().replace(
        "\"state\":\"false_positive\"",
        "\"state\":\"exploitable\",\"state\":\"false_positive\"",
    );
    std::fs::write(&decisions_path, duplicate)?;
    let refused = assess("check", &report_path, &snapshot)
        .arg("--decisions")
        .arg(&decisions_path)
        .output()?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let mut tampered = decisions.clone();
    tampered["report_digest"] = json!("0".repeat(64));
    std::fs::write(&decisions_path, tampered.to_string())?;
    let refused = assess("check", &report_path, &snapshot)
        .arg("--decisions")
        .arg(&decisions_path)
        .output()?;
    assert!(!refused.status.success());
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("\"allowed\":true"));
    let refused = assess("vex", &report_path, &snapshot)
        .arg("--decisions")
        .arg(&decisions_path)
        .output()?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let policy_path = dir.path().join("policy.json");
    let mut policy = json!({"schema_version":1,"max_age_seconds":604800,"exceptions":[{"finding_id":assessment["findings"][0]["id"],"report_digest":assessment["report_digest"],"snapshot_digest":assessment["snapshot_digest"],"author":"fixture-reviewer","reason":"Temporary synthetic risk acceptance","evidence":["fixture:acceptance"],"issued_at":"2026-11-03T12:00:00Z","expires_at":"2026-11-05T12:00:00Z"}]});
    std::fs::write(&policy_path, policy.to_string())?;
    assert_eq!(
        json_output(
            &assess("check", &report_path, &snapshot)
                .arg("--policy")
                .arg(&policy_path)
                .output()?,
            0
        )?["allowed"],
        true
    );
    let duplicate = policy.to_string().replace(
        "\"expires_at\":",
        "\"expires_at\":\"2026-11-03T13:00:00Z\",\"expires_at\":",
    );
    std::fs::write(&policy_path, duplicate)?;
    let refused = assess("check", &report_path, &snapshot)
        .arg("--policy")
        .arg(&policy_path)
        .output()?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    policy["exceptions"][0]["expires_at"] = json!("2026-11-04T11:00:00Z");
    std::fs::write(&policy_path, policy.to_string())?;
    let expired = assess("check", &report_path, &snapshot)
        .arg("--policy")
        .arg(&policy_path)
        .output()?;
    assert!(!expired.status.success());
    assert!(!String::from_utf8_lossy(&expired.stdout).contains("\"allowed\":true"));
    Ok(())
}

#[test]
fn aggregate_import_budget_and_auxiliary_documents_are_bounded() -> Result {
    use std::io::Write;
    let dir = tempfile::tempdir()?;
    let large = dir.path().join("large.json");
    let mut file = std::fs::File::create(&large)?;
    file.write_all(b"[]")?;
    let spaces = vec![b' '; 1024 * 1024];
    for _ in 0..33 {
        file.write_all(&spaces)?;
    }
    drop(file);
    let output = dir.path().join("budget.json");
    let refused = cli(&[
        "import",
        "--source",
        "local",
        "--fetched-at",
        DATE,
        "--ecosystem",
        "npm",
    ])
    .arg("--input")
    .arg(&large)
    .arg("--input")
    .arg(&large)
    .arg("--output")
    .arg(&output)
    .output()?;
    assert!(!refused.status.success());
    assert!(!output.exists());
    let too_many = dir.path().join("too-many.json");
    std::fs::write(&too_many, json!(vec![json!({}); 100_001]).to_string())?;
    let refused = import(&too_many, &output, true)?;
    assert!(!refused.status.success());
    assert!(!output.exists());
    let report_path = dir.path().join("report.json");
    let input = dir.path().join("advisory.json");
    let snapshot = dir.path().join("snapshot.json");
    report(&report_path)?;
    std::fs::write(&input, advisory("OSV-ONE", "7.0.0").to_string())?;
    assert!(import(&input, &snapshot, true)?.status.success());
    let signals = dir.path().join("signals.json");
    std::fs::write(&signals, json!({"schema_version":1,"source":"local-reviewed-signals","fetched_at":DATE,"entries":[{"id":"OSV-ONE","known_exploited":true,"epss":0.9}]}).to_string())?;
    let checked = json_output(
        &assess("check", &report_path, &snapshot)
            .arg("--signals")
            .arg(&signals)
            .output()?,
        2,
    )?;
    assert_eq!(checked["allowed"], false);
    std::fs::File::create(&signals)?.set_len(4 * 1024 * 1024 + 1)?;
    let refused = assess("check", &report_path, &snapshot)
        .arg("--signals")
        .arg(&signals)
        .output()?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    Ok(())
}

fn duplicate_osv_records() -> [String; 2] {
    [
        format!(
            r#"{{"id":"OSV-DUPLICATE","modified":"{DATE}","affected":[{{"package":{{"ecosystem":"npm","name":"is-number"}},"versions":["7.0.0"]}}],"affected":[]}}"#
        ),
        format!(
            r#"{{"id":"OSV-DUPLICATE","modified":"{DATE}","affected":[{{"package":{{"ecosystem":"npm","name":"is-number"}},"versions":["7.0.0"],"versions":["8.0.0"]}}]}}"#
        ),
    ]
}

#[test]
fn imports_reject_nested_duplicate_osv_keys() -> Result {
    let dir = tempfile::tempdir()?;
    for (index, record) in duplicate_osv_records().iter().enumerate() {
        let input = dir.path().join(format!("duplicate-{index}.json"));
        let snapshot = dir.path().join(format!("snapshot-{index}.json"));
        std::fs::write(&input, record)?;
        let refused = import(&input, &snapshot, true)?;
        assert!(
            !refused.status.success(),
            "duplicate OSV keys must fail closed"
        );
        assert!(refused.stdout.is_empty());
        assert!(!snapshot.exists());
    }
    Ok(())
}

#[test]
fn raw_snapshots_reject_nested_duplicate_osv_keys() -> Result {
    let dir = tempfile::tempdir()?;
    let report_path = dir.path().join("report.json");
    report(&report_path)?;
    for (index, record) in duplicate_osv_records().iter().enumerate() {
        let snapshot = dir.path().join(format!("raw-snapshot-{index}.json"));
        let envelope = json!({"schema_version":1,"source":"synthetic-local","fetched_at":DATE,"complete":true,"ecosystems":["npm"],"advisories":[]}).to_string();
        let bytes = envelope.replace("\"advisories\":[]", &format!("\"advisories\":[{record}]"));
        std::fs::write(&snapshot, bytes)?;
        for command in ["assess", "check", "vex"] {
            let refused = assess(command, &report_path, &snapshot).output()?;
            assert!(
                !refused.status.success(),
                "{command} accepted duplicate OSV keys"
            );
            assert!(
                refused.stdout.is_empty(),
                "{command} emitted a derived result"
            );
        }
    }
    Ok(())
}

#[test]
fn snapshots_with_more_than_ten_thousand_advisories_remain_readable() -> Result {
    let dir = tempfile::tempdir()?;
    let report_path = dir.path().join("report.json");
    report(&report_path)?;
    let input = dir.path().join("many-advisories.json");
    let snapshot = dir.path().join("snapshot.json");
    let records: Vec<_> = (0..10_001)
        .map(|index| advisory(&format!("OSV-BULK-{index:05}"), "8.0.0"))
        .collect();
    std::fs::write(&input, serde_json::to_vec(&records)?)?;
    let imported = import(&input, &snapshot, true)?;
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let assessment = json_output(&assess("assess", &report_path, &snapshot).output()?, 0)?;
    assert_eq!(assessment["complete"], true);
    assert!(assessment["findings"]
        .as_array()
        .ok_or("findings")?
        .is_empty());
    Ok(())
}

#[test]
fn local_vex_profile_embeds_components_and_keeps_default_bom_links() -> Result {
    let dir = tempfile::tempdir()?;
    let report_path = dir.path().join("report.json");
    let input = dir.path().join("advisories.json");
    let snapshot = dir.path().join("snapshot.json");
    report(&report_path)?;
    std::fs::write(&input, advisory("GHSA-test-test-test", "7.0.0").to_string())?;
    assert!(import(&input, &snapshot, true)?.status.success());
    let default = json_output(&assess("vex", &report_path, &snapshot).output()?, 0)?;
    assert!(default["vulnerabilities"][0]["affects"][0]["ref"]
        .as_str()
        .ok_or("ref")?
        .starts_with("urn:cdx:"));
    let local = json_output(
        &assess("vex", &report_path, &snapshot)
            .args(["--profile", "local-components"])
            .output()?,
        0,
    )?;
    assert_eq!(local["components"].as_array().ok_or("components")?.len(), 1);
    assert_eq!(local["components"][0]["purl"], "pkg:npm/is-number@7.0.0");
    assert_eq!(
        local["components"][0]["bom-ref"],
        local["vulnerabilities"][0]["affects"][0]["ref"]
    );
    assert_ne!(default["serialNumber"], local["serialNumber"]);
    Ok(())
}

#[test]
fn public_vex_cli_redacts_reviews_and_private_profile_is_explicit() -> Result {
    let dir = tempfile::tempdir()?;
    let report_path = dir.path().join("report.json");
    let input = dir.path().join("advisory.json");
    let snapshot = dir.path().join("snapshot.json");
    report(&report_path)?;
    let mut native: Value = serde_json::from_slice(&std::fs::read(&report_path)?)?;
    native["projects"][0]["components"][0]["metadata"]["privateNote"] =
        json!("VEX_CLI_SECRET_NATIVE");
    std::fs::write(&report_path, serde_json::to_vec(&native)?)?;
    std::fs::write(&input, advisory("OSV-ONE", "7.0.0").to_string())?;
    assert!(import(&input, &snapshot, true)?.status.success());
    let a = json_output(&assess("assess", &report_path, &snapshot).output()?, 0)?;
    let decisions_path = dir.path().join("decisions.json");
    std::fs::write(&decisions_path,json!({"schema_version":1,"report_digest":a["report_digest"],"snapshot_digest":a["snapshot_digest"],"decisions":[{"finding_id":a["findings"][0]["id"],"state":"not_affected","justification":"code_not_reachable","detail":"VEX_CLI_SECRET_DETAIL","author":"VEX_CLI_SECRET_AUTHOR","evidence":["https://private.test/VEX_CLI_SECRET_EVIDENCE"],"issued_at":"2026-11-04T11:00:00Z","expires_at":"2026-11-05T12:00:00Z"}]}).to_string())?;
    let export = |profile: &str| {
        assess("vex", &report_path, &snapshot)
            .args(["--profile", "local-components", "--export-profile", profile])
            .arg("--decisions")
            .arg(&decisions_path)
            .output()
    };
    let public = json_output(&export("public")?, 0)?;
    let private = json_output(&export("private-detailed")?, 0)?;
    assert!(!serde_json::to_string(&public)?.contains("VEX_CLI_SECRET"));
    assert!(serde_json::to_string(&private)?.contains("VEX_CLI_SECRET_AUTHOR"));
    assert_ne!(public["serialNumber"], private["serialNumber"]);
    assert_eq!(
        public["vulnerabilities"][0]["analysis"]["state"],
        "not_affected"
    );
    assert_eq!(
        public["components"][0]["bom-ref"],
        private["components"][0]["bom-ref"]
    );
    Ok(())
}
