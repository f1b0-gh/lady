use ladybom::{
    deps::{
        self, graph,
        usage::{self, UsageStatus},
    },
    files,
};
use serde_json::json;
use std::{fs, path::Path};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn write(root: &Path, path: &str, text: &str) -> TestResult {
    let path = root.join(path);
    fs::create_dir_all(path.parent().ok_or("parent")?)?;
    fs::write(path, text)?;
    Ok(())
}
fn rust(root: &Path, extra: &str, source: &str) -> TestResult {
    write(root, "sdk/Cargo.toml", &format!("[package]\nname='demo'\nversion='1.0.0'\n[dependencies]\nrenamed={{package='actual-name',version='1'}}\nunused='1'\n[dev-dependencies]\ntempfile='1'\n{extra}"))?;
    write(root, "sdk/Cargo.lock", "version=4\n[[package]]\nname='actual-name'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n[[package]]\nname='unused'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n[[package]]\nname='tempfile'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n")?;
    write(root, "sdk/src/lib.rs", source)
}
fn analyze(root: &Path, manifest: &str) -> Result<usage::UsageReport, Box<dyn std::error::Error>> {
    let graph = graph::project(deps::scan_project(root)?)?;
    Ok(usage::analyze(root, &graph, &[manifest.into()])?)
}
fn status(
    report: &usage::UsageReport,
    name: &str,
) -> Result<UsageStatus, Box<dyn std::error::Error>> {
    Ok(report
        .findings
        .iter()
        .find(|f| f.declaration.name == name)
        .ok_or("finding")?
        .status
        .clone())
}

#[test]
fn dependency_referenced_only_in_credentials_module_is_not_a_prune_candidate() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "pub mod credentials;")?;
    write(
        root.path(),
        "sdk/src/credentials/mod.rs",
        "pub fn authenticate() { renamed::run(); }",
    )?;
    let report = analyze(root.path(), "sdk/Cargo.toml")?;
    assert_eq!(status(&report, "renamed")?, UsageStatus::Referenced);
    assert!(report.inputs.contains_key("sdk/src/credentials/mod.rs"));
    Ok(())
}

#[test]
fn credentials_project_directory_is_inventoried_and_analyzed() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "pub fn authenticate() { renamed::run(); }")?;
    fs::rename(root.path().join("sdk"), root.path().join("credentials"))?;
    let report = analyze(root.path(), "credentials/Cargo.toml")?;
    assert_eq!(status(&report, "renamed")?, UsageStatus::Referenced);
    assert!(ladybom::inventory::inventory(root.path())?.contains_key("credentials/src/lib.rs"));
    Ok(())
}

#[test]
fn credentials_files_and_links_do_not_enter_project_inventories() -> TestResult {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    fs::write(root.path().join("credentials"), b"synthetic token")?;
    assert!(deps::project_sources(root.path())?.include.is_empty());
    assert!(ladybom::inventory::inventory(root.path())?.is_empty());
    fs::remove_file(root.path().join("credentials"))?;
    fs::write(
        outside.path().join("Cargo.toml"),
        "[package]\nname='outside'",
    )?;
    std::os::unix::fs::symlink(outside.path(), root.path().join("credentials"))?;
    assert!(deps::project_sources(root.path())?.include.is_empty());
    assert!(ladybom::inventory::inventory(root.path())?.is_empty());
    Ok(())
}

#[test]
fn cargo_explicit_targets_outside_crate_and_aliases_are_referenced() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(
        root.path(),
        "[[test]]\nname='saga'\npath='../demos/saga_bridge_tests.rs'",
        "pub fn call() { renamed::run(); } // unused::run();\n",
    )?;
    write(
        root.path(),
        "demos/saga_bridge_tests.rs",
        "#[test] fn bridge() { tempfile::tempdir(); }",
    )?;
    let report = analyze(root.path(), "sdk/Cargo.toml")?;
    assert_eq!(status(&report, "renamed")?, UsageStatus::Referenced);
    assert_eq!(status(&report, "tempfile")?, UsageStatus::Referenced);
    assert_eq!(status(&report, "unused")?, UsageStatus::Candidate);
    assert_eq!(
        report.inputs["demos/saga_bridge_tests.rs"].sha256,
        files::hash(b"#[test] fn bridge() { tempfile::tempdir(); }")
    );
    let alias = report
        .findings
        .iter()
        .find(|f| f.declaration.name == "renamed")
        .ok_or("alias")?;
    assert_eq!(alias.targets[0].purl, "pkg:cargo/actual-name@1.0.0");
    assert_eq!(alias.root_ids.len(), 1);
    assert!(!report.complete);
    Ok(())
}

#[test]
fn cargo_path_and_include_sources_are_followed_and_missing_sources_are_unknown() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "#[path = \"../../shared/module.rs\"] mod support;\ninclude!(\"../../shared/included.rs\");")?;
    write(
        root.path(),
        "shared/module.rs",
        "pub fn call() { renamed::run(); }",
    )?;
    write(
        root.path(),
        "shared/included.rs",
        "fn temp() { tempfile::tempdir(); }",
    )?;
    let report = analyze(root.path(), "sdk/Cargo.toml")?;
    assert_eq!(status(&report, "renamed")?, UsageStatus::Referenced);
    assert_eq!(status(&report, "tempfile")?, UsageStatus::Referenced);
    fs::remove_file(root.path().join("shared/included.rs"))?;
    assert_eq!(
        status(&analyze(root.path(), "sdk/Cargo.toml")?, "unused")?,
        UsageStatus::Unknown
    );
    Ok(())
}

#[test]
fn cargo_target_escapes_and_source_symlinks_are_refused() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(
        root.path(),
        "[[example]]\nname='outside'\npath='../../outside.rs'",
        "",
    )?;
    assert!(analyze(root.path(), "sdk/Cargo.toml").is_err());
    rust(root.path(), "", "")?;
    std::os::unix::fs::symlink("/etc/passwd", root.path().join("sdk/src/evil.rs"))?;
    assert!(analyze(root.path(), "sdk/Cargo.toml").is_err());
    Ok(())
}

#[test]
fn stale_manifest_is_refused_and_changed_source_changes_report_snapshot() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "pub fn call() {}")?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let first = usage::analyze(root.path(), &graph, &["sdk/Cargo.toml".into()])?;
    write(
        root.path(),
        "sdk/src/lib.rs",
        "pub fn call() { unused::run(); }",
    )?;
    let second = usage::analyze(root.path(), &graph, &["sdk/Cargo.toml".into()])?;
    assert_ne!(
        first.inputs["sdk/src/lib.rs"],
        second.inputs["sdk/src/lib.rs"]
    );
    assert_eq!(status(&second, "unused")?, UsageStatus::Referenced);
    write(
        root.path(),
        "sdk/Cargo.toml",
        "[package]\nname='changed'\nversion='1.0.0'",
    )?;
    assert!(usage::analyze(root.path(), &graph, &["sdk/Cargo.toml".into()]).is_err());
    Ok(())
}

#[test]
fn cargo_generated_sources_and_features_prevent_candidates() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(
        root.path(),
        "",
        "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
    )?;
    assert_eq!(
        status(&analyze(root.path(), "sdk/Cargo.toml")?, "unused")?,
        UsageStatus::Unknown
    );
    rust(
        root.path(),
        "[features]\nextra=['unused/feature']",
        "pub fn call() {}",
    )?;
    assert_eq!(
        status(&analyze(root.path(), "sdk/Cargo.toml")?, "unused")?,
        UsageStatus::Unknown
    );
    Ok(())
}

#[test]
fn npm_literal_imports_are_referenced_but_scripts_types_and_dynamic_imports_are_uncertain(
) -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(),"package.json",&json!({"dependencies":{"used":"1","absent":"1","@types/node":"1"},"devDependencies":{"runner":"1"},"scripts":{"test":"runner"}}).to_string())?;
    write(
        root.path(),
        "index.ts",
        "import { x } from 'used/subpath'; // import 'absent';\n",
    )?;
    let report = analyze(root.path(), "package.json")?;
    assert_eq!(status(&report, "used")?, UsageStatus::Referenced);
    assert_eq!(status(&report, "absent")?, UsageStatus::Unknown);
    assert_eq!(status(&report, "runner")?, UsageStatus::Unknown);
    assert_eq!(status(&report, "@types/node")?, UsageStatus::Unknown);
    write(
        root.path(),
        "package.json",
        r#"{"dependencies":{"used":"1","absent":"1"}}"#,
    )?;
    assert_eq!(
        status(&analyze(root.path(), "package.json")?, "absent")?,
        UsageStatus::Candidate
    );
    write(root.path(), "index.ts", "import(variable);")?;
    assert_eq!(
        status(&analyze(root.path(), "package.json")?, "absent")?,
        UsageStatus::Unknown
    );
    Ok(())
}

#[test]
fn python_import_names_are_not_assumed_to_equal_distribution_names() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(),"pyproject.toml","[project]\nname='demo'\nversion='1'\ndependencies=['requests', 'Pillow', 'unused']\n[dependency-groups]\ndev=['pytest']\n")?;
    write(
        root.path(),
        "main.py",
        "import requests\nfrom PIL import Image\n# import unused\n",
    )?;
    let report = analyze(root.path(), "pyproject.toml")?;
    assert_eq!(status(&report, "requests")?, UsageStatus::Referenced);
    assert_eq!(status(&report, "pillow")?, UsageStatus::Unknown);
    assert_eq!(status(&report, "pytest")?, UsageStatus::Unknown);
    assert_eq!(status(&report, "unused")?, UsageStatus::Unknown);
    Ok(())
}

#[test]
fn native_evidence_is_validated_and_cannot_override_real_reference() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "fn call() { renamed::run(); }")?;
    let mut report = analyze(root.path(), "sdk/Cargo.toml")?;
    usage::enrich(
        &mut report,
        "cargo-machete",
        &json!({"crates":[{"package_name":"demo","manifest_path":"sdk/Cargo.toml","unused":["renamed","unused"],"ignored_used":[]}]}),
    )?;
    assert_eq!(status(&report, "renamed")?, UsageStatus::Referenced);
    assert!(report
        .findings
        .iter()
        .find(|f| f.declaration.name == "unused")
        .ok_or("unused")?
        .evidence
        .iter()
        .any(|e| e.contains("cargo-machete")));
    let before = serde_json::to_value(&report)?;
    assert!(usage::enrich(
        &mut report,
        "cargo-machete",
        &json!({"crates":[{"manifest_path":"../../outside/Cargo.toml","unused":["unused"]}]})
    )
    .is_err());
    assert_eq!(before, serde_json::to_value(&report)?);
    assert!(usage::enrich(&mut report, "knip", &json!({"issues":"bad"})).is_err());
    assert!(usage::enrich(&mut report, "deptry", &json!([{"error":{"code":"DEP002"}}])).is_err());
    Ok(())
}

#[test]
fn external_path_modules_cover_their_siblings_and_missing_modules_are_unknown() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(
        root.path(),
        "",
        "#[path = \"../../shared/module.rs\"] mod support;",
    )?;
    write(root.path(), "shared/module.rs", "mod sibling;")?;
    write(
        root.path(),
        "shared/module/sibling.rs",
        "fn call() { unused::run(); }",
    )?;
    assert_eq!(
        status(&analyze(root.path(), "sdk/Cargo.toml")?, "unused")?,
        UsageStatus::Referenced
    );
    fs::remove_file(root.path().join("shared/module/sibling.rs"))?;
    assert_eq!(
        status(&analyze(root.path(), "sdk/Cargo.toml")?, "unused")?,
        UsageStatus::Unknown
    );
    Ok(())
}

#[test]
fn explicit_python_module_mapping_allows_candidates_but_dynamic_loading_blocks_them() -> TestResult
{
    let root = tempfile::tempdir()?;
    write(root.path(),"pyproject.toml","[project]\nname='demo'\nversion='1'\ndependencies=['Pillow', 'absent']\n[tool.deptry.package_module_name_map]\npillow='PIL'\nabsent=['absent_module']\n")?;
    write(root.path(), "main.py", "from PIL import Image\n")?;
    let mut report = analyze(root.path(), "pyproject.toml")?;
    assert_eq!(status(&report, "pillow")?, UsageStatus::Referenced);
    assert_eq!(status(&report, "absent")?, UsageStatus::Candidate);
    usage::enrich(
        &mut report,
        "deptry",
        &json!([{"error":{"code":"DEP002","message":"absent unused"},"module":"absent","location":{"file":"pyproject.toml","line":null,"column":null}}]),
    )?;
    assert!(report
        .findings
        .iter()
        .find(|f| f.declaration.name == "absent")
        .ok_or("absent")?
        .evidence
        .iter()
        .any(|e| e.contains("deptry")));
    write(
        root.path(),
        "main.py",
        "import importlib\nimportlib.import_module(variable)\n",
    )?;
    assert_eq!(
        status(&analyze(root.path(), "pyproject.toml")?, "absent")?,
        UsageStatus::Unknown
    );
    Ok(())
}

#[test]
fn npm_require_resolve_references_and_knip_imports_are_supported() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "package.json",
        r#"{"dependencies":{"used":"1","absent":"1"}}"#,
    )?;
    write(
        root.path(),
        "index.js",
        "const path = require.resolve('used');\n",
    )?;
    let mut report = analyze(root.path(), "package.json")?;
    assert_eq!(status(&report, "used")?, UsageStatus::Referenced);
    usage::enrich(
        &mut report,
        "knip",
        &json!({"issues":[{"file":"package.json","dependencies":[{"name":"used"},{"name":"absent"}],"devDependencies":[]}]}),
    )?;
    assert_eq!(status(&report, "used")?, UsageStatus::Referenced);
    assert!(report
        .findings
        .iter()
        .find(|f| f.declaration.name == "absent")
        .ok_or("absent")?
        .evidence
        .iter()
        .any(|e| e.contains("knip")));
    Ok(())
}

#[test]
fn invalid_source_utf8_and_missing_explicit_targets_do_not_yield_candidates() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(
        root.path(),
        "[[bench]]\nname='missing'\npath='benches/missing.rs'",
        "fn run() {}",
    )?;
    assert_eq!(
        status(&analyze(root.path(), "sdk/Cargo.toml")?, "unused")?,
        UsageStatus::Unknown
    );
    rust(root.path(), "", "fn run() {}")?;
    fs::write(root.path().join("sdk/src/lib.rs"), [0xff, 0xfe])?;
    assert_eq!(
        status(&analyze(root.path(), "sdk/Cargo.toml")?, "unused")?,
        UsageStatus::Unknown
    );
    Ok(())
}

#[test]
fn cargo_build_scripts_are_never_executed_and_oversized_sources_are_refused() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "fn run() {}")?;
    write(
        root.path(),
        "sdk/build.rs",
        "fn main() { std::fs::write(\"EXECUTED\", \"bad\").unwrap(); }",
    )?;
    assert_eq!(
        status(&analyze(root.path(), "sdk/Cargo.toml")?, "unused")?,
        UsageStatus::Unknown
    );
    assert!(!root.path().join("EXECUTED").exists());
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let file = fs::File::create(root.path().join("sdk/src/huge.rs"))?;
    file.set_len(8 * 1024 * 1024 + 1)?;
    assert!(usage::analyze(root.path(), &graph, &["sdk/Cargo.toml".into()]).is_err());
    Ok(())
}

#[test]
fn matching_package_specs_preserve_distinct_declared_alias_roots() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "fn run() {}")?;
    write(root.path(),"sdk/Cargo.toml","[package]\nname='demo'\nversion='1.0.0'\n[dependencies]\none={package='actual-name',version='1'}\ntwo={package='actual-name',version='1'}\n")?;
    let report = analyze(root.path(), "sdk/Cargo.toml")?;
    assert_eq!(report.findings.len(), 2);
    assert!(report.findings.iter().all(|f| f.root_ids.len() == 1));
    assert_eq!(report.findings[0].targets, report.findings[1].targets);
    assert_ne!(report.findings[0].root_ids, report.findings[1].root_ids);
    Ok(())
}

#[test]
fn cargo_aliases_of_different_versions_bind_their_own_roots() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "fn run() { one::call(); }")?;
    write(root.path(),"sdk/Cargo.toml","[package]\nname='demo'\nversion='1.0.0'\n[dependencies]\none={package='actual-name',version='1'}\ntwo={package='actual-name',version='2'}\n")?;
    write(root.path(),"sdk/Cargo.lock","version=4\n[[package]]\nname='actual-name'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n[[package]]\nname='actual-name'\nversion='2.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n")?;
    let report = analyze(root.path(), "sdk/Cargo.toml")?;
    let one = report
        .findings
        .iter()
        .find(|f| f.declaration.name == "one")
        .ok_or("one")?;
    let two = report
        .findings
        .iter()
        .find(|f| f.declaration.name == "two")
        .ok_or("two")?;
    assert_eq!(one.targets[0].purl, "pkg:cargo/actual-name@1.0.0");
    assert_eq!(two.targets[0].purl, "pkg:cargo/actual-name@2.0.0");
    Ok(())
}

#[test]
fn python_multi_imports_and_invalid_module_maps_do_not_create_false_candidates() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(),"pyproject.toml","[project]\nname='demo'\nversion='1'\ndependencies=['first', 'second', 'invalid']\n[tool.deptry.package_module_name_map]\nfirst='alpha'\nsecond=['beta.child']\ninvalid=42\n")?;
    write(root.path(), "main.py", "import alpha, beta\n")?;
    let report = analyze(root.path(), "pyproject.toml")?;
    assert_eq!(status(&report, "second")?, UsageStatus::Referenced);
    assert_eq!(status(&report, "invalid")?, UsageStatus::Unknown);
    Ok(())
}

#[test]
fn incomplete_inventory_and_native_npm_hooks_prevent_candidates() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "package.json",
        r#"{"dependencies":{"native-addon":"1"}}"#,
    )?;
    write(root.path(),"package-lock.json",&json!({"lockfileVersion":3,"packages":{"":{},"node_modules/native-addon":{"version":"1.0.0","hasInstallScript":true}}}).to_string())?;
    write(root.path(), "index.js", "export const value = 1;")?;
    assert_eq!(
        status(&analyze(root.path(), "package.json")?, "native-addon")?,
        UsageStatus::Unknown
    );
    write(root.path(),"pyproject.toml","[project]\nname='demo'\nversion='1'\ndependencies=['absent']\ndynamic=['dependencies']\n[tool.deptry.package_module_name_map]\nabsent='absent'\n")?;
    write(root.path(), "main.py", "print('hello')")?;
    assert_eq!(
        status(&analyze(root.path(), "pyproject.toml")?, "absent")?,
        UsageStatus::Unknown
    );
    Ok(())
}

#[test]
fn unrelated_archives_and_other_projects_do_not_consume_source_budget() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(
        root.path(),
        "[[test]]\nname='external'\npath='../demos/test.rs'",
        "fn run() {}",
    )?;
    write(
        root.path(),
        "demos/test.rs",
        "fn test() { tempfile::tempdir(); }",
    )?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    fs::create_dir(root.path().join("archive"))?;
    let file = fs::File::create(root.path().join("archive/old.rs"))?;
    file.set_len(128 * 1024 * 1024)?;
    fs::create_dir(root.path().join("unrelated"))?;
    let file = fs::File::create(root.path().join("unrelated/large.bin"))?;
    file.set_len(128 * 1024 * 1024)?;
    let report = usage::analyze(root.path(), &graph, &["sdk/Cargo.toml".into()])?;
    assert_eq!(status(&report, "tempfile")?, UsageStatus::Referenced);
    assert!(!report.inputs.contains_key("archive/old.rs"));
    assert!(!report.inputs.contains_key("unrelated/large.bin"));
    Ok(())
}

#[test]
fn npm_import_maps_are_uncertain_without_loading_configuration() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "package.json",
        r##"{"dependencies":{"used":"1"},"imports":{"#internal":"used"}}"##,
    )?;
    write(root.path(), "index.js", "import '#internal';")?;
    assert_eq!(
        status(&analyze(root.path(), "package.json")?, "used")?,
        UsageStatus::Unknown
    );
    Ok(())
}

#[test]
fn clean_cargo_machete_report_is_accepted_but_malformed_objects_are_refused() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "fn run() {}")?;
    let mut report = analyze(root.path(), "sdk/Cargo.toml")?;
    let before = serde_json::to_value(&report)?;
    usage::enrich(&mut report, "cargo-machete", &json!({}))?;
    assert_eq!(before, serde_json::to_value(&report)?);
    assert!(usage::enrich(&mut report, "cargo-machete", &json!({"unexpected":true})).is_err());
    Ok(())
}

#[test]
fn ignored_regular_files_still_count_toward_enumeration_limit() -> TestResult {
    let root = tempfile::tempdir()?;
    rust(root.path(), "", "fn run() {}")?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    for i in 0..20_001 {
        fs::File::create(root.path().join(format!("sdk/src/ignored-{i}.txt")))?;
    }
    assert!(usage::analyze(root.path(), &graph, &["sdk/Cargo.toml".into()]).is_err());
    Ok(())
}

#[test]
fn nested_project_selection_does_not_change_outer_rust_findings() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "Cargo.toml", "[package]\nname='outer'\nversion='1.0.0'\n[lib]\npath='lib.rs'\n[dependencies]\nonly-inner='1'\n")?;
    write(root.path(), "lib.rs", "pub fn run() {}")?;
    write(
        root.path(),
        "nested/Cargo.toml",
        "[package]\nname='inner'\nversion='1.0.0'\n[dependencies]\nonly-inner='1'\n",
    )?;
    write(
        root.path(),
        "nested/src/lib.rs",
        "pub fn run() { only_inner::run(); }",
    )?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let alone = usage::analyze(root.path(), &graph, &["Cargo.toml".into()])?;
    let together = usage::analyze(
        root.path(),
        &graph,
        &["Cargo.toml".into(), "nested/Cargo.toml".into()],
    )?;
    let reversed = usage::analyze(
        root.path(),
        &graph,
        &["nested/Cargo.toml".into(), "Cargo.toml".into()],
    )?;
    let outer =
        |report: &usage::UsageReport| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
            Ok(serde_json::to_value(
                report
                    .findings
                    .iter()
                    .find(|f| f.declaration.manifest == "Cargo.toml")
                    .ok_or("outer finding")?,
            )?)
        };
    assert_eq!(status(&alone, "only-inner")?, UsageStatus::Candidate);
    assert_eq!(outer(&alone)?, outer(&together)?);
    assert_eq!(outer(&alone)?, outer(&reversed)?);
    Ok(())
}

#[test]
fn nested_project_configuration_does_not_change_outer_npm_coverage() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "package.json",
        r#"{"dependencies":{"unused":"1"}}"#,
    )?;
    write(root.path(), "index.js", "export const value = 1;")?;
    write(root.path(), "nested/package.json", r#"{"name":"inner"}"#)?;
    write(
        root.path(),
        "nested/tsconfig.json",
        r#"{"compilerOptions":{"types":["unused"]}}"#,
    )?;
    write(root.path(), "nested/index.ts", "export const value = 1;")?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let alone = usage::analyze(root.path(), &graph, &["package.json".into()])?;
    let together = usage::analyze(
        root.path(),
        &graph,
        &["package.json".into(), "nested/package.json".into()],
    )?;
    assert_eq!(status(&alone, "unused")?, UsageStatus::Candidate);
    assert_eq!(
        serde_json::to_value(alone.findings)?,
        serde_json::to_value(together.findings)?
    );
    Ok(())
}

#[test]
fn explicit_external_target_inside_nested_project_includes_its_module_closure() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "Cargo.toml", "[package]\nname='outer'\nversion='1.0.0'\n[dependencies]\nonly-inner='1'\nonly-sibling='1'\n[[test]]\nname='external'\npath='nested/src/lib.rs'\n")?;
    write(root.path(), "src/lib.rs", "pub fn run() {}")?;
    write(
        root.path(),
        "nested/Cargo.toml",
        "[package]\nname='inner'\nversion='1.0.0'\n",
    )?;
    write(
        root.path(),
        "nested/src/lib.rs",
        "mod sibling;\npub fn run() { only_inner::run(); }",
    )?;
    write(
        root.path(),
        "nested/src/sibling.rs",
        "pub fn run() { only_sibling::run(); }",
    )?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let alone = usage::analyze(root.path(), &graph, &["Cargo.toml".into()])?;
    let together = usage::analyze(
        root.path(),
        &graph,
        &["Cargo.toml".into(), "nested/Cargo.toml".into()],
    )?;
    assert_eq!(status(&alone, "only-inner")?, UsageStatus::Referenced);
    assert_eq!(status(&alone, "only-sibling")?, UsageStatus::Referenced);
    assert_eq!(
        serde_json::to_value(alone.findings)?,
        serde_json::to_value(together.findings)?
    );
    Ok(())
}

#[test]
fn colocated_rust_project_does_not_add_npm_configuration_inputs() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "package.json",
        r#"{"dependencies":{"unused":"1"}}"#,
    )?;
    write(root.path(), "index.js", "export const value = 1;")?;
    write(
        root.path(),
        "Cargo.toml",
        "[package]\nname='rust'\nversion='1.0.0'\n",
    )?;
    write(root.path(), "src/webpack.rs", "pub fn rust_code() {}")?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let alone = usage::analyze(root.path(), &graph, &["package.json".into()])?;
    let together = usage::analyze(
        root.path(),
        &graph,
        &["package.json".into(), "Cargo.toml".into()],
    )?;
    assert_eq!(status(&alone, "unused")?, UsageStatus::Candidate);
    assert_eq!(
        serde_json::to_value(alone.findings)?,
        serde_json::to_value(together.findings)?
    );
    Ok(())
}
