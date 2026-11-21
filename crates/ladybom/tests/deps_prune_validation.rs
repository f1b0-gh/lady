use ladybom::{
    deps::{self, graph, prune_validation},
    inventory as snapshot,
};
use serde_json::json;
use std::fs;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn setup(root: &std::path::Path) -> Result<graph::Graph> {
    fs::write(
        root.join("package.json"),
        json!({"dependencies":{"a":"1"}}).to_string(),
    )?;
    fs::write(
        root.join("package-lock.json"),
        json!({"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0"}}})
            .to_string(),
    )?;
    Ok(graph::project(deps::scan_project(root)?)?)
}
#[test]
fn validation_plan_refuses_unchanged_declaration_and_stale_source_inventory() -> Result {
    let dir = tempfile::tempdir()?;
    let before = setup(dir.path())?;
    let request =
        graph::RemovalRequest::new(&before, vec![graph::root_catalog(&before)?[0].id.clone()])?;
    assert!(prune_validation::plan(&before, &before, &request, dir.path(), &[]).is_err());
    fs::write(dir.path().join("package.json"), "{\"dependencies\":{}}")?;
    let after = graph::project(deps::scan_project(dir.path())?)?;
    let plan = prune_validation::plan(&before, &after, &request, dir.path(), &[])?;
    assert_eq!(plan.removed_declarations.len(), 1);
    assert!(plan.expected.contains_key("package.json"));
    let inventory = snapshot::inventory(dir.path())?;
    prune_validation::verify_inventory(&plan, &inventory)?;
    fs::write(dir.path().join("index.js"), "require('a');")?;
    assert!(prune_validation::verify_inventory(&plan, &snapshot::inventory(dir.path())?).is_err());
    fs::write(dir.path().join("package.json"), "{}")?;
    assert!(prune_validation::plan(&before, &after, &request, dir.path(), &[]).is_err());
    Ok(())
}
#[test]
fn validation_plan_rejects_removed_project_and_changed_version_as_removal() -> Result {
    let dir = tempfile::tempdir()?;
    let before = setup(dir.path())?;
    let request =
        graph::RemovalRequest::new(&before, vec![graph::root_catalog(&before)?[0].id.clone()])?;
    fs::write(
        dir.path().join("package.json"),
        json!({"dependencies":{"a":"2"}}).to_string(),
    )?;
    let after = graph::project(deps::scan_project(dir.path())?)?;
    assert!(prune_validation::plan(&before, &after, &request, dir.path(), &[]).is_err());
    let mut after = before.clone();
    after.inventory.projects.clear();
    after.roots.clear();
    assert!(prune_validation::plan(&before, &after, &request, dir.path(), &[]).is_err());
    Ok(())
}

#[test]
fn validation_preserves_cargo_alias_identity_and_rejects_version_only_changes() -> Result {
    let dir = tempfile::tempdir()?;
    let manifest="[package]\nname='demo'\nversion='0.1.0'\n[dependencies]\none={package='actual',version='1'}\ntwo={package='actual',version='2'}\n";
    fs::write(dir.path().join("Cargo.toml"), manifest)?;
    fs::write(dir.path().join("Cargo.lock"),"version=3\n[[package]]\nname='actual'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n[[package]]\nname='actual'\nversion='2.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n")?;
    let before = graph::project(deps::scan_project(dir.path())?)?;
    let id = graph::root_catalog(&before)?
        .into_iter()
        .find(|r| r.root.to.purl == "pkg:cargo/actual@2.0.0")
        .ok_or("alias root")?
        .id;
    let request = graph::RemovalRequest::new(&before, vec![id])?;
    fs::write(
        dir.path().join("Cargo.toml"),
        manifest.replace("two={package='actual',version='2'}\n", ""),
    )?;
    let after = graph::project(deps::scan_project(dir.path())?)?;
    let plan = prune_validation::plan(&before, &after, &request, dir.path(), &[])?;
    assert_eq!(plan.removed_declarations.len(), 1);
    fs::write(
        dir.path().join("Cargo.toml"),
        manifest.replace("version='2'", "version='3'"),
    )?;
    let after = graph::project(deps::scan_project(dir.path())?)?;
    assert!(prune_validation::plan(&before, &after, &request, dir.path(), &[]).is_err());
    Ok(())
}
