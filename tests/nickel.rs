use ladyshell::nickel::evaluate;
use std::{fs, path::Path};
fn resources() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
#[test]
fn evaluates_dev_and_inherited_audit_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let entry = resources().join("tests/fixtures/nickel/sandbox.ncl");
    let dev = evaluate(&entry, "dev", resources())?;
    assert_eq!(dev.config.tools.len(), 1);
    assert_eq!(dev.config.tools["zig"].version, "0.17.0");
    let audit = evaluate(&entry, "audit", resources())?;
    assert_eq!(audit.config.tools.len(), 2);
    assert_eq!(audit.config.checks.len(), 2);
    assert_eq!(audit.modules_sha256.len(), 1);
    Ok(())
}

#[test]
fn dependency_preparation_is_optional_and_requires_explicit_projects_and_hosts(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let fixture = fs::read_to_string(resources().join("tests/fixtures/nickel/sandbox.ncl"))?;
    let entry = dir.path().join("sandbox.ncl");
    fs::write(&entry, format!("({fixture}) & {{ dependencies = {{ projects = [\"package.json\"], allowed_hosts = [\"registry.npmjs.org\"] }} }}"))?;
    let resolved = evaluate(&entry, "dev", resources())?;
    let dependencies = resolved.config.dependencies.ok_or("dependencies lost")?;
    assert_eq!(dependencies.projects, ["package.json"]);
    assert_eq!(dependencies.allowed_hosts, ["registry.npmjs.org"]);
    assert!(evaluate(
        &resources().join("tests/fixtures/nickel/sandbox.ncl"),
        "dev",
        resources()
    )?
    .config
    .dependencies
    .is_none());
    Ok(())
}

#[test]
fn native_audit_configuration_survives_nickel_resolution() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let fixture = fs::read_to_string(resources().join("tests/fixtures/nickel/sandbox.ncl"))?;
    let entry = dir.path().join("sandbox.ncl");
    fs::write(&entry,format!("({fixture}) & {{ audit = {{ profile = \"quick\", scope_paths = [\"src\"], exclude_paths = [], tools = {{}}, checks = [[\"cargo\", \"test\", \"--offline\"]], budget = {{ invocations = 8, seconds = 300 }}, limits = {{ cpu_seconds = 30, memory_bytes = 268435456, processes = 32, files = 128, disk_bytes = 67108864 }} }} }}"))?;
    let resolved = evaluate(&entry, "audit", resources())?;
    let audit = resolved.config.audit.ok_or("audit block lost")?;
    assert_eq!(audit.scope_paths, vec!["src"]);
    assert_eq!(audit.checks, vec![vec!["cargo", "test", "--offline"]]);
    assert!(audit.tools.is_empty());
    assert_eq!(resolved.config.tools.len(), 2);
    Ok(())
}
#[test]
fn refuses_external_import_and_symlink_ancestors() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let modules = dir.path().join("modules");
    fs::create_dir(&modules)?;
    let entry = modules.join("test.ncl");
    let fixture = fs::read(resources().join("tests/fixtures/nickel/sandbox.ncl"))?;
    fs::write(&entry, &fixture)?;
    // A failed evaluator must never count as proof that the import was confined.
    assert_eq!(
        evaluate(&entry, "dev", resources())?.config.name,
        "fixture-project"
    );
    let outside = dir.path().join("outside.ncl");
    fs::write(&outside, &fixture)?;
    fs::write(
        &entry,
        format!(
            "import {}",
            serde_json::to_string(outside.to_str().ok_or("Non-UTF-8 path")?)?
        ),
    )?;
    let error = evaluate(&entry, "dev", resources())
        .err()
        .ok_or("External import was accepted")?;
    assert!(
        matches!(&error, ladyshell::error::Error::Nickel { .. }),
        "The import must be rejected by isolated Nickel, not by a missing prerequisite: {error}"
    );
    fs::write(&entry, fixture)?;
    assert_eq!(
        evaluate(&entry, "dev", resources())?.config.name,
        "fixture-project"
    );
    let link = dir.path().join("linked");
    std::os::unix::fs::symlink(resources().join("tests/fixtures/nickel"), &link)?;
    assert!(evaluate(&link.join("sandbox.ncl"), "dev", resources()).is_err());
    Ok(())
}
#[test]
fn permits_local_modules_but_not_readable_external_configuration(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let inside = dir.path().join("modules");
    fs::create_dir(&inside)?;
    let fixture = fs::read(resources().join("tests/fixtures/nickel/sandbox.ncl"))?;
    let outside = dir.path().join("outside.ncl");
    fs::write(&outside, &fixture)?;
    let entry = inside.join("entry.ncl");
    fs::write(
        &entry,
        format!(
            "import {}",
            serde_json::to_string(outside.to_str().ok_or("Invalid fixture: missing value")?)?
        ),
    )?;
    assert!(evaluate(&entry, "dev", resources()).is_err());
    fs::write(inside.join("module.ncl"), fixture)?;
    fs::write(&entry, "import \"module.ncl\"")?;
    let resolved = evaluate(&entry, "audit", resources())?;
    assert_eq!(resolved.modules_sha256.len(), 2);
    Ok(())
}
#[test]
fn resources_can_be_relocated_without_original_repository() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("nix"))?;
    fs::create_dir(dir.path().join("config"))?;
    for name in [
        "flake.nix",
        "flake.lock",
        "build.nix",
        "image.nix",
        "dependencies.nix",
        "openssl.nix",
        "tpm2-tss.nix",
        "network-tools.nix",
    ] {
        fs::copy(
            resources().join("nix").join(name),
            dir.path().join("nix").join(name),
        )?;
    }
    fs::copy(
        resources().join("config/schema.ncl"),
        dir.path().join("config/schema.ncl"),
    )?;
    assert_eq!(
        evaluate(
            &resources().join("tests/fixtures/nickel/sandbox.ncl"),
            "dev",
            dir.path()
        )?
        .config
        .name,
        "fixture-project"
    );
    Ok(())
}
#[test]
fn ignores_caches_and_unrelated_links_but_never_imports_through_them(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let entry = dir.path().join("sandbox.ncl");
    fs::copy(
        resources().join("tests/fixtures/nickel/sandbox.ncl"),
        &entry,
    )?;
    fs::create_dir(dir.path().join("node_modules"))?;
    fs::write(
        dir.path().join("node_modules/invalid.ncl"),
        "invalid Nickel!",
    )?;
    std::os::unix::fs::symlink("/etc", dir.path().join("unrelated-link"))?;
    let config = evaluate(&entry, "dev", resources())?;
    assert_eq!(config.modules_sha256.len(), 1);
    fs::write(&entry, "import \"unrelated-link/host.ncl\"")?;
    assert!(evaluate(&entry, "dev", resources()).is_err());
    Ok(())
}
