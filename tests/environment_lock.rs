use ladyshell::{
    environment_lock::{create, verify, write},
    nickel::evaluate,
};
use std::{fs, path::Path};
#[test]
fn locks_explicit_artifacts_and_refuses_changed_or_missing_lock(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = tempfile::tempdir()?;
    let a = dir.path().join("codex");
    let b = dir.path().join("host");
    fs::write(&a, b"\x7fELFfixture-a")?;
    fs::write(&b, b"\x7fELFfixture-b")?;
    let evaluated = evaluate(&root.join("tests/fixtures/nickel/sandbox.ncl"), "dev", root)?;
    let receipt = create(evaluated.clone(), root, &a, &b)?;
    let path = dir.path().join("environment.lock.json");
    assert!(verify(&path, &receipt).is_err());
    write(&path, &receipt)?;
    verify(&path, &receipt)?;
    fs::write(&a, b"\x7fELFchanged")?;
    let changed = create(evaluated.clone(), root, &a, &b)?;
    assert!(verify(&path, &changed).is_err());
    fs::write(&b, b"#!/bin/bash")?;
    assert!(create(evaluated, root, &a, &b).is_err());
    let before = fs::read(&path)?;
    assert!(verify(&path, &changed).is_err());
    assert_eq!(before, fs::read(&path)?);
    Ok(())
}
#[test]
fn refuses_symlink_lock_without_overwriting_target() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = tempfile::tempdir()?;
    let artifact = dir.path().join("artifact");
    fs::write(&artifact, b"\x7fELFfixture")?;
    let receipt = create(
        evaluate(&root.join("tests/fixtures/nickel/sandbox.ncl"), "dev", root)?,
        root,
        &artifact,
        &artifact,
    )?;
    let target = dir.path().join("target");
    fs::write(&target, "keep")?;
    let link = dir.path().join("lock");
    std::os::unix::fs::symlink(&target, &link)?;
    assert!(write(&link, &receipt).is_err());
    assert_eq!(fs::read_to_string(target)?, "keep");
    Ok(())
}
#[test]
fn audit_distribution_is_part_of_the_environment_lock() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir()?;
    let artifact = temp.path().join("artifact");
    fs::write(&artifact, b"\x7fELFfixture")?;
    let receipt = create(
        evaluate(&root.join("tests/fixtures/nickel/sandbox.ncl"), "dev", root)?,
        root,
        &artifact,
        &artifact,
    )?;
    let key = "crates/ladyshell/resources/audit/security-audit/SKILL.md";
    assert_eq!(
        receipt.recipes_sha256.get(key),
        Some(&ladyshell::files::hash(&fs::read(root.join(key))?))
    );
    Ok(())
}

#[test]
fn dependency_recipe_changes_require_a_new_explicit_lock() -> Result<(), Box<dyn std::error::Error>>
{
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir()?;
    let resources = temp.path().join("resources");
    fs::create_dir(&resources)?;
    ladyshell::sources::snapshot(
        root,
        &ladyshell::config::Sources {
            include: vec!["nix".into(), "crates/ladyshell/resources/audit".into()],
            exclude: vec![],
        },
        Some(&resources),
    )?;
    let artifact = temp.path().join("artifact");
    fs::write(&artifact, b"\x7fELFfixture")?;
    let config = evaluate(&root.join("tests/fixtures/nickel/sandbox.ncl"), "dev", root)?;
    let before = create(config.clone(), &resources, &artifact, &artifact)?;
    let path = temp.path().join("environment.lock.json");
    write(&path, &before)?;
    let bytes = fs::read(&path)?;
    for name in [
        "dependencies.nix",
        "openssl.nix",
        "tpm2-tss.nix",
        "network-tools.nix",
    ] {
        let recipe = resources.join("nix").join(name);
        let original = fs::read(&recipe)?;
        fs::write(&recipe, "# changed recipe\n")?;
        let after = create(config.clone(), &resources, &artifact, &artifact)?;
        assert_ne!(before.recipes_sha256[name], after.recipes_sha256[name]);
        assert!(verify(&path, &after).is_err());
        assert_eq!(bytes, fs::read(&path)?);
        fs::write(&recipe, original)?;
    }
    Ok(())
}
