//! Public-library consumers must not depend on the CLI parser.
use nickel_util::evaluation::{evaluate, EvaluationRequest};
use std::{fs, path::Path};

#[test]
fn artifact_evaluator_sees_only_selected_recipe_files() -> Result<(), Box<dyn std::error::Error>> {
    use ladyboot::artifact::{check, ArtifactRequest};
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir()?;
    let recipes = temp.path();
    fs::create_dir(recipes.join("nix"))?;
    fs::create_dir(recipes.join("profiles"))?;
    fs::create_dir(recipes.join("tests"))?;
    let flake = fs::read_to_string(root.join("flake.nix"))?;
    let selected_only = flake.replace(
        "outputs = { nixpkgs, ... }:",
        "outputs = { nixpkgs, ... }: assert !(builtins.pathExists ./.env);",
    );
    assert_ne!(selected_only, flake);
    fs::write(recipes.join("flake.nix"), selected_only)?;
    fs::copy(root.join("flake.lock"), recipes.join("flake.lock"))?;
    fs::write(recipes.join(".env"), "SYNTHETIC_SENTINEL=not-a-secret\n")?;
    fs::write(recipes.join("nix/build.nix"), "{}")?;
    fs::write(recipes.join("nix/image.nix"), "{}")?;
    fs::write(
        recipes.join("profiles/schema.ncl"),
        "{ schema_version | Number, architecture | String, os_id | String, revision | String, needs | Array String }",
    )?;
    let config = recipes.join("profiles/minimal.ncl");
    fs::write(
        &config,
        r#"{ schema_version = 1, architecture = "x86_64-linux", os_id = "ladyboot", revision = "1", needs = ["bootc-base"] }"#,
    )?;
    let lock = check(&ArtifactRequest {
        config,
        resources: recipes.to_owned(),
    })?;
    assert_eq!(lock.configuration["os_id"], "ladyboot");
    assert!(!lock.inputs_sha256.contains_key(".env"));
    assert!(recipes.join(".env").exists());
    Ok(())
}

#[test]
fn evaluates_public_data_with_contract_and_confines_imports(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let temp = tempfile::tempdir()?;
    let modules = temp.path().join("modules");
    fs::create_dir(&modules)?;
    let entry = modules.join("profile.ncl");
    let contract = temp.path().join("schema.ncl");
    fs::write(&contract, "{ revision | Number }")?;
    fs::write(&entry, "{ revision = 2 }")?;
    let nix = root.to_path_buf();
    let request = EvaluationRequest {
        entry: &entry,
        contract: Some(&contract),
        nix: &nix,
    };
    let value = evaluate(&request)?;
    assert_eq!(value.value, serde_json::json!({"revision":2}));
    assert_eq!(value.modules_sha256.len(), 1);
    assert!(value.contract_sha256.is_some());
    let outside = temp.path().join("outside.ncl");
    fs::write(&outside, "{ revision = 2 }")?;
    fs::write(
        &entry,
        format!("import {}", serde_json::to_string(&outside)?),
    )?;
    assert!(matches!(
        evaluate(&request),
        Err(nickel_util::error::Error::Nickel { .. })
    ));
    fs::write(&entry, "{ revision = 2 }")?;
    assert_eq!(evaluate(&request)?.value["revision"], 2);
    fs::write(&entry, "{ revision = \"wrong\" }")?;
    assert!(evaluate(&request).is_err());
    Ok(())
}

#[test]
fn artifact_lock_rejects_changed_configuration_or_recipe() -> Result<(), Box<dyn std::error::Error>>
{
    use ladyboot::artifact::{verify_lock, ArtifactLock};
    let base = ArtifactLock {
        schema_version: 1,
        profile: "bootc".into(),
        configuration: serde_json::json!({"revision":"2"}),
        inputs_sha256: std::collections::BTreeMap::from([("nix/image.nix".into(), "a".repeat(64))]),
        evaluator: "/nix/store/evaluator/bin/nickel".into(),
        modules_sha256: Default::default(),
    };
    verify_lock(&base, &base)?;
    let mut changed = base.clone();
    changed.configuration["revision"] = "3".into();
    assert!(verify_lock(&base, &changed).is_err());
    changed = base.clone();
    changed
        .inputs_sha256
        .insert("nix/image.nix".into(), "b".repeat(64));
    assert!(verify_lock(&base, &changed).is_err());
    Ok(())
}
