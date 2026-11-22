use ladyshell::{config::Config, environment_lock, nickel::Evaluated};
use serde_json::json;
use std::{collections::BTreeMap, fs};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn config() -> serde_json::Value {
    json!({"schema_version":1,"name":"broker","sources":{"include":[],"exclude":[]},
        "tools":{},"missions":{"dev":{"tools":[],"include":[],"depends_on":[],"checks":[]}},
        "sandbox":{"gateway":"g","workspace":"w"},
        "image":{"backend":"nix","profile":"openshell-wasi","platform":"x86_64-linux"},
        "storage":{"control":{"bytes":65536,"inodes":32},
            "artifacts":{"bytes":262144,"inodes":64},"incoming":{"bytes":262144,"inodes":64}}})
}
#[test]
fn fixed_broker_profile_requires_caps_and_refuses_provider_tools_and_extra_permissions(
) -> Result<()> {
    let config = config();
    let resolved = Config::from_value(config.clone())?.resolve("dev")?;
    assert!(resolved.sandbox.provider.is_none());
    let mut missing_storage = config.clone();
    missing_storage
        .as_object_mut()
        .ok_or("config")?
        .remove("storage");
    assert!(Config::from_value(missing_storage).is_err());
    let mut changed = config.clone();
    changed["sandbox"]["provider"] = json!("secret-provider");
    assert!(Config::from_value(changed).is_err());
    changed = config.clone();
    changed["tools"] = json!({"rust":{"version":"1.99.1"}});
    assert!(Config::from_value(changed).is_err());
    changed = config.clone();
    changed["permissions"] = json!({"network":[{"tool":"codex","host":"api.openai.com","port":443,"justification":"not the broker profile"}],"filesystem":[]});
    assert!(Config::from_value(changed).is_err());
    changed = config.clone();
    changed["missions"]["dev"]["checks"] = json!([["/bin/sh"]]);
    assert!(Config::from_value(changed).is_err());
    changed = config.clone();
    changed["dependencies"] = json!({"projects":["Cargo.toml"],"allowed_hosts":["crates.io"]});
    assert!(Config::from_value(changed).is_err());
    // Existing native configurations still require a provider.
    changed = config;
    changed["image"]["profile"] = json!("openshell-native");
    assert!(Config::from_value(changed).is_err());
    Ok(())
}
#[test]
fn broker_lock_names_and_hashes_native_artifacts_without_codex_substitution() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("nix"))?;
    for name in [
        "flake.nix",
        "flake.lock",
        "broker-build.nix",
        "broker-image.nix",
        "openssl.nix",
    ] {
        fs::write(root.path().join("nix").join(name), name)?;
    }
    let runtime = root.path().join("ladyshell");
    let broker = root.path().join("lo-executor-worker");
    fs::write(&runtime, b"\x7fELFsynthetic-runtime")?;
    fs::write(&broker, b"\x7fELFsynthetic-broker")?;
    let evaluated = Evaluated {
        config: Config::from_value(config())?.resolve("dev")?,
        modules_sha256: BTreeMap::new(),
        schema_sha256: "fixture".into(),
        flake_lock_sha256: "fixture".into(),
        evaluator: "fixture".into(),
    };
    let original =
        environment_lock::create_broker(evaluated.clone(), root.path(), &broker, &runtime)?;
    assert_eq!(original.artifacts_sha256.len(), 2);
    assert_eq!(
        original.artifacts_sha256["lo-executor-worker"],
        environment_lock::artifact_hash(&broker)?
    );
    assert_eq!(
        original.artifacts_sha256["ladyshell"],
        environment_lock::artifact_hash(&runtime)?
    );
    assert_eq!(original.recipes_sha256.len(), 5);
    let path = root.path().join("lock.json");
    environment_lock::write(&path, &original)?;
    environment_lock::verify(&path, &original)?;
    fs::write(&broker, b"\x7fELFchanged-broker")?;
    let changed =
        environment_lock::create_broker(evaluated.clone(), root.path(), &broker, &runtime)?;
    assert!(environment_lock::verify(&path, &changed).is_err());
    assert!(environment_lock::create(evaluated, root.path(), &broker, &runtime).is_err());
    Ok(())
}
