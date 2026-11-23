use ladyshell::{config::Config, environment_lock, image, nickel::Evaluated};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn broker_build_checks_explicit_artifact_before_any_native_tool_or_codex_lookup() -> Result<()> {
    let root = tempfile::tempdir()?;
    let project = root.path().join("project");
    let state = root.path().join("state");
    let resources = root.path().join("resources");
    fs::create_dir(&project)?;
    ladyshell::state::create_directory(&state)?;
    fs::create_dir_all(resources.join("nix"))?;
    for name in [
        "flake.nix",
        "flake.lock",
        "broker-build.nix",
        "broker-image.nix",
        "openssl.nix",
    ] {
        fs::write(resources.join("nix").join(name), "synthetic, never execute")?;
    }
    let broker = root.path().join("broker");
    let runtime = root.path().join("runtime");
    fs::write(&broker, b"\x7fELForiginal")?;
    fs::write(&runtime, b"\x7fELFruntime")?;
    let config = Config::from_value(json!({"schema_version":1,"name":"fixture",
        "sources":{"include":[],"exclude":[]},"tools":{},
        "missions":{"dev":{"tools":[],"include":[],"depends_on":[],"checks":[]}},
        "sandbox":{"gateway":"unused","workspace":"default"},
        "image":{"backend":"nix","profile":"openshell-worker-v1","platform":"x86_64-linux"},
        "storage":{"control":{"bytes":65536,"inodes":32},
            "artifacts":{"bytes":262144,"inodes":64},"incoming":{"bytes":262144,"inodes":64}}}))?
    .resolve("dev")?;
    let evaluated = Evaluated {
        config,
        modules_sha256: BTreeMap::new(),
        schema_sha256: "fixture".into(),
        flake_lock_sha256: "fixture".into(),
        evaluator: "fixture".into(),
    };
    let lock = environment_lock::create_broker(evaluated.clone(), &resources, &broker, &runtime)?;
    let mut desired = json!({"project":project,"resources":resources,"sources":{},
        "evaluated":evaluated,"environment_lock":lock,
        "artifacts":{"worker":{"path":broker,"sha256":environment_lock::artifact_hash(&broker)?},
            "ladyshell":{"path":runtime,"sha256":environment_lock::artifact_hash(&runtime)?}}});
    fs::write(&broker, b"\x7fELFchanged")?;
    let error = image::build(&desired, &state, None)
        .err()
        .ok_or("changed broker accepted")?;
    assert!(
        error
            .to_string()
            .contains("Artifact changed since plan: worker"),
        "{error}"
    );
    use std::os::unix::fs::PermissionsExt;
    for entry in fs::read_dir(&state)? {
        let entry = entry?;
        assert_eq!(
            entry.metadata()?.permissions().mode() & 0o777,
            0o700,
            "staged native artifacts require a private build directory"
        );
    }
    // An old native artifact cannot be substituted into the fixed broker slot.
    desired["artifacts"]["worker"] = Value::Null;
    let error = image::build(&desired, &state, None)
        .err()
        .ok_or("missing broker accepted")?;
    assert!(
        error.to_string().contains("Missing broker artifact"),
        "{error}"
    );
    Ok(())
}
