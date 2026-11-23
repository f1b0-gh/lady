use ladyshell::{app, request::BrokerDesired};
use serde_json::Value;
use std::{fs, path::Path};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn explicit_broker_inputs_keep_the_embedding_executable_out_of_the_image() -> Result<()> {
    let root = tempfile::tempdir()?;
    let project = root.path().join("project");
    fs::create_dir(&project)?;
    fs::write(project.join("README.md"), "Synthetic broker task inputs\n")?;
    let config = root.path().join("broker.ncl");
    fs::write(
        &config,
        r#"{
        schema_version = 1, name = "broker-fixture",
        image = {backend = "nix", profile = "openshell-worker-v1", platform = "x86_64-linux"},
        sources = {include = ["README.md"], exclude = []}, tools = {},
        missions = { dev = {tools = [], include = [], depends_on = [], checks = []} },
        sandbox = {gateway = "unused", workspace = "default"},
        storage = {control = {bytes = 65536, inodes = 32},
            artifacts = {bytes = 262144, inodes = 64}, incoming = {bytes = 262144, inodes = 64}},
    }"#,
    )?;
    let worker = root.path().join("worker");
    let runtime = root.path().join("runtime");
    fs::copy("/bin/true", &worker)?;
    fs::copy("/bin/false", &runtime)?;
    let args = BrokerDesired {
        config,
        project,
        state: root.path().join("state"),
        resources: Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf(),
        worker,
        runtime,
        lock: Some(root.path().join("broker.lock.json")),
        ladybom: None,
        mission: "dev".into(),
    };
    assert!(
        app::desired_broker(&args).is_err(),
        "missing explicit environment lock"
    );
    app::lock_broker(&args)?;
    let desired = app::desired_broker(&args)?;
    assert_eq!(
        desired["artifacts"].as_object().ok_or("artifacts")?.len(),
        2
    );
    assert_eq!(
        desired["artifacts"]["worker"]["path"],
        args.worker.to_str().ok_or("worker")?
    );
    assert_eq!(
        desired["artifacts"]["ladyshell"]["path"],
        args.runtime.to_str().ok_or("runtime")?
    );
    assert_ne!(
        desired["artifacts"]["ladyshell"]["path"],
        std::env::current_exe()?
            .to_str()
            .ok_or("current executable")?
    );
    assert_eq!(desired["dependency_scan"]["complete"], true);
    let plan = app::make_broker_plan(&args)?;
    assert_eq!(plan["desired"], desired);
    assert_eq!(plan["blocked"], false);
    let retained: Value = serde_json::from_slice(&fs::read(args.state.join("plan.json"))?)?;
    assert_eq!(retained, plan);
    fs::copy("/bin/false", &args.worker)?;
    assert!(
        app::desired_broker(&args).is_err(),
        "changed native broker must require explicit relock"
    );
    Ok(())
}
