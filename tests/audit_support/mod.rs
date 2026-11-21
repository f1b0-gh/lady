#![allow(dead_code)]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    path::Path,
    process::{Command, Output},
};
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn command(args: &[&str], path: &Path) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .env_clear()
        .arg("audit")
        .args(args)
        .arg(path)
        .output()?)
}
pub fn write_json(path: &Path, value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, &bytes)?;
    Ok(bytes)
}
pub fn edit_metadata(root: &Path, pointer: &str, value: Value) -> Result<(), Box<dyn Error>> {
    let path = root.join("run-metadata.json");
    let mut meta: Value = serde_json::from_slice(&fs::read(&path)?)?;
    *meta.pointer_mut(pointer).ok_or("missing field")? = value;
    write_json(&path, &meta)?;
    Ok(())
}

pub fn replace_document(root: &Path, name: &str, value: &Value) -> Result<(), Box<dyn Error>> {
    let bytes = write_json(&root.join(name), value)?;
    edit_metadata(root, &format!("/documents/{name}"), json!(hash(&bytes)))
}
pub fn close_run(root: &Path) -> Result<(), Box<dyn Error>> {
    edit_metadata(root, "/status", json!("complete"))?;
    edit_metadata(root, "/open_obligations", json!([]))?;
    edit_metadata(root, "/environment_verified", json!(true))?;
    edit_metadata(root, "/cleanup_verified", json!(true))?;
    let mut meta: Value = serde_json::from_slice(&fs::read(root.join("run-metadata.json"))?)?;
    meta["invocations"]
        .as_array_mut()
        .ok_or("invocations")?
        .push(json!({"id":"critic","role":"critic","status":"finished"}));
    write_json(&root.join("run-metadata.json"), &meta)?;
    Ok(())
}
pub fn fixture(confirmed: bool) -> Result<tempfile::TempDir, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let mut findings = json!([]);
    let mut coverage = json!([]);
    let mut links = json!([]);
    let mut invocations = json!([]);
    let mut artifacts = json!([]);
    if confirmed {
        let all: Value = serde_json::from_str(include_str!("../fixtures/audit/findings.json"))?;
        findings = json!([all[0]]);
        coverage = serde_json::from_str(include_str!("../fixtures/audit/coverage.json"))?;
        let unit = &mut coverage[0];
        unit["status"] = json!("candidate");
        unit["agent_id"] = json!("hunter");
        unit["reviewed_paths"] = json!(["src/handler.c"]);
        unit["local_checks"] = json!([{"agent_id":"hunter","reviewed_paths":["src/handler.c"],"invariant":"ownership","method":"source","result":"candidate","artifact":null}]);
        unit["result_fingerprints"] = json!([all[0]["fingerprint"]]);
        let proof_path = "agents/verifier/artifacts/proof.txt";
        fs::create_dir_all(root.join("agents/verifier/artifacts"))?;
        fs::write(root.join(proof_path), "synthetic evidence")?;
        artifacts = json!([{"id":"proof","path":proof_path,"size":18,"sha256":hash(b"synthetic evidence"),"producer":"verifier","command":["synthetic-check"]}]);
        links = json!([{"fingerprint":all[0]["fingerprint"],"coverage_ids":[unit["coverage_id"]],"artifact_ids":["proof"],"hunter_id":"hunter","verifier_id":"verifier"}]);
        invocations = json!([{"id":"hunter","role":"hunter","status":"finished"},{"id":"verifier","role":"verifier","status":"finished"}]);
    }
    let sources = json!({"schema_version":1,"files":(["src/handler.c","src/model.c","src/store.c","src/router.ts","src/authz.ts"].map(|path| json!({"path":path,"size":0,"sha256":hash(b"")})))});
    let manifest = json!({"schema_version":1,"artifacts":artifacts});
    let mut documents = serde_json::Map::new();
    for (name, value) in [
        ("findings.json", findings),
        ("coverage-ledger.json", coverage),
        ("source-manifest.json", sources),
        ("evidence-manifest.json", manifest),
    ] {
        let bytes = write_json(&root.join(name), &value)?;
        documents.insert(name.into(), json!(hash(&bytes)));
    }
    write_json(
        &root.join("run-metadata.json"),
        &json!({"schema_version":1,"document_schema":"upstream-v1","run_id":"synthetic-test","status":"partial","profile":"quick","scope_paths":["src"],"config_sha256":hash(b"config"),"toolchain_sha256":hash(b"tools"),"method_sha256":hash(b"method"),"documents":documents,"links":links,"invocations":invocations,"budget":{"invocations":10,"seconds":60},"elapsed_seconds":1,"open_obligations":["partial scope"],"environment_verified":false,"cleanup_verified":false}),
    )?;
    Ok(dir)
}
