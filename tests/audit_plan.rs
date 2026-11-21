use serde_json::{json, Value};
use std::{error::Error, fs, process::Command};

fn audit_config() -> Value {
    json!({"profile":"quick","scope_paths":["src"],"exclude_paths":[],"tools":{},"checks":[["test-tool","--offline"]],"budget":{"invocations":8,"seconds":300},"limits":{"cpu_seconds":30,"memory_bytes":268435456,"processes":32,"files":128,"disk_bytes":67108864}})
}
#[test]
fn config_rejects_weak_limits_and_plan_does_not_execute_or_modify_state(
) -> Result<(), Box<dyn Error>> {
    let config: ladyshell::audit::config::AuditConfig = serde_json::from_value(audit_config())?;
    config.validate()?;
    for (pointer, value) in [
        ("/limits/processes", json!(0)),
        ("/limits/cpu_seconds", json!(4)),
        ("/scope_paths", json!(["../outside"])),
        ("/checks", json!([[]])),
        ("/budget/seconds", json!(0)),
    ] {
        let mut value_config = audit_config();
        *value_config.pointer_mut(pointer).ok_or("field")? = value;
        let parsed: ladyshell::audit::config::AuditConfig = serde_json::from_value(value_config)?;
        assert!(parsed.validate().is_err(), "{pointer}");
    }
    let dir = tempfile::tempdir()?;
    let project = dir.path().join("project");
    let state = dir.path().join("state");
    fs::create_dir_all(project.join("src"))?;
    fs::create_dir(&state)?;
    fs::write(project.join("src/file.rs"), "project data, never execute")?;
    let v = json!({"schema_version":2,"sandbox_name":"existing","sandbox_id":"id","policy_hash":"hash","codex_binary":"/bin/codex","owner":"owner","desired_hash":"hash","image_id":"image","project_snapshot":project,"build_dir":"/build","context":{"gateway":"openshell","workspace":"default"},"desired_inputs":{"project":project,"evaluated":{"config":{"audit":audit_config(),"sources":{"include":["src"],"exclude":[]}}}}});
    let bytes = serde_json::to_vec(&v)?;
    fs::write(state.join("state.json"), &bytes)?;
    for op in ["plan", "run"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .env_clear()
            .args(["audit", op, "--state"])
            .arg(&state)
            .output()?;
        assert_eq!(output.status.code(), Some(2), "{:?}", output);
        let value: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(value["blocked"], true);
        assert_eq!(value["target_executed"], false);
        assert!(value["inputs"]["source_snapshot"].is_object());
        assert!(value["blockers"]
            .as_array()
            .ok_or("blockers")?
            .iter()
            .any(|b| b["code"] == "runtime_preflight_required"));
        assert!(!value["blockers"].as_array().ok_or("blockers")?.is_empty());
    }
    assert_eq!(fs::read(state.join("state.json"))?, bytes);
    assert_eq!(fs::read_dir(&state)?.count(), 1);
    let mut small = v.clone();
    small["desired_inputs"]["evaluated"]["config"]["audit"]["budget"]["invocations"] = json!(6);
    fs::write(state.join("state.json"), serde_json::to_vec(&small)?)?;
    let value = ladyshell::audit::plan::make(&state, None, false)?;
    assert!(value["blockers"]
        .as_array()
        .ok_or("blockers")?
        .iter()
        .any(|b| b["code"] == "insufficient_budget"));
    Ok(())
}
