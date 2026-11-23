use ladyshell::openshell::Backend;
use serde_json::{json, Value};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn probe(observed: Value, scenario: &str, transport: &str) -> TestResult {
    let directory = tempfile::tempdir()?;
    let observation = directory.path().join("observation.json");
    fs::write(&observation, serde_json::to_vec(&observed)?)?;
    let openshell = directory.path().join("openshell");
    fs::write(
        &openshell,
        r#"#!/bin/bash
set -euo pipefail
[[ "$*" == '--gateway test --workspace default --color never sandbox get fixture --output json' ]]
case "$LADYSHELL_BACKEND_TRANSPORT" in
  not-found) printf 'Sandbox not found\n' >&2; exit 1 ;;
  unavailable) printf 'Gateway unavailable\n' >&2; exit 1 ;;
  ok) /bin/cat "$LADYSHELL_BACKEND_OBSERVATION" ;;
  *) exit 99 ;;
esac
"#,
    )?;
    fs::set_permissions(&openshell, fs::Permissions::from_mode(0o700))?;
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", "identity_probe", "--nocapture"])
        .env_clear()
        .env("PATH", directory.path())
        .env("LADYSHELL_BACKEND_OBSERVATION", observation)
        .env("LADYSHELL_BACKEND_SCENARIO", scenario)
        .env("LADYSHELL_BACKEND_TRANSPORT", transport)
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn identity_probe() -> TestResult {
    let Ok(scenario) = std::env::var("LADYSHELL_BACKEND_SCENARIO") else {
        return Ok(());
    };
    let backend = Backend {
        gateway: "test".into(),
        workspace: "default".into(),
    };
    match scenario.as_str() {
        "broker-storage" => {
            let current = json!({"sandbox_name":"fixture","sandbox_id":"resource-id",
                "owner":"owner","policy_hash":"hash","image_profile":"openshell-worker-v1","storage":{}});
            let error = backend
                .verify_execution(&current)
                .err()
                .ok_or("missing broker storage accepted")?;
            assert!(
                error.to_string().contains("directory"),
                "broker must verify original storage instead of native provider fields: {error}"
            );
        }
        "unadmitted" => {
            let observed: Value = serde_json::from_slice(&fs::read(
                std::env::var_os("LADYSHELL_BACKEND_OBSERVATION").ok_or("observation")?,
            )?)?;
            let identity = backend
                .sandbox_identity("fixture")?
                .ok_or("identity absent")?;
            assert_eq!(identity["id"], "resource-id");
            assert_eq!(identity["phase"], observed["phase"]);
            assert_eq!(identity["labels"]["ladyshell.audit.owner"], "owner");
            assert_eq!(identity["conditions"], observed["conditions"]);
            assert!(identity.get("policy_hash").is_none());
            assert!(
                backend.sandbox("fixture").is_err(),
                "strict development observation accepted an empty hash"
            );
        }
        "ready" => {
            let identity = backend
                .sandbox_identity("fixture")?
                .ok_or("identity absent")?;
            assert_eq!(identity["id"], "resource-id");
            assert_eq!(identity["phase"], "Ready");
            assert!(identity.get("policy_hash").is_none());
            assert_eq!(
                backend
                    .sandbox("fixture")?
                    .ok_or("strict observation absent")?["policy_hash"],
                "hash"
            );
        }
        "invalid" => assert!(backend.sandbox_identity("fixture").is_err()),
        "not-found" => {
            assert!(backend.sandbox_identity("fixture")?.is_none());
            assert!(backend.sandbox("fixture")?.is_none());
        }
        "unavailable" => {
            assert!(backend.sandbox_identity("fixture").is_err());
            assert!(backend.sandbox("fixture").is_err());
        }
        _ => return Err("unknown scenario".into()),
    }
    Ok(())
}

#[test]
fn identity_observation_accepts_unadmitted_error_provisioning_and_ready() -> TestResult {
    for phase in ["Error", "Provisioning", "Ready"] {
        probe(
            json!({"id":"resource-id","phase":phase,"labels":{"ladyshell.audit.owner":"owner"},
            "configuration_admission":{"policy_hash":""},
            "conditions":[{"type":"Ready","status":"False","reason":"DriverError","message":"synthetic mount refusal"}]}),
            "unadmitted",
            "ok",
        )?;
    }
    Ok(())
}

#[test]
fn strict_observation_still_requires_the_ready_policy_hash() -> TestResult {
    probe(
        json!({"id":"resource-id","phase":"Ready","labels":{"ladyshell.audit.owner":"owner"},"configuration_admission":{"policy_hash":"hash"}}),
        "ready",
        "ok",
    )
}

#[test]
fn identity_observation_refuses_empty_ids_phases_and_malformed_labels() -> TestResult {
    for mut observed in [
        json!({"id":"","phase":"Ready","labels":{}}),
        json!({"phase":"Error","labels":{}}),
        json!({"id":"resource-id","phase":"","labels":{}}),
        json!({"id":"resource-id","phase":"Ready","labels":[]}),
        json!({"id":"resource-id","phase":"Ready","labels":{"ladyshell.audit.owner":42}}),
    ] {
        observed["configuration_admission"] = json!({"policy_hash":"hash"});
        probe(observed, "invalid", "ok")?;
    }
    Ok(())
}

#[test]
fn missing_resource_is_distinguished_from_transport_failure() -> TestResult {
    probe(json!({}), "not-found", "not-found")?;
    probe(json!({}), "unavailable", "unavailable")
}

#[test]
fn broker_execution_requires_its_original_storage_binding() -> TestResult {
    probe(
        json!({"id":"resource-id","phase":"Ready","labels":{"ladyshell.owner":"owner"},"configuration_admission":{"policy_hash":"hash"}}),
        "broker-storage",
        "ok",
    )
}
