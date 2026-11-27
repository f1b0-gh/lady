use ladyshell::{config::Config, policy};
use serde_json::{json, Value};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const BINARY: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ladyshell-codex/bin/codex";
fn config() -> Value {
    json!({"schema_version":1,"name":"offline","sources":{"include":[],"exclude":[]},
        "tools":{},"missions":{"dev":{"tools":[],"include":[],"depends_on":[],"checks":[["/bin/true"]]}},
        "sandbox":{"gateway":"g","workspace":"w","mode":"offline"}})
}
#[test]
fn offline_is_explicit_and_refuses_providers_network_requests_and_agent_audits() -> Result<()> {
    let value = config();
    Config::from_value(value.clone())?.resolve("dev")?;
    for (pointer, replacement) in [
        ("/sandbox/mode", json!("provider")),
        ("/sandbox/mode", json!("unknown")),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(pointer).ok_or("pointer")? = replacement;
        assert!(Config::from_value(bad).is_err());
    }
    let mut bad = value.clone();
    bad["sandbox"]["provider"] = json!("dummy");
    assert!(Config::from_value(bad).is_err());
    let mut bad = value.clone();
    bad["audit"] = json!({"profile":"quick","scope_paths":["src"],"exclude_paths":[],"tools":{},"checks":[],
        "budget":{"invocations":1,"seconds":60},"limits":{"cpu_seconds":5,"memory_bytes":1048576,"processes":8,"files":32,"disk_bytes":1048576}});
    assert!(Config::from_value(bad).is_err());
    let mut bad = value;
    bad["permissions"] = json!({"network":[{"tool":"codex","host":"api.openai.com","port":443,"justification":"unwanted"}],"filesystem":[]});
    assert!(Config::from_value(bad).is_err());
    Ok(())
}
#[test]
fn offline_policy_requires_no_network_or_middleware_and_preserves_confinement() -> Result<()> {
    let policy = policy::offline_policy();
    assert_eq!(policy["network_policies"], json!({}));
    policy::validate_offline_effective(&policy)?;
    assert!(policy::validate_effective(&policy, BINARY).is_err());
    assert!(policy::validate_offline_effective(&policy::native_policy(BINARY)?).is_err());
    for (key, value) in [
        (
            "network_policies",
            json!({"unused":{"endpoints":[],"binaries":[]}}),
        ),
        ("network_policies", Value::Null),
        ("network_middlewares", json!({"credentials":{}})),
        ("landlock", json!({"compatibility":"best_effort"})),
        (
            "process",
            json!({"run_as_user":"root","run_as_group":"root"}),
        ),
    ] {
        let mut bad = policy.clone();
        bad[key] = value;
        assert!(policy::validate_offline_effective(&bad).is_err(), "{key}");
    }
    let mut omitted = policy;
    omitted
        .as_object_mut()
        .ok_or("policy")?
        .remove("network_policies");
    policy::validate_offline_effective(&omitted)?;
    Ok(())
}

#[test]
fn default_mode_preserves_provider_requirement_and_serialized_config() -> Result<()> {
    let mut value = config();
    value["sandbox"]
        .as_object_mut()
        .ok_or("sandbox")?
        .remove("mode");
    assert!(Config::from_value(value.clone()).is_err());
    value["sandbox"]["provider"] = json!("selected");
    let resolved = serde_json::to_value(Config::from_value(value)?.resolve("dev")?)?;
    assert!(resolved["sandbox"].get("mode").is_none());
    Ok(())
}
#[test]
fn offline_interactive_commands_refuse_model_sessions() -> Result<()> {
    use ladyshell::{
        interactive::{command, Kind},
        openshell::Backend,
    };
    let backend = Backend::new(&json!({"gateway":"g","workspace":"w"}))?;
    let state = json!({"sandbox_name":"offline", "sandbox_mode":"offline"});
    command(&backend, &state, Kind::Shell, None)?;
    assert!(command(&backend, &state, Kind::Chat, Some("unused")).is_err());
    assert!(command(&backend, &state, Kind::Resume, Some("unused")).is_err());
    Ok(())
}
