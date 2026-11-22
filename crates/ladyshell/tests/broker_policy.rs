use ladyshell::policy::{broker_policy, validate_broker_effective};
use serde_json::json;
#[test]
fn broker_policy_has_mandatory_landlock_no_network_and_only_bounded_writable_roots(
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = broker_policy();
    assert_eq!(policy["landlock"]["compatibility"], "hard_requirement");
    assert_eq!(policy["network_policies"], json!({}));
    assert_eq!(policy["filesystem_policy"]["include_workdir"], false);
    assert_eq!(
        policy["filesystem_policy"]["read_write"],
        json!([
            "/dev/null",
            "/var/lib/ladyshell/broker/control",
            "/var/lib/ladyshell/broker/artifacts",
            "/var/lib/ladyshell/broker/incoming"
        ])
    );
    validate_broker_effective(&policy)?;
    for field in ["/tmp", "/sandbox/workspace", "/var/run/docker.sock"] {
        let mut widened = policy.clone();
        widened["filesystem_policy"]["read_write"]
            .as_array_mut()
            .ok_or("paths")?
            .push(json!(field));
        assert!(validate_broker_effective(&widened).is_err());
    }
    let mut widened = policy.clone();
    widened["network_policies"] = json!({"injected":{"endpoints":[]}});
    assert!(validate_broker_effective(&widened).is_err());
    widened = policy.clone();
    widened["landlock"]["compatibility"] = json!("best_effort");
    assert!(validate_broker_effective(&widened).is_err());
    widened = policy.clone();
    widened["filesystem_policy"]["include_workdir"] = json!(true);
    assert!(validate_broker_effective(&widened).is_err());
    widened = policy.clone();
    widened["network_middlewares"] = json!({"injected":{}});
    assert!(validate_broker_effective(&widened).is_err());
    Ok(())
}

#[test]
fn empty_network_map_omission_in_effective_policy_still_means_no_rules(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut policy = broker_policy();
    policy
        .as_object_mut()
        .ok_or("policy")?
        .remove("network_policies");
    validate_broker_effective(&policy)?;
    policy["network_policies"] = json!(null);
    assert!(validate_broker_effective(&policy).is_err());
    Ok(())
}
