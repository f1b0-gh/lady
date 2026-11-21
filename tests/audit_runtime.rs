use ladyshell::audit::runtime::{agent_policy, target_policy, validate_policy};
use serde_json::json;
use std::error::Error;
const BIN: &str = "/nix/store/00000000000000000000000000000000-ladyshell-codex/bin/codex";
#[test]
fn refuses_any_target_network_or_writable_source() -> Result<(), Box<dyn Error>> {
    let expected = target_policy();
    validate_policy(&expected, &expected, None)?;
    for malformed in [json!([]), json!(null), json!(false)] {
        let mut p = expected.clone();
        p["network_policies"] = malformed;
        assert!(validate_policy(&p, &expected, None).is_err());
    }
    let mut p = expected.clone();
    p["network_policies"] = json!({"extra":{"binaries":[{"path":BIN}],"endpoints":[{"host":"example.com","port":443}]}});
    assert!(validate_policy(&p, &expected, None).is_err());
    let mut p = expected.clone();
    p["filesystem_policy"]["read_write"]
        .as_array_mut()
        .ok_or("array")?
        .push(json!("/audit/source"));
    assert!(validate_policy(&p, &expected, None).is_err());
    let mut p = expected.clone();
    p["landlock"]["compatibility"] = json!("best_effort");
    assert!(validate_policy(&p, &expected, None).is_err());
    Ok(())
}
#[test]
fn provider_duplicate_is_allowed_only_with_identical_endpoint_and_pinned_binary(
) -> Result<(), Box<dyn Error>> {
    let expected = agent_policy(BIN)?;
    let mut p = expected.clone();
    p["network_policies"]["provider"] = p["network_policies"]["openai_codex"].clone();
    validate_policy(&p, &expected, Some(BIN))?;
    p["network_policies"]["provider"]["endpoints"][0]["host"] = json!("extra.example");
    assert!(validate_policy(&p, &expected, Some(BIN)).is_err());
    p = expected.clone();
    p["network_policies"]["openai_codex"]["binaries"][0]["path"] = json!("/bin/bash");
    assert!(validate_policy(&p, &expected, Some(BIN)).is_err());
    p = expected.clone();
    p["network_policies"]["empty"] = json!({});
    assert!(validate_policy(&p, &expected, Some(BIN)).is_err());
    Ok(())
}
