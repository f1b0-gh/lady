use ladyshell::audit::{
    agent::{self, TargetCheck},
    run,
};
use serde_json::Value;
#[test]
fn confirmation_requires_independent_matching_execution() -> Result<(), Box<dyn std::error::Error>>
{
    let findings: Vec<Value> = serde_json::from_str(include_str!("fixtures/audit/findings.json"))?;
    let confirmed = &findings[0];
    assert!(run::validate_disposition(confirmed, confirmed, false).is_err());
    run::validate_disposition(confirmed, confirmed, true)?;
    let mut changed = confirmed.clone();
    changed["fingerprint"] = Value::String("different".into());
    assert!(run::validate_disposition(confirmed, &changed, true).is_err());
    let check = TargetCheck {
        argv: vec!["printf".into(), "witness".into()],
        expected_exit: 0,
        expected_stdout: "witness".into(),
        artifacts: vec![],
    };
    agent::validate_check(&check)?;
    assert!(run::oracle_matches(&check, 0, false, false, b"witness"));
    assert!(!run::oracle_matches(&check, 0, true, false, b"witness"));
    assert!(!run::oracle_matches(&check, 1, false, false, b"witness"));
    assert!(!run::oracle_matches(&check, 0, false, false, b"different"));
    let mut no_oracle = check;
    no_oracle.expected_stdout.clear();
    assert!(!run::oracle_matches(&no_oracle, 0, false, false, b""));
    Ok(())
}
