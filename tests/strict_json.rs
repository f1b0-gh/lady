#[test]
fn rejects_duplicate_keys_at_any_depth() -> Result<(), Box<dyn std::error::Error>> {
    assert!(ladyshell::json::parse(br#"{"files":{"a":1,"a":2}}"#).is_err());
    assert_eq!(
        ladyshell::json::parse(br#"{"files":{"a":1}}"#)?["files"]["a"],
        1
    );
    Ok(())
}
