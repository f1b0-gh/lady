use serde_json::json;
#[test]
fn renders_changes_and_escapes_terminal_controls() -> Result<(), Box<dyn std::error::Error>> {
    let value = json!({"applied":true,"changes":[{"action":"modify","path":"README.md"},{"action":"add","path":"reports/a.md"},{"action":"delete","path":"old.zig"}],"conflicts":[],"backup":"/state/backup"});
    let mut out = Vec::new();
    ladyshell::presentation::sync(&value, &mut out)?;
    let text = String::from_utf8(out)?;
    assert!(text.contains("Modified README.md"));
    assert!(text.contains("3 changes applied"));
    assert!(text.contains("Backup retained"));
    let mut out = Vec::new();
    ladyshell::presentation::sync(
        &json!({"changes":[{"action":"add","path":"bad\u{1b}[31m"}],"conflicts":[]}),
        &mut out,
    )?;
    assert!(!out.contains(&27));
    Ok(())
}
