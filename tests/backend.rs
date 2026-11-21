use ladyshell::openshell::Backend;
use serde_json::json;
#[test]
fn backend_pins_context_and_does_not_use_shell_arguments() -> Result<(), Box<dyn std::error::Error>>
{
    let backend = Backend::new(&json!({"gateway":"host-a","workspace":"dev"}))?;
    let command = backend.command();
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [
            "--gateway",
            "host-a",
            "--workspace",
            "dev",
            "--color",
            "never"
        ]
    );
    assert!(Backend::new(&json!({"gateway":"x; sh","workspace":"dev"})).is_err());
    Ok(())
}
