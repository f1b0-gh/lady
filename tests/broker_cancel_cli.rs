use std::process::Command;
#[test]
fn cancellation_selects_explicit_state_without_loading_native_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("state");
    ladyshell::state::create_directory(&directory)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["cancel-broker", "--state"])
        .arg(&directory)
        .env("PATH", root.path())
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Original provisioning operation missing"),
        "{output:?}"
    );
    assert!(!directory.join("broker-cancel.json").exists());
    Ok(())
}
