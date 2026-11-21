use ladyshell::process::capture;
use std::{
    process::Command,
    time::{Duration, Instant},
};
#[test]
fn captures_success_and_rejects_failure() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("/bin/printf");
    command.arg("a b");
    assert_eq!(capture(command, Duration::from_secs(2), 100)?, b"a b");
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 7"]);
    assert!(capture(command, Duration::from_secs(2), 100).is_err());
    Ok(())
}
#[test]
fn terminates_excessive_output_and_process_tree_on_timeout(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("/usr/bin/yes");
    command.arg("data");
    assert!(capture(command, Duration::from_secs(2), 100).is_err());
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 10 & wait"]);
    let start = Instant::now();
    assert!(capture(command, Duration::from_millis(100), 100).is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
    Ok(())
}
#[test]
fn detached_descendant_cannot_hold_capture_pipes_open() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "setsid sleep 2 & wait"]);
    let start = Instant::now();
    assert!(capture(command, Duration::from_millis(100), 100).is_err());
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "Capture retained a detached child's pipes"
    );
    Ok(())
}

#[test]
fn captured_input_is_literal_bounded_and_does_not_block_on_unread_input(
) -> Result<(), Box<dyn std::error::Error>> {
    use ladyshell::process::capture_input;
    let input = b"$(touch should-not-exist)\nquoted ' \"\0 bytes";
    let command = Command::new("/bin/cat");
    assert_eq!(
        capture_input(command, input, Duration::from_secs(2), 1024)?,
        input
    );
    let mut command = Command::new("/bin/sleep");
    command.arg("10");
    let start = Instant::now();
    assert!(capture_input(
        command,
        &vec![b'x'; 1024 * 1024],
        Duration::from_millis(100),
        100
    )
    .is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    Ok(())
}
