use ladyshell::{
    error::{exit_code, Error},
    process::capture,
};
use std::{process::Command, time::Duration};
#[test]
fn process_errors_retain_distinct_types_and_sources() -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 7"]);
    let error = capture(command, Duration::from_secs(1), 1024)
        .err()
        .ok_or("expected error")?;
    assert!(matches!(&error,Error::ProcessExit{status,..} if status.code()==Some(7)));
    assert_eq!(exit_code(&error), 1);
    let mut command = Command::new("/bin/sleep");
    command.arg("2");
    let error = capture(command, Duration::from_millis(10), 1024)
        .err()
        .ok_or("expected timeout")?;
    assert!(matches!(&error, Error::ProcessTimeout { .. }));
    let wrapped = Error::Nickel {
        source: Box::new(error),
    };
    assert_eq!(wrapped.exit_code(), 1);
    assert!(std::error::Error::source(&wrapped).is_some());
    Ok(())
}
