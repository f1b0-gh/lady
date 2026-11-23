use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn broker_export_rejects_bad_request_without_writing_an_archive(
) -> Result<(), Box<dyn std::error::Error>> {
    for request in [br#"{"format":1,"token":"invalid","profile":{"control":{"bytes":65536,"inodes":32},"artifacts":{"bytes":65536,"inodes":32},"incoming":{"bytes":65536,"inodes":32}}}"#.to_vec(), vec![b' '; 16385]] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .arg("broker-export").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let _ = child.stdin.take().ok_or("stdin")?.write_all(&request);
        let result = child.wait_with_output()?;
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        let error = String::from_utf8(result.stderr)?;
        assert!(error.contains("Invalid export request") || error.contains("Export request exceeds"), "{error}");
    }
    Ok(())
}
