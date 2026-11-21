use std::{
    ffi::OsString,
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    process::Command,
};

fn marker_tool(directory: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let path = directory.join("ladyboot");
    fs::write(
        &path,
        "#!/bin/sh\nprintf executed > \"$ARTIFACT_MARKER\"\nexit 37\n",
    )?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

#[test]
fn retired_artifact_invocations_never_execute_path_or_override_tools(
) -> Result<(), Box<dyn std::error::Error>> {
    let cases: Vec<(Vec<OsString>, i32)> = vec![
        (vec!["artifact".into()], 2),
        (vec!["artifact".into(), "check".into()], 2),
        (vec!["artifact".into(), "--help".into()], 0),
        (vec!["artifact".into(), "-h".into()], 0),
        (vec!["help".into(), "artifact".into()], 0),
        (vec!["artifact".into(), "--".into(), "--help".into()], 2),
        (
            vec![
                "artifact".into(),
                "inspect".into(),
                "--receipt".into(),
                OsString::from_vec(b"hostile path-\xff.json".to_vec()),
            ],
            2,
        ),
    ];
    for override_tool in [false, true] {
        for (arguments, code) in &cases {
            let temp = tempfile::tempdir()?;
            let child = marker_tool(temp.path())?;
            let marker = temp.path().join("executed");
            let mut command = Command::new(env!("CARGO_BIN_EXE_ladyshell"));
            command
                .args(arguments)
                .env_clear()
                .env("PATH", temp.path())
                .env("HOME", temp.path())
                .env("ARTIFACT_MARKER", &marker)
                .current_dir(temp.path());
            if override_tool {
                command.env("LADYSHELL_BOOTC_BIN", child);
            }
            let output = command.output()?;
            assert!(!marker.exists(), "External tool ran for {arguments:?}");
            assert_eq!(output.status.code(), Some(*code), "{output:?}");
            let text = String::from_utf8(if *code == 0 {
                assert!(output.stderr.is_empty());
                output.stdout
            } else {
                assert!(output.stdout.is_empty());
                output.stderr
            })?;
            assert!(text.contains("ladyboot"), "{text}");
            assert!(text.contains("directly"), "{text}");
            assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        }
    }
    Ok(())
}

#[test]
fn retired_artifact_does_not_require_an_installed_ladyboot(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["artifact", "--help"])
        .env_clear()
        .env("PATH", temp.path())
        .env("LADYSHELL_BOOTC_BIN", temp.path().join("missing"))
        .output()?;
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8(output.stdout)?.contains("ladyboot"));
    assert_eq!(fs::read_dir(temp.path())?.count(), 0);
    Ok(())
}
