use ladyshell::{
    auth,
    interactive::{self, Kind},
    openshell::Backend,
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
};
const ACCOUNT: &str = "12345678-1234-5678-9abc-123456789abc";
const REFERENCE: &str = "openshell:resolve:env:CODEX_AUTH_ACCESS_TOKEN";
#[test]
fn auth_contains_only_opaque_access_and_synthetic_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    auth::prepare(temp.path(), REFERENCE, ACCOUNT, 1700000000)?;
    let path = temp.path().join("auth.json");
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    assert_eq!(value["tokens"]["access_token"], REFERENCE);
    assert_eq!(value["tokens"]["account_id"], ACCOUNT);
    assert_eq!(value["tokens"]["refresh_token"], "");
    assert_eq!(value["last_refresh"], "2023-11-14T22:13:20Z");
    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    Ok(())
}
#[test]
fn auth_rejects_raw_tokens_bad_uuid_and_symlink_ancestors() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    for (reference, account) in [
        ("secret-marker", ACCOUNT),
        (REFERENCE, "bad"),
        (
            "openshell:resolve:env:OTHER_CODEX_AUTH_ACCESS_TOKEN",
            ACCOUNT,
        ),
    ] {
        let error = auth::prepare(temp.path(), reference, account, 1700000000)
            .err()
            .ok_or("expected refusal")?;
        assert!(!error.to_string().contains("secret-marker"));
    }
    let target = temp.path().join("target");
    fs::create_dir(&target)?;
    symlink(&target, temp.path().join("link"))?;
    assert!(auth::prepare(
        &temp.path().join("link/nested"),
        REFERENCE,
        ACCOUNT,
        1700000000
    )
    .is_err());
    assert!(!target.join("nested").exists());
    symlink(temp.path().join("victim"), target.join("auth.json"))?;
    assert!(auth::prepare(&target, REFERENCE, ACCOUNT, 1700000000).is_err());
    Ok(())
}
#[test]
fn native_arguments_preserve_shell_and_resume_contract() -> Result<(), Box<dyn std::error::Error>> {
    let backend = Backend::new(&json!({"gateway":"local", "workspace":"default"}))?;
    let state = json!({"sandbox_name":"test", "codex_binary":"/usr/local/bin/codex"});
    let shell = interactive::command(&backend, &state, Kind::Shell, None)?;
    let args: Vec<_> = shell
        .get_args()
        .map(|x| x.to_string_lossy().into_owned())
        .collect();
    assert!(args
        .windows(4)
        .any(|w| w == ["sandbox", "exec", "--tty", "--no-login-shell"]));
    assert_eq!(&args[args.len() - 3..], ["--", "/bin/bash", "-i"]);
    for variable in [
        "PKG_CONFIG_PATH=/usr/local/lib/ladyshell/pkgconfig",
        "LD_LIBRARY_PATH=/usr/local/lib/ladyshell",
    ] {
        assert!(args.windows(2).any(|w| w == ["--env", variable]));
    }
    let chat = interactive::command(&backend, &state, Kind::Resume, Some(ACCOUNT))?;
    let args: Vec<_> = chat
        .get_args()
        .map(|x| x.to_string_lossy().into_owned())
        .collect();
    assert_eq!(&args[args.len() - 2..], ["resume", "--last"]);
    assert!(args
        .windows(2)
        .any(|w| w == ["--sandbox", "danger-full-access"]));
    assert!(args
        .windows(2)
        .any(|w| w == ["-C", "/sandbox/workspace/project"]));
    assert!(interactive::command(&backend, &state, Kind::Chat, None).is_err());
    Ok(())
}
#[test]
fn continuous_resume_uses_explicit_context_instead_of_unbound_history(
) -> Result<(), Box<dyn std::error::Error>> {
    let backend = Backend::new(&json!({"gateway":"local", "workspace":"default"}))?;
    for epoch in [0, 1, 32] {
        let state = json!({"sandbox_name":"test", "codex_binary":"/usr/local/bin/codex",
            "continuous":{"epoch":epoch}});
        let command = interactive::command(&backend, &state, Kind::Resume, Some(ACCOUNT))?;
        let args: Vec<_> = command
            .get_args()
            .map(|x| x.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|arg| arg == "--last"));
        assert_eq!(
            args.iter()
                .any(|arg| arg.contains(".ladyshell-cs/context.json")),
            epoch > 0
        );
    }
    Ok(())
}
#[test]
fn host_identity_reads_only_account_and_redacts_errors() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("auth.json");
    fs::write(
        &path,
        serde_json::to_vec(
            &json!({"tokens":{"account_id":ACCOUNT,"access_token":"SECRET","id_token":"SECRET"}}),
        )?,
    )?;
    assert_eq!(auth::host_account(&path)?, ACCOUNT);
    fs::write(&path, b"SECRET malformed json")?;
    let error = auth::host_account(&path).err().ok_or("expected refusal")?;
    assert!(!error.to_string().contains("SECRET"));
    assert!(auth::host_account(Path::new("/missing/auth.json")).is_err());
    Ok(())
}
#[test]
fn terminal_status_preserves_exit_and_signal_codes() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        interactive::terminal_status(
            std::process::Command::new("/bin/sh").args(["-c", "exit 37"])
        )?,
        37
    );
    assert_eq!(
        interactive::terminal_status(
            std::process::Command::new("/bin/sh").args(["-c", "kill -TERM $$"])
        )?,
        143
    );
    assert!(
        interactive::terminal_status(&mut std::process::Command::new(
            "/no-such-ladyshell-command"
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn terminal_forwards_parent_termination_and_keeps_waiting_for_child(
) -> Result<(), Box<dyn std::error::Error>> {
    // Separate helper process avoids delivering test signals to the parallel test runner.
    let exe = std::env::current_exe()?;
    let temp = tempfile::tempdir()?;
    let ready = temp.path().join("ready");
    let done = temp.path().join("done");
    let mut helper = std::process::Command::new(exe)
        .args(["--exact", "terminal_signal_helper", "--nocapture"])
        .env("LADYSHELL_SIGNAL_READY", &ready)
        .env("LADYSHELL_SIGNAL_DONE", &done)
        .spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(ready.exists());
    // SAFETY: helper owns this live child PID, signal is valid.
    assert_eq!(unsafe { libc::kill(helper.id() as i32, libc::SIGTERM) }, 0);
    let status = helper.wait()?;
    assert!(status.success());
    assert_eq!(fs::read_to_string(done)?, "forwarded");
    Ok(())
}
#[test]
fn terminal_signal_helper() -> Result<(), Box<dyn std::error::Error>> {
    let Some(ready) = std::env::var_os("LADYSHELL_SIGNAL_READY") else {
        return Ok(());
    };
    let done = std::env::var_os("LADYSHELL_SIGNAL_DONE").ok_or("done missing")?;
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c","trap 'printf forwarded > \"$2\"; exit 23' TERM; : > \"$1\"; while :; do sleep 0.1; done","helper"]).arg(ready).arg(done);
    assert_eq!(interactive::terminal_status(&mut command)?, 23);
    Ok(())
}
#[test]
fn terminal_preserves_pty_input_and_output() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::process::CommandExt,
        },
        process::Stdio,
    };
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: output descriptors are writable; default terminal settings are requested.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openpty succeeded and returned uniquely owned descriptors.
    let mut master = unsafe { fs::File::from_raw_fd(master) };
    // SAFETY: ownership of the second openpty descriptor is transferred once.
    let slave = unsafe { fs::File::from_raw_fd(slave) };
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["--exact", "terminal_pty_helper", "--nocapture"])
        .env("LADYSHELL_PTY_HELPER", "1")
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    // SAFETY: pre_exec invokes only async-signal-safe session/terminal syscalls.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    master.write_all(b"keyboard\n")?;
    let mut output = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to a valid single-element pollfd buffer.
        if unsafe { libc::poll(&mut poll, 1, 100) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if poll.revents & libc::POLLIN != 0 {
            let mut buffer = [0; 4096];
            let size = master.read(&mut buffer)?;
            output.extend_from_slice(&buffer[..size]);
        }
        if child.try_wait()?.is_some() {
            break;
        }
    }
    if child.try_wait()?.is_none() {
        child.kill()?;
        return Err("PTY helper timed out".into());
    }
    assert!(child.wait()?.success());
    assert!(String::from_utf8_lossy(&output).contains("received:keyboard"));
    Ok(())
}
#[test]
fn terminal_pty_helper() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("LADYSHELL_PTY_HELPER").is_none() {
        return Ok(());
    }
    assert_eq!(interactive::terminal_status(std::process::Command::new("/bin/sh").args(["-c","test -t 0 && test -t 1 || exit 8; read -r line; printf 'received:%s\\n' \"$line\"; exit 19"]))?,19);
    Ok(())
}

fn run_fixture(root: &Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let state = root.join("state");
    ladyshell::state::create_directory(&state)?;
    let binary = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ladyshell-codex/bin/codex";
    fs::write(
        state.join("state.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_name":"test","sandbox_id":"id","policy_hash":"hash","codex_binary":binary,"owner":"owner","owner_label":"ladyshell.owner","desired_hash":"desired","image_id":"image","project_snapshot":"snapshot","build_dir":root,"context":{"gateway":"local","workspace":"default"}}),
        )?,
    )?;
    fs::write(
        root.join("observed.json"),
        serde_json::to_vec(
            &json!({"id":"id","phase":"Ready","configuration_admission":{"state":"accepted","policy_hash":"hash"},"labels":{"ladyshell.owner":"owner"}}),
        )?,
    )?;
    fs::write(
        root.join("policy.json"),
        serde_json::to_vec(&json!({"policy":ladyshell::policy::native_policy(binary)?}))?,
    )?;
    let script = root.join("openshell");
    fs::write(&script,"#!/bin/sh\ncase \"$7:$8\" in\nsandbox:get) cat \"$LADYSHELL_RUN_ROOT/observed.json\";;\npolicy:get) cat \"$LADYSHELL_RUN_ROOT/policy.json\";;\nsandbox:exec) : > \"$LADYSHELL_RUN_ROOT/ready\"; while test ! -f \"$LADYSHELL_RUN_ROOT/release\"; do sleep 0.02; done; exit 17;;\n*) exit 45;;\nesac\n")?;
    fs::set_permissions(script, fs::Permissions::from_mode(0o700))?;
    Ok(state)
}
fn run_helper(
    root: &Path,
    refusal: bool,
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    Ok(std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "interactive_run_helper", "--nocapture"])
        .env("LADYSHELL_RUN_ROOT", root)
        .env("LADYSHELL_RUN_REFUSAL", if refusal { "1" } else { "0" })
        .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
        .spawn()?)
}
#[test]
fn interactive_holds_session_lease_but_releases_state_lock(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let state = run_fixture(temp.path())?;
    let mut child = run_helper(temp.path(), false)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !temp.path().join("ready").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(temp.path().join("ready").exists());
    let lock = ladyshell::state::StateLock::acquire(&state)?;
    assert!(ladyshell::state::SessionLock::acquire(&state, true).is_err());
    let shared = ladyshell::state::SessionLock::acquire(&state, false)?;
    drop(shared);
    drop(lock);
    fs::write(temp.path().join("release"), b"")?;
    assert!(child.wait()?.success());
    let _exclusive = ladyshell::state::SessionLock::acquire(&state, true)?;
    Ok(())
}
#[test]
fn interactive_refuses_changed_identity_owner_policy_and_phase(
) -> Result<(), Box<dyn std::error::Error>> {
    for field in ["id", "owner", "policy", "phase"] {
        let temp = tempfile::tempdir()?;
        run_fixture(temp.path())?;
        let path = temp.path().join("observed.json");
        let mut observed: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        match field {
            "id" => observed["id"] = json!("different"),
            "owner" => observed["labels"]["ladyshell.owner"] = json!("different"),
            "policy" => observed["configuration_admission"]["policy_hash"] = json!("different"),
            _ => observed["phase"] = json!("Pending"),
        };
        fs::write(path, serde_json::to_vec(&observed)?)?;
        assert!(run_helper(temp.path(), true)?.wait()?.success());
        assert!(!temp.path().join("ready").exists());
    }
    Ok(())
}
#[test]
fn interactive_run_helper() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = std::env::var_os("LADYSHELL_RUN_ROOT") else {
        return Ok(());
    };
    let result = interactive::run(&Path::new(&root).join("state"), Kind::Shell);
    if std::env::var("LADYSHELL_RUN_REFUSAL")? == "1" {
        assert!(result.is_err());
    } else {
        assert_eq!(result?, 17);
    }
    Ok(())
}
#[test]
fn terminal_disconnect_reports_hangup_exit_code() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        os::{fd::FromRawFd, unix::process::CommandExt},
        process::Stdio,
    };
    let temp = tempfile::tempdir()?;
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: writable descriptor pointers, default PTY settings.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the PTY descriptors are valid; the child must not inherit the master.
    if unsafe { libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the successful openpty call returned newly owned descriptors.
    let master = unsafe { fs::File::from_raw_fd(master) };
    // SAFETY: slave is the other newly owned descriptor.
    let slave = unsafe { fs::File::from_raw_fd(slave) };
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["--exact", "terminal_disconnect_helper", "--nocapture"])
        .env("LADYSHELL_DISCONNECT_ROOT", temp.path())
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    // SAFETY: only async-signal-safe syscalls run between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !temp.path().join("ready").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(temp.path().join("ready").exists());
    drop(master);
    while child.try_wait()?.is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if child.try_wait()?.is_none() {
        child.kill()?;
        return Err("Disconnect helper timed out".into());
    }
    assert!(child.wait()?.success());
    assert_eq!(fs::read_to_string(temp.path().join("status"))?, "129");
    Ok(())
}
#[test]
fn terminal_disconnect_helper() -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = std::env::var_os("LADYSHELL_DISCONNECT_ROOT") else {
        return Ok(());
    };
    let status = interactive::terminal_status(
        std::process::Command::new("/bin/sh")
            .args(["-c", ": > \"$1\"; while :; do sleep 0.1; done", "helper"])
            .arg(Path::new(&root).join("ready")),
    )?;
    fs::write(Path::new(&root).join("status"), status.to_string())?;
    // The test harness itself cannot print its summary after its PTY has disconnected.
    std::process::exit(0)
}
#[test]
fn auth_accepts_versioned_openshell_reference_without_raw_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let home = tempfile::tempdir()?;
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700))?;
    let reference = "openshell:resolve:env:v12_CODEX_AUTH_ACCESS_TOKEN";
    auth::prepare(home.path(), reference, ACCOUNT, 1700000000)?;
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(home.path().join("auth.json"))?)?;
    assert_eq!(value["tokens"]["access_token"], reference);
    for invalid in [
        "openshell:resolve:env:vX_CODEX_AUTH_ACCESS_TOKEN",
        "openshell:resolve:env:v12_OTHER_CODEX_AUTH_ACCESS_TOKEN",
        "raw-token",
    ] {
        assert!(auth::prepare(home.path(), invalid, ACCOUNT, 1700000000).is_err());
    }
    Ok(())
}
