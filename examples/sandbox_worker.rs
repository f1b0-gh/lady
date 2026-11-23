//! Independent fixture for the sandbox-worker contract; not an application runner.
//! It echoes opaque JSON, retains results, and supports capped binary intake.
use ladyshell::{files, sandbox_worker::PROTOCOL};
use serde_json::{json, Value};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn lock(control: &Path, exclusive: bool) -> Result<File> {
    let file = files::open_directory(control)?;
    let mode = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    // SAFETY: the owned descriptor stays open for the entire guarded operation.
    if unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}
fn directory(path: &Path) -> Result<()> {
    DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
fn digest(text: &str) -> Result<()> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid digest".into());
    }
    Ok(())
}
fn lifecycle(control: &Path, input: &Value) -> Result<Value> {
    if input["format"] != 1 {
        return Err("unsupported control format".into());
    }
    let action = input["action"].as_str().ok_or("missing action")?;
    if action == "probe" && input == &json!({"format":1,"action":"probe"}) {
        return Ok(json!({"format":1,"protocol":PROTOCOL}));
    }
    let token = input["token"].as_str().ok_or("missing token")?;
    digest(token)?;
    if !matches!(action, "initialize" | "seal")
        || input != &json!({"format":1,"action":action,"token":token})
    {
        return Err("unsupported control request".into());
    }
    let guard = lock(control, true)?;
    let lifecycle = control.join(".lifecycle");
    if !lifecycle.try_exists()? {
        if action == "seal" || fs::read_dir(control)?.next().is_some() {
            return Err("cannot initialize this generation".into());
        }
        directory(&lifecycle)?;
        directory(&lifecycle.join("open"))?;
    }
    let state = files::open_directory(&lifecycle)?;
    let open = match files::open_child(&state, std::ffi::OsStr::new("open"), true) {
        Ok(_) => true,
        Err(ladyshell::error::Error::PathIo { source, .. })
            if source.raw_os_error() == Some(libc::ENOENT) =>
        {
            false
        }
        Err(error) => return Err(error.into()),
    };
    if action == "seal" && open {
        fs::remove_dir(lifecycle.join("open"))?;
    }
    state.sync_all()?;
    guard.sync_all()?;
    Ok(json!({"format":1,"token":token,"accepting":open && action != "seal"}))
}
fn accepting(control: &Path) -> Result<File> {
    let guard = lock(control, false)?;
    files::open_directory(&control.join(".lifecycle/open"))?;
    Ok(guard)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    files::open_directory(path.parent().ok_or("missing parent")?)?.sync_all()?;
    Ok(())
}
fn application(mode: &str, control: &Path, input: &Value) -> Result<Value> {
    let key = input["key"].as_str().ok_or("missing original key")?;
    digest(key)?;
    let path = control.join(format!("{key}.json"));
    if mode == "sandbox-observe" {
        let retained = ladyshell::json::parse(&files::read_limited(&path, 16384)?)?;
        if retained["input"] != *input {
            return Err("original input changed".into());
        }
        return Ok(retained["result"].clone());
    }
    let _guard = accepting(control)?;
    let result = json!({"echo":input["value"]});
    let retained = serde_json::to_vec(&json!({"input":input,"result":result}))?;
    if retained.len() > 16384 {
        return Err("retained record exceeds bound".into());
    }
    write_new(&path, &retained)?;
    Ok(result)
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 && args.len() != 6 {
        return Err("worker requires fixed roots".into());
    }
    let mode = args[1].to_str().ok_or("invalid mode")?;
    let roots: Vec<_> = args[2..5].iter().map(PathBuf::from).collect();
    for root in &roots {
        files::open_directory(root)?;
    }
    let limit = if mode == "sandbox-upload" {
        2 * 1024 * 1024
    } else {
        16384
    };
    let mut bytes = Vec::new();
    std::io::stdin().take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("input exceeds bound".into());
    }
    let output = if mode == "sandbox-upload" && args.len() == 6 {
        let hash = args[5].to_str().ok_or("missing digest")?;
        digest(hash)?;
        if bytes.is_empty() || files::hash(&bytes) != hash {
            return Err("content changed".into());
        }
        let _guard = accepting(&roots[0])?;
        write_new(&roots[2].join(format!("{hash}.wasm")), &bytes)?;
        json!({"Ok":{"component":hash,"bytes":bytes.len()}})
    } else if args.len() == 5 {
        let input = ladyshell::json::parse(&bytes)?;
        match mode {
            "sandbox-control" => lifecycle(&roots[0], &input)?,
            "sandbox-execute" | "sandbox-observe" => application(mode, &roots[0], &input)?,
            _ => return Err("unsupported entry point".into()),
        }
    } else {
        return Err("unsupported arguments".into());
    };
    let output = serde_json::to_vec(&output)?;
    if output.len() > 16384 {
        return Err("output exceeds bound".into());
    }
    std::io::stdout().write_all(&output)?;
    Ok(())
}
fn main() -> Result<()> {
    run()
}
