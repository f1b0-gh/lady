//! Host adapters. Owner credentials never enter runtime configuration or argv.
use super::*;
use crate::{
    Config,
    app::{self, SystemClock},
    lifecycle,
};
use jjpr::forge::{AuthScheme, ForgeClient, PaginationStyle, http::HttpError};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

pub struct Client(pub ForgeClient);
fn response(result: Result<Value>, method: &str) -> Result<Option<Value>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            if let Some(http) = error.downcast_ref::<HttpError>() {
                if method == "GET" && http.status == 404 {
                    return Ok(None);
                }
                // Retain machine-readable status without keeping provider payloads
                // or request paths that might contain sensitive information.
                return Err(HttpError {
                    status: http.status,
                    method: method.to_owned(),
                    path: "[withheld]".into(),
                    body: "[withheld]".into(),
                }
                .into());
            }
            anyhow::bail!("GitHub {method} outcome unavailable; inspect retained intent");
        }
    }
}
impl Api for Client {
    fn get(&mut self, path: &str) -> Result<Option<Value>> {
        response(self.0.get(path), "GET")
    }
    fn post(&mut self, path: &str, body: &Value) -> Result<Value> {
        response(self.0.post(path, body), "POST")?.context("Missing GitHub response")
    }
    fn delete(&mut self, path: &str) -> Result<()> {
        response(self.0.delete(path).map(|()| Value::Null), "DELETE")?;
        Ok(())
    }
}
impl Client {
    pub fn installation(config: &Config) -> Result<Self> {
        let token = app::mint(config)?;
        Ok(Self(ForgeClient::new(
            "https://api.github.com",
            token.value(&SystemClock)?.to_owned(),
            AuthScheme::Bearer,
            PaginationStyle::LinkHeader,
        )))
    }
    pub fn put(&mut self, path: &str, value: &Value) -> Result<Value> {
        response(self.0.put(path, value), "PUT")?.context("Missing GitHub response")
    }
}

pub fn command(executable: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(executable);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("GIT_")
            || name.starts_with("GH_")
            || name.starts_with("GITHUB_")
            || name.starts_with("JJ_")
            || name == "SSH_AUTH_SOCK"
        {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("JJ_CONFIG", "/dev/null");
    command
}
pub fn output(mut command: Command, label: &str) -> Result<String> {
    let output = command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("Cannot run {label}"))?;
    ensure!(
        output.status.success(),
        "{label} failed; no credential or command output disclosed"
    );
    ensure!(
        output.stdout.len() <= 4 * 1024 * 1024,
        "{label} output exceeds bound"
    );
    Ok(String::from_utf8(output.stdout)
        .context("Host output is not UTF-8")?
        .trim_end()
        .to_owned())
}
pub fn git(workspace: &Path, args: &[&str]) -> Result<String> {
    let mut cmd = command("git");
    cmd.arg("-C")
        .arg(workspace)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args);
    output(cmd, "Git operation")
}
pub fn git_bytes(workspace: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = command("git")
        .arg("-C")
        .arg(workspace)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 4 * 1024 * 1024,
        "Git byte read failed or exceeds bound"
    );
    Ok(out.stdout)
}

pub fn git_input(workspace: &Path, args: &[&str], input: &[u8]) -> Result<String> {
    let mut child = command("git")
        .arg("-C")
        .arg(workspace)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let write = child
        .stdin
        .take()
        .context("Git input unavailable")?
        .write_all(input);
    let out = child.wait_with_output()?;
    ensure!(
        write.is_ok() && out.status.success(),
        "Git operation failed; output withheld"
    );
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

pub fn owner(store: &Store, allow_login: bool) -> Result<Client> {
    let directory = store.directory("owner-auth")?;
    let token = || -> Result<String> {
        let mut cmd = command(&store.spec.gh);
        cmd.env("GH_CONFIG_DIR", &directory)
            .args(["auth", "token", "--hostname", "github.com"]);
        output(cmd, "Owner credential lookup")
    };
    let secret = match token() {
        Ok(value) => value,
        Err(error) if !allow_login => return Err(error),
        Err(_) => {
            eprintln!(
                "Owner setup authorization is needed to manage rules and the signing key. The publisher App will not receive administration permission."
            );
            let status = command(&store.spec.gh)
                .env("GH_CONFIG_DIR", &directory)
                .args([
                    "auth",
                    "login",
                    "--hostname",
                    "github.com",
                    "--git-protocol",
                    "https",
                    "--web",
                    "--clipboard=false",
                    "--insecure-storage",
                    "--scopes",
                    "write:ssh_signing_key",
                ])
                .stdout(Stdio::null())
                .status()?;
            ensure!(
                status.success(),
                "Owner authorization incomplete; rerun init to resume"
            );
            token()?
        }
    };
    ensure!(
        !secret.is_empty() && !secret.contains(['\r', '\n']),
        "Invalid owner credential response"
    );
    Ok(Client(ForgeClient::new(
        "https://api.github.com",
        secret,
        AuthScheme::Bearer,
        PaginationStyle::LinkHeader,
    )))
}
pub fn clear_owner(store: &Store) -> Result<()> {
    let directory = store.root.join("owner-auth");
    if !directory.exists() {
        return Ok(());
    }
    lifecycle::private_directory(&directory)?;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        ensure!(
            matches!(entry.file_name().to_str(), Some("hosts.yml" | "config.yml")),
            "Unexpected owner-auth file; preserving directory"
        );
        ensure!(
            entry.file_type()?.is_file(),
            "Unexpected owner-auth entry; preserving it"
        );
    }
    for entry in fs::read_dir(&directory)? {
        fs::remove_file(entry?.path())?;
    }
    fs::remove_dir(&directory)?;
    Ok(())
}
pub fn nonce() -> Result<String> {
    let mut cmd = command("/usr/bin/openssl");
    cmd.env_clear().args(["rand", "-hex", "12"]);
    let value = output(cmd, "Setup identity generation")?;
    ensure!(
        value.len() == 24 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid setup identity"
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_repository_status_is_preserved_without_provider_payload() {
        let raw = HttpError {
            status: 409,
            method: "sensitive-method".into(),
            path: "sensitive-path".into(),
            body: "sensitive-body".into(),
        };
        let error = response(Err(raw.into()), "GET").unwrap_err();
        assert_eq!(
            error.downcast_ref::<HttpError>().map(|e| e.status),
            Some(409)
        );
        assert!(!format!("{error:?} {error}").contains("sensitive"));
    }
}
