//! Bounded owner-consented GitHub manifest flow over a loopback listener.
use super::*;
use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime},
};

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn respond(stream: &mut TcpStream, status: &str, body: &str) -> Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; form-action https://github.com; base-uri 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}
fn request(stream: &mut TcpStream, authority: &str, deadline: Instant) -> Result<Option<String>> {
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("HTTP request deadline elapsed")?;
        ensure!(!remaining.is_zero(), "HTTP request deadline elapsed");
        stream.set_read_timeout(Some(remaining))?;
        let n = match stream.read(&mut chunk) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(n) => n,
            Err(error)
                if bytes.is_empty()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                return Ok(None);
            }
            Err(_) => bail!(
                "HTTP request incomplete before deadline ({} bytes, {} line feeds)",
                bytes.len(),
                bytes.iter().filter(|b| **b == b'\n').count()
            ),
        };
        ensure!(
            n > 0 && bytes.len() + n <= 16384,
            "Invalid HTTP request size"
        );
        bytes.extend_from_slice(&chunk[..n]);
    }
    let text = std::str::from_utf8(&bytes).context("Invalid HTTP encoding")?;
    let mut lines = text.split("\r\n");
    let parts: Vec<_> = lines
        .next()
        .context("Missing request")?
        .split(' ')
        .collect();
    ensure!(
        parts.len() == 3 && parts[0] == "GET" && parts[2] == "HTTP/1.1",
        "Only HTTP/1.1 GET is supported"
    );
    let hosts: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .collect();
    ensure!(
        hosts.len() == 1 && hosts[0].1.trim() == authority,
        "Loopback Host differs"
    );
    Ok(Some(parts[1].to_owned()))
}
fn transport() -> Command {
    let mut command = Command::new("/usr/bin/curl");
    command.env_clear().arg("--disable");
    command
}
fn exchange(code: &str) -> Result<Vec<u8>> {
    // curl is a transport adapter, with fixed HTTPS origin and no redirects.
    // The temporary code is sent on stdin, never on the process command line.
    let mut child = transport()
        .args([
            "--no-location",
            "--max-redirs",
            "0",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "30",
            "--max-filesize",
            "65536",
            "--proto",
            "=https",
            "--request",
            "POST",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "Content-Type: application/json",
            "--data",
            "{}",
            "--config",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut input = child.stdin.take().context("Transport stdin missing")?;
    writeln!(
        input,
        "url = \"https://api.github.com/app-manifests/{code}/conversions\""
    )?;
    drop(input);
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 65536,
        "Manifest exchange outcome unknown; do not repeat creation automatically"
    );
    Ok(output.stdout)
}

fn manifest(owner: &str, repository: &str, name: &str, authority: &str, ci_read: bool) -> Value {
    let mut value = json!({"name":name,"url":format!("https://github.com/{owner}/{repository}"),"redirect_url":format!("http://{authority}/callback"),"public":false,"hook_attributes":{"active":false,"url":format!("https://github.com/{owner}/{repository}")},"request_oauth_on_install":false,"default_permissions":{"contents":"write","pull_requests":"write","statuses":"write","workflows":"write"},"default_events":[],"description":"Ladyhost experiment: host publication, sandbox continuation, separate human review."});
    let mut permissions = registration_permissions(ci_read);
    if let Some(fields) = permissions.as_object_mut() {
        fields.remove("metadata");
    }
    value["default_permissions"] = permissions;
    value
}

/// Check both the exported project and the invoking source checkout before storing secrets.
pub fn registration_storage(directory: &Path, workspace: &Path) -> Result<()> {
    ensure!(workspace.is_absolute(), "Workspace must be absolute");
    private_directory(directory)?;
    let actual = directory.canonicalize()?;
    let cwd = std::env::current_dir()?.canonicalize()?;
    let mut roots = vec![workspace.canonicalize()?];
    if [".git", ".jj", "Cargo.toml", "package.json"]
        .iter()
        .any(|marker| cwd.join(marker).exists())
    {
        roots.push(cwd);
    }
    for root in roots {
        ensure!(
            !actual.starts_with(root),
            "Registration state must remain outside project roots"
        );
    }
    Ok(())
}

/// Recover only a retained response; never repeat the one-use conversion.
pub fn recover(
    directory: &Path,
    workspace: &Path,
    owner: &str,
    name: &str,
    ci_read: bool,
) -> Result<Option<Value>> {
    registration_storage(directory, workspace)?;
    let response = directory.join("registration-response.private.json");
    if !response.try_exists()? {
        return Ok(None);
    }
    let value = retained_json(&response)
        .map_err(|_| anyhow::anyhow!("Invalid retained registration response; content withheld"))?;
    let bytes = serde_json::to_vec(&value)?;
    let public = registration_public_with_ci(&bytes, owner, name, ci_read)?;
    let registration: Registration = serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("Invalid retained registration; content withheld"))?;
    let key = directory.join("app.private-key.pem");
    if key.try_exists()? {
        let metadata = fs::symlink_metadata(&key)?;
        ensure!(
            metadata.is_file()
                && metadata.len() <= 16384
                && metadata.permissions().mode() & 0o077 == 0,
            "Retained App key custody differs"
        );
        ensure!(
            fs::read(&key)? == registration.pem.as_bytes(),
            "Retained App key differs"
        );
    } else {
        retain(&key, registration.pem.as_bytes())?;
    }
    let metadata = directory.join("app.json");
    if metadata.try_exists()? {
        ensure!(
            retained_json(&metadata)? == public,
            "Retained App identity differs"
        );
    } else {
        retain(&metadata, &serde_json::to_vec_pretty(&public)?)?;
    }
    Ok(Some(public))
}

pub fn serve(
    directory: &Path,
    workspace: &Path,
    owner: &str,
    repository: &str,
    name: &str,
) -> Result<Value> {
    serve_with(directory, workspace, owner, repository, name, false, false)
}

pub fn serve_with(
    directory: &Path,
    workspace: &Path,
    owner: &str,
    repository: &str,
    name: &str,
    organization: bool,
    ci_read: bool,
) -> Result<Value> {
    for value in [owner, name] {
        ensure!(crate::identifier(value, false), "Invalid manifest identity");
    }
    ensure!(
        crate::identifier(repository, true),
        "Invalid repository name"
    );
    registration_storage(directory, workspace)?;
    if let Some(public) = recover(directory, workspace, owner, name, ci_read)? {
        return Ok(public);
    }
    let registration_url = if organization {
        format!("https://github.com/organizations/{owner}/settings/apps/new")
    } else {
        "https://github.com/settings/apps/new".to_owned()
    };
    let session_path = directory.join("registration-session.json");
    ensure!(
        !directory.join("exchange-intent.private.json").exists(),
        "Exchange already attempted; inspect retained response instead of consuming the code again"
    );
    let (listener, state, manifest, remaining) = if session_path.exists() {
        let session = retained_json(&session_path)?;
        ensure!(
            session["schema_version"] == 1
                && session["owner"] == owner
                && session["repository"] == repository
                && session["name"] == name
                && session
                    .get("organization")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    == organization
                && session
                    .get("ci_read")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    == ci_read,
            "Registration session identity differs"
        );
        let state = session["state"]
            .as_str()
            .context("Missing session state")?
            .to_owned();
        ensure!(
            state.len() == 64 && state.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid session state"
        );
        let url = session["url"].as_str().context("Missing session URL")?;
        let port = url
            .strip_prefix("http://127.0.0.1:")
            .and_then(|s| s.strip_suffix(&format!("/start/{state}")))
            .context("Invalid retained loopback URL")?
            .parse::<u16>()?;
        ensure!(port > 0, "Invalid retained port");
        let elapsed = SystemTime::now().duration_since(fs::metadata(&session_path)?.modified()?)?;
        let remaining = Duration::from_secs(3600)
            .checked_sub(elapsed)
            .context("Registration session expired")?;
        (
            TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?,
            state,
            session["manifest"].clone(),
            remaining,
        )
    } else {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let authority = listener.local_addr()?.to_string();
        let nonce = Command::new("/usr/bin/openssl")
            .env_clear()
            .args(["rand", "-hex", "32"])
            .output()?;
        ensure!(nonce.status.success(), "Nonce generation failed");
        let state = String::from_utf8(nonce.stdout)?.trim().to_owned();
        ensure!(
            state.len() == 64 && state.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid nonce"
        );
        let manifest = manifest(owner, repository, name, &authority, ci_read);
        let url = format!("http://{authority}/start/{state}");
        retain(
            &session_path,
            &serde_json::to_vec_pretty(
                &json!({"schema_version":1,"owner":owner,"repository":repository,"name":name,"url":url,"state":state,"manifest":manifest,"organization":organization,"ci_read":ci_read}),
            )?,
        )?;
        (listener, state, manifest, Duration::from_secs(3600))
    };
    listener.set_nonblocking(true)?;
    let authority = listener.local_addr()?.to_string();
    ensure!(
        manifest == self::manifest(owner, repository, name, &authority, ci_read),
        "Retained manifest differs"
    );
    let start = format!("/start/{state}");
    let url = format!("http://{authority}{start}");
    eprintln!(
        "{}",
        json!({"url":url,"expires_in_seconds":remaining.as_secs(),"expected_owner":owner,"name":name})
    );
    std::io::stderr().flush()?;
    let deadline = Instant::now() + remaining;
    while Instant::now() < deadline {
        let (mut stream, peer) = match listener.accept() {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let target = match request(
            &mut stream,
            &authority,
            deadline.min(Instant::now() + Duration::from_secs(3)),
        ) {
            Ok(Some(v)) => v,
            Ok(None) => continue, // Close idle browser preconnections without an unsolicited response.
            Err(error) => {
                // Parser errors are fixed diagnostics; never echo request bytes or callback codes.
                let _ = respond(
                    &mut stream,
                    "400 Bad Request",
                    &format!("Invalid setup request: {}", escape(&error.to_string())),
                );
                continue;
            }
        };
        if target == start {
            let html = format!(
                "<!doctype html><title>Create {}</title><h1>Create {}</h1><p>Sign in to GitHub as {}. This private App will publish to {}. Install it on that repository only.</p><form method=\"post\" action=\"{}?state={}\"><input type=\"hidden\" name=\"manifest\" value=\"{}\"><button type=\"submit\">Create App on GitHub</button></form>",
                escape(name),
                escape(name),
                escape(owner),
                escape(repository),
                registration_url,
                state,
                escape(&manifest.to_string())
            );
            respond(&mut stream, "200 OK", &html)?;
            continue;
        }
        let code = match callback_code(&target, &state) {
            Ok(v) => v,
            Err(_) => {
                let _ = respond(
                    &mut stream,
                    "400 Bad Request",
                    "Invalid or expired callback.",
                );
                continue;
            }
        };
        // Persist exact secret intent before a one-use code is consumed.
        retain(
            &directory.join("exchange-intent.private.json"),
            &serde_json::to_vec(&json!({"code":code,"state":state}))?,
        )?;
        let result = (|| -> Result<Value> {
            let bytes = exchange(&code)?;
            retain(
                &directory.join("registration-response.private.json"),
                &bytes,
            )?;
            recover(directory, workspace, owner, name, ci_read)?
                .context("Retained response missing after exchange")
        })();
        match result {
            Ok(public) => {
                respond(
                    &mut stream,
                    "200 OK",
                    &format!(
                        "<!doctype html><title>App registered</title><h1>{} registered</h1><p>The App ID and key are saved privately on the host.</p><p><a href=\"https://github.com/apps/{}/installations/new\">Install on {}/{}</a>, choose Only select repositories, and select {}. Then return to the conversation.</p>",
                        escape(name),
                        escape(name),
                        escape(owner),
                        escape(repository),
                        escape(repository)
                    ),
                )?;
                return Ok(public);
            }
            Err(error) => {
                let _ = respond(
                    &mut stream,
                    "502 Bad Gateway",
                    "Registration needs host inspection. Private recovery evidence is retained. Do not create another App automatically.",
                );
                return Err(error);
            }
        }
    }
    bail!("Registration listener expired; no owner response received")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_browser_request_and_absolute_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        write!(
            client,
            "GET /start/test HTTP/1.1\r\nHost: {address}\r\nConnection: keep-alive\r\n\r\n"
        )
        .unwrap();
        assert_eq!(
            request(
                &mut server,
                &address.to_string(),
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap(),
            Some("/start/test".to_owned())
        );
        let worker = std::thread::spawn(move || {
            for _ in 0..20 {
                if client.write_all(b"G").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = Instant::now();
        assert!(
            request(
                &mut server,
                &address.to_string(),
                start + Duration::from_millis(100)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_millis(350));
        drop(server);
        worker.join().unwrap();
    }
    #[test]
    fn idle_browser_preconnect_has_no_http_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        assert!(
            request(
                &mut server,
                &address.to_string(),
                Instant::now() + Duration::from_millis(20)
            )
            .unwrap()
            .is_none()
        );
        drop(server);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.is_empty());
    }
    #[test]
    fn transport_ignores_default_configuration() {
        let root = std::env::temp_dir().join(format!("ladyhost-curl-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join(".curlrc"), "definitely-invalid-ladyhost-option\n").unwrap();
        let output = transport()
            .env("CURL_HOME", &root)
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            output.stderr.is_empty(),
            "Default curl configuration was read"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn registration_storage_rejects_project_and_aliases() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("ladyhost-storage-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let project = root.join("project");
        fs::create_dir(&project).unwrap();
        let secret = project.join("secret");
        private_directory(&secret).unwrap();
        let alias = root.join("alias");
        symlink(&project, &alias).unwrap();
        assert!(registration_storage(&secret, &project).is_err());
        assert!(registration_storage(&alias.join("secret"), &project).is_err());
        assert!(registration_storage(&root.join("safe"), &project).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
