use anyhow::Result;
use ladyhost::{
    Config,
    app::{AppApi, Clock, authenticate, credential_response},
};
use serde_json::{Value, json};
use std::collections::VecDeque;

struct Fixed(u64);
impl Clock for Fixed {
    fn now(&self) -> Result<u64> {
        Ok(self.0)
    }
}
const NOW: u64 = 1_704_067_200;

#[test]
fn git_http_challenges_do_not_override_the_pinned_destination() {
    let request = "capability[]=authtype\nprotocol=https\nhost=github.com\npath=owner/repo.git\nwwwauth[]=Basic realm=GitHub\nwwwauth[]=host=evil.test\n\n";
    let response = credential_response(
        &config(),
        "get",
        request,
        || authenticate(&config(), &mut Api::new(responses()), &Fixed(NOW)),
        &Fixed(NOW),
    )
    .unwrap();
    assert_eq!(
        response,
        "username=x-access-token\npassword=secret-installation-token\n\n"
    );
    let wrong = request.replace("host=github.com", "host=evil.test");
    assert!(
        credential_response(
            &config(),
            "get",
            &wrong,
            || panic!("must not mint"),
            &Fixed(NOW)
        )
        .is_err()
    );
}
fn config() -> Config {
    serde_json::from_value(json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"repo","workspace":"/tmp/app-test-project","expected_actor":"publisher[bot]","expected_repository_id":42,"github_app":{"app_id":123,"installation_id":456,"slug":"publisher","private_key":"/tmp/host/key.pem","openssl":"/usr/bin/openssl"}})).unwrap()
}
fn installation() -> Value {
    json!({"id":456,"app_id":123,"app_slug":"publisher","account":{"login":"owner"},"suspended_at":null,"repository_selection":"selected"})
}
fn responses() -> Vec<Value> {
    vec![
        json!({"id":123,"slug":"publisher"}),
        installation(),
        installation(),
        json!({"token":"secret-installation-token","expires_at":"2024-01-01T01:00:00Z","permissions":{"contents":"write","pull_requests":"write","statuses":"write","metadata":"read"},"repositories":[{"id":42,"full_name":"owner/repo","private":true}]}),
    ]
}
struct Api {
    responses: VecDeque<Value>,
    calls: Vec<(String, Option<Value>)>,
}
impl Api {
    fn new(responses: Vec<Value>) -> Self {
        Self {
            responses: responses.into(),
            calls: vec![],
        }
    }
}
impl AppApi for Api {
    fn get(&mut self, path: &str) -> Result<Value> {
        self.calls.push((path.into(), None));
        Ok(self.responses.pop_front().unwrap())
    }
    fn post(&mut self, path: &str, body: &Value) -> Result<Value> {
        self.calls.push((path.into(), Some(body.clone())));
        Ok(self.responses.pop_front().unwrap())
    }
}
#[test]
fn protocol_binds_app_installation_owner_repository_and_exact_permissions() {
    let mut api = Api::new(responses());
    let token = authenticate(&config(), &mut api, &Fixed(NOW)).unwrap();
    assert_eq!(token.actor(), "publisher[bot]");
    assert_eq!(
        token.value(&Fixed(NOW)).unwrap(),
        "secret-installation-token"
    );
    assert!(!format!("{token:?}").contains("secret-installation-token"));
    assert_eq!(
        api.calls,
        vec![
            ("/app".into(), None),
            ("/app/installations/456".into(), None),
            ("/repos/owner/repo/installation".into(), None),
            (
                "/app/installations/456/access_tokens".into(),
                Some(
                    json!({"repository_ids":[42],"permissions":{"contents":"write","pull_requests":"write","statuses":"write"}})
                )
            )
        ]
    );
}
#[test]
fn refuses_replaced_app_installation_owner_and_suspension_before_token_mint() {
    for (index, field, value) in [
        (0, "id", json!(124)),
        (0, "slug", json!("wrong")),
        (1, "id", json!(457)),
        (1, "app_id", json!(124)),
        (1, "app_slug", json!("wrong")),
        (1, "account", json!({"login":"other"})),
        (1, "suspended_at", json!("2024-01-01T00:00:00Z")),
        (2, "id", json!(457)),
        (1, "suspended_at", json!(false)),
    ] {
        let mut replies = responses();
        replies[index][field] = value;
        let mut api = Api::new(replies);
        assert!(
            authenticate(&config(), &mut api, &Fixed(NOW)).is_err(),
            "{index}:{field}"
        );
        assert!(!api.calls.iter().any(|(_, body)| body.is_some()));
    }
}
#[test]
fn refuses_excess_missing_or_wrong_scope_and_malformed_expiry() {
    for (field, value) in [
        (
            "permissions",
            json!({"contents":"write","pull_requests":"write","statuses":"write","metadata":"read","administration":"write"}),
        ),
        (
            "permissions",
            json!({"contents":"read","pull_requests":"write","statuses":"write"}),
        ),
        ("repositories", json!([])),
        (
            "repositories",
            json!([{"id":43,"full_name":"owner/repo","private":true}]),
        ),
        (
            "repositories",
            json!([{"id":42,"full_name":"other/repo","private":true}]),
        ),
        (
            "repositories",
            json!([{"id":42,"full_name":"owner/repo","private":true},{"id":43}]),
        ),
        ("expires_at", json!("2024-01-01T00:00:00Z")),
        ("expires_at", json!("2024-02-30T01:00:00Z")),
        ("expires_at", json!("never")),
        ("token", json!("bad\ncredential")),
    ] {
        let mut replies = responses();
        replies[3][field] = value;
        let mut api = Api::new(replies);
        assert!(
            authenticate(&config(), &mut api, &Fixed(NOW)).is_err(),
            "{field}"
        );
    }
}
#[test]
fn expiry_and_replacement_never_reuse_old_credential() {
    let token = authenticate(&config(), &mut Api::new(responses()), &Fixed(NOW)).unwrap();
    assert!(token.value(&Fixed(NOW + 3600)).is_err());
    let mut second = responses();
    second[3]["token"] = json!("replacement");
    let replacement = authenticate(&config(), &mut Api::new(second), &Fixed(NOW + 100)).unwrap();
    assert_eq!(replacement.value(&Fixed(NOW + 100)).unwrap(), "replacement");
    let mut wrong = responses();
    wrong[0]["id"] = json!(999);
    assert!(authenticate(&config(), &mut Api::new(wrong), &Fixed(NOW + 100)).is_err());
}
#[test]
fn helper_returns_secret_only_for_exact_https_destination_and_never_stores() {
    let request = "protocol=https\nhost=github.com\npath=owner/repo.git\n\n";
    let output = credential_response(
        &config(),
        "get",
        request,
        || authenticate(&config(), &mut Api::new(responses()), &Fixed(NOW)),
        &Fixed(NOW),
    )
    .unwrap();
    assert_eq!(
        output,
        "username=x-access-token\npassword=secret-installation-token\n\n"
    );
    for operation in ["store", "erase"] {
        assert_eq!(
            credential_response(
                &config(),
                operation,
                request,
                || panic!("must not mint"),
                &Fixed(NOW)
            )
            .unwrap(),
            ""
        );
    }
    for request in [
        "protocol=http\nhost=github.com\npath=owner/repo.git\n\n",
        "protocol=https\nhost=evil.test\npath=owner/repo.git\n\n",
        "protocol=https\nhost=github.com\npath=other/repo.git\n\n",
        "protocol=https\nhost=github.com\npath=owner/repo.git\nhost=github.com\n\n",
        "protocol=https\nhost=github.com\n\n",
        "protocol=https\nhost=github.com\npath=owner/repo.git\nusername=human\n\n",
    ] {
        assert!(
            credential_response(
                &config(),
                "get",
                request,
                || panic!("must not mint"),
                &Fixed(NOW)
            )
            .is_err()
        );
    }
}

#[test]
fn app_forge_uses_verified_bot_without_user_endpoint_and_refuses_expiry_and_merge() {
    use jjpr::forge::{AuthScheme, Forge, ForgeClient, GitHubForge, MergeMethod, PaginationStyle};
    use ladyhost::app::AppForge;
    use std::sync::Arc;
    let inner = || {
        Box::new(GitHubForge::new(ForgeClient::new(
            "http://127.0.0.1:1",
            "never-sent".into(),
            AuthScheme::Bearer,
            PaginationStyle::LinkHeader,
        )))
    };
    let token = authenticate(&config(), &mut Api::new(responses()), &Fixed(NOW)).unwrap();
    let forge = AppForge::new(inner(), token, Arc::new(Fixed(NOW)));
    assert_eq!(forge.get_authenticated_user().unwrap(), "publisher[bot]");
    assert!(
        forge
            .merge_pr("owner", "repo", 1, MergeMethod::Merge)
            .is_err()
    );
    let token = authenticate(&config(), &mut Api::new(responses()), &Fixed(NOW)).unwrap();
    let expired = AppForge::new(inner(), token, Arc::new(Fixed(NOW + 3600)));
    assert!(expired.get_authenticated_user().is_err());
    let error = expired.list_open_prs("owner", "repo").unwrap_err();
    assert!(error.to_string().contains("expired"));
}

#[test]
fn upstream_auth_errors_cannot_echo_token_in_error_chain() {
    struct Leaky;
    impl AppApi for Leaky {
        fn get(&mut self, _: &str) -> Result<Value> {
            anyhow::bail!("response echoed secret-installation-token")
        }
        fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
            unreachable!()
        }
    }
    let error = authenticate(&config(), &mut Leaky, &Fixed(NOW)).unwrap_err();
    assert!(!format!("{error:#?}").contains("secret-installation-token"));
}

#[cfg(unix)]
#[test]
fn openssl_rs256_signature_is_verified_independently_and_private_permissions_enforced() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    let root = std::env::temp_dir().join(format!("jjpr-app-signing-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let key = root.join("key.pem");
    let public = root.join("public.pem");
    assert!(
        Command::new("/usr/bin/openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out"
            ])
            .arg(&key)
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        Command::new("/usr/bin/openssl")
            .args(["pkey", "-in"])
            .arg(&key)
            .args(["-pubout", "-out"])
            .arg(&public)
            .status()
            .unwrap()
            .success()
    );
    let mut cfg = config();
    cfg.github_app.as_mut().unwrap().private_key = key.clone();
    let app = cfg.github_app.as_ref().unwrap();
    let jwt = app.jwt(&Fixed(NOW)).unwrap();
    let (message, signature) = jwt.rsplit_once('.').unwrap();
    let decode = |value: &str| {
        let mut encoded = value.replace('-', "+").replace('_', "/");
        while !encoded.len().is_multiple_of(4) {
            encoded.push('=');
        }
        let mut child = Command::new("/usr/bin/openssl")
            .args(["base64", "-d", "-A"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(encoded.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap().stdout
    };
    let (header, payload) = message.split_once('.').unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&decode(header)).unwrap(),
        json!({"alg":"RS256","typ":"JWT"})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&decode(payload)).unwrap(),
        json!({"iat":1704067140u64,"exp":1704067740u64,"iss":123})
    );
    let signature_path = root.join("signature");
    std::fs::write(&signature_path, decode(signature)).unwrap();
    let mut child = Command::new("/usr/bin/openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(&public)
        .arg("-signature")
        .arg(signature_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(message.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(app.jwt(&Fixed(NOW)).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn jwt_rejects_non_rsa_keys_before_any_api_request() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    let root = std::env::temp_dir().join(format!("jjpr-app-ec-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let key = root.join("key.pem");
    assert!(
        Command::new("/usr/bin/openssl")
            .args([
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out"
            ])
            .arg(&key)
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut cfg = config();
    cfg.github_app.as_mut().unwrap().private_key = key;
    let result = cfg.github_app.as_ref().unwrap().jwt(&Fixed(NOW));
    std::fs::remove_dir_all(root).unwrap();
    assert!(
        result.is_err(),
        "RS256 must not silently sign with an EC key"
    );
}

#[test]
fn workflow_permission_is_explicit_and_exact() {
    let mut selected = config();
    selected.github_app.as_mut().unwrap().workflow_write = true;
    let mut replies = responses();
    replies[3]["permissions"]["workflows"] = json!("write");
    let mut api = Api::new(replies.clone());
    authenticate(&selected, &mut api, &Fixed(NOW)).unwrap();
    assert_eq!(
        api.calls[3].1.as_ref().unwrap()["permissions"]["workflows"],
        "write"
    );
    assert!(authenticate(&config(), &mut Api::new(replies), &Fixed(NOW)).is_err());
    assert!(authenticate(&selected, &mut Api::new(responses()), &Fixed(NOW)).is_err());
    let mut extra = responses();
    extra[3]["permissions"]["workflows"] = json!("write");
    extra[3]["permissions"]["administration"] = json!("write");
    assert!(authenticate(&selected, &mut Api::new(extra), &Fixed(NOW)).is_err());
}

#[test]
fn ci_observation_permissions_are_explicit_and_do_not_grant_administration() {
    let selected: Config = serde_json::from_value(json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"repo","workspace":"/tmp/app-test-project","expected_actor":"publisher[bot]","expected_repository_id":42,"github_app":{"app_id":123,"installation_id":456,"slug":"publisher","private_key":"/tmp/host/key.pem","openssl":"/usr/bin/openssl","ci_read":true}})).unwrap();
    let mut replies = responses();
    replies[3]["permissions"]["checks"] = json!("read");
    replies[3]["permissions"]["actions"] = json!("read");
    let mut api = Api::new(replies.clone());
    authenticate(&selected, &mut api, &Fixed(NOW)).unwrap();
    assert_eq!(
        api.calls[3].1.as_ref().unwrap()["permissions"]["checks"],
        "read"
    );
    assert!(authenticate(&config(), &mut Api::new(replies.clone()), &Fixed(NOW)).is_err());
    assert!(authenticate(&selected, &mut Api::new(responses()), &Fixed(NOW)).is_err());
    replies[3]["permissions"]["administration"] = json!("read");
    assert!(authenticate(&selected, &mut Api::new(replies), &Fixed(NOW)).is_err());
}
