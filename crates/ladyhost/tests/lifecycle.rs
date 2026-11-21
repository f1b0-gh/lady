use ladyhost::{Config, lifecycle::*};
use serde_json::{Value, json};

fn config() -> Config {
    serde_json::from_value(json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"repo","workspace":"/tmp/lifecycle-project","expected_actor":"publisher[bot]","expected_repository_id":42,"github_app":{"app_id":123,"installation_id":456,"slug":"publisher","private_key":"/tmp/key.pem","openssl":"/usr/bin/openssl"}})).unwrap()
}
fn snapshot() -> Value {
    json!({"app":{"id":123,"slug":"publisher","owner":{"login":"owner"}},"installations":[{"id":456,"app_id":123,"app_slug":"publisher","account":{"login":"owner"},"repository_selection":"selected","suspended_at":null}],"repositories":[{"id":42,"full_name":"owner/repo","private":true}]})
}
#[test]
fn removal_only_accepts_the_exact_app_installation_and_repository() {
    validate_inventory(&config(), &snapshot()).unwrap();
    for field in ["app", "installations", "repositories"] {
        let mut bad = snapshot();
        bad[field] = Value::Null;
        assert!(validate_inventory(&config(), &bad).is_err(), "{field}");
    }
    let mut extra = snapshot();
    extra["repositories"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":43,"full_name":"owner/other"}));
    assert!(validate_inventory(&config(), &extra).is_err());
    let mut wrong = snapshot();
    wrong["installations"][0]["app_id"] = json!(789);
    assert!(validate_inventory(&config(), &wrong).is_err());
}
#[test]
fn callback_requires_exact_state_single_code_and_bounded_literals() {
    let state = "a".repeat(64);
    assert_eq!(
        callback_code(&format!("/callback?code=abc123&state={state}"), &state).unwrap(),
        "abc123"
    );
    for target in [
        "/callback?code=abc&state=wrong".into(),
        format!("/callback?code=abc&code=other&state={state}"),
        format!("/callback?code=../../secret&state={state}"),
        format!("/callback?code=abc&state={state}&unexpected=1"),
        format!("/other?code=abc&state={state}"),
    ] {
        assert!(callback_code(&target, &state).is_err(), "{target}");
    }
}
#[test]
fn registration_is_owner_bound_and_does_not_publish_credentials() {
    let response = json!({"id":321,"name":"ladyhost-1","slug":"ladyhost-1","owner":{"login":"owner"},"pem":"-----BEGIN RSA PRIVATE KEY-----\nSECRET\n-----END RSA PRIVATE KEY-----\n","client_secret":"SECRET","webhook_secret":"SECRET","permissions":{"contents":"write","pull_requests":"write","statuses":"write","workflows":"write","metadata":"read"}});
    let bytes = serde_json::to_vec(&response).unwrap();
    let public = registration_public(&bytes, "owner", "ladyhost-1").unwrap();
    assert!(!public.to_string().contains("SECRET"));
    assert_eq!(public["app_id"], 321);
    assert!(registration_public(&bytes, "other", "ladyhost-1").is_err());
    assert!(registration_public(&bytes, "owner", "renamed").is_err());
    let mut excessive = response;
    excessive["permissions"]["administration"] = json!("write");
    assert!(
        registration_public(
            &serde_json::to_vec(&excessive).unwrap(),
            "owner",
            "ladyhost-1"
        )
        .is_err()
    );
}

struct Removal {
    snapshot: Value,
    calls: usize,
    absent: bool,
    lost: bool,
    applied: bool,
}
impl RemovalApi for Removal {
    fn inventory(&mut self) -> anyhow::Result<Value> {
        Ok(self.snapshot.clone())
    }
    fn delete_installation(&mut self, id: u64) -> anyhow::Result<()> {
        assert_eq!(id, 456);
        self.calls += 1;
        self.absent = self.applied;
        if self.lost {
            anyhow::bail!("lost reply");
        }
        Ok(())
    }
    fn installation_absent(&mut self, id: u64) -> anyhow::Result<bool> {
        assert_eq!(id, 456);
        Ok(self.absent)
    }
}
#[test]
fn removal_recovery_never_repeats_an_uncertain_effect_or_changes_binding() {
    use std::os::unix::fs::PermissionsExt;
    for applied in [false, true] {
        let root =
            std::env::temp_dir().join(format!("ladyhost-removal-{}-{applied}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let state = root.join("state");
        let mut c = config();
        c.workspace = workspace;
        let mut api = Removal {
            snapshot: snapshot(),
            calls: 0,
            absent: false,
            lost: true,
            applied,
        };
        assert!(remove_with(&c, &state, &mut api).is_err());
        assert_eq!(api.calls, 1);
        assert!(state.join("remove-intent.json").exists());
        assert_eq!(remove_with(&c, &state, &mut api).is_ok(), applied);
        assert_eq!(api.calls, 1);
        c.github_app.as_mut().unwrap().installation_id = 789;
        assert!(remove_with(&c, &state, &mut api).is_err());
        assert_eq!(api.calls, 1);
        assert_eq!(
            std::fs::metadata(state.join("remove-intent.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn retained_manifest_response_recovers_without_reusing_conversion_code() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!(
        "ladyhost-registration-recover-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let workspace = root.join("project");
    std::fs::create_dir(&workspace).unwrap();
    let state = root.join("state");
    private_directory(&state).unwrap();
    let response = json!({"id":321,"name":"project-host","slug":"project-host","owner":{"login":"owner"},"pem":"-----BEGIN RSA PRIVATE KEY-----\nSECRET\n-----END RSA PRIVATE KEY-----\n","permissions":registration_permissions(true)});
    retain(
        &state.join("registration-response.private.json"),
        &serde_json::to_vec(&response).unwrap(),
    )
    .unwrap();
    let public = registration::recover(&state, &workspace, "owner", "project-host", true)
        .unwrap()
        .unwrap();
    assert_eq!(public["app_id"], 321);
    assert!(!public.to_string().contains("SECRET"));
    assert_eq!(
        registration::recover(&state, &workspace, "owner", "project-host", true).unwrap(),
        Some(public)
    );
    assert!(registration::recover(&state, &workspace, "other", "project-host", true).is_err());
    assert!(registration::recover(&state, &workspace, "owner", "project-host", false).is_err());
    assert_eq!(
        std::fs::metadata(state.join("app.private-key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    std::fs::remove_dir_all(root).unwrap();
}
