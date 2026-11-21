use ladyhost::Config;
use serde_json::json;

#[test]
fn explicit_stack_base_accepts_git_refs_and_rejects_revision_expressions() {
    for base in ["app-experiment-base", "experiments/app-v2"] {
        let mut value = github();
        value["stack_base"] = json!(base);
        let config: Config = serde_json::from_value(value).unwrap();
        assert!(config.validate().is_ok());
    }
    for base in [
        "",
        "../main",
        "main~1",
        "main:other",
        "a.lock",
        "a\nb",
        "/main",
    ] {
        let mut value = github();
        value["stack_base"] = json!(base);
        let config: Config = serde_json::from_value(value).unwrap();
        assert!(config.validate().is_err(), "accepted {base:?}");
    }
}

fn configuration(endpoint: &str) -> serde_json::Value {
    json!({
        "endpoint": endpoint,
        "owner": "owner",
        "repository": "stack-lab",
        "workspace": "/tmp/jjpr-task",
        "token_file": "/tmp/jjpr-fixture/worker.secret.json"
    })
}

#[test]
fn local_fixture_config_rejects_other_authorities_and_embedded_credentials() {
    for endpoint in [
        "http://127.0.0.1:34080@evil.example",
        "http://localhost:34080",
        "http://127.0.0.1:34080/api/v1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "https://public.example",
    ] {
        let config: Config = serde_json::from_value(configuration(endpoint)).unwrap();
        assert!(config.validate().is_err(), "accepted {endpoint}");
    }
    let config: Config = serde_json::from_value(configuration("http://127.0.0.1:34080")).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn config_rejects_path_substitution_and_unknown_fields() {
    for (field, value) in [
        ("owner", "../other"),
        ("repository", "repo?token=x"),
        ("workspace", "relative"),
        ("token_file", "relative"),
    ] {
        let mut input = configuration("http://127.0.0.1:34080");
        input[field] = json!(value);
        let config: Config = serde_json::from_value(input).unwrap();
        assert!(config.validate().is_err(), "accepted {field}={value}");
    }
    let mut input = configuration("http://127.0.0.1:34080");
    input["signing_command"] = json!("agent-controlled");
    assert!(serde_json::from_value::<Config>(input).is_err());
}

fn github() -> serde_json::Value {
    let mut input = configuration("https://api.github.com");
    input["provider"] = json!("github");
    input["owner"] = json!("example-owner");
    input["repository"] = json!("jjpr.lab");
    input["expected_actor"] = json!("example-worker");
    input["reviewers"] = json!(["example-reviewer"]);
    input
}

#[test]
fn github_requires_exact_api_origin_and_explicit_actor() {
    let config: Config = serde_json::from_value(github()).unwrap();
    assert!(config.validate().is_ok());
    for endpoint in [
        "https://api.github.com.evil.test",
        "https://api.github.com@evil.test",
        "http://api.github.com",
        "http://127.0.0.1:34080",
        "https://api.github.com/path",
    ] {
        let mut input = github();
        input["endpoint"] = json!(endpoint);
        let config: Config = serde_json::from_value(input).unwrap();
        assert!(config.validate().is_err(), "accepted {endpoint}");
    }
    let mut input = github();
    input.as_object_mut().unwrap().remove("expected_actor");
    let config: Config = serde_json::from_value(input).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn github_auth_has_one_explicit_host_source() {
    let mut input = github();
    input["gh_cli"] = json!("/opt/bin/gh");
    let config: Config = serde_json::from_value(input.clone()).unwrap();
    assert!(config.validate().is_err());
    input.as_object_mut().unwrap().remove("token_file");
    let config: Config = serde_json::from_value(input.clone()).unwrap();
    assert!(config.validate().is_ok());
    input["gh_cli"] = json!("gh");
    let config: Config = serde_json::from_value(input).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn github_remote_and_actor_must_match_before_fetch() {
    let config: Config = serde_json::from_value(github()).unwrap();
    for remote in [
        "https://github.com/example-owner/jjpr.lab.git",
        "git@github.com:example-owner/jjpr.lab.git",
    ] {
        assert!(
            config
                .validate_binding("example-worker", &[("origin".into(), remote.into())])
                .is_ok()
        );
    }
    for remote in [
        "https://github.com/other/jjpr.lab.git",
        "https://secret@github.com/example-owner/jjpr.lab.git",
        "https://github.com/example-owner/jjpr.lab.git?x=1",
        "file:///tmp/repo",
    ] {
        assert!(
            config
                .validate_binding("example-worker", &[("origin".into(), remote.into())])
                .is_err()
        );
    }
    assert!(
        config
            .validate_binding(
                "other",
                &[(
                    "origin".into(),
                    "https://github.com/example-owner/jjpr.lab.git".into()
                )]
            )
            .is_err()
    );
    assert!(config.validate_binding("example-worker", &[]).is_err());
}

#[test]
fn credentials_and_receipts_cannot_be_placed_in_project_or_use_parent_paths() {
    for field in ["token_file", "gh_cli"] {
        let mut input = github();
        input.as_object_mut().unwrap().remove("token_file");
        input[field] = json!("/tmp/jjpr-task/secret");
        let config: Config = serde_json::from_value(input).unwrap();
        assert!(config.validate().is_err());
    }
    let mut input = github();
    input["publication"] = json!({"task":"a","receipt_dir":"/tmp/out/../jjpr-task/receipt"});
    let config: Config = serde_json::from_value(input).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn private_repository_is_not_enough_when_name_or_identity_changed() {
    let mut input = github();
    input["expected_repository_id"] = json!(42);
    let config: Config = serde_json::from_value(input).unwrap();
    for response in [
        json!({"private":true,"full_name":"other/repo","id":42}),
        json!({"private":true,"full_name":"example-owner/jjpr.lab","id":43}),
        json!({"private":false,"full_name":"example-owner/jjpr.lab","id":42}),
    ] {
        assert!(config.validate_repository(&response).is_err());
    }
    assert!(
        config
            .validate_repository(
                &json!({"private":true,"full_name":"example-owner/jjpr.lab","id":42})
            )
            .is_ok()
    );
}

#[cfg(unix)]
#[test]
fn symlink_alias_cannot_hide_authentication_inside_workspace() {
    use std::os::unix::fs::symlink;
    let root = std::env::temp_dir().join(format!("jjpr-host-paths-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let workspace = root.join("project");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join("secret"), b"{}").unwrap();
    symlink(&workspace, root.join("alias")).unwrap();
    let mut input = github();
    input["workspace"] = json!(workspace);
    input["token_file"] = json!(root.join("alias/secret"));
    let config: Config = serde_json::from_value(input).unwrap();
    assert!(config.validate_host_paths().is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn public_visibility_is_an_explicit_selection_not_an_automatic_fallback() {
    let mut input = github();
    input["visibility"] = json!("public");
    let config: Config = serde_json::from_value(input.clone()).unwrap();
    assert!(
        config
            .validate_repository(
                &json!({"private":false,"full_name":"example-owner/jjpr.lab","id":42})
            )
            .is_ok()
    );
    assert!(
        config
            .validate_repository(
                &json!({"private":true,"full_name":"example-owner/jjpr.lab","id":42})
            )
            .is_err()
    );
    input["visibility"] = json!("anything");
    assert!(serde_json::from_value::<Config>(input).is_err());
}

#[test]
fn revision_publication_never_creates_a_replacement_pr() {
    use ladyhost::Publication;
    use std::collections::BTreeMap;
    let binding: Publication = serde_json::from_value(json!({"task":"ranges","receipt_dir":"/tmp/receipts/2","bookmarks":{"child":"a".repeat(40)},"revision_prs":{"child":5}})).unwrap();
    let exact = BTreeMap::from([("child".to_owned(), 5)]);
    assert!(binding.validate_revisions(&exact, 0).is_ok());
    assert!(binding.validate_revisions(&exact, 1).is_err());
    assert!(binding.validate_revisions(&BTreeMap::new(), 1).is_err());
    assert!(
        binding
            .validate_revisions(&BTreeMap::from([("child".to_owned(), 6)]), 0)
            .is_err()
    );
    let bad: Publication = serde_json::from_value(json!({"task":"ranges","receipt_dir":"/tmp/receipts/2","bookmarks":{"child":"a".repeat(40)},"revision_prs":{"other":5}})).unwrap();
    assert!(
        bad.validate_revisions(&BTreeMap::from([("other".to_owned(), 5)]), 0)
            .is_err()
    );
}

#[test]
fn publication_cannot_rebind_checked_objects_after_fetch() {
    use ladyhost::Publication;
    use std::collections::BTreeMap;
    let binding:Publication=serde_json::from_value(json!({"task":"statistics","receipt_dir":"/tmp/receipts/1","bookmarks":{"parent":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}})).unwrap();
    let exact = BTreeMap::from([("parent".to_owned(), "a".repeat(40))]);
    assert!(binding.validate_candidates(&exact).is_ok());
    assert!(
        binding
            .validate_candidates(&BTreeMap::from([("parent".to_owned(), "b".repeat(40))]))
            .is_err()
    );
    let mut extra = exact;
    extra.insert("child".to_owned(), "c".repeat(40));
    assert!(binding.validate_candidates(&extra).is_err());
}

fn app_config() -> serde_json::Value {
    let mut input = github();
    input.as_object_mut().unwrap().remove("token_file");
    input["expected_actor"] = json!("publisher[bot]");
    input["expected_repository_id"] = json!(42);
    input["github_app"] = json!({"app_id":123,"installation_id":456,"slug":"publisher","private_key":"/tmp/host/publisher.pem","openssl":"/usr/bin/openssl"});
    input
}

#[test]
fn app_auth_accepts_only_pinned_bot_and_exclusive_host_source() {
    let config: Config =
        serde_json::from_value(app_config()).expect("App configuration must deserialize");
    assert!(config.validate().is_ok());
    for (field, value) in [
        ("expected_actor", json!("publisher")),
        ("expected_repository_id", json!(null)),
        ("token_file", json!("/tmp/host/token")),
        ("gh_cli", json!("/usr/bin/gh")),
    ] {
        let mut input = app_config();
        input[field] = value;
        assert!(
            serde_json::from_value::<Config>(input)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for (field, value) in [
        ("app_id", json!(0)),
        ("installation_id", json!(0)),
        ("slug", json!("other")),
        ("private_key", json!("/tmp/jjpr-task/key.pem")),
        ("openssl", json!("openssl")),
    ] {
        let mut input = app_config();
        input["github_app"][field] = value;
        assert!(
            serde_json::from_value::<Config>(input)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut ordinary = github();
    ordinary["expected_actor"] = json!("publisher[bot]");
    assert!(
        serde_json::from_value::<Config>(ordinary)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn app_git_destination_cannot_bypass_installation_with_ssh() {
    let config: Config = serde_json::from_value(app_config()).unwrap();
    assert!(
        config
            .validate_binding(
                "publisher[bot]",
                &[(
                    "origin".into(),
                    "https://github.com/example-owner/jjpr.lab.git".into()
                )]
            )
            .is_ok()
    );
    assert!(
        config
            .validate_binding(
                "publisher[bot]",
                &[(
                    "origin".into(),
                    "git@github.com:example-owner/jjpr.lab.git".into()
                )]
            )
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn app_host_paths_resolve_private_key_and_executable_aliases() {
    use std::os::unix::fs::symlink;
    let root = std::env::temp_dir().join(format!("jjpr-app-paths-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let workspace = root.join("project");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join("secret"), b"key").unwrap();
    symlink(&workspace, root.join("alias")).unwrap();
    for field in ["private_key", "openssl"] {
        let mut input = app_config();
        input["workspace"] = json!(workspace);
        input["github_app"][field] = json!(root.join("alias/secret"));
        assert!(
            serde_json::from_value::<Config>(input)
                .unwrap()
                .validate_host_paths()
                .is_err()
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
