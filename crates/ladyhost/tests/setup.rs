use ladyhost::setup::{Spec, policies};
use serde_json::json;

fn spec() -> Spec {
    serde_json::from_value(json!({"schema_version":1,"repository":"owner/project","workspace":"/tmp/project","target":"main","app_name":"project-host","checks":[["python3","-m","unittest","discover"]],"gh":"/usr/bin/gh","jj":"/usr/bin/jj"})).unwrap()
}
#[test]
fn setup_inputs_bind_project_and_explicit_checks() {
    spec().validate().unwrap();
    let mut bad = spec();
    bad.repository = "owner/../other".into();
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.target = "--delete".into();
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.checks.clear();
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.checks[0][0] = "bad\0command".into();
    assert!(bad.validate().is_err());
    let mut bad = spec();
    bad.workspace = "relative".into();
    assert!(bad.validate().is_err());
}
#[test]
fn policies_only_grant_publisher_update_bypass() {
    let (update, quality) = policies(&spec(), "nonce", 123, 456).unwrap();
    assert_eq!(
        update["conditions"]["ref_name"]["include"],
        json!(["refs/heads/main"])
    );
    assert_eq!(
        update["bypass_actors"],
        json!([{"actor_id":123,"actor_type":"Integration","bypass_mode":"always"}])
    );
    assert_eq!(quality["bypass_actors"], json!([]));
    let rules = quality["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 6);
    let checks = &rules
        .iter()
        .find(|r| r["type"] == "required_status_checks")
        .unwrap()["parameters"];
    assert_eq!(checks["strict_required_status_checks_policy"], true);
    assert_eq!(
        checks["required_status_checks"],
        json!([{"context":"fixture/verify","integration_id":123},{"context":"ci/ladyhost","integration_id":456}])
    );
    assert!(policies(&spec(), "nonce", 123, 123).is_err());
}

use anyhow::{Result, bail};
use ladyhost::setup::{Api, Store, ensure_ruleset, remove_ruleset};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};
struct Fake {
    resources: BTreeMap<u64, Value>,
    posts: usize,
    deletes: usize,
    lose_create: bool,
    lose_delete: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            resources: BTreeMap::new(),
            posts: 0,
            deletes: 0,
            lose_create: false,
            lose_delete: false,
        }
    }
}
impl Api for Fake {
    fn get(&mut self, path: &str) -> Result<Option<Value>> {
        if path.contains('?') {
            return Ok(Some(json!(self.resources.values().collect::<Vec<_>>())));
        }
        let id = path.rsplit('/').next().unwrap().parse::<u64>().unwrap();
        Ok(self.resources.get(&id).cloned())
    }
    fn post(&mut self, _: &str, body: &Value) -> Result<Value> {
        self.posts += 1;
        let mut value = body.clone();
        value["id"] = json!(self.posts as u64 + 100);
        value["source"] = json!("owner/project");
        value["source_type"] = json!("Repository");
        self.resources
            .insert(self.posts as u64 + 100, value.clone());
        if self.lose_create {
            bail!("lost create reply");
        }
        Ok(value)
    }
    fn delete(&mut self, path: &str) -> Result<()> {
        self.deletes += 1;
        self.resources
            .remove(&path.rsplit('/').next().unwrap().parse::<u64>().unwrap());
        if self.lose_delete {
            bail!("lost delete reply");
        }
        Ok(())
    }
}
fn root(label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("ladyhost-setup-{}-{label}", std::process::id()));
    std::fs::create_dir(&p).unwrap();
    std::fs::create_dir(p.join("project")).unwrap();
    p
}
#[test]
fn lost_create_reply_is_reconciled_without_duplicate_creation_and_drift_is_preserved() {
    let root = root("create");
    let mut s = spec();
    s.workspace = root.join("project");
    let store = Store::open(&root.join("state"), &s).unwrap();
    assert!(
        Store::open(&root.join("state"), &s).is_err(),
        "Only one setup writer"
    );
    let (desired, _) = policies(&s, "nonce", 123, 456).unwrap();
    let mut api = Fake::new();
    api.lose_create = true;
    assert!(ensure_ruleset(&store, "update", &desired, &mut api).is_err());
    assert_eq!(api.posts, 1);
    let id = ensure_ruleset(&store, "update", &desired, &mut api).unwrap();
    assert_eq!(id, 101);
    assert_eq!(api.posts, 1);
    api.resources.get_mut(&id).unwrap()["enforcement"] = json!("disabled");
    assert!(ensure_ruleset(&store, "update", &desired, &mut api).is_err());
    assert!(remove_ruleset(&store, "update", &desired, &mut api).is_err());
    assert_eq!(api.deletes, 0);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn partial_uninstall_reconciles_absence_without_another_delete() {
    let root = root("delete");
    let mut s = spec();
    s.workspace = root.join("project");
    let store = Store::open(&root.join("state"), &s).unwrap();
    let (desired, _) = policies(&s, "nonce", 123, 456).unwrap();
    let mut api = Fake::new();
    ensure_ruleset(&store, "update", &desired, &mut api).unwrap();
    api.lose_delete = true;
    assert!(remove_ruleset(&store, "update", &desired, &mut api).is_err());
    remove_ruleset(&store, "update", &desired, &mut api).unwrap();
    assert_eq!(api.deletes, 1);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn workflow_keeps_check_arguments_as_data_even_with_provider_expressions() {
    let mut s = spec();
    s.checks = vec![vec![
        "python3".into(),
        "-c".into(),
        "print('${{ secrets.TOKEN }} __TARGET__ \\n')".into(),
    ]];
    let rendered = ladyhost::setup::workflow::render(&s).unwrap();
    assert!(!rendered.contains("secrets.TOKEN"));
    let encoded = rendered
        .lines()
        .find_map(|l| l.trim().strip_prefix("LADYHOST_CHECKS: "))
        .unwrap();
    let encoded: String = serde_json::from_str(encoded).unwrap();
    let bytes: Vec<u8> = serde_json::from_str(&encoded).unwrap();
    let checks: Vec<Vec<String>> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(checks, s.checks);
}

#[test]
fn setup_plan_describes_owned_resources_without_contacting_provider() {
    let plan = ladyhost::setup::engine::plan(&spec()).unwrap();
    assert_eq!(plan["repository"], "owner/project");
    assert_eq!(plan["target"], "main");
    assert_eq!(plan["owner_credentials_in_runtime"], false);
    assert_eq!(plan["source_checkout_modified"], false);
    assert_eq!(
        plan["required_checks"],
        json!(["fixture/verify", "ci/ladyhost"])
    );
}

#[test]
fn nested_source_cannot_hide_state_inside_the_actual_git_checkout() {
    let root = root("nested");
    let project = root.join("project");
    ladyhost::setup::native::git(&project, &["init"]).unwrap();
    std::fs::create_dir(project.join("src")).unwrap();
    let mut s = spec();
    s.workspace = project.join("src");
    assert!(Store::open(&project.join("private-state"), &s).is_err());
    assert!(!project.join("private-state").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn deterministic_create_recovery_rejects_missing_ambiguous_and_changed_resources() {
    for mode in 0..4 {
        let root = root(&format!("recovery-{mode}"));
        let mut s = spec();
        s.workspace = root.join("project");
        let store = Store::open(&root.join("state"), &s).unwrap();
        let (desired, _) = policies(&s, "nonce", 123, 456).unwrap();
        let mut api = Fake::new();
        api.lose_create = true;
        assert!(ensure_ruleset(&store, "update", &desired, &mut api).is_err());
        match mode {
            0 => api.resources.clear(),
            1 => {
                let mut v = api.resources[&101].clone();
                v["id"] = json!(102);
                api.resources.insert(102, v);
            }
            2 => {
                api.resources.get_mut(&101).unwrap()["conditions"] =
                    json!({"ref_name":{"include":["~ALL"],"exclude":[]}});
            }
            _ => {}
        }
        assert_eq!(
            ensure_ruleset(&store, "update", &desired, &mut api).is_ok(),
            mode == 3
        );
        assert_eq!(api.posts, 1);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn cancelling_before_registration_preserves_source_and_is_resumable() {
    let root = root("cancel");
    let mut s = spec();
    s.workspace = root.join("project");
    std::fs::write(s.workspace.join("keep.txt"), "uncommitted source").unwrap();
    let store = Store::open(&root.join("state"), &s).unwrap();
    let result = ladyhost::setup::engine::uninstall(&store).unwrap();
    assert_eq!(result["status"], "uninstalled");
    assert_eq!(result["installation_access_revoked"], false);
    assert_eq!(result, ladyhost::setup::engine::uninstall(&store).unwrap());
    assert_eq!(
        std::fs::read_to_string(s.workspace.join("keep.txt")).unwrap(),
        "uncommitted source"
    );
    assert!(ladyhost::setup::engine::init(&store).is_err());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn incomplete_manifest_is_not_misreported_as_remote_app_deletion() {
    let root = root("manifest-cancel");
    let mut s = spec();
    s.workspace = root.join("project");
    let store = Store::open(&root.join("state"), &s).unwrap();
    store.directory("registration").unwrap();
    store
        .record(
            "repository.json",
            &json!({"owner":{"login":"owner","type":"User"}}),
        )
        .unwrap();
    let result = ladyhost::setup::engine::uninstall(&store).unwrap();
    assert_eq!(result["status"], "pending");
    assert!(store.read("uninstall-complete.json").unwrap().is_none());
    assert_eq!(result, ladyhost::setup::engine::uninstall(&store).unwrap());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn workflow_slot_names_in_inputs_are_not_rescanned_as_template_code() {
    let mut s = spec();
    s.target = "__CHECK_NAME__".into();
    s.ci_check = "__CHECKS__".into();
    let text = ladyhost::setup::workflow::render(&s).unwrap();
    assert!(text.contains("'ladyhost/**', \"__CHECK_NAME__\""));
    assert!(text.contains("name: \"__CHECKS__\""));
}
