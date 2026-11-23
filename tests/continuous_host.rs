#![allow(clippy::unwrap_used)] // Synthetic CS state and driver fixtures only.
use ladyshell::{
    continuous::{
        environment,
        host::{self, Driver, Observation},
        model::*,
    },
    error::Result,
    plan, snapshot,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};

struct Fake {
    root: PathBuf,
    control: PathBuf,
    runtime: String,
    phase: String,
    fail_start: bool,
    drift: bool,
    calls: Vec<&'static str>,
}
impl Driver for Fake {
    fn can_swap_source(&mut self, _: &Value) -> Result<bool> {
        Ok(ladyshell::continuous::worker::profile(&self.root)["warm_source_swap"] == true)
    }
    fn observe(&mut self, _: &Value) -> Result<Observation> {
        Ok(Observation {
            sandbox_id: "sandbox".into(),
            owner: "owner".into(),
            runtime: self.runtime.clone(),
            phase: self.phase.clone(),
        })
    }
    fn verify(&mut self, _: &Value) -> Result<()> {
        assert_eq!(self.phase, "Ready");
        Ok(())
    }
    fn export(&mut self, state: &Value, dir: &Path) -> Result<Value> {
        struct Local(PathBuf);
        impl ladyshell::sync::Transport for Local {
            fn inventory(&mut self) -> Result<Vec<u8>> {
                Ok(serde_json::to_vec(&snapshot::inventory(&self.0)?)?)
            }
            fn file(&mut self, p: &str) -> Result<Vec<u8>> {
                Ok(serde_json::to_vec(&snapshot::read_file(&self.0, p)?)?)
            }
        }
        ladyshell::sync::sync_with(state, dir, &mut Local(self.root.clone()), false)
    }
    fn stop(&mut self, _: &Value) -> Result<()> {
        self.calls.push("stop");
        self.phase = "Stopped".into();
        Ok(())
    }
    fn start(&mut self, _: &Value) -> Result<()> {
        self.calls.push("start");
        self.phase = "Ready".into();
        self.runtime = "runtime-2".into();
        if self.drift {
            fs::write(self.root.join("app.py"), "late edit")?;
        }
        if self.fail_start {
            self.fail_start = false;
            return Err(ladyshell::error::Error::InvalidInput {
                message: "lost start reply".into(),
            });
        }
        Ok(())
    }
    fn apply(&mut self, _: &Value, bytes: &[u8]) -> Result<Acknowledgement> {
        ladyshell::continuous::worker::apply(&self.root, &self.control, bytes)
    }
    fn inventory(&mut self, _: &Value) -> Result<snapshot::Inventory> {
        snapshot::inventory(&self.root)
    }
}
fn fixture(
) -> std::result::Result<(tempfile::TempDir, PathBuf, Value, Fake), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let state = tmp.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let source = tmp.path().join("source");
    let root = tmp.path().join("root");
    fs::create_dir(&source)?;
    fs::create_dir(&root)?;
    fs::write(source.join("app.py"), "old")?;
    fs::write(root.join("app.py"), "old")?;
    let inv = snapshot::inventory(&source)?;
    let records: Value = serde_json::to_value(
        inv.iter()
            .map(|(p, e)| (p, json!({"sha256":e.sha256,"executable":e.executable})))
            .collect::<std::collections::BTreeMap<_, _>>(),
    )?;
    let desired = json!({"schema_version":2,"context":{},"evaluated":{"config":{"sources":{"include":["app.py"],"exclude":[]}}},"environment_lock":{"schema_version":1},
  "artifacts":{"ladyshell":{"sha256":"a".repeat(64)},"codex":{"sha256":"b".repeat(64)},"codex-code-mode-host":{"sha256":"c".repeat(64)}},
  "dependency_scan":{"complete":true,"missing":[]},"dependency_inventory":{"complete":true,"inputs":{},"projects":[]},"sources":records,"project":source});
    let cs = Session::new(
        "task".into(),
        "sandbox".into(),
        "owner".into(),
        "runtime-1".into(),
        environment::identity(&desired)?,
        plan::digest(&inv)?,
    )?;
    let current = json!({"schema_version":2,"sandbox_id":"sandbox","sandbox_name":"test","owner":"owner","policy_hash":"policy","codex_binary":"codex","desired_hash":"desired","image_id":"image","context":{"gateway":"test","workspace":"default"},"build_dir":"build","project_snapshot":source,"host_sources":records,"sync":{"destination":"exports"},"desired_inputs":desired,"continuous":cs});
    ladyshell::files::publish_json(&state.join("state.json"), &current, true)?;
    let fake = Fake {
        root,
        control: tmp.path().join("control"),
        runtime: "runtime-1".into(),
        phase: "Ready".into(),
        fail_start: true,
        drift: false,
        calls: vec![],
    };
    Ok((tmp, state, current, fake))
}
#[test]
fn lost_restart_reply_recovers_without_restarting_again_and_refresh_rebinds_exports(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (tmp, dir, current, mut fake) = fixture()?;
    assert!(host::checkpoint_with(&dir, &mut fake, "checkpoint", 0).is_err());
    let pending = ladyshell::state::load(&dir)?.unwrap();
    assert!(host::ensure_ready(&pending).is_err());
    let done = host::checkpoint_with(&dir, &mut fake, "checkpoint", 0)?;
    assert_eq!(done["continuous"]["phase"], "checkpointed");
    assert_eq!(fake.calls, vec!["stop", "start"]);
    let old_export = done["last_sync"].as_str().unwrap().to_owned();
    let candidate = tmp.path().join("candidate");
    fs::create_dir(&candidate)?;
    fs::write(candidate.join("app.py"), "new")?;
    let mut desired = current["desired_inputs"].clone();
    desired["project"] = json!(candidate);
    desired["sources"]["app.py"]["sha256"] = json!(ladyshell::files::hash(b"new"));
    let context = json!({"objective":"Continue","upstream":"host selected","next":"test app.py"});
    let refreshed = host::refresh_with(&dir, &mut fake, &desired, "refresh", &context)?;
    assert_eq!(refreshed["continuous"]["phase"], "refreshed");
    assert!(host::ensure_ready(&refreshed).is_err());
    let ready = host::resume_with(&dir, &mut fake, 1)?;
    host::ensure_ready(&ready)?;
    assert_eq!(fs::read(fake.root.join("app.py"))?, b"new");
    assert_eq!(ready["checkout_base"], desired["sources"]);
    let old = ladyshell::state::read(&Path::new(&old_export).join("manifest.json"))?.unwrap();
    assert!(host::verify_export(&ready, &old).is_err());
    assert!(host::checkpoint_with(&dir, &mut fake, "old", 0).is_err());
    Ok(())
}
#[test]
fn active_session_blocks_checkpoint_and_changed_environment_requests_replacement(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, dir, current, mut fake) = fixture()?;
    fake.fail_start = false;
    let lease = ladyshell::state::SessionLock::acquire(&dir, false)?;
    assert!(host::checkpoint_with(&dir, &mut fake, "checkpoint", 0).is_err());
    assert!(fake.calls.is_empty());
    drop(lease);
    host::checkpoint_with(&dir, &mut fake, "checkpoint", 0)?;
    let mut desired = current["desired_inputs"].clone();
    desired["dependency_inventory"]["inputs"] = json!({"new-manifest":"d".repeat(64)});
    let result = host::refresh_with(
        &dir,
        &mut fake,
        &desired,
        "refresh",
        &json!({"next":"fresh environment"}),
    )?;
    assert_eq!(result["continuous"]["phase"], "replacement_required");
    assert!(host::ensure_ready(&result).is_err());
    assert_eq!(fs::read(fake.root.join("app.py"))?, b"old");
    Ok(())
}

struct Replacement {
    old: Fake,
    new: Fake,
    creates: usize,
    retired: Vec<String>,
    lose_delete_reply: bool,
    desired: Value,
}

#[test]
fn local_runtime_distinguishes_restart_even_when_gateway_generation_is_reused(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use ladyshell::continuous::native::runtime_binding;
    let state = json!({"sandbox_id":"sandbox","sandbox_name":"name","image_id":"image","context":{"workspace":"default"}});
    let mut gateway =
        json!({"id":"sandbox","phase":"Ready","runtime_generation":"same-generation"});
    let mut container = json!({"id":"a".repeat(64),"image":"image","state":{"StartedAt":"2026-11-06T09:00:00Z","Running":true,"Paused":false,"Restarting":false},"labels":{"openshell.ai/sandbox-id":"sandbox","openshell.ai/sandbox-name":"name","openshell.ai/sandbox-workspace":"default","openshell.ai/isolation-role":"sandbox","openshell.ai/managed-by":"openshell"}});
    let before = runtime_binding(&state, &gateway, &container)?;
    gateway["phase"] = json!("Stopped");
    assert!(runtime_binding(&state, &gateway, &container).is_err());
    container["state"]["Running"] = json!(false);
    assert_eq!(runtime_binding(&state, &gateway, &container)?, before);
    gateway["phase"] = json!("Ready");
    container["state"]["Running"] = json!(true);
    container["state"]["StartedAt"] = json!("2026-11-06T09:01:00Z");
    assert_ne!(runtime_binding(&state, &gateway, &container)?, before);
    container["labels"]["openshell.ai/sandbox-id"] = json!("other");
    assert!(runtime_binding(&state, &gateway, &container).is_err());
    Ok(())
}

#[test]
fn checkpoint_discrepancy_retains_both_sides_until_exact_host_reconciliation(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, dir, _current, mut driver) = fixture()?;
    driver.fail_start = false;
    driver.drift = true;
    assert!(host::checkpoint_with(&dir, &mut driver, "checkpoint", 0).is_err());
    let current = ladyshell::state::load(&dir)?.unwrap();
    let c = &current["continuous_checkpoint"];
    let before = c["before_tree"].as_str().unwrap();
    let after = c["after_tree"].as_str().unwrap();
    assert_ne!(before, after);
    assert!(host::reconcile_checkpoint_with(&dir, &mut driver, before, before).is_err());
    let fixed = host::reconcile_checkpoint_with(&dir, &mut driver, before, after)?;
    assert_eq!(fixed["continuous"]["phase"], "checkpointed");
    assert_eq!(fixed["continuous"]["checkpoint_tree"], after);
    assert_eq!(
        fs::read(Path::new(c["before_export"].as_str().unwrap()).join("project/app.py"))?,
        b"old"
    );
    assert_eq!(
        fs::read(Path::new(c["after_export"].as_str().unwrap()).join("project/app.py"))?,
        b"late edit"
    );
    Ok(())
}

#[test]
fn retained_build_resources_refuse_recipe_drift_and_remain_independent(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir()?;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700))?;
    let resources = tmp.path().join("resources");
    fs::create_dir_all(resources.join("nix"))?;
    fs::write(resources.join("nix/build.nix"), "trusted")?;
    let desired = json!({"resources":resources,"environment_lock":{"recipes_sha256":{"build.nix":ladyshell::files::hash(b"trusted")}}});
    fs::write(resources.join("nix/build.nix"), "changed")?;
    let frozen = tmp.path().join("frozen");
    assert!(ladyshell::continuous::native::freeze_resources(&desired, &frozen).is_err());
    fs::write(resources.join("nix/build.nix"), "trusted")?;
    ladyshell::continuous::native::freeze_resources(&desired, &frozen)?;
    fs::write(resources.join("nix/build.nix"), "changed again")?;
    ladyshell::continuous::native::freeze_resources(&desired, &frozen)?;
    assert_eq!(fs::read(frozen.join("nix/build.nix"))?, b"trusted");
    fs::write(frozen.join("nix/build.nix"), "tampered retained")?;
    assert!(ladyshell::continuous::native::freeze_resources(&desired, &frozen).is_err());
    Ok(())
}
#[test]
fn retained_audit_resources_preserve_paths_and_refuse_changed_content(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    for path in [
        "resources/audit/security-audit/SKILL.md",
        "crates/ladyshell/resources/audit/security-audit/SKILL.md",
    ] {
        let tmp = tempfile::tempdir()?;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700))?;
        let resources = tmp.path().join("resources");
        let asset = resources.join(path);
        fs::create_dir_all(asset.parent().ok_or("asset parent")?)?;
        fs::write(&asset, b"trusted audit method")?;
        let desired = json!({"resources":resources,"environment_lock":{"recipes_sha256":{
            path: ladyshell::files::hash(b"trusted audit method")
        }}});
        let frozen = tmp.path().join("frozen");
        ladyshell::continuous::native::freeze_resources(&desired, &frozen)?;
        assert_eq!(fs::read(frozen.join(path))?, b"trusted audit method");
        fs::write(&asset, b"changed audit method")?;
        assert!(ladyshell::continuous::native::freeze_resources(
            &desired,
            &tmp.path().join("changed")
        )
        .is_err());
        assert!(!tmp.path().join("changed").exists());
        fs::write(frozen.join(path), b"tampered retained method")?;
        assert!(ladyshell::continuous::native::freeze_resources(&desired, &frozen).is_err());
    }
    Ok(())
}

impl Driver for Replacement {
    fn can_swap_source(&mut self, s: &Value) -> Result<bool> {
        if s["sandbox_id"] == "sandbox" {
            self.old.can_swap_source(s)
        } else {
            self.new.can_swap_source(s)
        }
    }
    fn observe(&mut self, s: &Value) -> Result<Observation> {
        if s["sandbox_id"] == "sandbox" {
            self.old.observe(s)
        } else {
            Ok(Observation {
                sandbox_id: "replacement".into(),
                owner: "new-owner".into(),
                runtime: "new-runtime".into(),
                phase: "Ready".into(),
            })
        }
    }
    fn verify(&mut self, _: &Value) -> Result<()> {
        Ok(())
    }
    fn export(&mut self, s: &Value, p: &Path) -> Result<Value> {
        self.old.export(s, p)
    }
    fn stop(&mut self, s: &Value) -> Result<()> {
        self.old.stop(s)
    }
    fn start(&mut self, s: &Value) -> Result<()> {
        self.old.start(s)
    }
    fn apply(&mut self, s: &Value, b: &[u8]) -> Result<Acknowledgement> {
        self.new.apply(s, b)
    }
    fn inventory(&mut self, s: &Value) -> Result<snapshot::Inventory> {
        if s["sandbox_id"] == "sandbox" {
            self.old.inventory(s)
        } else {
            self.new.inventory(s)
        }
    }
}
impl host::ReplacementDriver for Replacement {
    fn create(&mut self, desired: &Value, _: &Path) -> Result<Value> {
        self.creates += 1;
        assert_eq!(*desired, self.desired);
        Ok(
            json!({"schema_version":2,"sandbox_id":"replacement","sandbox_name":"new","owner":"new-owner","policy_hash":"policy","codex_binary":"codex","desired_hash":"desired","image_id":"image","context":{"gateway":"test","workspace":"default"},"build_dir":"build","project_snapshot":self.new.root,"host_sources":host::records(&snapshot::inventory(&self.new.root)?),"sync":{"destination":"exports"},"desired_inputs":desired}),
        )
    }
    fn retire(&mut self, s: &Value) -> Result<()> {
        let id = s["sandbox_id"].as_str().unwrap().to_owned();
        assert_eq!(id, "sandbox");
        if !self.retired.contains(&id) {
            self.retired.push(id);
        }
        if self.lose_delete_reply {
            self.lose_delete_reply = false;
            return Err(ladyshell::error::Error::InvalidInput {
                message: "lost delete reply".into(),
            });
        }
        Ok(())
    }
}
#[test]
fn replacement_activates_once_preserves_task_epoch_and_recovers_old_retirement(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    for storage_refusal in [false, true] {
        let (tmp, dir, current, mut old) = fixture()?;
        old.fail_start = false;
        host::checkpoint_with(&dir, &mut old, "checkpoint", 0)?;
        let mut desired = current["desired_inputs"].clone();
        if storage_refusal {
            std::os::unix::fs::symlink("/absent-generated-environment", old.root.join(".venv"))?;
            fs::write(
                Path::new(desired["project"].as_str().unwrap()).join("app.py"),
                "new",
            )?;
            desired["sources"]["app.py"]["sha256"] = json!(ladyshell::files::hash(b"new"));
        } else {
            desired["dependency_inventory"]["inputs"] = json!({"new-manifest":"d".repeat(64)});
        }
        let selected = host::refresh_with(
            &dir,
            &mut old,
            &desired,
            "refresh",
            &json!({"next":"fresh environment"}),
        )?;
        assert_eq!(selected["continuous"]["phase"], "replacement_required");
        assert_eq!(
            selected["continuous_replacement_reason"],
            if storage_refusal {
                "source_storage_profile"
            } else {
                "environment_changed"
            }
        );
        assert_eq!(fs::read(old.root.join("app.py"))?, b"old");
        let new_root = tmp.path().join("new-root");
        fs::create_dir(&new_root)?;
        fs::write(
            new_root.join("app.py"),
            if storage_refusal { "new" } else { "old" },
        )?;
        let new = Fake {
            root: new_root,
            control: tmp.path().join("new-control"),
            runtime: "new-runtime".into(),
            phase: "Ready".into(),
            fail_start: false,
            drift: false,
            calls: vec![],
        };
        let mut driver = Replacement {
            old,
            new,
            creates: 0,
            retired: vec![],
            lose_delete_reply: true,
            desired: selected["continuous_selection"]["desired"].clone(),
        };
        assert!(host::replace_with(&dir, &mut driver).is_err());
        let pending = ladyshell::state::load(&dir)?.unwrap();
        assert_eq!(pending["sandbox_id"], "replacement");
        assert!(host::ensure_ready(&pending).is_err());
        let ready = host::replace_with(&dir, &mut driver)?;
        host::ensure_ready(&ready)?;
        assert_eq!(ready["continuous"]["task"], "task");
        assert_eq!(ready["continuous"]["epoch"], 1);
        assert_eq!(ready["continuous"]["incarnation_epoch"], 0);
        let context: Value =
            serde_json::from_slice(&fs::read(driver.new.control.join("context.json"))?)?;
        assert_eq!(context["context"]["next"], "fresh environment");
        assert_eq!(driver.creates, 1);
        assert_eq!(driver.retired, vec!["sandbox"]);
        assert_eq!(host::replace_with(&dir, &mut driver)?, ready);
        assert_eq!(driver.creates, 1);
    }
    Ok(())
}

#[test]
fn deletion_fence_blocks_checkpoint_before_any_runtime_effect(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, directory, current, mut driver) = fixture()?;
    driver.fail_start = false;
    fs::write(directory.join("broker-destroy.json"), b"pending")?;
    assert!(host::checkpoint_with(&directory, &mut driver, "checkpoint", 0).is_err());
    assert!(driver.calls.is_empty());
    assert_eq!(ladyshell::state::load(&directory)?, Some(current));
    Ok(())
}
