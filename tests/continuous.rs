#![allow(clippy::unwrap_used)] // Synthetic CS state and driver fixtures only.
use ladyshell::continuous::{environment, model::*};
use serde_json::{json, Value};

fn environment_input() -> Value {
    json!({"schema_version":2,"context":{"gateway":"test","workspace":"default"},
        "evaluated":{"config":{"sources":{"include":["src"],"exclude":[]},"tools":{"python":{"version":"3.12.15"}},"mission":"dev"}},
        "environment_lock":{"schema_version":1,"recipes_sha256":{"image.nix":"a".repeat(64)}},
        "artifacts":{"ladyshell":{"sha256":"a".repeat(64)},"codex":{"sha256":"b".repeat(64)},"codex-code-mode-host":{"sha256":"c".repeat(64)}},
        "sources":{"src/app.py":{"sha256":"a".repeat(64),"executable":false}},
        "dependency_scan":{"complete":true,"missing":[]},
        "dependency_inventory":{"complete":true,"inputs":{},"projects":[]},
        "dependency_preparation":null})
}

#[test]
fn environment_identity_separates_source_from_provisioning_and_refuses_unknown() {
    let before = environment_input();
    let expected = environment::identity(&before).unwrap();
    let mut after = before.clone();
    after["sources"]["src/app.py"]["sha256"] = json!("d".repeat(64));
    assert_eq!(environment::identity(&after).unwrap(), expected);
    for pointer in [
        "/environment_lock/recipes_sha256/image.nix",
        "/artifacts/ladyshell/sha256",
        "/evaluated/config/tools/python/version",
    ] {
        let mut after = before.clone();
        *after.pointer_mut(pointer).unwrap() = json!("d".repeat(64));
        assert_ne!(
            environment::identity(&after).unwrap(),
            expected,
            "{pointer}"
        );
    }
    let mut after = before.clone();
    after["dependency_inventory"]["inputs"] = json!({"nested/new/Cargo.toml":"d".repeat(64)});
    assert_ne!(environment::identity(&after).unwrap(), expected);
    for pointer in [
        "/dependency_scan/complete",
        "/dependency_inventory/complete",
    ] {
        let mut after = before.clone();
        *after.pointer_mut(pointer).unwrap() = json!(false);
        assert!(environment::identity(&after).is_err());
    }
    let mut prepared = before.clone();
    prepared["dependency_preparation"] = json!({"inputs":before["sources"],"projects":[]});
    let mut changed = prepared.clone();
    changed["dependency_preparation"]["inputs"]["src/app.py"]["sha256"] = json!("d".repeat(64));
    assert_ne!(
        environment::identity(&prepared).unwrap(),
        environment::identity(&changed).unwrap()
    );
}

fn session() -> Session {
    Session::new(
        "task-a".into(),
        "sandbox-a".into(),
        "owner-a".into(),
        "runtime-a".into(),
        "a".repeat(64),
        "b".repeat(64),
    )
    .unwrap()
}

#[test]
fn checkpoint_refresh_and_resume_require_exact_binding_and_new_runtime() {
    let mut state = session();
    state.begin_checkpoint("cycle-1", 0).unwrap();
    assert!(state.admit("sandbox-a", "runtime-a").is_err());
    assert!(state
        .finish_checkpoint("cycle-1", "runtime-a", "c".repeat(64))
        .is_err());
    state
        .finish_checkpoint("cycle-1", "runtime-b", "c".repeat(64))
        .unwrap();
    let offer = RefreshOffer::new(&state, "refresh-1", "d".repeat(64), "e".repeat(64)).unwrap();
    let mut wrong = offer.clone();
    wrong.sandbox_id = "sandbox-b".into();
    assert!(state.begin_refresh(&wrong).is_err());
    state.begin_refresh(&offer).unwrap();
    let mut ack = Acknowledgement::for_offer(&offer, "runtime-b");
    ack.tree = "f".repeat(64);
    assert!(state.acknowledge(&offer, &ack).is_err());
    let ack = Acknowledgement::for_offer(&offer, "runtime-b");
    state.acknowledge(&offer, &ack).unwrap();
    assert!(state.admit("sandbox-a", "runtime-b").is_err());
    state.resume(&ack).unwrap();
    assert_eq!(state.epoch, 1);
    assert_eq!(state.tree, "d".repeat(64));
    state.admit("sandbox-a", "runtime-b").unwrap();
    assert!(state.admit("sandbox-a", "runtime-a").is_err());
    assert!(state.begin_refresh(&offer).is_err());
    assert!(state.begin_checkpoint("cycle-2", 0).is_err());
}

#[test]
fn deterministic_duplicate_reordered_and_cross_incarnation_messages_never_resume() {
    let mut refused = 0;
    for seed in 0..300u64 {
        let mut state = session();
        state.epoch = seed;
        state.begin_checkpoint("checkpoint", seed).unwrap();
        state
            .finish_checkpoint("checkpoint", "runtime-b", "c".repeat(64))
            .unwrap();
        let offer = RefreshOffer::new(&state, "refresh", "d".repeat(64), "e".repeat(64)).unwrap();
        state.begin_refresh(&offer).unwrap();
        let original = state.clone();
        let mut ack = Acknowledgement::for_offer(&offer, "runtime-b");
        match seed % 6 {
            0 => ack.task = "other-task".into(),
            1 => ack.sandbox_id = "other-sandbox".into(),
            2 => ack.epoch = seed,
            3 => ack.attempt = "other-attempt".into(),
            4 => ack.environment = "f".repeat(64),
            _ => ack.context = "f".repeat(64),
        }
        assert!(state.acknowledge(&offer, &ack).is_err(), "seed={seed}");
        assert_eq!(state, original, "seed={seed}");
        assert!(state.resume(&ack).is_err(), "seed={seed}");
        assert!(
            state.admit("sandbox-a", "runtime-b").is_err(),
            "seed={seed}"
        );
        refused += 1;
    }
    assert_eq!(refused, 300);
}
