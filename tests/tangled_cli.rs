use ladyshell_cli::cli::validate_args;
#[test]
fn review_handoff_requires_exact_explicit_bindings() {
    let args = [
        "ladyshell",
        "review",
        "handoff",
        "--state",
        "/candidate",
        "--from-state",
        "/predecessor",
        "--from-attempt",
        "attempt",
        "--head",
        "head",
        "--base",
        "base",
        "--policy",
        "/policy",
        "--config",
        "/review-config",
    ];
    assert!(validate_args(&args).is_ok());
    for index in (3..args.len()).step_by(2) {
        let mut missing = args.to_vec();
        missing.drain(index..index + 2);
        assert!(validate_args(&missing).is_err(), "missing {}", args[index]);
    }
}
#[test]
fn ticket_creation_and_recovery_require_explicit_intent() {
    let create = [
        "ladyshell",
        "review",
        "submit",
        "--state",
        "/state",
        "--config",
        "/config",
        "--created-at",
        "2026-11-05T14:20:00Z",
        "--target-base",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--title",
        "Proposed change",
    ];
    assert!(validate_args(&create).is_ok());
    let mut predicted = create.to_vec();
    predicted.extend(["--ticket", "2"]);
    assert!(validate_args(&predicted).is_err());
    predicted.push("--resubmit");
    assert!(validate_args(&predicted).is_ok());
    let mut missing = create.to_vec();
    missing.push("--resubmit");
    assert!(validate_args(&missing).is_err());
    let selection = [
        "ladyshell",
        "review",
        "select-ticket",
        "--state",
        "/state",
        "--config",
        "/config",
        "--ticket-uri",
        "at://did:plc:repo/org.tangled.track.ticket/2",
        "--ticket-cid",
        "bafyrecord",
    ];
    assert!(validate_args(&selection).is_ok());
    assert!(validate_args(&selection[..selection.len() - 2]).is_err());
    let abandon = [
        "ladyshell",
        "review",
        "abandon-ticket",
        "--state",
        "/state",
        "--config",
        "/config",
        "--explanation",
        "Preserve uncertain attempt before a new request",
    ];
    assert!(validate_args(&abandon).is_ok());
    assert!(validate_args(&abandon[..abandon.len() - 2]).is_err());
}
#[test]
fn publication_policy_and_cleanup_require_sync() {
    assert!(validate_args(&[
        "ladyshell",
        "run",
        "--state",
        "/state",
        "--policy",
        "/policy",
        "--",
        "true"
    ])
    .is_err());
    assert!(validate_args(&[
        "ladyshell",
        "run",
        "--state",
        "/state",
        "--cleanup",
        "--",
        "true"
    ])
    .is_err());
    assert!(validate_args(&[
        "ladyshell",
        "run",
        "--state",
        "/state",
        "--sync",
        "--publish",
        "knot",
        "--branch",
        "agent/test",
        "--message",
        "Test",
        "--policy",
        "/policy",
        "--cleanup",
        "--",
        "true"
    ])
    .is_ok());
}
#[test]
fn recovery_and_task_commands_are_explicit() {
    for args in [
        vec!["ladyshell", "publication", "status", "--state", "/state"],
        vec![
            "ladyshell",
            "publication",
            "reconcile",
            "--state",
            "/state",
            "--retry",
        ],
        vec!["ladyshell", "task", "inspect", "--state", "/state"],
        vec!["ladyshell", "task", "complete", "--state", "/state"],
    ] {
        assert!(validate_args(&args).is_ok(), "{args:?}");
    }
    assert!(validate_args(&[
        "ladyshell",
        "publication",
        "reconcile",
        "--state",
        "/state",
        "--retry",
        "--abandon"
    ])
    .is_err());
}

#[test]
fn review_credential_rebind_is_explicit_and_requires_retained_state_and_config() {
    assert!(validate_args(&[
        "ladyshell",
        "review",
        "rebind-credentials",
        "--state",
        "/state",
        "--config",
        "/host-review.json"
    ])
    .is_ok());
    assert!(validate_args(&[
        "ladyshell",
        "review",
        "rebind-credentials",
        "--state",
        "/state"
    ])
    .is_err());
}

#[test]
fn merge_check_requires_explicit_exact_bindings() {
    let args = [
        "ladyshell",
        "review",
        "merge-check",
        "--state",
        "/state",
        "--config",
        "/config",
        "--policy",
        "/policy",
        "--remote",
        "knot",
        "--branch",
        "main",
        "--head",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--expected-target",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ];
    assert!(validate_args(&args).is_ok());
    assert!(validate_args(&args[..args.len() - 2]).is_err());
}

#[test]
fn host_owner_decision_requires_explicit_round_and_supported_decision() {
    let args = [
        "ladyshell",
        "review",
        "owner-decision",
        "--state",
        "/state",
        "--config",
        "/config",
        "--decision",
        "approved",
        "--head",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--base",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--patch-uri",
        "at://did:plc:repo/org.tangled.review.patch/round1",
        "--patch-cid",
        "roundcid",
    ];
    assert!(validate_args(&args).is_ok());
    assert!(validate_args(&args[..args.len() - 2]).is_err());
    let mut invalid = args;
    invalid[8] = "inferred";
    assert!(validate_args(&invalid).is_err());
}
