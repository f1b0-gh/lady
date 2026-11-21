use ladyshell::audit::agent::parse_transcript;
use serde_json::json;
use std::error::Error;

fn transcript(result: serde_json::Value) -> Vec<u8> {
    format!(
        "{}\n{}\n",
        json!({"type":"item.completed","item":{"type":"agent_message","text":result.to_string()}}),
        json!({"type":"turn.completed","usage":{}})
    )
    .into_bytes()
}
fn response() -> serde_json::Value {
    json!({"summary":"Fixture review", "reviewed_paths":["src/main.rs"], "candidates":[], "finding_json":null, "unresolved":[]})
}
#[test]
fn requires_completed_codex_turn_and_strict_controller_protocol() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        parse_transcript(&transcript(response()))?.reviewed_paths,
        ["src/main.rs"]
    );
    assert!(parse_transcript(b"{\"type\":\"turn.completed\"}\n").is_err());
    let mut no_end = transcript(response());
    no_end.truncate(no_end.iter().position(|b| *b == b'\n').ok_or("newline")?);
    assert!(parse_transcript(&no_end).is_err());
    let mut extra = transcript(response());
    extra.extend_from_slice(b"{\"type\":\"turn.failed\"}\n");
    assert!(parse_transcript(&extra).is_err());
    let mut forged = response();
    forged["environment_verified"] = json!(true);
    assert!(parse_transcript(&transcript(forged)).is_err());
    Ok(())
}
#[test]
fn refuses_hostile_artifact_paths_and_unbounded_commands() -> Result<(), Box<dyn Error>> {
    let valid = ladyshell::audit::agent::TargetCheck {
        argv: vec!["printf".into(), "ok".into()],
        expected_exit: 0,
        expected_stdout: "ok".into(),
        artifacts: vec!["result.txt".into()],
    };
    ladyshell::audit::agent::validate_check(&valid)?;
    for path in ["/etc/passwd", "../outside", "a/../b", "a//b"] {
        let mut check = valid.clone();
        check.artifacts = vec![path.into()];
        assert!(
            ladyshell::audit::agent::validate_check(&check).is_err(),
            "{path}"
        );
        let mut v = response();
        v["candidates"] = json!([{"finding_json":"{}","checks":[{"argv":["printf","ok"],"expected_exit":0,"expected_stdout":"ok","artifacts":[path]}]}]);
        assert!(parse_transcript(&transcript(v)).is_err(), "{path}");
    }
    let mut v = response();
    v["reviewed_paths"] = json!(["../secret"]);
    assert!(parse_transcript(&transcript(v)).is_err());
    Ok(())
}

#[test]
fn rejects_unexpected_local_tools_even_with_a_valid_final_response() {
    let suffix = transcript(response());
    let event = json!({"type":"item.completed","item":{"type":"file_change","changes":[]}})
        .to_string()
        .into_bytes();
    let mut bytes = event;
    bytes.push(b'\n');
    bytes.extend_from_slice(&suffix);
    assert!(parse_transcript(&bytes).is_err());
}

#[test]
fn accepts_only_pinned_capability_warnings_before_the_model_turn() -> Result<(), Box<dyn Error>> {
    let warnings = [
        "Under-development features enabled: skip_host_skill_discovery. Under-development features are incomplete and may behave unpredictably. To suppress this warning, set `suppress_unstable_features_warning = true` in /audit/agent/.codex/config.toml.",
        "Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`.",
    ];
    let started = b"{\"type\":\"turn.started\"}\n";
    for message in warnings {
        let warning = format!(
            "{}\n",
            json!({"type":"item.completed","item":{"type":"error","message":message}})
        )
        .into_bytes();
        let good = [warning.as_slice(), started, &transcript(response())].concat();
        parse_transcript(&good)?;
        for bad in [
            [started.as_slice(), &warning, &transcript(response())].concat(),
            [warning.as_slice(), &transcript(response())].concat(),
            [
                warning.as_slice(),
                &warning,
                started,
                &transcript(response()),
            ]
            .concat(),
        ] {
            assert!(parse_transcript(&bad).is_err());
        }
    }
    for message in ["Authentication failed", "Code Mode is unavailable", ""] {
        let warning = format!(
            "{}\n",
            json!({"type":"item.completed","item":{"type":"error","message":message}})
        );
        assert!(
            parse_transcript(&[warning.as_bytes(), started, &transcript(response())].concat())
                .is_err()
        );
    }
    Ok(())
}
