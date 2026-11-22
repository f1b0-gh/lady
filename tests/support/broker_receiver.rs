//! Ordinary worker transport qualification; the fixture supplies host admission.
use super::*;
use ladyshell::execution::{
    self, Admission, ClientResult, InputChannel, Invocation, Phase, Store, Stream, TaskDefinition,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn verify(root: &Path, state: &Path) -> Result<()> {
    let definition = TaskDefinition {
        id: "lo-broker".into(),
        argv: [
            "/usr/local/bin/lo-executor-worker",
            "broker",
            "/var/lib/ladyshell/broker/control",
            "/var/lib/ladyshell/broker/artifacts",
            "/var/lib/ladyshell/broker/incoming",
        ]
        .map(String::from)
        .into(),
        timeout_seconds: 30,
        output_limit_bytes: 16384,
        input: Some(InputChannel::IntentJsonV1 { max_bytes: 16384 }),
    };
    let receiver = root.join("receiver");
    let binding = execution::install(state, &receiver, vec![definition])?;
    let store = Store::open(&receiver, &binding.receiver_id)?;
    store.bind_owner("transport-qualification", None)?;
    store.advance_claim("transport-qualification", None, 1)?;
    let clock = || -> ladyshell::error::Result<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .as_secs()
            + 1)
    };
    let invocation = Invocation {
        scope: "transport-qualification".into(),
        id: "original-initialize".into(),
        task: "lo-broker".into(),
        definition_sha256: store.catalog().definition_digest("lo-broker")?,
        intent: json!({"format":1,"operation":{"kind":"initialize","token":"c".repeat(64)}}),
    };
    let admission = Admission {
        reference: "synthetic-transport-qualification".into(),
        admit_before: clock()? + 300,
        owner: None,
        claim: 1,
    };
    let acceptance = store.accept_protected_with_clock(&invocation, &admission, clock)?;
    atomic_json(
        &root.join("receiver-acceptance.json"),
        &serde_json::to_value(acceptance)?,
    )?;
    let key = invocation.key();
    let record = execution::worker(&store, &key)?;
    atomic_json(
        &root.join("receiver-outcome.json"),
        &serde_json::to_value(&record)?,
    )?;
    assert_eq!(record.phase, Phase::Completed);
    let outcome = record
        .outcome
        .as_ref()
        .ok_or("missing ordinary worker outcome")?;
    assert_eq!(outcome.result, ClientResult::Exit { code: 0 });
    assert!(!outcome.stdout.truncated && !outcome.stderr.truncated);
    let output = store.read_output(&key, Stream::Stdout, 0, 16384)?;
    assert_eq!(
        ladyshell::json::parse(&output)?,
        json!({"Ok":{"token":"c".repeat(64),"accepting":true}})
    );
    assert!(execution::worker(&store, &key).is_err());
    let reopened = Store::open(&receiver, &binding.receiver_id)?;
    assert_eq!(
        serde_json::to_value(reopened.inspect(&key)?)?,
        serde_json::to_value(&record)?
    );
    assert_eq!(
        reopened.read_output(&key, Stream::Stdout, 0, 16384)?,
        output
    );
    Ok(())
}
