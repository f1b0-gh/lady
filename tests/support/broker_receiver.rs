//! Ordinary worker transport qualification; the fixture supplies host admission.
use super::*;
use ladyshell::execution::{
    self, Admission, ClientResult, InputChannel, Invocation, Phase, Store, Stream, TaskDefinition,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
pub(super) enum Case {
    Transport,
    Components,
}

pub(super) fn verify(root: &Path, state: &Path, case: Case) -> Result<()> {
    let definition = TaskDefinition {
        id: "fixture-worker".into(),
        argv: [
            "/usr/local/bin/sandbox-worker",
            "sandbox-execute",
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
        id: "original-echo".into(),
        task: "fixture-worker".into(),
        definition_sha256: store.catalog().definition_digest("fixture-worker")?,
        intent: json!({"key":"c".repeat(64),"value":{"message":"independent application"}}),
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
        json!({"echo":{"message":"independent application"}})
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
    if matches!(case, Case::Components) {
        components(root, &store)?;
    }
    Ok(())
}

fn operation(store: &Store, id: &str, operation: Value) -> Result<Value> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let invocation = Invocation {
        scope: "transport-qualification".into(),
        id: id.into(),
        task: "fixture-worker".into(),
        definition_sha256: store.catalog().definition_digest("fixture-worker")?,
        intent: operation,
    };
    store.accept_protected_with_clock(
        &invocation,
        &Admission {
            reference: format!("synthetic-{id}"),
            admit_before: now + 300,
            owner: None,
            claim: 1,
        },
        || Ok(now),
    )?;
    let record = execution::worker(store, &invocation.key())?;
    assert_eq!(record.phase, Phase::Completed);
    let outcome = record.outcome.ok_or("missing operation outcome")?;
    assert_eq!(outcome.result, ClientResult::Exit { code: 0 });
    assert!(!outcome.stdout.truncated && !outcome.stderr.truncated);
    Ok(ladyshell::json::parse(&store.read_output(
        &invocation.key(),
        Stream::Stdout,
        0,
        16384,
    )?)?)
}

fn components(root: &Path, store: &Store) -> Result<()> {
    // Arbitrary bytes and application JSON: no component format or external executor.
    let bytes = vec![23; 65536];
    let component = &ladyshell::files::hash(&bytes);
    let environment = &store.catalog().environment;
    let uploaded = execution::upload(environment, component, &bytes, 30)?;
    assert_eq!(uploaded.component, component.as_str());
    assert_eq!(uploaded.bytes, bytes.len() as u64);
    atomic_json(
        &root.join("component-upload.json"),
        &serde_json::to_value(uploaded)?,
    )?;
    assert!(execution::upload(environment, component, &bytes, 30).is_err());
    // The original complete component occupies part of the capped incoming area.
    // A larger distinct input must leave a partial file and report no receipt.
    let partial = vec![37; 2 * 1024 * 1024];
    let partial_digest = ladyshell::files::hash(&partial);
    assert!(execution::upload(environment, &partial_digest, &partial, 30).is_err());
    let backend = ladyshell::openshell::Backend::new(&environment.context)?;
    let mut probe = backend.command();
    probe.args([
        "sandbox",
        "exec",
        "--no-tty",
        "--no-login-shell",
        &environment.sandbox_name,
        "--",
        "/usr/local/bin/ladyshell",
        "broker-storage-probe",
    ]);
    let measured: Vec<ladyshell::storage::Filesystem> = serde_json::from_slice(
        &ladyshell::process::capture(probe, Duration::from_secs(30), 16384)?,
    )?;
    let incoming = measured
        .iter()
        .find(|m| m.target.ends_with("/incoming"))
        .ok_or("incoming cap observation")?;
    assert_eq!(incoming.available_bytes, 0);
    assert_eq!(incoming.bytes, 262144);
    assert!(execution::upload(environment, &partial_digest, &partial, 30).is_err());

    let executed = operation(
        store,
        "execute",
        json!({"key":"e".repeat(64), "value":{"uploaded":component}}),
    )?;
    assert_eq!(executed, json!({"echo":{"uploaded":component}}));
    atomic_json(
        &root.join("component-execution.json"),
        &json!({"execution":executed, "incoming":incoming,
            "partial_digest":partial_digest, "partial_bytes":partial.len(),
            "repeated_upload_refused":true, "independent_worker":true}),
    )?;
    Ok(())
}
