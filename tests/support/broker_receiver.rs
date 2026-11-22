//! Ordinary worker transport qualification; the fixture supplies host admission.
use super::*;
use ladyshell::execution::{
    self, Admission, ClientResult, InputChannel, Invocation, Phase, Store, Stream, TaskDefinition,
};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy)]
pub(super) enum Case {
    Transport,
    Components,
}

pub(super) fn verify(root: &Path, state: &Path, case: Case) -> Result<()> {
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
        task: "lo-broker".into(),
        definition_sha256: store.catalog().definition_digest("lo-broker")?,
        intent: json!({"format":1,"operation":operation}),
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
    let fixture = std::path::PathBuf::from(
        std::env::var_os("LADYSHELL_BROKER_TEST_PACKAGE")
            .ok_or("explicit maintained summary package fixture required")?,
    );
    let artifact = ladyshell::json::parse(&ladyshell::files::read_limited(
        &fixture.join("artifact.json"),
        16384,
    )?)?;
    let component = artifact["descriptor"]["component"]
        .as_str()
        .ok_or("component digest")?;
    assert!(component.len() == 64 && component.bytes().all(|b| b.is_ascii_hexdigit()));
    let bytes = ladyshell::files::read_limited(
        &fixture.join("components").join(format!("{component}.wasm")),
        2 * 1024 * 1024,
    )?;
    let environment = &store.catalog().environment;
    let uploaded = execution::upload(environment, component, &bytes, 30)?;
    assert_eq!(uploaded.component, component);
    assert_eq!(uploaded.bytes, bytes.len() as u64);
    atomic_json(
        &root.join("component-upload.json"),
        &serde_json::to_value(uploaded)?,
    )?;
    assert!(execution::upload(environment, component, &bytes, 30).is_err());
    let staged = operation(
        store,
        "stage",
        json!({"kind":"stage", "descriptor":artifact["descriptor"], "approved":artifact["pin"]}),
    )?;
    assert_eq!(staged["Ok"]["pin"], artifact["pin"]);

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

    let input = r#"{"alerts":[],"inventory":{"devices":[]}}"#;
    let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 300;
    let executed = operation(
        store,
        "execute",
        json!({"kind":"execute", "start": {
        "request":{"worker":"native-qualification","deployment":"fixed-broker", "incarnation":"a".repeat(64),"sequence":1,
            "binding":{"task":"transport-fixture","invocation":"original","attempt":1,"generation":1,
                "package":artifact["pin"],"action":"alerts.review", "input_digest":ladyshell::files::hash(input.as_bytes()),
                "context_digest":"b".repeat(64),"not_after":before}}, "input":input}}),
    )?;
    assert_eq!(executed["Ok"]["record"]["phase"], "completed");
    let result = executed["Ok"]["record"]["result"]["Ok"]
        .as_str()
        .ok_or("component result")?;
    assert_eq!(
        ladyshell::json::parse(result.as_bytes())?,
        json!({"high_priority":0,"matched_assets":0})
    );
    atomic_json(
        &root.join("component-execution.json"),
        &json!({"stage":staged, "execution":executed,
        "incoming":incoming, "partial_digest":partial_digest, "attempted_bytes":partial.len(),
        "repeated_upload_refused":true}),
    )?;
    Ok(())
}

/// Inspect the already verified archive after ordinary destruction. Both the
/// complete component and the actual interrupted input must survive deletion.
pub(super) fn verify_component_export(root: &Path) -> Result<()> {
    use std::io::Read;
    let read = |name| -> Result<Value> {
        Ok(ladyshell::json::parse(&ladyshell::files::read_limited(
            &root.join(name),
            16384,
        )?)?)
    };
    let uploaded = read("component-upload.json")?;
    let executed = read("component-execution.json")?;
    let destroyed = read("ordinary-destroy.json")?;
    assert_eq!(destroyed["destroy"]["deleted"], true);
    let original_digest = uploaded["component"].as_str().ok_or("component digest")?;
    let partial_digest = executed["partial_digest"]
        .as_str()
        .ok_or("partial digest")?;
    let original_path = PathBuf::from(format!("incoming/{original_digest}.wasm"));
    let partial_path = PathBuf::from(format!("incoming/{partial_digest}.wasm"));
    let path = destroyed["destroy"]["export"]["path"]
        .as_str()
        .ok_or("retained archive path")?;
    let mut archive = tar::Archive::new(ladyshell::files::open_regular(Path::new(path))?);
    let mut original_found = false;
    let mut partial_receipt = None;
    for entry in archive.entries()? {
        let entry = entry?;
        let name = entry.path()?.into_owned();
        if name != original_path && name != partial_path {
            continue;
        }
        assert!(entry.header().entry_type().is_file());
        let mut bytes = Vec::new();
        entry.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        assert!(bytes.len() <= 2 * 1024 * 1024);
        if name == original_path {
            assert!(!original_found);
            assert_eq!(ladyshell::files::hash(&bytes), original_digest);
            assert_eq!(json!(bytes.len()), uploaded["bytes"]);
            original_found = true;
        } else {
            assert!(partial_receipt.is_none());
            assert!(!bytes.is_empty() && bytes.len() < 2 * 1024 * 1024);
            assert!(bytes.iter().all(|byte| *byte == 37));
            assert_ne!(ladyshell::files::hash(&bytes), partial_digest);
            partial_receipt = Some(json!({
                "path":name, "bytes":bytes.len(), "sha256":ladyshell::files::hash(&bytes)
            }));
        }
    }
    assert!(original_found);
    let partial = partial_receipt.ok_or("missing original partial intake in export")?;
    atomic_json(
        &root.join("component-export.json"),
        &json!({"original_component":uploaded,"partial":partial,
            "attempted_bytes":executed["attempted_bytes"],"verified_after_deletion":true}),
    )?;
    Ok(())
}
