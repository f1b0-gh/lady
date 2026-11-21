use ladyshell::audit::{
    config::Limits,
    model::SourceFile,
    worker::{execute, validate_request, ArtifactRequest, WorkerRequest},
};

fn request() -> WorkerRequest {
    WorkerRequest {
        schema_version: 1,
        invocation_id: "synthetic-test".into(),
        command: vec!["/bin/true".into()],
        limits: Limits {
            cpu_seconds: 5,
            memory_bytes: 256 * 1024 * 1024,
            processes: 32,
            files: 128,
            disk_bytes: 1024 * 1024,
        },
        timeout_seconds: 1,
        sources: vec![],
        artifacts: vec![ArtifactRequest {
            id: "result".into(),
            path: "out/result.txt".into(),
            max_bytes: 1024,
        }],
    }
}

#[test]
fn accepts_a_bounded_request_without_executing_it() -> ladyshell::error::Result<()> {
    validate_request(&request())
}

#[test]
fn rejects_hostile_paths_and_reserved_artifacts() {
    for path in [
        "../result",
        "/result",
        "out/../result",
        "out//result",
        "out/./result",
        "out\nresult",
        "stdout.txt",
        "stderr.txt",
    ] {
        let mut request = request();
        request.artifacts[0].path = path.into();
        assert!(validate_request(&request).is_err(), "accepted {path:?}");
    }
    for id in ["stdout", "stderr", "../escape", "", "-bad"] {
        let mut request = request();
        request.artifacts[0].id = id.into();
        assert!(validate_request(&request).is_err(), "accepted {id:?}");
    }
}

#[test]
fn rejects_duplicate_ids_paths_and_file_directory_collisions() {
    for artifact in [
        ArtifactRequest {
            id: "result".into(),
            path: "other".into(),
            max_bytes: 1,
        },
        ArtifactRequest {
            id: "other".into(),
            path: "out/result.txt".into(),
            max_bytes: 1,
        },
        ArtifactRequest {
            id: "other".into(),
            path: "out/result.txt/nested".into(),
            max_bytes: 1,
        },
    ] {
        let mut request = request();
        request.artifacts.push(artifact);
        assert!(validate_request(&request).is_err());
    }
}

#[test]
fn rejects_source_hashes_sizes_duplicates_and_escape() {
    for (path, size, sha256) in [
        ("../escape", 0, "0".repeat(64)),
        ("file", u64::MAX, "0".repeat(64)),
        ("file", 0, "x".repeat(64)),
        ("file", 0, "0".repeat(63)),
    ] {
        let mut request = request();
        request.sources.push(SourceFile {
            path: path.into(),
            size,
            sha256,
        });
        assert!(validate_request(&request).is_err());
    }
    let mut request = request();
    let source = SourceFile {
        path: "file".into(),
        size: 0,
        sha256: "0".repeat(64),
    };
    request.sources = vec![source.clone(), source];
    assert!(validate_request(&request).is_err());
}

#[test]
fn rejects_excessive_or_zero_limits_and_invalid_commands() {
    let mut variants = Vec::new();
    let mut value = request();
    value.schema_version = 2;
    variants.push(value);
    let mut value = request();
    value.invocation_id = "../escape".into();
    variants.push(value);
    let mut value = request();
    value.timeout_seconds = 0;
    variants.push(value);
    let mut value = request();
    value.limits.cpu_seconds = 0;
    variants.push(value);
    let mut value = request();
    value.limits.processes = 2049;
    variants.push(value);
    let mut value = request();
    value.limits.files = 0;
    variants.push(value);
    let mut value = request();
    value.artifacts[0].max_bytes = 16 * 1024 * 1024 + 1;
    variants.push(value);
    let mut value = request();
    value.artifacts = (0..1025)
        .map(|i| ArtifactRequest {
            id: format!("a{i}"),
            path: format!("a{i}"),
            max_bytes: 1,
        })
        .collect();
    variants.push(value);
    let mut value = request();
    value.command = vec![];
    variants.push(value);
    let mut value = request();
    value.command = vec!["/bin/true\0".into()];
    variants.push(value);
    for value in variants {
        assert!(validate_request(&value).is_err(), "accepted {value:?}");
    }
}

#[test]
fn counts_reserved_logs_in_the_total_artifact_cap() {
    let mut request = request();
    request.limits.files = 2048;
    request.artifacts = (0..1023)
        .map(|index| ArtifactRequest {
            id: format!("a{index}"),
            path: format!("a{index}"),
            max_bytes: 1,
        })
        .collect();
    assert!(validate_request(&request).is_err());
}

#[test]
fn refuses_cpu_budgets_that_cannot_reserve_cleanup_time() {
    for cpu_seconds in 1..5 {
        let mut request = request();
        request.limits.cpu_seconds = cpu_seconds;
        assert!(validate_request(&request).is_err());
    }
}

#[test]
fn rejects_unknown_wire_fields_and_host_execution() -> Result<(), Box<dyn std::error::Error>> {
    let mut wire = serde_json::to_value(request())?;
    wire["disable_guards"] = true.into();
    assert!(serde_json::from_value::<WorkerRequest>(wire).is_err());
    // This executable must never provide a host execution fallback.
    assert!(execute(request()).is_err());
    Ok(())
}
