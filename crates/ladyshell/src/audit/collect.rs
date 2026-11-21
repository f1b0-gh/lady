//! Promotion of bounded, declared evidence after the native runtime proves stop
//! and cleanup. Scratch trees and agent-provided paths are never copied wholesale.
use super::{invalid, model::Artifact, runtime::StoppedExecution, worker};
use crate::{config, error::Result, files};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::{File, Permissions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

const ARTIFACT_LIMIT: u64 = 16 * 1024 * 1024;
const COLLECTION_LIMIT: u64 = 64 * 1024 * 1024;
const LOG_LIMIT: u64 = 1024 * 1024;
const TRANSCRIPT_LIMIT: usize = 4 * 1024 * 1024;

/// An execution can only be supplied by the native runtime after cleanup.
/// External code cannot manufacture the witness from an untrusted receipt.
///
/// ```compile_fail
/// use ladyshell::audit::{runtime::StoppedExecution, worker::{WorkerReceipt, WorkerRequest}};
/// fn forge(receipt: WorkerReceipt, request: WorkerRequest) -> StoppedExecution {
///     StoppedExecution { receipt, request }
/// }
/// ```
pub fn collect_target(
    directory: &Path,
    producer: &str,
    check_id: &str,
    stopped: StoppedExecution,
) -> Result<Vec<Artifact>> {
    config::identifier(producer)?;
    config::identifier(check_id)?;
    let validated = validate_target(producer, check_id, stopped)?;
    let retained = artifact_directory(directory, producer)?;
    let stage = tempfile::Builder::new()
        .prefix(".audit-collect-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(fd_path(&retained))?;
    let name = stage
        .path()
        .file_name()
        .ok_or_else(|| invalid("Dossier temporaire absent"))?;
    let stage_root = files::open_child(&retained, name, true)?;
    for item in &validated {
        write_new(&stage_root, &item.relative_path, &item.bytes)?;
    }
    stage_root.sync_all()?;
    publish(&retained, name, check_id.as_ref())?;
    Ok(validated.into_iter().map(|item| item.artifact).collect())
}

/// Retains controller-captured agent output as data. The controller separately
/// validates its transcript contract and attributes the actual invocation.
pub fn retain_agent(
    directory: &Path,
    producer: &str,
    bytes: &[u8],
    command: impl AsRef<[String]>,
) -> Result<Artifact> {
    let command = command.as_ref();
    config::identifier(producer)?;
    validate_command(command)?;
    if bytes.len() > TRANSCRIPT_LIMIT {
        return Err(invalid("Transcript d’agent supérieur à 4 Mio"));
    }
    let id = format!("{producer}-transcript");
    config::identifier(&id)?;
    let artifact = Artifact {
        id,
        path: format!("agents/{producer}/artifacts/transcript.jsonl"),
        size: bytes.len() as u64,
        sha256: files::hash(bytes),
        producer: producer.to_owned(),
        command: command.to_vec(),
    };
    let retained = artifact_directory(directory, producer)?;
    let mut temporary = tempfile::NamedTempFile::new_in(fd_path(&retained))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    let name = temporary
        .path()
        .file_name()
        .ok_or_else(|| invalid("Fichier temporaire absent"))?;
    publish(&retained, name, "transcript.jsonl".as_ref())?;
    Ok(artifact)
}

struct ValidatedArtifact {
    relative_path: String,
    artifact: Artifact,
    bytes: Vec<u8>,
}

fn validate_target(
    producer: &str,
    check_id: &str,
    stopped: StoppedExecution,
) -> Result<Vec<ValidatedArtifact>> {
    let StoppedExecution { request, receipt } = stopped;
    worker::validate_request(&request)?;
    if receipt.schema_version != 1
        || receipt.invocation_id != request.invocation_id
        || !receipt.stopped
        || !(0..=255).contains(&receipt.exit_code)
        || receipt.cpu_usage_usec > request.limits.cpu_seconds.saturating_mul(1_000_000)
        || receipt.artifacts.len() >= 1024
    {
        return Err(invalid(
            "Reçu de cible incompatible, divergent ou hors limites",
        ));
    }
    let mut allowed = BTreeMap::from([
        ("stdout", ("stdout.txt", LOG_LIMIT)),
        ("stderr", ("stderr.txt", LOG_LIMIT)),
    ]);
    for artifact in &request.artifacts {
        if artifact.id == "execution"
            || artifact.path == "execution.json"
            || artifact.path.starts_with("execution.json/")
        {
            return Err(invalid(
                "Identifiant ou chemin réservé au reçu d’exécution du contrôleur",
            ));
        }
        allowed.insert(
            artifact.id.as_str(),
            (artifact.path.as_str(), artifact.max_bytes),
        );
    }
    if receipt.artifacts.len() != allowed.len() {
        return Err(invalid(
            "Artefacts requis manquants ou artefacts supplémentaires",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    let mut output = Vec::with_capacity(receipt.artifacts.len() + 1);
    for entry in receipt.artifacts {
        config::identifier(&entry.id)?;
        let &(path, limit) = allowed
            .get(entry.id.as_str())
            .ok_or_else(|| invalid("Artefact non déclaré"))?;
        if entry.path != path || !seen.insert(entry.id.clone()) {
            return Err(invalid(
                "Chemin d’artefact divergent ou identifiant dupliqué",
            ));
        }
        validate_path(&entry.path)?;
        if entry.size > limit
            || entry.size > ARTIFACT_LIMIT
            || entry.content_base64.len() as u64 != entry.size.div_ceil(3) * 4
        {
            return Err(invalid("Taille d’artefact ou contenu encodé hors limites"));
        }
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| invalid("Volume d’artefacts débordant"))?;
        if total > COLLECTION_LIMIT {
            return Err(invalid("Volume cumulé de collecte excessif"));
        }
        let bytes = STANDARD
            .decode(&entry.content_base64)
            .map_err(|_| invalid("Contenu base64 d’artefact invalide"))?;
        if bytes.len() as u64 != entry.size
            || STANDARD.encode(&bytes) != entry.content_base64
            || files::hash(&bytes) != entry.sha256
        {
            return Err(invalid(
                "Taille, encodage ou empreinte d’artefact divergent",
            ));
        }
        let id = format!("{producer}-{check_id}-{}", entry.id);
        config::identifier(&id)?;
        let artifact = Artifact {
            id,
            path: format!("agents/{producer}/artifacts/{check_id}/{}", entry.path),
            size: entry.size,
            sha256: entry.sha256,
            producer: producer.to_owned(),
            command: request.command.clone(),
        };
        validate_path(&artifact.path)?;
        // Commands are repeated in the public manifest. Count their serialized
        // size too, so many artifacts cannot amplify bounded command input.
        total = total
            .checked_add(serde_json::to_vec(&artifact)?.len() as u64)
            .ok_or_else(|| invalid("Métadonnées de collecte débordantes"))?;
        if total > COLLECTION_LIMIT {
            return Err(invalid("Collecte et métadonnées au-delà du plafond cumulé"));
        }
        output.push(ValidatedArtifact {
            relative_path: entry.path,
            artifact,
            bytes,
        });
    }
    output.sort_by(|left, right| left.artifact.id.cmp(&right.artifact.id));
    let references: Vec<_> = output
        .iter()
        .map(|item| {
            serde_json::json!({
                "id": item.artifact.id,
                "path": item.artifact.path,
                "size": item.artifact.size,
                "sha256": item.artifact.sha256,
            })
        })
        .collect();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "invocation_id": receipt.invocation_id,
        "exit_code": receipt.exit_code,
        "timed_out": receipt.timed_out,
        "output_limited": receipt.output_limited,
        "stopped": receipt.stopped,
        "cpu_usage_usec": receipt.cpu_usage_usec,
        "command": request.command,
        "artifacts": references,
    }))?;
    let id = format!("{producer}-{check_id}-execution");
    config::identifier(&id)?;
    let execution = Artifact {
        id,
        path: format!("agents/{producer}/artifacts/{check_id}/execution.json"),
        size: bytes.len() as u64,
        sha256: files::hash(&bytes),
        producer: producer.to_owned(),
        command: request.command,
    };
    let execution_metadata_size = serde_json::to_vec(&execution)?.len() as u64;
    total = total
        .checked_add(execution.size)
        .and_then(|size| size.checked_add(execution_metadata_size))
        .ok_or_else(|| invalid("Volume du reçu d’exécution débordant"))?;
    if execution.size > ARTIFACT_LIMIT || total > COLLECTION_LIMIT {
        return Err(invalid("Reçu d’exécution au-delà du plafond de collecte"));
    }
    output.push(ValidatedArtifact {
        relative_path: "execution.json".into(),
        artifact: execution,
        bytes,
    });
    output.sort_by(|left, right| left.artifact.id.cmp(&right.artifact.id));
    Ok(output)
}

fn validate_command(command: &[String]) -> Result<()> {
    if command.is_empty()
        || command.len() > 128
        || command
            .iter()
            .any(|argument| argument.is_empty() || argument.len() > 4096 || argument.contains('\0'))
    {
        return Err(invalid("Commande d’artefact absente ou hors limites"));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    config::relative_path(path)?;
    if path.len() > 4096 || path.split('/').any(|component| component.len() > 255) {
        return Err(invalid("Chemin d’artefact trop long"));
    }
    Ok(())
}

fn fd_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn private_directory(directory: &File) -> Result<()> {
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "Répertoire de preuves non privé ou propriétaire divergent",
        ));
    }
    Ok(())
}

fn child_directory(parent: &File, name: &str) -> Result<File> {
    let name_c = CString::new(name)?;
    // SAFETY: parent owns a pinned descriptor and name is a validated component.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) };
    if created != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    let child = files::open_child(parent, name.as_ref(), true)?;
    private_directory(&child)?;
    if created == 0 {
        child.sync_all()?;
        parent.sync_all()?;
    }
    Ok(child)
}

fn artifact_directory(directory: &Path, producer: &str) -> Result<File> {
    let root = files::open_directory(directory)?;
    private_directory(&root)?;
    let agents = child_directory(&root, "agents")?;
    let producer = child_directory(&agents, producer)?;
    child_directory(&producer, "artifacts")
}

fn write_new(root: &File, path: &str, bytes: &[u8]) -> Result<()> {
    let mut parent = root.try_clone()?;
    let mut parts = path.split('/').peekable();
    while let Some(component) = parts.next() {
        if parts.peek().is_some() {
            parent = child_directory(&parent, component)?;
        } else {
            let name = CString::new(component)?;
            // SAFETY: parent is pinned; the NUL-terminated name is one validated
            // component. O_EXCL and O_NOFOLLOW prevent adoption or replacement.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: fd is a fresh owned descriptor, transferred exactly once.
            let mut file = unsafe { File::from_raw_fd(fd) };
            file.write_all(bytes)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
                return Err(invalid("Fichier de preuve partagé ou non privé"));
            }
            file.sync_all()?;
            parent.sync_all()?;
        }
    }
    Ok(())
}

fn publish(parent: &File, temporary: &OsStr, destination: &OsStr) -> Result<()> {
    let source = CString::new(temporary.as_bytes())?;
    let target = CString::new(destination.as_bytes())?;
    // SAFETY: names are single validated components in the same pinned directory.
    // NOREPLACE makes the whole batch publication exclusive, including races.
    let result = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        config::Limits,
        runtime::StoppedExecution,
        worker::{ArtifactRequest, WorkerArtifact, WorkerReceipt, WorkerRequest},
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn root() -> std::io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
    }

    fn artifact(id: &str, path: &str, bytes: &[u8]) -> WorkerArtifact {
        WorkerArtifact {
            id: id.into(),
            path: path.into(),
            size: bytes.len() as u64,
            sha256: crate::files::hash(bytes),
            content_base64: STANDARD.encode(bytes),
        }
    }

    fn stopped() -> StoppedExecution {
        StoppedExecution {
            request: WorkerRequest {
                schema_version: 1,
                invocation_id: "target-check".into(),
                command: vec!["/fixture/check".into(), "--synthetic".into()],
                limits: Limits {
                    cpu_seconds: 10,
                    memory_bytes: 128 * 1024 * 1024,
                    processes: 64,
                    files: 128,
                    disk_bytes: 8 * 1024 * 1024,
                },
                timeout_seconds: 5,
                sources: vec![],
                artifacts: vec![ArtifactRequest {
                    id: "proof".into(),
                    path: "nested/proof.txt".into(),
                    max_bytes: 32,
                }],
            },
            receipt: WorkerReceipt {
                schema_version: 1,
                invocation_id: "target-check".into(),
                exit_code: 1,
                timed_out: false,
                output_limited: false,
                stopped: true,
                cpu_usage_usec: 1000,
                artifacts: vec![
                    artifact("stdout", "stdout.txt", b"synthetic output\n"),
                    artifact("stderr", "stderr.txt", b""),
                    artifact("proof", "nested/proof.txt", b"proof\n"),
                ],
            },
        }
    }

    #[test]
    fn promotes_only_declared_bytes_with_controller_identity_and_command() -> TestResult {
        let directory = root()?;
        let artifacts = collect_target(directory.path(), "hunter", "check-one", stopped())?;
        assert_eq!(artifacts.len(), 4);
        let proof = artifacts
            .iter()
            .find(|entry| entry.id == "hunter-check-one-proof")
            .ok_or("proof missing")?;
        assert_eq!(
            proof.path,
            "agents/hunter/artifacts/check-one/nested/proof.txt"
        );
        assert_eq!(proof.producer, "hunter");
        assert_eq!(proof.command, ["/fixture/check", "--synthetic"]);
        assert_eq!(proof.size, 6);
        assert_eq!(fs::read(directory.path().join(&proof.path))?, b"proof\n");
        assert_eq!(proof.sha256, crate::files::hash(b"proof\n"));
        assert_eq!(
            fs::metadata(directory.path().join(&proof.path))?
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert!(collect_target(directory.path(), "hunter", "check-one", stopped()).is_err());
        assert_eq!(fs::read(directory.path().join(&proof.path))?, b"proof\n");
        assert_eq!(
            fs::read_dir(directory.path().join("agents/hunter/artifacts"))?.count(),
            1
        );
        Ok(())
    }

    #[test]
    fn rejects_unproven_stop_identity_version_or_cpu_usage_before_publication() -> TestResult {
        let mutations: &[fn(&mut StoppedExecution)] = &[
            |value| value.receipt.stopped = false,
            |value| value.receipt.invocation_id = "other".into(),
            |value| value.receipt.schema_version = 2,
            |value| value.request.schema_version = 2,
            |value| value.receipt.cpu_usage_usec = 10_000_001,
            |value| value.receipt.exit_code = 256,
        ];
        for mutate in mutations {
            let directory = root()?;
            let mut value = stopped();
            mutate(&mut value);
            assert!(collect_target(directory.path(), "hunter", "check-one", value).is_err());
            assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        }
        Ok(())
    }

    #[test]
    fn retains_execution_outcome_and_artifact_references_without_embedded_contents() -> TestResult {
        let directory = root()?;
        let mut value = stopped();
        value.receipt.exit_code = 137;
        value.receipt.timed_out = true;
        value.receipt.output_limited = true;
        value.receipt.cpu_usage_usec = 4321;
        let artifacts = collect_target(directory.path(), "hunter", "check", value)?;
        let execution = artifacts
            .iter()
            .find(|item| item.id == "hunter-check-execution")
            .ok_or("execution record missing")?;
        assert_eq!(
            execution.path,
            "agents/hunter/artifacts/check/execution.json"
        );
        let bytes = fs::read(directory.path().join(&execution.path))?;
        assert_eq!(execution.size, bytes.len() as u64);
        assert_eq!(execution.sha256, crate::files::hash(&bytes));
        let document = crate::json::parse(&bytes)?;
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["invocation_id"], "target-check");
        assert_eq!(document["exit_code"], 137);
        assert_eq!(document["timed_out"], true);
        assert_eq!(document["output_limited"], true);
        assert_eq!(document["stopped"], true);
        assert_eq!(document["cpu_usage_usec"], 4321);
        assert_eq!(
            document["command"],
            serde_json::json!(["/fixture/check", "--synthetic"])
        );
        let references = document["artifacts"]
            .as_array()
            .ok_or("artifact references missing")?;
        assert_eq!(references.len(), 3);
        for reference in references {
            assert_eq!(reference.as_object().ok_or("invalid reference")?.len(), 4);
            let id = reference["id"].as_str().ok_or("reference ID missing")?;
            let retained = artifacts
                .iter()
                .find(|item| item.id == id)
                .ok_or("unretained reference")?;
            assert_ne!(id, execution.id);
            assert_eq!(reference["path"], retained.path);
            assert_eq!(reference["size"], retained.size);
            assert_eq!(reference["sha256"], retained.sha256);
        }
        assert!(!String::from_utf8(bytes)?.contains("content_base64"));
        assert_eq!(
            fs::read_dir(directory.path().join("agents/hunter/artifacts/check"))?.count(),
            4
        );
        Ok(())
    }

    #[test]
    fn refuses_worker_claims_on_execution_record_id_or_path_before_publication() -> TestResult {
        for (id, path) in [
            ("execution", "ordinary.json"),
            ("proof", "execution.json"),
            ("proof", "execution.json/child"),
        ] {
            let directory = root()?;
            let mut value = stopped();
            value.request.artifacts[0].id = id.into();
            value.request.artifacts[0].path = path.into();
            value.receipt.artifacts[2].id = id.into();
            value.receipt.artifacts[2].path = path.into();
            assert!(
                collect_target(directory.path(), "hunter", "check", value).is_err(),
                "accepted {id}/{path}"
            );
            assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        }
        Ok(())
    }

    #[test]
    fn reserves_one_artifact_slot_for_controller_execution_record() -> TestResult {
        for requested in [1021, 1022] {
            let mut value = stopped();
            value.request.limits.files = 4096;
            value.request.artifacts = (0..requested)
                .map(|index| ArtifactRequest {
                    id: format!("a{index}"),
                    path: format!("a{index}"),
                    max_bytes: 1,
                })
                .collect();
            value.receipt.artifacts.truncate(2);
            value.receipt.artifacts.extend(
                (0..requested)
                    .map(|index| artifact(&format!("a{index}"), &format!("a{index}"), b"x")),
            );
            let result = validate_target("hunter", "check", value);
            if requested == 1021 {
                assert_eq!(result?.len(), 1024);
            } else {
                assert!(
                    result.is_err(),
                    "controller record was omitted from the count cap"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn execution_record_bytes_and_metadata_count_toward_collection_limit() -> TestResult {
        let directory = root()?;
        let mut value = stopped();
        value.request.limits.files = 4096;
        // With this bounded command, worker artifacts and their metadata fit
        // under 64 MiB; adding execution.json exceeds the cap by about 40 KiB.
        value.request.command = vec!["x".repeat(4070); 16];
        value.request.artifacts = (0..1021)
            .map(|index| ArtifactRequest {
                id: format!("a{index}"),
                path: format!("a{index}"),
                max_bytes: 1,
            })
            .collect();
        value.receipt.artifacts.truncate(2);
        value.receipt.artifacts.extend(
            (0..1021).map(|index| artifact(&format!("a{index}"), &format!("a{index}"), b"x")),
        );
        assert!(collect_target(directory.path(), "hunter", "check", value).is_err());
        assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn rejects_missing_unrequested_duplicated_or_relabelled_artifacts() -> TestResult {
        let mutations: &[fn(&mut StoppedExecution)] = &[
            |value| {
                value.receipt.artifacts.pop();
            },
            |value| {
                value
                    .receipt
                    .artifacts
                    .push(artifact("extra", "secret.txt", b"undeclared"))
            },
            |value| {
                value
                    .receipt
                    .artifacts
                    .push(value.receipt.artifacts[0].clone())
            },
            |value| value.receipt.artifacts[2].path = "stdout.txt".into(),
            |value| value.receipt.artifacts[2].id = "stdout".into(),
            |value| value.receipt.artifacts[0].path = "other.log".into(),
            |value| value.request.artifacts[0].path = "stdout.txt/nested".into(),
            |value| value.request.artifacts[0].id = "stdout".into(),
        ];
        for mutate in mutations {
            let directory = root()?;
            let mut value = stopped();
            mutate(&mut value);
            assert!(collect_target(directory.path(), "hunter", "check-one", value).is_err());
            assert!(!directory.path().join("agents").exists());
        }
        Ok(())
    }

    #[test]
    fn rejects_bad_base64_sizes_digests_and_per_artifact_caps_before_writing() -> TestResult {
        let mutations: &[fn(&mut StoppedExecution)] = &[
            |value| value.receipt.artifacts[2].content_base64 = "not base64".into(),
            |value| value.receipt.artifacts[2].content_base64.push('\n'),
            |value| value.receipt.artifacts[2].sha256 = "0".repeat(64),
            |value| value.receipt.artifacts[2].sha256 = "a".repeat(63),
            |value| value.receipt.artifacts[2].size += 1,
            |value| value.receipt.artifacts[2].size = u64::MAX,
            |value| value.request.artifacts[0].max_bytes = 5,
            |value| {
                value.receipt.artifacts[0] =
                    artifact("stdout", "stdout.txt", &vec![b'x'; 1024 * 1024 + 1])
            },
        ];
        for mutate in mutations {
            let directory = root()?;
            let mut value = stopped();
            mutate(&mut value);
            assert!(collect_target(directory.path(), "hunter", "check-one", value).is_err());
            assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        }
        Ok(())
    }

    #[test]
    fn rejects_hostile_paths_ids_and_oversized_composite_identifiers() -> TestResult {
        for path in ["../proof", "/proof", "a//b", "a/./b", "a/../b", "a\nb"] {
            let directory = root()?;
            let mut value = stopped();
            value.request.artifacts[0].path = path.into();
            value.receipt.artifacts[2].path = path.into();
            assert!(collect_target(directory.path(), "hunter", "check-one", value).is_err());
            assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        }
        for (producer, check) in [
            ("../hunter", "check"),
            ("hunter", "../check"),
            ("", "check"),
            ("Hunter", "check"),
        ] {
            let directory = root()?;
            assert!(collect_target(directory.path(), producer, check, stopped()).is_err());
            assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        }
        let directory = root()?;
        assert!(collect_target(
            directory.path(),
            &"h".repeat(40),
            &"c".repeat(40),
            stopped()
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn rejects_aggregate_count_and_declared_byte_limits() -> TestResult {
        let directory = root()?;
        let mut value = stopped();
        value.request.artifacts = (0..5)
            .map(|index| ArtifactRequest {
                id: format!("a{index}"),
                path: format!("a{index}"),
                max_bytes: 16 * 1024 * 1024,
            })
            .collect();
        assert!(collect_target(directory.path(), "hunter", "check", value).is_err());
        let mut value = stopped();
        value.receipt.artifacts = vec![artifact("stdout", "stdout.txt", b""); 1025];
        assert!(collect_target(directory.path(), "hunter", "check", value).is_err());
        assert!(!directory.path().join("agents").exists());
        Ok(())
    }

    #[test]
    fn refuses_linked_parent_components_and_existing_check_directories() -> TestResult {
        for path in ["agents", "agents/hunter", "agents/hunter/artifacts"] {
            let directory = root()?;
            let external = root()?;
            let linked = directory.path().join(path);
            let parent = linked.parent().ok_or("missing parent")?;
            fs::create_dir_all(parent)?;
            let mut current = parent;
            while current != directory.path() {
                fs::set_permissions(current, fs::Permissions::from_mode(0o700))?;
                current = current.parent().ok_or("missing ancestor")?;
            }
            symlink(external.path(), &linked)?;
            assert!(collect_target(directory.path(), "hunter", "check", stopped()).is_err());
            assert_eq!(fs::read_dir(external.path())?.count(), 0);
        }
        let directory = root()?;
        let first = collect_target(directory.path(), "hunter", "check", stopped())?;
        assert!(collect_target(directory.path(), "hunter", "check", stopped()).is_err());
        assert_eq!(
            fs::read(directory.path().join(&first[0].path))?.len() as u64,
            first[0].size
        );
        Ok(())
    }

    #[test]
    fn refuses_hardlinks_special_files_and_symlink_run_ancestors() -> TestResult {
        let directory = root()?;
        fs::write(directory.path().join("sentinel"), b"unchanged")?;
        fs::hard_link(
            directory.path().join("sentinel"),
            directory.path().join("agents"),
        )?;
        assert!(collect_target(directory.path(), "hunter", "check", stopped()).is_err());
        assert_eq!(fs::read(directory.path().join("sentinel"))?, b"unchanged");
        let outer = root()?;
        let real = root()?;
        symlink(real.path(), outer.path().join("linked"))?;
        assert!(
            collect_target(&outer.path().join("linked"), "hunter", "check", stopped()).is_err()
        );
        assert_eq!(fs::read_dir(real.path())?.count(), 0);
        let directory = root()?;
        let fifo = CString::new(directory.path().join("agents").as_os_str().as_bytes())?;
        // SAFETY: fifo is a live NUL-terminated path in the private fixture.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(collect_target(directory.path(), "hunter", "check", stopped()).is_err());
        Ok(())
    }

    #[test]
    fn concurrent_collection_publishes_one_complete_batch_without_overwrite() -> TestResult {
        let directory = root()?;
        let outcomes = std::thread::scope(|scope| {
            let first =
                scope.spawn(|| collect_target(directory.path(), "hunter", "check", stopped()));
            let second =
                scope.spawn(|| collect_target(directory.path(), "hunter", "check", stopped()));
            (first.join(), second.join())
        });
        let first = outcomes.0.map_err(|_| "first collection thread panicked")?;
        let second = outcomes
            .1
            .map_err(|_| "second collection thread panicked")?;
        assert_ne!(first.is_ok(), second.is_ok());
        let artifacts = first.or(second)?;
        assert_eq!(artifacts.len(), 4);
        for artifact in artifacts {
            let bytes = fs::read(directory.path().join(&artifact.path))?;
            assert_eq!(bytes.len() as u64, artifact.size);
            assert_eq!(crate::files::hash(&bytes), artifact.sha256);
        }
        assert_eq!(
            fs::read_dir(directory.path().join("agents/hunter/artifacts"))?.count(),
            1
        );
        Ok(())
    }
}
