//! Publication of verified audit documents. Quick and targeted profiles describe
//! partial scope; a single aggregate coverage unit never establishes exhaustivity.
use super::{
    documents::DOCUMENT_LIMIT,
    invalid,
    model::{Artifact, EvidenceManifest, FindingLink, RunMetadata, SourceManifest},
    report, verify,
};
use crate::{
    config,
    error::{ensure, Result},
    files,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

#[derive(Clone, Debug)]
pub struct Output {
    pub findings: Vec<Value>,
    pub coverage: Vec<Value>,
    pub artifacts: Vec<Artifact>,
    pub links: Vec<FindingLink>,
    pub sources: SourceManifest,
}

/// The caller owns the private run journal and holds its lock. Failed validation
/// retains partial documents for diagnosis but never emits a success report.
pub fn write(directory: &Path, mut metadata: RunMetadata, output: Output) -> Result<Value> {
    let directory = files::absolute(directory)?;
    let root = files::open_directory(&directory)?;
    let identity = root.metadata()?;
    // SAFETY: geteuid has no preconditions or side effects.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        identity.uid() == uid && identity.mode() & 0o077 == 0,
        "Private publication directory required"
    );
    for name in [
        "findings.json",
        "coverage-ledger.json",
        "source-manifest.json",
        "evidence-manifest.json",
        "run-metadata.json",
        "REPORT.md",
    ] {
        absent(&root, name)?;
    }
    let mut documents = BTreeMap::from([
        ("findings.json", encode(&output.findings)?),
        ("coverage-ledger.json", encode(&output.coverage)?),
        ("source-manifest.json", encode(&output.sources)?),
        (
            "evidence-manifest.json",
            encode(&EvidenceManifest {
                schema_version: 1,
                artifacts: output.artifacts,
            })?,
        ),
    ]);
    metadata.documents = documents
        .iter()
        .map(|(name, bytes)| ((*name).to_owned(), files::hash(bytes)))
        .collect();
    metadata.links = output.links;
    let metadata_bytes = encode(&metadata)?;
    for (name, bytes) in &documents {
        write_new(&root, name, bytes)?;
    }
    write_new(&root, "run-metadata.json", &metadata_bytes)?;
    documents.insert("run-metadata.json", metadata_bytes);
    same_directory(&root, &directory)?;
    let verified = verify::load(&directory)?;
    same_directory(&root, &directory)?;
    ensure!(
        documents
            .iter()
            .all(|(name, bytes)| verified.files.get(*name) == Some(bytes)),
        "Published documents changed during verification"
    );
    write_new(&root, "REPORT.md", report::render(&verified).as_bytes())?;
    same_directory(&root, &directory)?;
    Ok(verify::summary(&verified))
}

/// Build one aggregate unit, not a claim of exhaustive subsystem or attack-class
/// coverage. An absent hunter leaves an explicitly deferred, unreviewed unit.
pub fn coverage(
    paths: &[String],
    hunter_id: Option<&str>,
    summary: &str,
    fingerprints: &[String],
    unresolved: &[String],
) -> Result<Value> {
    ensure!(
        !paths.is_empty() && paths.len() <= 5000,
        "Coverage scope is empty or too large"
    );
    ensure!(
        fingerprints.len() <= 1024 && unresolved.len() <= 1024,
        "Coverage results too large"
    );
    for path in paths {
        config::relative_path(path)?;
    }
    if let Some(hunter) = hunter_id {
        config::identifier(hunter)?;
    } else {
        ensure!(
            fingerprints.is_empty(),
            "Finding without an identified hunter"
        );
    }
    let mut unresolved = unresolved.to_vec();
    let status = if hunter_id.is_none() {
        if unresolved.is_empty() {
            unresolved.push("No hunter finished: scope review deferred.".into());
        }
        "deferred"
    } else if !fingerprints.is_empty() {
        "candidate"
    } else if !unresolved.is_empty() {
        "blocked"
    } else {
        "covered"
    };
    let surface = format!("{}#audit-scope", paths[0]);
    let boundary = format!("{}#trust-boundaries", paths[0]);
    let subsystem = "profile/quick/all-in-scope-subsystems";
    let attack_class = "ATTACK-CLASSES.md#Access control";
    let coverage_id = [surface.as_str(), boundary.as_str(), subsystem, attack_class]
        .map(percent_encode)
        .join("::");
    let reviewed_paths = if hunter_id.is_some() { paths } else { &[] };
    let checks = match hunter_id {
        Some(hunter) => vec![json!({
            "agent_id": hunter,
            "reviewed_paths": paths,
            "invariant": "Aggregate review of the quick/targeted scope; partial coverage, with no completeness guarantee.",
            "method": "source",
            "result": summary,
            "artifact": null
        })],
        None => Vec::new(),
    };
    let unit = json!({
        "coverage_id": coverage_id,
        "canonical_refs": {
            "surface": surface,
            "boundary": boundary,
            "subsystem": subsystem,
            "attack_class": attack_class
        },
        "surface": "Aggregate audit scope",
        "boundary": "Scope trust boundaries",
        "subsystem": "Included subsystems, partial review",
        "attack_class": "Access control",
        "starting_paths": paths,
        "ordinary_attack_class_block": attack_class,
        "selected_companion_blocks": [],
        "excluded_blocks": [],
        "prior_status": "new",
        "attempts": [],
        "wave": 1,
        "status": status,
        "agent_id": hunter_id,
        "reviewed_paths": reviewed_paths,
        "local_checks": checks,
        "result_fingerprints": fingerprints,
        "unresolved": unresolved
    });
    crate::audit::validator::validate(
        crate::audit::validator::Mode::Coverage,
        &encode(std::slice::from_ref(&unit))?,
    )?;
    Ok(unit)
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

struct BoundedBytes(Vec<u8>);
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > DOCUMENT_LIMIT.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("Publication document too large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(value: &(impl Serialize + ?Sized)) -> Result<Vec<u8>> {
    let mut bytes = BoundedBytes(Vec::new());
    serde_json::to_writer_pretty(&mut bytes, value)?;
    bytes.write_all(b"\n")?;
    Ok(bytes.0)
}
fn absent(root: &File, name: &str) -> Result<()> {
    let name = CString::new(name)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: root owns a live descriptor, name is terminated, and metadata is
    // valid writable storage. Only the return status is inspected.
    let status = unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        return Err(invalid("A publication destination already exists"));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn write_new(root: &File, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= DOCUMENT_LIMIT, "Document too large");
    let name = CString::new(name)?;
    // SAFETY: root owns a live descriptor and name is terminated. O_EXCL and
    // O_NOFOLLOW prevent replacement or traversal of existing destinations.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd is newly opened and ownership is transferred exactly once.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.sync_all()?;
    root.sync_all()?;
    Ok(())
}
fn same_directory(root: &File, path: &Path) -> Result<()> {
    let expected = root.metadata()?;
    let actual = files::open_directory(path)?.metadata()?;
    ensure!(
        expected.dev() == actual.dev() && expected.ino() == actual.ino(),
        "Publication directory changed"
    );
    Ok(())
}
