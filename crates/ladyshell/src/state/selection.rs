//! Non-authorizing bindings for host-reviewed lifecycle operations.
use super::*;
use serde::{Deserialize, Serialize};

/// Original directory identity and exact selected record. This is evidence for
/// comparison under the lifecycle lock, never a permission or an admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    device: u64,
    inode: u64,
    digest: String,
}
impl Selection {
    pub fn capture(lock: &StateLock, record: &Value) -> Result<Self> {
        lock.verify_directory()?;
        let metadata = lock.directory_file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            digest: crate::plan::digest(record)?,
        })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn verify_directory(&self, lock: &StateLock) -> Result<()> {
        lock.verify_directory()?;
        let metadata = lock.directory_file.metadata()?;
        ensure!(
            metadata.dev() == self.device && metadata.ino() == self.inode,
            "Lifecycle selection directory changed"
        );
        Ok(())
    }
    pub fn verify(&self, lock: &StateLock, record: &Value) -> Result<()> {
        self.verify_directory(lock)?;
        ensure!(
            crate::plan::digest(record)? == self.digest,
            "Lifecycle selection record changed"
        );
        Ok(())
    }
    pub fn verify_generation(&self, lock: &StateLock, current: &Value) -> Result<()> {
        self.verify(lock, &generation(current)?)
    }
}
fn generation(current: &Value) -> Result<Value> {
    validate(current)?;
    let mut generation = current.clone();
    // Export progress changes no deployment identity. Bind every other field,
    // including unrecognized extensions, source inputs and continuous sessions.
    if let Some(object) = generation.as_object_mut() {
        object.remove("last_sync");
    }
    Ok(generation)
}
/// Select an existing native or broker generation without contacting its backend.
pub fn select_generation(directory: &Path) -> Result<Selection> {
    let lock = StateLock::acquire_existing(directory)?;
    let current = load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    Selection::capture(&lock, &generation(&current)?)
}
