//! Create-only setup evidence and a process-held exclusive writer lock.
use super::*;
use crate::lifecycle::{
    private_directory, registration::registration_storage, retain, retained_json,
};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub struct Store {
    pub root: PathBuf,
    pub spec: Spec,
    _lock: File,
}
impl Store {
    pub fn open(root: &Path, spec: &Spec) -> Result<Self> {
        spec.validate()?;
        if let Ok(top) = native::git(&spec.workspace, &["rev-parse", "--show-toplevel"]) {
            ensure!(
                spec.workspace.canonicalize()? == std::path::Path::new(&top).canonicalize()?,
                "Select the actual Git checkout root as --workspace, not a nested source directory"
            );
        }
        registration_storage(root, &spec.workspace)?;
        let root = root.canonicalize()?;
        let lock_path = root.join("writer.lock");
        if lock_path.exists() {
            ensure!(
                fs::symlink_metadata(&lock_path)?.is_file(),
                "Invalid setup lock file"
            );
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)?;
        lock.try_lock()
            .context("Another Ladyhost setup operation is active")?;
        let selected = serde_json::to_value(spec)?;
        ensure!(
            serde_json::to_vec(&selected)?.len() <= 65536,
            "Setup request exceeds limit"
        );
        let request = root.join("request.json");
        if request.exists() {
            ensure!(
                retained_json(&request)? == selected,
                "Setup inputs differ from retained intent"
            );
        } else {
            retain(&request, &serde_json::to_vec_pretty(&selected)?)?;
        }
        Ok(Self {
            root,
            spec: spec.clone(),
            _lock: lock,
        })
    }
    pub fn resume(root: &Path) -> Result<Self> {
        let spec: Spec = serde_json::from_value(retained_json(&root.join("request.json"))?)?;
        Self::open(root, &spec)
    }
    fn file(&self, name: &str) -> Result<PathBuf> {
        ensure!(
            !name.is_empty()
                && name.len() <= 120
                && !name.contains("..")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "Invalid setup artifact name"
        );
        Ok(self.root.join(name))
    }
    pub fn read(&self, name: &str) -> Result<Option<Value>> {
        let path = self.file(name)?;
        if !path.try_exists()? {
            return Ok(None);
        }
        Ok(Some(retained_json(&path)?))
    }
    pub fn record(&self, name: &str, value: &Value) -> Result<()> {
        if let Some(old) = self.read(name)? {
            ensure!(&old == value, "Retained setup evidence differs: {name}");
            return Ok(());
        }
        retain(&self.file(name)?, &serde_json::to_vec_pretty(value)?)
    }
    pub fn directory(&self, name: &str) -> Result<PathBuf> {
        let path = self.file(name)?;
        private_directory(&path)?;
        Ok(path)
    }
}
