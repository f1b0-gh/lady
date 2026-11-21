use super::{documents::DOCUMENT_LIMIT, invalid};
use crate::{error::Result, files};
use std::{collections::BTreeMap, fs::File, os::unix::fs::MetadataExt, path::Path};

pub const RUN_LIMIT: usize = 64 * 1024 * 1024;
pub const ARTIFACT_LIMIT: usize = 16 * 1024 * 1024;
pub(crate) struct Reader {
    root: File,
    total: usize,
    pub files: BTreeMap<String, Vec<u8>>,
}
impl Reader {
    pub fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            root: files::open_directory(path)?,
            total: 0,
            files: BTreeMap::new(),
        })
    }
    pub fn document(&mut self, name: &str) -> Result<&[u8]> {
        self.read(name, DOCUMENT_LIMIT)
    }
    pub fn read(&mut self, name: &str, limit: usize) -> Result<&[u8]> {
        crate::config::relative_path(name)?;
        if self.files.contains_key(name) {
            return Err(invalid("Duplicate file"));
        }
        if self.files.len() >= 1029 {
            return Err(invalid("Too many files in the run"));
        }
        let mut parent = self.root.try_clone()?;
        let mut parts = name.split('/').peekable();
        let mut file = None;
        while let Some(part) = parts.next() {
            if parts.peek().is_some() {
                parent = files::open_child(&parent, part.as_ref(), true)?;
            } else {
                file = Some(files::open_child(&parent, part.as_ref(), false)?);
            }
        }
        let file = file.ok_or_else(|| invalid("Empty path"))?;
        if file.metadata()?.nlink() != 1 {
            return Err(invalid("Multiple hard links forbidden"));
        }
        let bytes = files::read_file(file, limit.min(RUN_LIMIT.saturating_sub(self.total)))?;
        self.total += bytes.len();
        self.files.insert(name.into(), bytes);
        self.files
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| invalid("Missing document"))
    }
}
