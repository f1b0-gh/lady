//! Compatibility helpers retaining Ladyshell's typed application errors.
use crate::error::Result;
pub use nickel_util::files::hash;
use std::{
    ffi::OsStr,
    fs::File,
    path::{Path, PathBuf},
};
pub fn open_child(parent: &File, name: &OsStr, directory: bool) -> Result<File> {
    nickel_util::files::open_child(parent, name, directory).map_err(Into::into)
}
pub fn open_directory_child_path(parent: &File, name: &OsStr) -> Result<File> {
    nickel_util::files::open_directory_child_path(parent, name).map_err(Into::into)
}
pub fn open_entry(parent: &File, name: &OsStr) -> Result<File> {
    nickel_util::files::open_entry(parent, name).map_err(Into::into)
}
pub fn absolute(path: &Path) -> Result<PathBuf> {
    nickel_util::files::absolute(path).map_err(Into::into)
}
pub fn open_directory_path(path: &Path) -> Result<File> {
    nickel_util::files::open_directory_path(path).map_err(Into::into)
}
pub fn open_directory(path: &Path) -> Result<File> {
    nickel_util::files::open_directory(path).map_err(Into::into)
}
pub fn open_regular(path: &Path) -> Result<File> {
    nickel_util::files::open_regular(path).map_err(Into::into)
}
pub fn read_file(file: File, limit: usize) -> Result<Vec<u8>> {
    nickel_util::files::read_file(file, limit).map_err(Into::into)
}
pub fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    nickel_util::files::read_limited(path, limit).map_err(Into::into)
}
pub fn publish_json(path: &Path, value: &impl serde::Serialize, replace: bool) -> Result<()> {
    nickel_util::files::publish_json(path, value, replace).map_err(Into::into)
}
