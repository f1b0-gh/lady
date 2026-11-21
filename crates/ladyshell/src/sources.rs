//! Source selection retaining Ladyshell's typed application errors.
use crate::error::Result;
pub use nickel_util::sources::{excluded, FileRecord, Snapshot, Sources};
use std::path::Path;
pub fn snapshot(root: &Path, spec: &Sources, destination: Option<&Path>) -> Result<Snapshot> {
    nickel_util::sources::snapshot(root, spec, destination).map_err(Into::into)
}
