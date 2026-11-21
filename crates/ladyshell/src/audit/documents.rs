use super::invalid;
use crate::audit::validator::Mode;
use crate::{error::Result, files};
use serde_json::{json, Value};
use std::{os::unix::fs::MetadataExt, path::Path};

pub const DOCUMENT_LIMIT: usize = 5 * 1024 * 1024;
pub fn validate_file(mode: Mode, path: &Path) -> Result<Value> {
    let file = files::open_regular(path)?;
    if file.metadata()?.nlink() != 1 {
        return Err(invalid("Document partagé par liens physiques"));
    }
    let bytes = files::read_file(file, DOCUMENT_LIMIT)?;
    let count = crate::audit::validator::validate(mode, &bytes)?;
    Ok(
        json!({"schema_version":1,"operation":"validate", "document": match mode {
        Mode::Findings => "findings", Mode::Coverage => "coverage"
    }, "records":count,"document_valid":true}),
    )
}
