//! Bounded worker payloads over the shared Ladybom inventory contract.
use crate::error::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
pub use ladybom::inventory::{Entry, Inventory, FILE_LIMIT, JSON_LIMIT, TOTAL_LIMIT};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePayload {
    pub path: String,
    pub entry: Entry,
    pub data: String,
}

pub fn validate_path(path: &str) -> Result<()> {
    ladybom::inventory::validate_path(path).map_err(Into::into)
}
pub fn validate(inventory: &Inventory) -> Result<()> {
    ladybom::inventory::validate(inventory).map_err(Into::into)
}
pub fn local_bytes(root: &Path, path: &str) -> Result<(Entry, Vec<u8>)> {
    ladybom::inventory::local_bytes(root, path).map_err(Into::into)
}
pub fn inventory(root: &Path) -> Result<Inventory> {
    ladybom::inventory::inventory(root).map_err(Into::into)
}
pub fn inventory_filtered(root: &Path, exclude: &[String]) -> Result<Inventory> {
    ladybom::inventory::inventory_filtered(root, exclude).map_err(Into::into)
}
pub fn read_file(root: &Path, path: &str) -> Result<FilePayload> {
    let (entry, data) = local_bytes(root, path)?;
    Ok(FilePayload {
        path: path.into(),
        entry,
        data: STANDARD.encode(data),
    })
}

pub fn preview_filtered(root: &Path, exclude: &[String]) -> Result<ladybom::inventory::Preview> {
    ladybom::inventory::preview_filtered(root, exclude).map_err(Into::into)
}
