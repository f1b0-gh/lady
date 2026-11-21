//! Offline vulnerability assessment. No project execution, resolution or network I/O.
mod assess;
mod json;
pub use json::parse_json;
mod model;
pub use assess::assess;
pub(crate) use assess::public_identity;
pub mod osv;
pub use model::*;

use super::invalid;
use crate::{error::Result, files};
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub fn digest(value: &impl Serialize) -> Result<String> {
    Ok(files::hash(&serde_json::to_vec(value)?))
}

pub fn timestamp(value: &str) -> Result<i64> {
    instant(value).map(|date| date.unix_timestamp())
}

pub fn instant(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| invalid("Date RFC 3339 invalide".into()))
}

pub const MAX_RECORDS: usize = 100_000;
pub const MAX_FINDINGS: usize = 100_000;
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

pub mod policy;

pub mod vex;
pub mod vxdf;
