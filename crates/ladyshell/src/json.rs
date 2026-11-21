//! Strict JSON parsing with Ladyshell's typed application errors.
use crate::error::Result;
pub fn parse(bytes: &[u8]) -> Result<serde_json::Value> {
    nickel_util::json::parse(bytes).map_err(Into::into)
}
