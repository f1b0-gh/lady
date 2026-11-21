//! Explicit preparation and sandbox validation over the shared Ladybom model.
mod cargo_config;
pub mod input;
mod model;
pub mod prepare;
pub mod prune_validation;
use crate::error::{Error, Result};
pub use ladybom::deps::{
    basename, project_sources, scan_project, scan_snapshot, Artifact, Component, Diagnostic,
    Project, Report, Requirement, ToolRequirement,
};
pub use model::*;
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
fn parse_toml(content: &str) -> Result<toml::Value> {
    ladybom::deps::parse_toml(content).map_err(Into::into)
}
