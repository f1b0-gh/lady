//! Artifact lifecycle owned by ladyboot, using nickel-util shared host utilities.
pub mod artifact;
pub mod inventory;
pub mod profile;

#[cfg(feature = "cli")]
pub mod cli;
