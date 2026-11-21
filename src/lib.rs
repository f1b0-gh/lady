//! Compatibility exports for existing `ladyshell::` library consumers.
//!
//! Parsed CLI options convert explicitly to the CLI-independent business API:
//! ```no_run
//! use clap::Parser;
//! use ladyshell_cli::cli::{Cli, Command};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cli = Cli::parse();
//! if let Command::Apply(options) = cli.command {
//!     let request: ladyshell::request::Desired = options.into();
//!     ladyshell::app::apply(&request)?;
//! }
//! # Ok(())
//! # }
//! ```
pub use ladyshell::*;

pub mod artifact_cli;
pub mod audit_cli;
pub mod cli;
pub mod deps_cli;

pub mod management_cli;
