//! Public Rust API for Ladyshell’s OpenShell workflows.
//! Requests are plain Rust values; using the library does not load a CLI parser.
pub mod app;
pub mod apply;
pub mod audit;
pub mod auth;
pub mod check;
pub mod config;
pub mod continuous;
pub mod deps;
pub mod environment_lock;
pub mod error;
pub mod files;
pub mod image;
pub mod instances;
pub mod interactive;
pub mod json;
pub mod merge;
pub mod nickel;
pub mod openshell;
pub mod plan;
pub mod policy;
pub mod process;
pub mod request;
pub mod run;
pub mod scan;
pub mod snapshot;
pub mod sources;
pub mod state;
pub mod sync;

pub mod checkout;

pub mod associations;
pub mod presentation;

pub mod destroy;

pub mod evaluation;

pub mod publish;

pub mod publication_policy;
pub mod publication_recovery;

pub mod publication_checks;

pub mod tasks;

pub mod tangled_review;

pub mod retained_publication;

pub mod review_merge;

pub mod stacks;

pub mod management;
