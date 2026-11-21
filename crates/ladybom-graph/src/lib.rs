//! Persist Ladybom graph projections and analyze dependency alignment and removal.
mod alignment;
mod alignment_plan;
mod alignment_policy;
mod explain_alignment;
mod ladybug;
mod prune;
pub mod prune_validation;
mod snapshot;
pub mod usage;

pub use alignment::*;
pub use alignment_plan::*;
pub use alignment_policy::*;
pub use explain_alignment::*;
pub use ladybom::graph::*;
pub use ladybug::*;
pub use prune::*;
pub use snapshot::{read_snapshot, write_snapshot};

use ladybom::{
    error::{Error, Result},
    files,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

macro_rules! ensure {
    ($condition:expr,$($message:tt)*) => {
        if !$condition { return Err($crate::invalid(format!($($message)*))); }
    };
}
pub(crate) use ensure;
