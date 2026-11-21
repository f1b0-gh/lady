//! Static dependency analysis, independent of OpenShell and Nickel execution.
//! The optional `graph` feature adds graph persistence, usage and removal analysis.
pub mod artifact;
pub mod deps;
pub mod inventory;
pub use deps::*;
#[cfg(feature = "graph")]
use nickel_util::process;
pub use nickel_util::{files, json, sources};

mod config {
    pub use nickel_util::sources::{relative_path, Sources};
}
pub mod error {
    pub use nickel_util::error::{exit_code, Error, Result};
    macro_rules! ensure {
        ($condition:expr,$($message:tt)*) => {
            if !$condition { return Err(invalid(format!($($message)*))); }
        };
    }
    pub(crate) use ensure;
}
