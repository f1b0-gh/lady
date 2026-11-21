//! Static dependency analysis, independent of OpenShell and Nickel execution.
pub mod artifact;
pub mod deps;
pub mod inventory;
pub use deps::*;
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
