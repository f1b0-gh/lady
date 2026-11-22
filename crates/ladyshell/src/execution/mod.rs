//! Host-managed retained OpenShell invocation identities and receipts.
mod capture;
pub(crate) mod fence;
mod runtime;
pub use runtime::{
    install, reconcile, recover, status, submit, upload, worker, Status, UploadedComponent,
};
mod model;
mod store;
pub use model::*;
pub use store::{Store, WorkerLease};
#[cfg(test)]
mod store_tests;
fn invalid(message: impl Into<String>) -> crate::error::Error {
    crate::error::Error::InvalidInput {
        message: message.into(),
    }
}
