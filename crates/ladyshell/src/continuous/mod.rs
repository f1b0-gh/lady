//! Continuous source handoffs; credentials and revision authority stay on the host.
pub mod environment;
pub mod host;
pub mod model;
pub mod native;
pub mod worker;

pub(crate) fn invalid(message: impl Into<String>) -> crate::error::Error {
    crate::error::Error::InvalidInput {
        message: message.into(),
    }
}
