//! Shared evaluation exposed with Ladyshell's typed application errors.
use crate::error::Result;
pub use nickel_util::evaluation::{Evaluation, EvaluationRequest};
pub fn evaluate(request: &EvaluationRequest<'_>) -> Result<Evaluation> {
    nickel_util::evaluation::evaluate(request).map_err(Into::into)
}
