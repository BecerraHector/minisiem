//! A subset of the Sigma rule format (https://sigmahq.io).

pub mod condition;
pub mod rule;
mod value;
mod wildcard;

pub use rule::{RuleError, SigmaRule};
