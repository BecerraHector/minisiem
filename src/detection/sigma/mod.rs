//! A subset of the Sigma rule format (https://sigmahq.io).

pub mod condition;
mod detector;
mod matching;
pub mod rule;
mod value;
mod wildcard;

pub use detector::SigmaDetector;
pub use rule::{RuleError, SigmaRule};
