//! A subset of the Sigma rule format (https://sigmahq.io).

pub mod condition;
pub mod correlation;
mod correlation_state;
mod detector;
mod matching;
pub mod rule;
pub mod ruleset;
mod value;
mod wildcard;

pub use correlation::{CorrelationRule, RuleDocument, parse_documents};
pub use detector::SigmaDetector;
pub use rule::{RuleError, SigmaRule};
pub use ruleset::RuleSet;
