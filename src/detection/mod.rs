//! Detection rules (domain). Rules consume normalized events and know
//! nothing about where those events came from.

pub mod sigma;
mod ssh_brute_force;

pub use ssh_brute_force::SshBruteForce;

use crate::alert::Alert;
use crate::event::Event;

/// Port: a stateful detection rule fed one event at a time. One event can
/// raise several alerts (e.g. a rule and a correlation built on it).
pub trait Detector {
    fn evaluate(&mut self, event: &Event) -> Vec<Alert>;
}
