//! Alert delivery (adapters).

mod console;

pub use console::{ConsoleSink, EventLine};

use std::io;

use crate::alert::Alert;

/// Port: somewhere alerts are delivered to.
pub trait AlertSink {
    fn emit(&mut self, alert: &Alert) -> io::Result<()>;
}
