//! Syslog over UDP.

use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};

use chrono::{DateTime, Utc};

use super::Message;
use crate::event::Event;
use crate::ingestion::LogParser;

/// Largest datagram read; longer ones are truncated by the socket.
const MAX_DATAGRAM: usize = 8 * 1024;

/// A bound syslog UDP socket.
///
/// UDP syslog is unauthenticated: anyone who can reach the port can inject
/// events, with any host name and any timestamp. Hence loopback-only by
/// default, and arrival time instead of the claimed one.
pub struct SyslogUdp {
    socket: UdpSocket,
}

impl SyslogUdp {
    pub fn bind(addr: SocketAddr, allow_remote: bool) -> Result<Self, String> {
        if !allow_remote && !addr.ip().is_loopback() {
            return Err(format!(
                "refusing to listen on {addr}: syslog over UDP is unauthenticated and anyone who can reach \
                 the port can inject events; use a loopback address or pass --allow-remote-syslog"
            ));
        }
        let socket = UdpSocket::bind(addr).map_err(|e| format!("cannot listen on udp://{addr}: {e}"))?;
        Ok(Self { socket })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("bound socket has an address")
    }

    /// Reads datagrams on a new thread until the channel closes.
    pub fn spawn<P: LogParser + Send + 'static>(self, parser: P, events: Sender<Message>) -> JoinHandle<()> {
        thread::spawn(move || {
            let source = format!("udp://{}", self.local_addr());
            let mut buf = vec![0; MAX_DATAGRAM];
            loop {
                let len = match self.socket.recv_from(&mut buf) {
                    Ok((len, _sender)) => len,
                    Err(error) => {
                        let _ = events.send(Message::Failed {
                            source,
                            error: error.to_string(),
                        });
                        return;
                    }
                };
                // A closed channel means the pipeline is gone: stop quietly.
                if let Some(event) = event_from_datagram(&buf[..len], &parser, Utc::now())
                    && events.send(Message::Event(event)).is_err()
                {
                    return;
                }
            }
        })
    }
}

/// Parses one datagram, stamping the event with when it was `received`.
pub fn event_from_datagram(datagram: &[u8], parser: &dyn LogParser, received: DateTime<Utc>) -> Option<Event> {
    let text = String::from_utf8_lossy(datagram);
    let mut event = parser.parse(text.trim_end_matches(['\n', '\r', '\0']))?;
    event.timestamp = received;
    Some(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingestion::AutoParser;
    use chrono::{FixedOffset, TimeZone};

    fn parser() -> AutoParser {
        AutoParser::new(2026, FixedOffset::east_opt(0).unwrap())
    }

    #[test]
    fn stamps_events_with_arrival_time_not_the_claimed_one() {
        let received = Utc.with_ymd_and_hms(2026, 10, 22, 18, 0, 0).unwrap();
        // The sender claims a date far in the future, e.g. to flush windows.
        let datagram =
            b"<38>1 2099-01-01T00:00:00Z srv01 sshd 1 - - Failed password for root from 203.0.113.7 port 1 ssh2\n";

        let event = event_from_datagram(datagram, &parser(), received).unwrap();

        assert_eq!(event.timestamp, received);
        assert_eq!(event.user, "root");
    }

    #[test]
    fn tolerates_trailing_newlines_nul_bytes_and_invalid_utf8() {
        let received = Utc::now();
        let mut datagram = b"<38>Oct 22 10:00:00 srv01 sshd[1]: Invalid user \xff from 203.0.113.7 port 1".to_vec();
        datagram.extend(b"\r\n\0");

        let event = event_from_datagram(&datagram, &parser(), received).unwrap();

        assert_eq!(event.user, "\u{fffd}");
    }

    #[test]
    fn ignores_datagrams_that_are_not_sshd_events() {
        assert_eq!(event_from_datagram(b"", &parser(), Utc::now()), None);
        assert_eq!(event_from_datagram(b"<38>hello", &parser(), Utc::now()), None);
    }

    #[test]
    fn refuses_non_loopback_addresses_unless_allowed() {
        let error = SyslogUdp::bind("0.0.0.0:0".parse().unwrap(), false).err().unwrap();

        assert!(error.contains("refusing to listen on 0.0.0.0:0"), "{error}");
        assert!(error.contains("--allow-remote-syslog"), "{error}");
        assert!(SyslogUdp::bind("0.0.0.0:0".parse().unwrap(), true).is_ok());
    }

    #[test]
    fn binds_loopback_on_an_ephemeral_port() {
        let udp = SyslogUdp::bind("127.0.0.1:0".parse().unwrap(), false).unwrap();

        assert!(udp.local_addr().ip().is_loopback());
        assert_ne!(udp.local_addr().port(), 0);
    }

    #[test]
    fn spawned_reader_forwards_parsed_events() {
        let udp = SyslogUdp::bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let addr = udp.local_addr();
        let (tx, rx) = std::sync::mpsc::channel();
        udp.spawn(parser(), tx);

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"<38>hello", addr).unwrap();
        sender
            .send_to(
                b"<38>Oct 22 10:00:00 srv01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2",
                addr,
            )
            .unwrap();

        let message = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(matches!(message, Message::Event(event) if event.src_ip.to_string() == "203.0.113.7"));
    }
}
