//! Syslog over UDP.

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use super::Outlet;
use crate::event::Event;
use crate::ingestion::LogParser;

/// Largest datagram read; longer ones are truncated by the socket.
const MAX_DATAGRAM: usize = 8 * 1024;

/// How often the reader checks whether the kernel started dropping.
const DROPS_CHECK: Duration = Duration::from_secs(1);

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

    /// The kernel's drop counter for this socket, where the system exposes it.
    pub fn kernel_drops(&self) -> Option<KernelDrops> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;

            let fd = std::fs::metadata(format!("/proc/self/fd/{}", self.socket.as_raw_fd())).ok()?;
            let table = match self.local_addr() {
                SocketAddr::V4(_) => "/proc/net/udp",
                SocketAddr::V6(_) => "/proc/net/udp6",
            };
            let drops = KernelDrops {
                inode: fd.ino(),
                table,
                _socket: Arc::new(self.socket.try_clone().ok()?),
            };
            drops.count().map(|_| drops)
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    /// Reads datagrams on a new thread until the pipeline is gone.
    pub fn spawn<P: LogParser + Send + 'static>(self, parser: P, outlet: Outlet) -> JoinHandle<()> {
        thread::spawn(move || {
            let source = format!("udp://{}", self.local_addr());
            let mut buf = vec![0; MAX_DATAGRAM];
            let mut kernel_drops = self.kernel_drops().map(|drops| (drops, Instant::now()));
            // Wakes up even when no datagram arrives, as a flood that is over
            // still has its drops to report.
            if kernel_drops.is_some()
                && let Err(error) = self.socket.set_read_timeout(Some(DROPS_CHECK))
            {
                outlet.fail(&source, error.to_string());
                return;
            }
            loop {
                let received = match self.socket.recv_from(&mut buf) {
                    Ok((len, _sender)) => Some(len),
                    Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => None,
                    Err(error) => {
                        outlet.fail(&source, error.to_string());
                        return;
                    }
                };
                if let Some((drops, checked)) = &mut kernel_drops
                    && checked.elapsed() >= DROPS_CHECK
                {
                    *checked = Instant::now();
                    if drops.count().is_some_and(|count| count > 0) {
                        eprintln!(
                            "minisiem: warning: the kernel is dropping datagrams sent to {source}: they arrive \
                             faster than minisiem reads them, possibly because of a flood"
                        );
                        kernel_drops = None;
                    }
                }
                if let Some(len) = received
                    && let Some(event) = event_from_datagram(&buf[..len], &parser, Utc::now())
                    && !outlet.event(event)
                {
                    return;
                }
            }
        })
    }
}

/// Datagrams the kernel dropped for one socket because its receive buffer
/// was full: they never reach minisiem, so only the kernel can count them.
#[derive(Clone, Debug)]
pub struct KernelDrops {
    inode: u64,
    table: &'static str,
    /// Keeps the socket, and so its counter, alive once the reader is gone.
    _socket: Arc<UdpSocket>,
}

impl KernelDrops {
    /// The current count, or `None` if it cannot be read.
    pub fn count(&self) -> Option<u64> {
        drops_for_inode(&std::fs::read_to_string(self.table).ok()?, self.inode)
    }
}

/// The `drops` column of the socket with `inode` in a `/proc/net/udp` table.
fn drops_for_inode(table: &str, inode: u64) -> Option<u64> {
    table.lines().skip(1).find_map(|line| {
        let columns: Vec<&str> = line.split_whitespace().collect();
        match columns.get(9)?.parse::<u64>() {
            Ok(found) if found == inode => columns.get(12)?.parse().ok(),
            _ => None,
        }
    })
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
        let (outlet, inlet) = super::super::channel(10);
        udp.spawn(parser(), outlet);

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"<38>hello", addr).unwrap();
        sender
            .send_to(
                b"<38>Oct 22 10:00:00 srv01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2",
                addr,
            )
            .unwrap();

        let event = inlet.next(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(event.src_ip.to_string(), "203.0.113.7");
    }

    #[test]
    fn reads_the_drops_of_the_socket_from_a_proc_table() {
        let table = "\
   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 2423: 010011AC:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   974        0 14467 2 0000000024891afb 3
 2423: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   974        0 14465 2 00000000c7a16b0a 7
";

        assert_eq!(drops_for_inode(table, 14465), Some(7));
        assert_eq!(drops_for_inode(table, 1), None, "not this socket");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn counts_the_datagrams_the_kernel_drops_on_a_full_buffer() {
        let udp = SyslogUdp::bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let drops = udp.kernel_drops().expect("Linux exposes socket drops");
        assert_eq!(drops.count(), Some(0));
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        // Nobody reads: the receive buffer fills and the kernel drops the rest.
        let sent = 20_000;
        for _ in 0..sent {
            sender.send_to(&[b'x'; 200], udp.local_addr()).unwrap();
        }
        udp.socket.set_nonblocking(true).unwrap();
        let mut buf = [0; 512];
        let received = std::iter::from_fn(|| udp.socket.recv(&mut buf).ok()).count() as u64;

        let dropped = drops.count().unwrap();
        assert!(dropped > 0, "the flood overflowed the buffer");
        // Loopback can also lose datagrams before the socket (the per-CPU
        // backlog), which the socket's counter does not see.
        assert!(
            received + dropped <= sent,
            "{received} read + {dropped} dropped of {sent}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn keeps_counting_after_the_reader_closed_its_socket() {
        // The reader stops once the pipeline is gone, before the summary.
        let udp = SyslogUdp::bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let drops = udp.kernel_drops().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..20_000 {
            sender.send_to(&[b'x'; 200], udp.local_addr()).unwrap();
        }

        drop(udp);

        assert!(drops.count().is_some_and(|count| count > 0));
    }
}
