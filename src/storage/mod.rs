//! Event and alert storage (adapter): a SQLite database file that keeps
//! normalized events and alerts for later search.
//!
//! Writes are grouped in transactions and the journal is in WAL mode, so a
//! flood does not sync to disk once per event. Times are stored as fixed-width
//! RFC 3339 UTC text, which sorts in time order and reads well in `sqlite3`.

use std::fmt;
use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use crate::alert::{Alert, Evidence};
use crate::event::Event;

/// The schema this version of minisiem writes, kept in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 1;

/// Rows written before the open transaction is committed on its own.
const BATCH: usize = 1_000;

/// How long to wait for another process holding the database.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

const SCHEMA: &str = "
CREATE TABLE events (
    id       INTEGER PRIMARY KEY,
    time     TEXT NOT NULL,
    host     TEXT NOT NULL,
    process  TEXT NOT NULL,
    kind     TEXT NOT NULL,
    user     TEXT NOT NULL,
    src_ip   TEXT NOT NULL,
    message  TEXT NOT NULL,
    product  TEXT,
    service  TEXT,
    category TEXT
);
CREATE INDEX events_time ON events (time);
CREATE INDEX events_src_ip ON events (src_ip, time);
CREATE INDEX events_user ON events (user, time);
CREATE INDEX events_host ON events (host, time);

CREATE TABLE alerts (
    id       INTEGER PRIMARY KEY,
    time     TEXT NOT NULL,
    rule_id  TEXT NOT NULL,
    title    TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip   TEXT NOT NULL,
    host     TEXT NOT NULL,
    alert    TEXT NOT NULL
);
CREATE INDEX alerts_time ON alerts (time);
CREATE INDEX alerts_src_ip ON alerts (src_ip, time);
CREATE INDEX alerts_host ON alerts (host, time);
";

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    /// The file was written by another version of minisiem.
    UnknownSchema(i64),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sqlite(e) => write!(f, "{e}"),
            StoreError::Json(e) => write!(f, "cannot encode alert: {e}"),
            StoreError::UnknownSchema(version) => write!(
                f,
                "unknown database schema version {version} (this minisiem writes version {SCHEMA_VERSION})"
            ),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// An open minisiem database.
pub struct Store {
    connection: Connection,
    /// Rows written in the open transaction, if one is open.
    pending: Option<usize>,
}

impl Store {
    /// Opens the database at `path`, creating it and its schema if needed.
    /// Refuses a database written with an unknown schema version.
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        // Another process may hold the file (e.g. creating it): wait for it.
        connection.busy_timeout(BUSY_TIMEOUT)?;
        enable_wal(&connection)?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        // The version is read and the schema created in one write
        // transaction: a crash leaves no half-created schema, and of several
        // processes opening a new file, one creates it and the others see it.
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let created = match connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))? {
            0 => connection
                .execute_batch(SCHEMA)
                .and_then(|()| connection.pragma_update(None, "user_version", SCHEMA_VERSION)),
            SCHEMA_VERSION => Ok(()),
            other => {
                connection.execute_batch("ROLLBACK")?;
                return Err(StoreError::UnknownSchema(other));
            }
        };
        match created {
            Ok(()) => connection.execute_batch("COMMIT")?,
            Err(e) => {
                let _ = connection.execute_batch("ROLLBACK");
                return Err(e.into());
            }
        }
        Ok(Self {
            connection,
            pending: None,
        })
    }

    /// Writes an event. It is durable after the next [`Store::flush`].
    pub fn record_event(&mut self, event: &Event) -> Result<()> {
        self.begin()?;
        self.connection
            .prepare_cached(
                "INSERT INTO events (time, host, process, kind, user, src_ip, message, product, service, category)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?
            .execute(params![
                time_text(event.timestamp),
                event.host,
                event.process,
                event.kind.as_str(),
                event.user,
                event.src_ip.to_string(),
                event.message,
                event.logsource.product,
                event.logsource.service,
                event.logsource.category,
            ])?;
        self.written()
    }

    /// Writes an alert. It is durable after the next [`Store::flush`].
    pub fn record_alert(&mut self, alert: &Alert) -> Result<()> {
        let encoded = serde_json::to_string(alert)?;
        self.begin()?;
        self.connection
            .prepare_cached(
                "INSERT INTO alerts (time, rule_id, title, severity, src_ip, host, alert)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?
            .execute(params![
                time_text(alert_time(alert)),
                alert.rule_id,
                alert.title,
                alert.severity.to_string(),
                alert.src_ip.to_string(),
                alert.host,
                encoded,
            ])?;
        self.written()
    }

    /// Commits what was written so far.
    pub fn flush(&mut self) -> Result<()> {
        if self.pending.is_some() {
            // Still pending if COMMIT fails, so a later flush can retry it.
            self.connection.execute_batch("COMMIT")?;
            self.pending = None;
        }
        Ok(())
    }

    fn begin(&mut self) -> Result<()> {
        if self.pending.is_none() {
            self.connection.execute_batch("BEGIN")?;
            self.pending = Some(0);
        }
        Ok(())
    }

    fn written(&mut self) -> Result<()> {
        let rows = self.pending.map_or(1, |rows| rows + 1);
        self.pending = Some(rows);
        if rows >= BATCH {
            self.flush()?;
        }
        Ok(())
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // Best effort: callers that need to know flush themselves.
        let _ = self.flush();
    }
}

/// Switches the database to the WAL journal, which persists in the file.
/// Two processes switching a new file at once make SQLite report it locked
/// at once, without waiting: retry until one of them has switched it.
fn enable_wal(connection: &Connection) -> rusqlite::Result<()> {
    let deadline = std::time::Instant::now() + BUSY_TIMEOUT;
    loop {
        let mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if mode.eq_ignore_ascii_case("wal") {
            return Ok(());
        }
        match connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get::<_, String>(0)) {
            Ok(_) => return Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseBusy && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
}

/// When an alert happened: its last contributing event.
pub fn alert_time(alert: &Alert) -> DateTime<Utc> {
    match &alert.evidence {
        Evidence::Burst { last_seen, .. } | Evidence::Correlation { last_seen, .. } => *last_seen,
        Evidence::Event(event) => event.timestamp,
    }
}

/// Fixed-width RFC 3339 in UTC, so text order is time order.
pub fn time_text(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{MitreTechnique, Severity};
    use crate::event::{EventKind, LogSource};
    use chrono::TimeZone;

    fn temp_db() -> (tempdir::Dir, std::path::PathBuf) {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("minisiem.db");
        (dir, path)
    }

    /// A temporary directory removed when dropped, so tests leave nothing.
    mod tempdir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicUsize, Ordering};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                static NEXT: AtomicUsize = AtomicUsize::new(0);
                let path = std::env::temp_dir().join(format!(
                    "minisiem-store-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn event(secs: u32) -> Event {
        Event {
            timestamp: Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, secs).unwrap(),
            host: "srv01".into(),
            process: "sshd".into(),
            kind: EventKind::FailedLogin,
            user: "root".into(),
            src_ip: "203.0.113.7".parse().unwrap(),
            message: "Failed password for root from 203.0.113.7 port 1 ssh2".into(),
            logsource: LogSource::new("linux", "sshd"),
        }
    }

    fn burst() -> Alert {
        Alert {
            rule_id: "builtin-ssh-brute-force".into(),
            title: "SSH brute force".into(),
            severity: Severity::High,
            techniques: vec![MitreTechnique {
                id: "T1110.001".into(),
                name: Some("Password Guessing".into()),
            }],
            src_ip: "203.0.113.7".parse().unwrap(),
            host: "srv01".into(),
            evidence: Evidence::Burst {
                event_count: 10,
                first_seen: event(0).timestamp,
                last_seen: event(9).timestamp,
                users: vec!["admin".into(), "root".into()],
            },
        }
    }

    #[test]
    fn keeps_events_with_their_fields() {
        let (_dir, path) = temp_db();
        let mut store = Store::open(&path).unwrap();

        store.record_event(&event(5)).unwrap();
        store.flush().unwrap();

        let row: (String, String, String, String, String, String, String, Option<String>) = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT time, host, process, kind, user, src_ip, message, service FROM events",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                "2026-10-22T10:00:05.000000Z".into(),
                "srv01".into(),
                "sshd".into(),
                "failed_login".into(),
                "root".into(),
                "203.0.113.7".into(),
                "Failed password for root from 203.0.113.7 port 1 ssh2".into(),
                Some("sshd".into()),
            )
        );
    }

    #[test]
    fn keeps_alerts_whole_and_dated_by_their_last_event() {
        let (_dir, path) = temp_db();
        let mut store = Store::open(&path).unwrap();

        store.record_alert(&burst()).unwrap();
        store.flush().unwrap();

        let (time, severity, src_ip, encoded): (String, String, String, String) = Connection::open(&path)
            .unwrap()
            .query_row("SELECT time, severity, src_ip, alert FROM alerts", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap();
        assert_eq!(time, "2026-10-22T10:00:09.000000Z");
        assert_eq!((severity.as_str(), src_ip.as_str()), ("HIGH", "203.0.113.7"));
        let decoded: Alert = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, burst(), "the alert can be shown again exactly");
    }

    #[test]
    fn writes_are_kept_only_once_flushed_or_dropped() {
        let (_dir, path) = temp_db();
        let mut store = Store::open(&path).unwrap();
        store.record_event(&event(0)).unwrap();
        let count = || -> i64 {
            Connection::open(&path)
                .unwrap()
                .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
                .unwrap()
        };

        assert_eq!(count(), 0, "still in the open transaction");
        store.flush().unwrap();
        assert_eq!(count(), 1);
        store.record_event(&event(1)).unwrap();
        drop(store);
        assert_eq!(count(), 2, "dropping the store commits too");
    }

    #[test]
    fn commits_on_its_own_every_batch() {
        let (_dir, path) = temp_db();
        let mut store = Store::open(&path).unwrap();

        for secs in 0..BATCH as u32 + 1 {
            store.record_event(&event(secs % 60)).unwrap();
        }

        let committed: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(committed, BATCH as i64);
    }

    #[test]
    fn reopens_its_own_database_and_keeps_what_it_holds() {
        let (_dir, path) = temp_db();
        Store::open(&path).unwrap().record_event(&event(0)).unwrap();

        let mut reopened = Store::open(&path).unwrap();
        reopened.record_event(&event(1)).unwrap();
        reopened.flush().unwrap();

        let count: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn processes_opening_a_new_database_together_all_succeed() {
        // Two watches started at once on the same new file: one creates the
        // schema, the others must find it rather than create it again.
        for _ in 0..20 {
            let (_dir, path) = temp_db();
            let openers: Vec<_> = (0..4)
                .map(|_| {
                    let path = path.clone();
                    std::thread::spawn(move || Store::open(&path).map(|_| ()).map_err(|e| e.to_string()))
                })
                .collect();

            for opener in openers {
                assert_eq!(opener.join().unwrap(), Ok(()));
            }
        }
    }

    #[test]
    fn refuses_a_database_with_an_unknown_schema_version() {
        let (_dir, path) = temp_db();
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();

        let error = Store::open(&path).err().unwrap();

        assert_eq!(
            error.to_string(),
            "unknown database schema version 99 (this minisiem writes version 1)"
        );
    }

    #[test]
    fn times_sort_as_text_in_time_order() {
        let early = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        let later = early + chrono::Duration::microseconds(1);

        assert_eq!(time_text(early), "2026-01-02T03:04:05.000000Z");
        assert!(time_text(early) < time_text(later));
    }
}
