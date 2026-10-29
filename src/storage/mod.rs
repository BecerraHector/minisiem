//! Event and alert storage (adapter): a SQLite database file that keeps
//! normalized events and alerts for later search.
//!
//! Writes are grouped in transactions and the journal is in WAL mode, so a
//! flood does not sync to disk once per event. Times are stored as fixed-width
//! RFC 3339 UTC text, which sorts in time order and reads well in `sqlite3`.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags, Row, params, params_from_iter};

use crate::alert::{Alert, Evidence};
use crate::event::{Event, EventKind, LogSource};
use crate::pipeline::Archive;

/// The schema this version of minisiem writes, kept in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 3;

/// Rows written before the open transaction is committed on its own.
const BATCH: usize = 1_000;

/// How often retention deletes again what has grown too old.
const PRUNE_EVERY: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Rows deleted per statement, so pruning a large backlog never holds the
/// database for long at a time.
const PRUNE_CHUNK: usize = 10_000;

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
    src_ip   TEXT,
    message  TEXT NOT NULL,
    product  TEXT,
    service  TEXT,
    category TEXT,
    target_user TEXT,
    command  TEXT
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
    src_ip   TEXT,
    host     TEXT NOT NULL,
    alert    TEXT NOT NULL
);
CREATE INDEX alerts_time ON alerts (time);
CREATE INDEX alerts_src_ip ON alerts (src_ip, time);
CREATE INDEX alerts_host ON alerts (host, time);
";

fn user_version(connection: &Connection) -> rusqlite::Result<i64> {
    connection.pragma_query_value(None, "user_version", |row| row.get(0))
}

/// Version 2 had no columns for sudo's target user and command.
fn upgrade_from_2(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "ALTER TABLE events ADD COLUMN target_user TEXT;
         ALTER TABLE events ADD COLUMN command TEXT;",
    )
}

/// Version 1 required `src_ip`. SQLite cannot drop a NOT NULL constraint,
/// so the tables are rebuilt with every row. Runs inside the version check's
/// transaction: a crash leaves version 1 intact.
fn upgrade_from_1(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "DROP INDEX events_time;
         DROP INDEX events_src_ip;
         DROP INDEX events_user;
         DROP INDEX events_host;
         DROP INDEX alerts_time;
         DROP INDEX alerts_src_ip;
         DROP INDEX alerts_host;
         ALTER TABLE events RENAME TO events_v1;
         ALTER TABLE alerts RENAME TO alerts_v1;",
    )?;
    connection.execute_batch(SCHEMA)?;
    connection.execute_batch(
        "INSERT INTO events (id, time, host, process, kind, user, src_ip, message, product, service, category)
             SELECT id, time, host, process, kind, user, src_ip, message, product, service, category FROM events_v1;
         INSERT INTO alerts (id, time, rule_id, title, severity, src_ip, host, alert)
             SELECT id, time, rule_id, title, severity, src_ip, host, alert FROM alerts_v1;
         DROP TABLE events_v1;
         DROP TABLE alerts_v1;",
    )
}

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    /// The file was written by another version of minisiem.
    UnknownSchema(i64),
    /// A stored row minisiem cannot read back.
    Corrupt(String),
    /// A filter on a field alerts do not have.
    EventOnlyFilter(&'static str),
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
            StoreError::Corrupt(detail) => write!(f, "unreadable row: {detail}"),
            StoreError::EventOnlyFilter(field) => write!(f, "{field} only filters events"),
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
    path: PathBuf,
    /// Rows written in the open transaction, if one is open.
    pending: Option<usize>,
    retention: Option<Retention>,
}

/// Keep only what happened in the last `keep`.
struct Retention {
    keep: chrono::Duration,
    next_prune: std::time::Instant,
}

impl Store {
    /// Opens the database at `path`, creating it and its schema if needed.
    /// Refuses a database written with an unknown schema version.
    pub fn open(path: &Path) -> Result<Self> {
        Self::prepare(Connection::open(path)?, path, true)
    }

    /// Opens an existing database to search it, upgrading it like
    /// [`Store::open`]. Unlike it, a missing file is an error, not a new
    /// database, and a database minisiem did not create is left untouched.
    pub fn open_existing(path: &Path) -> Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(path, flags)?;
        // Checked before anything below changes the file (e.g. its journal).
        if user_version(&connection)? == 0 {
            return Err(StoreError::UnknownSchema(0));
        }
        Self::prepare(connection, path, false)
    }

    /// Sets the connection up and brings the schema to [`SCHEMA_VERSION`],
    /// creating it in an empty database if `create`.
    fn prepare(connection: Connection, path: &Path, create: bool) -> Result<Self> {
        // Another process may hold the file (e.g. creating it): wait for it.
        connection.busy_timeout(BUSY_TIMEOUT)?;
        enable_wal(&connection)?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        // The version is read and the schema created or upgraded in one write
        // transaction: a crash leaves no half-done schema, and of several
        // processes opening a new file, one creates it and the others see it.
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let created = match user_version(&connection)? {
            0 if create => connection
                .execute_batch(SCHEMA)
                .and_then(|()| connection.pragma_update(None, "user_version", SCHEMA_VERSION)),
            1 => upgrade_from_1(&connection)
                .and_then(|()| connection.pragma_update(None, "user_version", SCHEMA_VERSION)),
            2 => upgrade_from_2(&connection)
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
            path: path.to_owned(),
            pending: None,
            retention: None,
        })
    }

    /// The events matching `filter`, oldest first.
    pub fn events(&self, filter: &Filter) -> Result<Vec<Event>> {
        let (conditions, values) = filter.sql(true)?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT time, host, process, kind, user, src_ip, message, product, service, category, target_user, command
             FROM events {conditions} ORDER BY time, id"
        ))?;
        let rows = statement.query_map(params_from_iter(values), |row| Ok(event_from_row(row)))?;
        rows.map(|row| row?).collect()
    }

    /// The alerts matching `filter`, oldest first.
    pub fn alerts(&self, filter: &Filter) -> Result<Vec<Alert>> {
        let (conditions, values) = filter.sql(false)?;
        let mut statement = self
            .connection
            .prepare(&format!("SELECT alert FROM alerts {conditions} ORDER BY time, id"))?;
        let rows = statement.query_map(params_from_iter(values), |row| row.get::<_, String>(0))?;
        rows.map(|row| serde_json::from_str(&row?).map_err(|e| StoreError::Corrupt(format!("alert: {e}"))))
            .collect()
    }

    /// Writes an event. It is durable after the next [`Store::flush`].
    pub fn record_event(&mut self, event: &Event) -> Result<()> {
        self.begin()?;
        self.connection
            .prepare_cached(
                "INSERT INTO events (time, host, process, kind, user, src_ip, message, product, service, category,
                                     target_user, command)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?
            .execute(params![
                time_text(event.timestamp),
                event.host,
                event.process,
                event.kind.as_str(),
                event.user,
                event.src_ip.map(|ip| ip.to_string()),
                event.message,
                event.logsource.product,
                event.logsource.service,
                event.logsource.category,
                event.target_user,
                event.command,
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
                alert.src_ip.map(|ip| ip.to_string()),
                alert.host,
                encoded,
            ])?;
        self.written()
    }

    /// Commits what was written so far. With retention, also deletes what
    /// grew too old once [`PRUNE_EVERY`] has gone by.
    pub fn flush(&mut self) -> Result<()> {
        if self.pending.is_some() {
            // Still pending if COMMIT fails, so a later flush can retry it.
            self.connection.execute_batch("COMMIT")?;
            self.pending = None;
        }
        self.prune_if_due(std::time::Instant::now())
    }

    /// Deletes the events and alerts older than `keep` now, and again every
    /// [`PRUNE_EVERY`] from then on, when writes are committed.
    pub fn retain(&mut self, keep: chrono::Duration) -> Result<()> {
        self.flush()?;
        self.retention = Some(Retention {
            keep,
            next_prune: std::time::Instant::now(),
        });
        self.prune_if_due(std::time::Instant::now())
    }

    fn prune_if_due(&mut self, now: std::time::Instant) -> Result<()> {
        let Some(retention) = &mut self.retention else {
            return Ok(());
        };
        if now < retention.next_prune || self.pending.is_some() {
            return Ok(());
        }
        let cutoff = time_text(Utc::now() - retention.keep);
        for table in ["events", "alerts"] {
            let delete =
                format!("DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE time < ?1 LIMIT {PRUNE_CHUNK})");
            while self.connection.execute(&delete, [&cutoff])? > 0 {}
        }
        retention.next_prune = now + PRUNE_EVERY;
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

/// Errors name the database, as they reach the user next to other errors.
impl Archive for Store {
    fn record_event(&mut self, event: &Event) -> io::Result<()> {
        Store::record_event(self, event).map_err(|e| self.write_error(e))
    }

    fn record_alert(&mut self, alert: &Alert) -> io::Result<()> {
        Store::record_alert(self, alert).map_err(|e| self.write_error(e))
    }

    fn flush(&mut self) -> io::Result<()> {
        Store::flush(self).map_err(|e| self.write_error(e))
    }
}

impl Store {
    fn write_error(&self, error: StoreError) -> io::Error {
        io::Error::other(format!("cannot write to database {}: {error}", self.path.display()))
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

/// What a search looks for: every field given must match. Times are
/// inclusive.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub ip: Option<IpAddr>,
    pub user: Option<String>,
    pub host: Option<String>,
    pub kind: Option<EventKind>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl Filter {
    /// The `WHERE` clause and its values. Alerts have no user or kind.
    fn sql(&self, events: bool) -> Result<(String, Vec<String>)> {
        if !events {
            if self.user.is_some() {
                return Err(StoreError::EventOnlyFilter("user"));
            }
            if self.kind.is_some() {
                return Err(StoreError::EventOnlyFilter("kind"));
            }
        }
        let conditions = [
            ("src_ip = ?", self.ip.map(|ip| ip.to_string())),
            ("user = ?", self.user.clone()),
            ("host = ?", self.host.clone()),
            ("kind = ?", self.kind.map(|kind| kind.as_str().to_owned())),
            ("time >= ?", self.since.map(time_text)),
            ("time <= ?", self.until.map(time_text)),
        ];
        let (clauses, values): (Vec<&str>, Vec<String>) = conditions
            .into_iter()
            .filter_map(|(clause, value)| value.map(|value| (clause, value)))
            .unzip();
        match clauses.is_empty() {
            true => Ok((String::new(), values)),
            false => Ok((format!("WHERE {}", clauses.join(" AND ")), values)),
        }
    }
}

/// Reads back a row written by [`Store::record_event`].
fn event_from_row(row: &Row) -> Result<Event> {
    let corrupt = |what: &str, value: &str| StoreError::Corrupt(format!("event {what} '{value}'"));
    let time: String = row.get(0)?;
    let kind: String = row.get(3)?;
    let src_ip: Option<String> = row.get(5)?;
    Ok(Event {
        timestamp: DateTime::parse_from_rfc3339(&time)
            .map_err(|_| corrupt("time", &time))?
            .with_timezone(&Utc),
        host: row.get(1)?,
        process: row.get(2)?,
        kind: EventKind::from_name(&kind).ok_or_else(|| corrupt("kind", &kind))?,
        user: row.get(4)?,
        src_ip: match src_ip {
            None => None,
            Some(ip) => Some(ip.parse().map_err(|_| corrupt("src_ip", &ip))?),
        },
        target_user: row.get(10)?,
        command: row.get(11)?,
        message: row.get(6)?,
        logsource: LogSource {
            product: row.get(7)?,
            service: row.get(8)?,
            category: row.get(9)?,
        },
    })
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
            src_ip: Some("203.0.113.7".parse().unwrap()),
            target_user: None,
            command: None,
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
            src_ip: Some("203.0.113.7".parse().unwrap()),
            host: "srv01".into(),
            evidence: Evidence::Burst {
                event_count: 10,
                first_seen: event(0).timestamp,
                last_seen: event(9).timestamp,
                users: vec!["admin".into(), "root".into()],
            },
        }
    }

    fn event_at(timestamp: DateTime<Utc>) -> Event {
        Event { timestamp, ..event(0) }
    }

    fn count(path: &Path, table: &str) -> i64 {
        Connection::open(path)
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn keeps_events_and_alerts_without_a_source_ip() {
        let (_dir, path) = temp_db();
        let event = Event {
            src_ip: None,
            ..event(1)
        };
        let alert = Alert {
            src_ip: None,
            evidence: Evidence::Event(event.clone()),
            ..burst()
        };
        let mut store = Store::open(&path).unwrap();

        store.record_event(&event).unwrap();
        store.record_alert(&alert).unwrap();
        store.flush().unwrap();

        assert_eq!(store.events(&Filter::default()).unwrap(), [event]);
        assert_eq!(store.alerts(&Filter::default()).unwrap(), [alert]);
        let nulls: i64 = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT (SELECT count(*) FROM events WHERE src_ip IS NULL) + (SELECT count(*) FROM alerts WHERE src_ip IS NULL)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(nulls, 2);
    }

    /// The schema minisiem 0.1 wrote, before `src_ip` became optional.
    const SCHEMA_V1: &str = "
        CREATE TABLE events (id INTEGER PRIMARY KEY, time TEXT NOT NULL, host TEXT NOT NULL, process TEXT NOT NULL,
            kind TEXT NOT NULL, user TEXT NOT NULL, src_ip TEXT NOT NULL, message TEXT NOT NULL, product TEXT,
            service TEXT, category TEXT);
        CREATE INDEX events_time ON events (time);
        CREATE INDEX events_src_ip ON events (src_ip, time);
        CREATE INDEX events_user ON events (user, time);
        CREATE INDEX events_host ON events (host, time);
        CREATE TABLE alerts (id INTEGER PRIMARY KEY, time TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT NOT NULL,
            severity TEXT NOT NULL, src_ip TEXT NOT NULL, host TEXT NOT NULL, alert TEXT NOT NULL);
        CREATE INDEX alerts_time ON alerts (time);
        CREATE INDEX alerts_src_ip ON alerts (src_ip, time);
        CREATE INDEX alerts_host ON alerts (host, time);
        PRAGMA user_version = 1;
    ";

    #[test]
    fn upgrades_a_version_1_database_keeping_its_rows() {
        let (_dir, path) = temp_db();
        let old = Connection::open(&path).unwrap();
        old.execute_batch(SCHEMA_V1).unwrap();
        old.execute_batch(
            "INSERT INTO events (time, host, process, kind, user, src_ip, message, product, service, category)
             VALUES ('2026-10-22T10:00:05.000000Z', 'srv01', 'sshd', 'failed_login', 'root', '203.0.113.7',
                     'Failed password for root from 203.0.113.7 port 1 ssh2', 'linux', 'sshd', NULL);",
        )
        .unwrap();
        let encoded = serde_json::to_string(&burst()).unwrap();
        old.execute(
            "INSERT INTO alerts (time, rule_id, title, severity, src_ip, host, alert)
             VALUES ('2026-10-22T10:00:09.000000Z', 'ssh-brute-force', 'SSH brute force', 'HIGH', '203.0.113.7', 'srv01', ?1)",
            [&encoded],
        )
        .unwrap();
        drop(old);

        let mut store = Store::open(&path).unwrap();

        assert_eq!(store.events(&Filter::default()).unwrap(), [event(5)]);
        assert_eq!(store.alerts(&Filter::default()).unwrap(), [burst()]);
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        // Indexes came back with the rebuilt tables.
        let indexes: i64 = store
            .connection
            .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'index'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(indexes, 7);
        store
            .record_event(&Event {
                src_ip: None,
                ..event(6)
            })
            .unwrap();
        store.flush().unwrap();
    }

    #[test]
    fn search_upgrades_a_version_1_database_too() {
        let (_dir, path) = temp_db();
        let old = Connection::open(&path).unwrap();
        old.execute_batch(SCHEMA_V1).unwrap();
        old.execute_batch(
            "INSERT INTO events (time, host, process, kind, user, src_ip, message, product, service, category)
             VALUES ('2026-10-22T10:00:05.000000Z', 'srv01', 'sshd', 'failed_login', 'root', '203.0.113.7',
                     'Failed password for root from 203.0.113.7 port 1 ssh2', 'linux', 'sshd', NULL);",
        )
        .unwrap();
        drop(old);

        let store = Store::open_existing(&path).unwrap();

        assert_eq!(store.events(&Filter::default()).unwrap(), [event(5)]);
    }

    #[test]
    fn search_refuses_a_database_minisiem_did_not_create() {
        let (_dir, path) = temp_db();
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE other (x);")
            .unwrap();

        let error = Store::open_existing(&path).err().unwrap();

        assert!(
            error.to_string().starts_with("unknown database schema version 0"),
            "{error}"
        );
        let tables: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(tables, 1, "search must not create the schema");
    }

    fn sudo_event() -> Event {
        Event {
            process: "sudo".into(),
            kind: EventKind::SudoCommand,
            user: "hector".into(),
            src_ip: None,
            target_user: Some("root".into()),
            command: Some("/usr/bin/id".into()),
            message: "hector : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id".into(),
            logsource: LogSource::new("linux", "sudo"),
            ..event(7)
        }
    }

    #[test]
    fn keeps_the_target_user_and_command_of_sudo_events() {
        let (_dir, path) = temp_db();
        let mut store = Store::open(&path).unwrap();
        let alert = Alert {
            src_ip: None,
            evidence: Evidence::Event(sudo_event()),
            ..burst()
        };

        store.record_event(&sudo_event()).unwrap();
        store.record_alert(&alert).unwrap();
        store.flush().unwrap();

        assert_eq!(store.events(&Filter::default()).unwrap(), [sudo_event()]);
        assert_eq!(store.alerts(&Filter::default()).unwrap(), [alert]);
        let columns: (String, String) = Connection::open(&path)
            .unwrap()
            .query_row("SELECT target_user, command FROM events", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(columns, ("root".into(), "/usr/bin/id".into()));
    }

    #[test]
    fn upgrades_a_version_2_database_keeping_its_rows() {
        let (_dir, path) = temp_db();
        let old = Connection::open(&path).unwrap();
        old.execute_batch(
            &SCHEMA_V1
                .replace("src_ip TEXT NOT NULL", "src_ip TEXT")
                .replace("user_version = 1", "user_version = 2"),
        )
        .unwrap();
        old.execute_batch(
            "INSERT INTO events (time, host, process, kind, user, src_ip, message, product, service, category)
             VALUES ('2026-10-22T10:00:05.000000Z', 'srv01', 'sshd', 'failed_login', 'root', '203.0.113.7',
                     'Failed password for root from 203.0.113.7 port 1 ssh2', 'linux', 'sshd', NULL);",
        )
        .unwrap();
        drop(old);

        let mut store = Store::open(&path).unwrap();

        assert_eq!(store.events(&Filter::default()).unwrap(), [event(5)]);
        store.record_event(&sudo_event()).unwrap();
        store.flush().unwrap();
        assert_eq!(store.events(&Filter::default()).unwrap(), [event(5), sudo_event()]);
    }

    #[test]
    fn retain_deletes_what_is_older_at_once() {
        let (_dir, path) = temp_db();
        let old = event_at(Utc::now() - chrono::Duration::days(31));
        let recent = event_at(Utc::now() - chrono::Duration::days(29));
        {
            let mut store = Store::open(&path).unwrap();
            for event in [&old, &recent] {
                store.record_event(event).unwrap();
                store
                    .record_alert(&Alert {
                        evidence: Evidence::Event(event.clone()),
                        ..burst()
                    })
                    .unwrap();
            }
        }

        Store::open(&path).unwrap().retain(chrono::Duration::days(30)).unwrap();

        assert_eq!(count(&path, "events"), 1);
        assert_eq!(count(&path, "alerts"), 1);
        let kept: String = Connection::open(&path)
            .unwrap()
            .query_row("SELECT time FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(kept, time_text(recent.timestamp));
    }

    #[test]
    fn retention_runs_again_an_hour_later() {
        let (_dir, path) = temp_db();
        let mut store = Store::open(&path).unwrap();
        store.retain(chrono::Duration::days(30)).unwrap();
        store
            .record_event(&event_at(Utc::now() - chrono::Duration::days(31)))
            .unwrap();

        store.flush().unwrap();
        assert_eq!(count(&path, "events"), 1, "pruned before an hour went by");

        // An hour later, the next commit deletes it.
        store.retention.as_mut().unwrap().next_prune = std::time::Instant::now();
        store.record_event(&event_at(Utc::now())).unwrap();
        store.flush().unwrap();
        assert_eq!(count(&path, "events"), 1);
        let kept: String = Connection::open(&path)
            .unwrap()
            .query_row("SELECT time FROM events", [], |row| row.get(0))
            .unwrap();
        assert!(kept > time_text(Utc::now() - chrono::Duration::days(1)), "kept: {kept}");
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
            "unknown database schema version 99 (this minisiem writes version 3)"
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
