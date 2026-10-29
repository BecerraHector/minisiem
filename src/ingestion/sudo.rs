//! sudo log messages, whatever format carried them.

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::event::{Event, EventKind, LogSource};

/// The process name sudo logs under (`sudo:` in syslog files, `_COMM=sudo`
/// in journald).
pub const SUDO_PROCESS: &str = "sudo";

/// `<user> : [<outcome> ; ]TTY=... ; COMMAND=<command>`. sudo pads the user
/// name with spaces, which are dropped.
static MESSAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<user>\S+) : (?:(?P<denied>user NOT in sudoers|command not allowed)|(?P<failed>\d+ incorrect password attempts?)) ; (?P<fields>TTY=.*)$|^(?P<ran_by>\S+) : (?P<ran>TTY=.*)$",
    )
    .unwrap()
});

/// Builds an event from a sudo message. Returns `None` for messages that are
/// not a command, a refusal or a password failure (e.g. pam_unix sessions).
///
/// `PWD` (any directory the user can create) and the command's arguments can
/// hold a fake ` ; USER=.. ; COMMAND=..`. The command is read from the first
/// `COMMAND=` to the end of the line, so the command that really ran always
/// ends it; the target user is the last `USER=` before that, which a crafted
/// directory name can fake.
pub(super) fn sudo_event(timestamp: DateTime<Utc>, host: &str, process: &str, message: &str) -> Option<Event> {
    let message = message.trim_start();
    let caps = MESSAGE.captures(message)?;
    let (kind, user, fields) = if let Some(fields) = caps.name("ran") {
        (EventKind::SudoCommand, caps.name("ran_by")?, fields)
    } else if caps.name("denied").is_some() {
        (EventKind::SudoDenied, caps.name("user")?, caps.name("fields")?)
    } else {
        (EventKind::SudoFailedPassword, caps.name("user")?, caps.name("fields")?)
    };
    let (before, command) = fields.as_str().split_once(" ; COMMAND=")?;
    let target_user = before
        .rsplit_once(" ; USER=")
        .map(|(_, rest)| rest.split(" ; ").next().unwrap_or(rest).to_owned());
    Some(Event {
        timestamp,
        host: host.to_string(),
        process: process.to_string(),
        kind,
        user: user.as_str().to_string(),
        src_ip: None,
        target_user,
        command: Some(command.to_owned()),
        message: message.to_string(),
        logsource: LogSource::new("linux", "sudo"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, LogSource};
    use chrono::TimeZone;

    fn parse(message: &str) -> Option<Event> {
        let at = Utc.with_ymd_and_hms(2026, 10, 22, 10, 15, 32).unwrap();
        sudo_event(at, "srv01", "sudo", message)
    }

    fn summary(message: &str) -> (EventKind, String, Option<String>, Option<String>) {
        let event = parse(message).unwrap_or_else(|| panic!("not parsed: {message}"));
        (event.kind, event.user, event.target_user, event.command)
    }

    fn some(text: &str) -> Option<String> {
        Some(text.to_owned())
    }

    #[test]
    fn reads_a_command_run_as_another_user() {
        let event =
            parse("  hector : TTY=pts/0 ; PWD=/home/hector ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
                .unwrap();

        assert_eq!(event.kind, EventKind::SudoCommand);
        assert_eq!(event.user, "hector");
        assert_eq!(event.target_user, some("root"));
        assert_eq!(event.command, some("/usr/bin/systemctl restart nginx"));
        assert_eq!(event.src_ip, None);
        assert_eq!(event.process, "sudo");
        assert_eq!(event.host, "srv01");
        assert_eq!(event.logsource, LogSource::new("linux", "sudo"));
        assert_eq!(
            event.message,
            "hector : TTY=pts/0 ; PWD=/home/hector ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
        );
    }

    #[test]
    fn reads_refusals_as_denied() {
        assert_eq!(
            summary("     bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"),
            (EventKind::SudoDenied, "bob".into(), some("root"), some("/bin/bash"))
        );
        assert_eq!(
            summary(
                "  hector : command not allowed ; TTY=pts/0 ; PWD=/home/hector ; USER=root ; COMMAND=/usr/bin/vim /etc/shadow"
            ),
            (
                EventKind::SudoDenied,
                "hector".into(),
                some("root"),
                some("/usr/bin/vim /etc/shadow")
            )
        );
    }

    #[test]
    fn reads_password_failures() {
        assert_eq!(
            summary(
                "  hector : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/hector ; USER=root ; COMMAND=/usr/bin/id"
            ),
            (
                EventKind::SudoFailedPassword,
                "hector".into(),
                some("root"),
                some("/usr/bin/id")
            )
        );
        assert_eq!(
            summary("hector : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id").0,
            EventKind::SudoFailedPassword
        );
    }

    #[test]
    fn reads_the_target_user_before_group_and_environment() {
        assert_eq!(
            summary(
                "alice : TTY=pts/0 ; PWD=/ ; USER=postgres ; GROUP=postgres ; ENV=PGDATA=/srv SUDO_USER=x ; COMMAND=/usr/bin/psql"
            ),
            (
                EventKind::SudoCommand,
                "alice".into(),
                some("postgres"),
                some("/usr/bin/psql")
            )
        );
    }

    #[test]
    fn ignores_pam_and_other_sudo_messages() {
        for message in [
            "pam_unix(sudo:auth): authentication failure; logname=hector uid=1000 euid=0 tty=/dev/pts/0 ruser=hector rhost=  user=hector",
            "pam_unix(sudo:session): session opened for user root(uid=0) by hector(uid=1000)",
            "pam_unix(sudo:session): session closed for user root",
            "  hector : a password is required ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id",
        ] {
            assert_eq!(parse(message), None, "{message}");
        }
    }

    #[test]
    fn a_crafted_directory_cannot_hide_the_command_that_ran() {
        // PWD is any directory the user can create, e.g.
        // `mkdir "/tmp/x ; USER=nobody ; COMMAND=/usr/bin/true"`.
        let (kind, user, _target, command) = summary(
            "  mallory : TTY=pts/0 ; PWD=/tmp/x ; USER=nobody ; COMMAND=/usr/bin/true ; USER=root ; COMMAND=/bin/bash",
        );

        assert_eq!((kind, user.as_str()), (EventKind::SudoCommand, "mallory"));
        assert!(command.unwrap().ends_with("COMMAND=/bin/bash"));
    }
}
