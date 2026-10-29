//! Syslog messages as sent over the network: a `<PRI>` prefix followed by an
//! RFC 3164 line or an RFC 5424 message.

/// Rewrites a network syslog message as the line format [`super::SyslogParser`]
/// reads, or `None` if it is not well formed.
///
/// - RFC 3164: `<34>Oct 22 10:15:32 srv01 sshd[1]: msg` loses its `<PRI>`.
/// - RFC 5424: `<34>1 2026-10-22T10:15:32Z srv01 sshd 1 - - msg` becomes
///   `2026-10-22T10:15:32+00:00 srv01 sshd[1]: msg`.
pub(super) fn to_syslog_line(frame: &str) -> Option<String> {
    let rest = frame.strip_prefix('<')?;
    let (priority, body) = rest.split_once('>')?;
    // PRI = facility * 8 + severity, at most 23 * 8 + 7 = 191.
    let valid_priority = (1..=3).contains(&priority.len())
        && priority.bytes().all(|b| b.is_ascii_digit())
        && priority.parse::<u16>().is_ok_and(|p| p <= 191);
    if !valid_priority {
        return None;
    }

    match body.strip_prefix("1 ") {
        Some(rfc5424) => rewrite_rfc5424(rfc5424),
        None => Some(body.to_string()),
    }
}

/// `TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]`
fn rewrite_rfc5424(body: &str) -> Option<String> {
    let mut parts = body.splitn(6, ' ');
    let (timestamp, host, app, procid, _msgid, rest) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    if timestamp == "-" {
        return None;
    }

    let timestamp = match timestamp.strip_suffix('Z') {
        Some(local) => format!("{local}+00:00"),
        None => timestamp.to_string(),
    };
    let pid = if procid == "-" { "0" } else { procid };
    let message = skip_structured_data(rest)?;
    let message = message.strip_prefix('\u{feff}').unwrap_or(message);

    Some(format!("{timestamp} {host} {app}[{pid}]: {message}"))
}

/// Returns the message after STRUCTURED-DATA: either `-` or one or more
/// `[id key="value" ...]` elements. Inside values `]` must be escaped as
/// `\]`, so tracking escapes is enough to find where each element ends.
fn skip_structured_data(rest: &str) -> Option<&str> {
    if let Some(message) = rest.strip_prefix('-') {
        return Some(message.strip_prefix(' ').unwrap_or(message));
    }
    if !rest.starts_with('[') {
        return None;
    }

    let (mut inside, mut escaped) = (false, false);
    for (i, c) in rest.char_indices() {
        if !inside {
            match c {
                '[' => inside = true,
                _ => return Some(rest[i..].strip_prefix(' ').unwrap_or(&rest[i..])),
            }
        } else if escaped {
            escaped = false;
        } else {
            match c {
                '\\' => escaped = true,
                ']' => inside = false,
                _ => {}
            }
        }
    }
    // Ran out of input: fine after a complete element, malformed inside one.
    (!inside).then_some("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_priority_from_rfc3164_messages() {
        assert_eq!(
            to_syslog_line("<38>Oct 22 10:15:32 srv01 sshd[1234]: Failed password for root").as_deref(),
            Some("Oct 22 10:15:32 srv01 sshd[1234]: Failed password for root")
        );
    }

    #[test]
    fn rewrites_rfc5424_messages() {
        assert_eq!(
            to_syslog_line("<38>1 2026-10-22T10:15:32.123Z srv01 sshd-session 4321 - - Failed password for root")
                .as_deref(),
            Some("2026-10-22T10:15:32.123+00:00 srv01 sshd-session[4321]: Failed password for root")
        );
        assert_eq!(
            to_syslog_line("<38>1 2026-10-22T10:15:32-05:00 srv01 sshd 7 AUTH - msg").as_deref(),
            Some("2026-10-22T10:15:32-05:00 srv01 sshd[7]: msg"),
            "MSGID is ignored"
        );
    }

    #[test]
    fn skips_rfc5424_structured_data_with_spaces_and_escapes() {
        let frame =
            r#"<38>1 2026-10-22T10:15:32Z srv01 sshd 7 - [meta a="x y" b="z\]w"][origin ip="10.0.0.1"] msg here"#;

        assert_eq!(
            to_syslog_line(frame).as_deref(),
            Some("2026-10-22T10:15:32+00:00 srv01 sshd[7]: msg here")
        );
    }

    #[test]
    fn handles_rfc5424_optional_parts() {
        assert_eq!(
            to_syslog_line("<38>1 2026-10-22T10:15:32Z srv01 sshd - - - \u{feff}msg").as_deref(),
            Some("2026-10-22T10:15:32+00:00 srv01 sshd[0]: msg"),
            "a missing PROCID and the UTF-8 BOM are tolerated"
        );
    }

    #[test]
    fn rejects_malformed_frames() {
        let frames = [
            "",
            "no priority",
            "<>Oct 22 10:15:32 srv01 sshd[1]: msg",
            "<1000>Oct 22 10:15:32 srv01 sshd[1]: msg",
            "<38",
            "<38>1 - srv01 sshd 7 - - msg",
            "<38>1 2026-10-22T10:15:32Z srv01 sshd 7 - [unterminated msg",
            "<38>1 2026-10-22T10:15:32Z srv01",
        ];

        for frame in frames {
            assert_eq!(to_syslog_line(frame), None, "should be rejected: {frame:?}");
        }
    }
}
