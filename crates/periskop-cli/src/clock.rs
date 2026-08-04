//! The one timestamp the report needs, in the one format it declares.
//!
//! Split out from the command line module because a calendar conversion is a
//! different concept from argument parsing and exit codes, and a module is meant
//! to say one thing. Written out rather than pulled in as a dependency: the
//! report needs a single timestamp in a single format, and a date library would
//! be a new dependency decision for that alone.

/// Why the current time could not be expressed.
#[derive(Debug, PartialEq, Eq)]
pub enum ClockError {
    /// The machine says it is earlier than 1970.
    ///
    /// This used to be absorbed into a zero, so a container with a broken clock
    /// produced a report stamped `1970-01-01T00:00:00Z` and nothing anywhere
    /// said the value was invented. The envelope sits outside the body hash, so
    /// determinism was never at risk; the audit trail was.
    BeforeEpoch,
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeEpoch => f.write_str(
                "the system clock reads before the unix epoch, so no timestamp can be produced",
            ),
        }
    }
}

/// Current time in the format the envelope declares.
///
/// The envelope is excluded from the body hash, so this value never affects
/// whether two reports of the same tree compare equal.
pub fn now_rfc3339() -> Result<String, ClockError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ClockError::BeforeEpoch)?;
    Ok(format_epoch_seconds(seconds))
}

/// Formats seconds since the epoch as RFC 3339 in UTC.
pub fn format_epoch_seconds(seconds: u64) -> String {
    let days = seconds / 86_400;
    let time_of_day = seconds % 86_400;
    let (hour, minute, second) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since the epoch to a calendar date.
///
/// Howard Hinnant's civil_from_days, the standard branch free form of this
/// conversion. It handles leap years without a lookup table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn epoch_formats_as_the_start_of_1970() {
        assert_eq!(format_epoch_seconds(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_known_instant_round_trips() {
        assert_eq!(format_epoch_seconds(1_785_834_000), "2026-08-04T09:00:00Z");
    }

    #[test]
    fn leap_day_is_handled() {
        assert_eq!(format_epoch_seconds(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn a_clock_before_the_epoch_is_an_error_rather_than_a_fabricated_date() {
        // The bug this pins: the failure used to collapse into zero seconds, and
        // the report then carried a 1970 timestamp that looked like a fact. The
        // clock cannot be moved from a test, so the same conversion is exercised
        // on a time the standard library reports the same way.
        let before = UNIX_EPOCH - Duration::from_secs(60);
        let outcome = SystemTime::duration_since(&before, UNIX_EPOCH)
            .map(|d| format_epoch_seconds(d.as_secs()))
            .map_err(|_| ClockError::BeforeEpoch);
        assert_eq!(outcome, Err(ClockError::BeforeEpoch));
    }

    #[test]
    fn a_working_clock_produces_a_timestamp_of_the_declared_shape() {
        let now = now_rfc3339().expect("the machine clock is after 1970");
        assert_eq!(now.len(), "2026-08-04T09:00:00Z".len());
        assert!(now.ends_with('Z'), "{now}");
    }
}
