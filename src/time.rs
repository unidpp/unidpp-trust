//! Deterministic UTC timestamps (ISO 8601 / RFC 3339).
//!
//! Ported from `unidpp-registry`'s `time` (itself ported from
//! `unidpp-resolver`'s, itself ported from `unidpp-core`'s
//! `unidpp_model::time` — same doctrine): hand-rolled on purpose — no
//! external time dependency, exact integer arithmetic (seconds since
//! the UNIX epoch; sub-second precision is not needed at the trust
//! service), strict parsing, canonical display with the trailing `Z`.
//! All trust-service stamps are UTC; local time is a presentation
//! concern. [`Timestamp::to_model`] / [`Timestamp::from_model`] convert
//! to the core's nanosecond-precision [`unidpp_model::Timestamp`] at
//! the signatif boundary (second resolution; fractions are accepted on
//! input and discarded).

use std::fmt;
use std::str::FromStr;

/// Error returned for unparseable timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeParseError(pub String);

impl fmt::Display for TimeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid timestamp `{}` (expected RFC 3339 UTC)", self.0)
    }
}

impl std::error::Error for TimeParseError {}

/// Seconds since the UNIX epoch, UTC only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp {
    pub secs: i64,
}

impl Timestamp {
    pub const UNIX_EPOCH: Timestamp = Timestamp { secs: 0 };

    pub fn from_secs(secs: i64) -> Timestamp {
        Timestamp { secs }
    }

    /// Current wall-clock time. Handlers prefer explicit `at` values;
    /// this is only the default as-of instant (every response is
    /// as-of stamped and signed).
    pub fn now() -> Timestamp {
        use std::time::{SystemTime, UNIX_EPOCH};
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Timestamp {
                secs: d.as_secs() as i64,
            },
            Err(e) => Timestamp {
                secs: -(e.duration().as_secs() as i64),
            },
        }
    }

    /// Convert to the core's (nanosecond) timestamp.
    pub fn to_model(self) -> unidpp_model::Timestamp {
        unidpp_model::Timestamp::from_secs(self.secs)
    }

    /// Convert from the core's (nanosecond) timestamp, truncating to
    /// seconds.
    pub fn from_model(t: unidpp_model::Timestamp) -> Timestamp {
        Timestamp { secs: t.secs }
    }

    pub fn parse(input: &str) -> Result<Timestamp, TimeParseError> {
        let b = input.as_bytes();
        let err = || TimeParseError(input.to_string());
        if b.len() < 10 {
            return Err(err());
        }
        let year = digits(b, 0, 4).ok_or_else(err)?;
        if b[4] != b'-' {
            return Err(err());
        }
        let month = digits(b, 5, 2).ok_or_else(err)?;
        if b[7] != b'-' {
            return Err(err());
        }
        let day = digits(b, 8, 2).ok_or_else(err)?;
        if !(1..=12).contains(&month) {
            return Err(err());
        }
        if day < 1 || day > days_in_month(year, month as u32) as i64 {
            return Err(err());
        }
        let mut pos = 10;
        let (mut hour, mut min, mut sec) = (0i64, 0i64, 0i64);
        if b.len() > pos && (b[pos] == b'T' || b[pos] == b't' || b[pos] == b' ') {
            if b.len() < pos + 9 {
                return Err(err());
            }
            hour = digits(b, pos + 1, 2).ok_or_else(err)?;
            if b[pos + 3] != b':' {
                return Err(err());
            }
            min = digits(b, pos + 4, 2).ok_or_else(err)?;
            if b[pos + 6] != b':' {
                return Err(err());
            }
            sec = digits(b, pos + 7, 2).ok_or_else(err)?;
            if hour > 23 || min > 59 || sec > 59 {
                return Err(err());
            }
            pos += 9;
            // Fractional seconds accepted and discarded (second resolution).
            if b.len() > pos && b[pos] == b'.' {
                pos += 1;
                while pos < b.len() && b[pos].is_ascii_digit() {
                    pos += 1;
                }
            }
        }
        // Zone: 'Z' | 'z' | +hh:mm | +hhmm | nothing (treated as UTC).
        let mut offset_secs: i64 = 0;
        if pos < b.len() {
            match b[pos] {
                b'Z' | b'z' => pos += 1,
                b'+' | b'-' => {
                    let sign = if b[pos] == b'-' { -1i64 } else { 1i64 };
                    pos += 1;
                    let oh = digits(b, pos, 2).ok_or_else(err)?;
                    pos += 2;
                    if pos < b.len() && b[pos] == b':' {
                        pos += 1;
                    }
                    let om = digits(b, pos, 2).ok_or_else(err)?;
                    pos += 2;
                    if oh > 23 || om > 59 {
                        return Err(err());
                    }
                    offset_secs = sign * (oh * 3600 + om * 60);
                }
                _ => return Err(err()),
            }
            if pos != b.len() {
                return Err(err());
            }
        }
        let days = days_from_civil(year, month as u32, day as u32);
        Ok(Timestamp {
            secs: days * 86_400 + hour * 3_600 + min * 60 + sec - offset_secs,
        })
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.secs.div_euclid(86_400);
        let rem = self.secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year,
            month,
            day,
            rem / 3_600,
            (rem % 3_600) / 60,
            rem % 60
        )
    }
}

impl FromStr for Timestamp {
    type Err = TimeParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Timestamp::parse(s)
    }
}

fn digits(b: &[u8], pos: usize, len: usize) -> Option<i64> {
    if pos + len > b.len() {
        return None;
    }
    let mut v: i64 = 0;
    for &c in &b[pos..pos + len] {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as i64;
    }
    Some(v)
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's `days_from_civil` (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m as i64 - 3 } else { m as i64 + 9 };
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Howard Hinnant's `civil_from_days` (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_round_trip() {
        let t = Timestamp::UNIX_EPOCH;
        assert_eq!(t.to_string(), "1970-01-01T00:00:00Z");
        assert_eq!(Timestamp::parse("1970-01-01T00:00:00Z").unwrap(), t);
    }

    #[test]
    fn date_time_and_offset_forms() {
        assert_eq!(
            Timestamp::parse("2026-09-07").unwrap().to_string(),
            "2026-09-07T00:00:00Z"
        );
        let t = Timestamp::parse("2026-09-07T13:45:09").unwrap();
        assert_eq!(t.to_string(), "2026-09-07T13:45:09Z");
        assert_eq!(Timestamp::parse("2026-09-07 13:45:09Z").unwrap(), t);
        assert_eq!(Timestamp::parse("2026-09-07T13:45:09.250Z").unwrap(), t);
        let off = Timestamp::parse("2026-09-07T13:45:09+02:00").unwrap();
        assert_eq!(off.secs, t.secs - 7_200);
        let neg = Timestamp::parse("2026-09-07T13:45:09-0530").unwrap();
        assert_eq!(neg.secs, t.secs + 19_800);
    }

    #[test]
    fn rejects_bad_dates() {
        assert!(Timestamp::parse("2023-02-29").is_err());
        assert!(Timestamp::parse("2026-13-01").is_err());
        assert!(Timestamp::parse("2026-04-31").is_err());
        assert!(Timestamp::parse("not-a-date").is_err());
        assert!(Timestamp::parse("2026-09-07T25:00:00Z").is_err());
        assert!(Timestamp::parse("2026-09-07T10:00:00+99:00").is_err());
    }

    #[test]
    fn model_conversion_truncates_to_seconds() {
        let model = unidpp_model::Timestamp::from_secs(1_000_000);
        assert_eq!(
            Timestamp::from_model(model).to_string(),
            "1970-01-12T13:46:40Z"
        );
        assert_eq!(Timestamp::from_model(model).to_model(), model);
    }
}
