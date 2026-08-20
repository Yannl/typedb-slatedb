//! Calendar arithmetic without a dependency, so that waiver expiry is
//! evaluated deterministically and can be unit-tested against a fixed "today".

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: i64,
    pub month: u32,
    pub day: u32,
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl Date {
    /// Parse a strict `YYYY-MM-DD`. Anything else is rejected: a waiver with a
    /// sloppy date is an invalid waiver, not a lenient one.
    pub fn parse(s: &str) -> Result<Date, String> {
        let bytes = s.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return Err(format!("expected YYYY-MM-DD, got {s:?}"));
        }
        if !bytes.iter().enumerate().all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit()) {
            return Err(format!("expected YYYY-MM-DD, got {s:?}"));
        }
        let year: i64 = s[0..4].parse().map_err(|_| format!("bad year in {s:?}"))?;
        let month: u32 = s[5..7].parse().map_err(|_| format!("bad month in {s:?}"))?;
        let day: u32 = s[8..10].parse().map_err(|_| format!("bad day in {s:?}"))?;
        if !(1..=12).contains(&month) {
            return Err(format!("month out of range in {s:?}"));
        }
        if day < 1 || day > days_in_month(year, month) {
            return Err(format!("day out of range in {s:?}"));
        }
        Ok(Date { year, month, day })
    }

    /// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
    pub fn to_epoch_days(self) -> i64 {
        let y = if self.month <= 2 { self.year - 1 } else { self.year };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let m = self.month as i64;
        let d = self.day as i64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    pub fn from_epoch_days(z: i64) -> Date {
        let z = z + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        Date { year: if m <= 2 { y + 1 } else { y }, month: m as u32, day: d as u32 }
    }

    pub fn days_until(self, other: Date) -> i64 {
        other.to_epoch_days() - self.to_epoch_days()
    }

    /// Today in UTC, from the system clock.
    pub fn today_utc() -> Date {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        Date::from_epoch_days(secs.div_euclid(86_400))
    }
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// RFC3339 UTC timestamp for the report's `generated_at`.
pub fn now_rfc3339_utc() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let date = Date::from_epoch_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    format!("{date}T{:02}:{:02}:{:02}Z", tod / 3600, (tod % 3600) / 60, tod % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips() {
        let d = Date::parse("2026-08-20").unwrap();
        assert_eq!((d.year, d.month, d.day), (2026, 8, 20));
        assert_eq!(Date::from_epoch_days(d.to_epoch_days()), d);
        assert_eq!(d.to_string(), "2026-08-20");
    }

    #[test]
    fn epoch_anchor_is_correct() {
        assert_eq!(Date::parse("1970-01-01").unwrap().to_epoch_days(), 0);
        assert_eq!(Date::parse("2000-03-01").unwrap().to_epoch_days(), 11017);
    }

    #[test]
    fn rejects_malformed_or_impossible_dates() {
        for bad in ["2026-8-20", "20260820", "2026-13-01", "2026-02-30", "not-a-date", "2026-08-20T00:00:00Z", ""] {
            assert!(Date::parse(bad).is_err(), "should reject {bad:?}");
        }
        assert!(Date::parse("2024-02-29").is_ok(), "2024 is a leap year");
        assert!(Date::parse("2100-02-29").is_err(), "2100 is not a leap year");
    }

    #[test]
    fn ordering_and_distance() {
        let a = Date::parse("2026-08-20").unwrap();
        let b = Date::parse("2026-11-20").unwrap();
        assert!(a < b);
        assert_eq!(a.days_until(b), 92);
        assert_eq!(b.days_until(a), -92);
    }
}
