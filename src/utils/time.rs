//! Time helpers built on top of `time::OffsetDateTime`.

use time::OffsetDateTime;

/// Returns the current UTC time.
pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Returns a timestamp `secs` seconds from now. Used to compute `expires_at` fields.
pub fn in_secs(secs: u64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::seconds(secs as i64)
}
