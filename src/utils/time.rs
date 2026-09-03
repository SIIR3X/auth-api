//! The application's time source.
//!
//! Every decision that depends on the current time reads it from the `Clock`
//! held in `AppState`, so tests can move time forward without sleeping.
//! Comparisons made inside SQL (`NOW()`) and Redis TTLs follow the real clock:
//! a test covering those ages the stored data instead.

use time::{Duration, OffsetDateTime};

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> OffsetDateTime;

    /// `secs` seconds from now. Used to compute `expires_at` fields.
    fn in_secs(&self, secs: u64) -> OffsetDateTime {
        let secs = i64::try_from(secs).unwrap_or(i64::MAX);
        self.now().saturating_add(Duration::seconds(secs))
    }
}

/// The wall clock, in UTC. The only clock the service runs with.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(OffsetDateTime);

    impl Clock for Fixed {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    #[test]
    fn in_secs_is_relative_to_the_clock() {
        let clock = Fixed(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(
            clock.in_secs(90),
            OffsetDateTime::UNIX_EPOCH + Duration::seconds(90)
        );
    }

    #[test]
    fn in_secs_saturates_instead_of_overflowing() {
        let clock = Fixed(OffsetDateTime::UNIX_EPOCH);
        assert!(clock.in_secs(u64::MAX) > OffsetDateTime::UNIX_EPOCH);
    }

    #[test]
    fn system_clock_reads_the_wall_clock() {
        let before = OffsetDateTime::now_utc();
        let now = SystemClock.now();
        assert!(now >= before && now - before < Duration::seconds(5));
    }
}
