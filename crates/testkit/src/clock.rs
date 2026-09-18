//! The clock the test app runs with: the wall clock plus an adjustable offset.
//!
//! Time keeps flowing, so timeouts and database timestamps stay coherent, and
//! a test jumps forward with [`TestClock::advance`] instead of sleeping.
//!
//! Only decisions the application takes in Rust follow this clock: token
//! expiry, TOTP steps, lockout, session lifetime, brute-force windows. SQL
//! `NOW()` and Redis TTLs keep real time; a test covering those ages the stored
//! rows or deletes the key instead.

use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use auth_api::utils::time::Clock;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone, Default)]
pub struct TestClock {
    offset_nanos: Arc<AtomicI64>,
}

impl TestClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Move the clock forward (or back, with a negative duration).
    pub fn advance(&self, by: Duration) {
        let nanos = i64::try_from(by.whole_nanoseconds()).expect("offset fits in i64 nanoseconds");
        self.offset_nanos.fetch_add(nanos, Ordering::SeqCst);
    }

    /// Current offset from the wall clock.
    pub fn offset(&self) -> Duration {
        Duration::nanoseconds(self.offset_nanos.load(Ordering::SeqCst))
    }

    pub fn reset(&self) {
        self.offset_nanos.store(0, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc() + self.offset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advancing_moves_every_clone() {
        let clock = TestClock::new();
        let shared = clock.clone();
        let before = shared.now();

        clock.advance(Duration::days(91));

        let moved = shared.now() - before;
        assert!(moved >= Duration::days(91) && moved < Duration::days(91) + Duration::minutes(1));
    }

    #[test]
    fn reset_returns_to_the_wall_clock() {
        let clock = TestClock::new();
        clock.advance(Duration::hours(-3));
        clock.reset();
        assert_eq!(clock.offset(), Duration::ZERO);
    }
}
