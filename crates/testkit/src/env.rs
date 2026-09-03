//! Test infrastructure addresses.
//!
//! A missing variable fails the test instead of skipping it: a suite that
//! silently passes without its database has checked nothing.

use std::sync::Once;

pub const DATABASE_URL: &str = "TEST_DATABASE_URL";
pub const REDIS_URL: &str = "TEST_REDIS_URL";
pub const NATS_URL: &str = "TEST_NATS_URL";

fn load_dotenv() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        dotenvy::dotenv().ok();
    });
}

fn required(name: &str) -> String {
    load_dotenv();
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} must be set: start the test infrastructure (`make test-infra-up`) \
             and run the suites through `make test-local`, or export \
             TEST_DATABASE_URL, TEST_REDIS_URL and TEST_NATS_URL"
        )
    })
}

/// Administrative connection to the test PostgreSQL server.
pub fn database_url() -> String {
    required(DATABASE_URL)
}

pub fn redis_url() -> String {
    required(REDIS_URL)
}

pub fn nats_url() -> String {
    required(NATS_URL)
}
