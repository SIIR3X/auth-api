//! Shared harness of the auth-api test suites.
//!
//! - [`TestApp`]: the real router on a random port, with its own database, a
//!   controllable clock and an in-memory mail outbox;
//! - [`TestDb`]: a database cloned from a template migrated once per
//!   migration set, dropped when the value is;
//! - [`TestClock`]: the application clock, moved forward without sleeping;
//! - [`MailOutbox`]: every message the application sends, decoded;
//! - [`authenticator::SoftAuthenticator`]: a passkey authenticator in memory,
//!   answering WebAuthn ceremonies like a browser would pass them on;
//! - [`FaultProxy`]: a TCP proxy between the application and a dependency,
//!   adding latency, hanging or refusing connections on demand.
//!
//! The suites need PostgreSQL, Redis and NATS: `make test-infra-up`, then
//! `TEST_DATABASE_URL`, `TEST_REDIS_URL` and `TEST_NATS_URL` (see
//! [`env`]). The unit and property suites need none of it.

pub mod app;
pub mod authenticator;
pub mod clock;
pub mod contract;
pub mod db;
pub mod env;
pub mod faults;
pub mod fixtures;
pub mod keys;
pub mod logs;
pub mod mail;
pub mod mailpit;
pub mod sql;
pub mod tokens;

/// Re-exported for [`pg_args!`].
pub use sqlx;

pub use app::{TestApp, TestAppBuilder};
pub use clock::TestClock;
pub use db::TestDb;
pub use faults::{Fault, FaultProxy};
pub use mail::{CapturedMail, MailOutbox};

/// Install the test log subscriber once per process. `RUST_LOG` style
/// filtering goes through `TEST_LOG`, e.g. `TEST_LOG=auth_api=debug`.
pub fn init_tracing() {
    let filter = std::env::var("TEST_LOG").unwrap_or_else(|_| "auth_api=error".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_test_writer()
        .try_init();
}

/// Absolute path of a file or directory of the auth-api package.
pub fn workspace_path(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}
