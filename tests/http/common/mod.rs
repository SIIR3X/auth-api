//! Shared test infrastructure for HTTP integration tests.
//!
//! TestApp spins up the real Axum router bound to a random port,
//! backed by a temporary PostgreSQL database and a real Redis instance.
//! Each test gets its own database so tests are fully isolated.

pub mod app;
pub mod fixtures;
pub mod mailpit;
