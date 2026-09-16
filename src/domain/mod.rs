//! Domain types that mirror the database schema, and the decisions taken about
//! them.
//!
//! These structs are used internally by repositories and services.
//! They are never serialized directly to HTTP responses; DTOs handle that.
//! Decisions live here as plain functions of plain values (time included), so
//! unit and mutation tests reach them without Redis, PostgreSQL or HTTP; the
//! services do the I/O and map each verdict to its error.

pub mod audit;
pub mod captcha;
pub mod client_quota;
pub mod device;
pub mod email_change;
pub mod known_device;
pub mod login_attempt;
pub mod outbox;
pub mod pwned;
pub mod rate_limit;
pub mod registered_client;
pub mod role;
pub mod session;
pub mod token;
pub mod two_factor;
pub mod user;
