//! Domain types that mirror the database schema.
//!
//! These structs are used internally by repositories and services.
//! They are never serialized directly to HTTP responses; DTOs handle that.

pub mod audit;
pub mod login_attempt;
pub mod role;
pub mod session;
pub mod token;
pub mod two_factor;
pub mod user;
