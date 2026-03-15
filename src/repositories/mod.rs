//! Database repositories.
//!
//! Each module maps to one or more tables and exposes async functions
//! that accept a SQLx executor and return domain types. No business logic
//! lives here; only SQL and type conversions.

pub mod audit;
pub mod login_attempt;
pub mod recovery_code;
pub mod role;
pub mod session;
pub mod token;
pub mod two_factor;
pub mod user;
