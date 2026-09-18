//! Database repositories.
//!
//! Each module maps to one or more tables and exposes async functions
//! that accept a SQLx executor and return domain types. No business logic
//! lives here; only SQL and type conversions.

pub mod audit;
pub mod authorization_code;
pub mod client_quota;
pub mod email_2fa;
pub mod event_outbox;
pub mod export;
pub mod external_identity;
pub mod known_device;
pub mod login_attempt;
pub mod passkey;
pub mod personal_access_token;
pub mod recovery_code;
pub mod registered_client;
pub mod role;
pub mod session;
pub mod token;
pub mod two_factor;
pub mod user;
pub mod webhook;
