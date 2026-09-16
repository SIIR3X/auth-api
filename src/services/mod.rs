//! Business logic layer.
//!
//! Services orchestrate repositories, utils, and external integrations.
//! They take an AppState reference and return AppError on failure.
//! No HTTP types belong here; only domain types and errors.

pub mod auth;
pub mod authorize;
pub mod captcha;
pub mod cleanup;
pub mod device;
pub mod email;
pub mod email_2fa;
pub mod email_change;
pub mod events;
pub mod key_rotation;
pub mod mailer;
pub mod pwned;
pub mod reauth;
pub mod session;
pub mod two_factor;
pub mod user;
