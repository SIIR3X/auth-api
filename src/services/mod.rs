//! Business logic layer.
//!
//! Services orchestrate repositories, utils, and external integrations.
//! They take an AppState reference and return AppError on failure.
//! No HTTP types belong here; only domain types and errors.

pub mod auth;
pub mod email;
pub mod session;
pub mod two_factor;
pub mod user;
