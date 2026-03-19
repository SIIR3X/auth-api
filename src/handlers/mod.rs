//! HTTP layer: route definitions and handler registration.
//!
//! All routes are assembled here and the AppState is bound once at the top level.
//! Public routes (no auth required) are separated from protected routes.

use axum::{
    routing::{delete, get, patch, post},
    Router,
};

use crate::state::AppState;

pub mod auth;
pub mod extractors;
pub mod session;
pub mod two_factor;
pub mod user;

pub fn router(state: AppState) -> Router {
    Router::new()
        .nest("/auth", auth_router())
        .nest("/users/me", me_router())
        .with_state(state)
}

// Public auth routes

fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/logout", post(auth::logout))
        .route("/refresh", post(auth::refresh))
        .route("/verify-email", get(auth::verify_email))
        .route("/forgot-password", post(auth::forgot_password))
        .route("/reset-password", post(auth::reset_password))
        .route("/two-factor/complete", post(auth::complete_two_factor))
        .route("/two-factor/recovery", post(auth::recovery_login))
}

// Protected routes under /users/me (all require a valid JWT)

fn me_router() -> Router<AppState> {
    Router::new()
        // Profile
        .route("/", get(user::me))
        .route("/username", patch(user::change_username))
        .route("/email", patch(user::change_email))
        .route("/password", patch(user::change_password))
        .route("/locale", patch(user::change_locale))
        // Sessions
        .route("/sessions", get(session::list))
        .route("/sessions", delete(session::revoke_all))
        .route("/sessions/:id", delete(session::revoke))
        // Two-factor
        .route("/two-factor/totp/setup", post(two_factor::setup_totp))
        .route("/two-factor/totp/:id/verify", post(two_factor::verify_totp_setup))
        .route("/two-factor/totp/:id", delete(two_factor::disable_totp))
        .route("/two-factor/recovery-codes", post(two_factor::regenerate_recovery_codes))
        .route("/two-factor/recovery-codes/use", post(two_factor::use_recovery_code))
}
