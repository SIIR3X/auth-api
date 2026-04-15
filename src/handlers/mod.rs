//! HTTP layer: route definitions and handler registration.
//!
//! All routes are assembled here and the AppState is bound once at the top level.
//! Public routes (no auth required) are separated from protected routes.
//! Global middlewares (request ID, security headers, rate limiting) are applied
//! at the top level so every route benefits from them.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{Method, header},
    middleware,
    routing::{delete, get, patch, post},
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    middleware::{
        rate_limit::{self, RateLimitState},
        request_id, security_headers,
    },
    state::AppState,
};

pub mod auth;
pub mod extractors;
pub mod session;
pub mod two_factor;
pub mod user;
pub mod webauthn;

pub fn router(state: AppState) -> Router {
    let rl_general = RateLimitState {
        redis: state.redis.clone(),
        limit: state.config.rate_limit.requests_per_minute,
        trusted_proxy_cidrs: state.config.server.trusted_proxy_cidrs.clone(),
        fail_open_on_redis_error: state.config.rate_limit.fail_open_on_redis_error,
        allow_requests_without_ip: state.config.rate_limit.allow_requests_without_ip,
    };
    let rl_auth = RateLimitState {
        redis: state.redis.clone(),
        limit: state.config.rate_limit.auth_requests_per_minute,
        trusted_proxy_cidrs: state.config.server.trusted_proxy_cidrs.clone(),
        fail_open_on_redis_error: state.config.rate_limit.fail_open_on_redis_error,
        allow_requests_without_ip: state.config.rate_limit.allow_requests_without_ip,
    };
    let security_headers_state = security_headers::SecurityHeadersState {
        enable_hsts: state.config.is_production()
            && state.config.server.public_url.starts_with("https://"),
    };

    let cors = build_cors(&state.config.cors);

    Router::new()
        .nest(
            "/auth",
            auth_router().layer(middleware::from_fn_with_state(
                rl_auth,
                rate_limit::layer_with_state,
            )),
        )
        .nest("/users/me", me_router())
        .layer(cors)
        .layer(middleware::from_fn_with_state(
            rl_general,
            rate_limit::layer_with_state,
        ))
        .layer(middleware::from_fn_with_state(
            security_headers_state,
            security_headers::layer,
        ))
        .layer(middleware::from_fn(request_id::layer))
        // 64 KB is more than sufficient for any JSON payload this API accepts.
        // Overrides Axum's default 2 MB limit to reduce DoS exposure.
        .layer(DefaultBodyLimit::max(65_536))
        .with_state(state)
}

fn build_cors(cfg: &crate::config::CorsConfig) -> CorsLayer {
    let allow_origin = if cfg.allowed_origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        let origins = cfg
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect::<Vec<_>>();
        AllowOrigin::list(origins)
    };

    let layer = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]);

    if cfg.allow_credentials {
        layer.allow_credentials(true)
    } else {
        layer
    }
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
        .route(
            "/two-factor/email/complete",
            post(auth::complete_email_two_factor),
        )
        .route(
            "/two-factor/email/resend",
            post(auth::resend_email_two_factor),
        )
        .route(
            "/two-factor/webauthn/start",
            post(webauthn::start_authentication),
        )
        .route(
            "/two-factor/webauthn/finish",
            post(webauthn::finish_authentication),
        )
}

// Protected routes under /users/me (all require a valid JWT)

fn me_router() -> Router<AppState> {
    Router::new()
        // Profile
        .route("/", get(user::me))
        .route("/reauth", post(user::reauthenticate))
        .route("/username", patch(user::change_username))
        .route("/email", patch(user::change_email))
        .route("/password", patch(user::change_password))
        .route("/locale", patch(user::change_locale))
        .route("/", delete(user::delete_account))
        // Sessions
        .route("/sessions", get(session::list))
        .route("/sessions", delete(session::revoke_all))
        .route("/sessions/{id}", delete(session::revoke))
        // Two-factor: TOTP
        .route("/two-factor/totp/setup", post(two_factor::setup_totp))
        .route(
            "/two-factor/totp/{id}/verify",
            post(two_factor::verify_totp_setup),
        )
        .route("/two-factor/totp/{id}", delete(two_factor::disable_totp))
        .route(
            "/two-factor/recovery-codes",
            post(two_factor::regenerate_recovery_codes),
        )
        .route(
            "/two-factor/recovery-codes/use",
            post(two_factor::use_recovery_code),
        )
        // Two-factor: Email OTP
        .route("/two-factor/email/setup", post(two_factor::setup_email_otp))
        .route(
            "/two-factor/email/send",
            post(two_factor::send_email_otp_code),
        )
        .route(
            "/two-factor/email/{id}/verify",
            post(two_factor::verify_email_otp_setup),
        )
        .route(
            "/two-factor/email/{id}",
            delete(two_factor::disable_email_otp),
        )
        // Two-factor: WebAuthn/passkey
        .route(
            "/two-factor/webauthn/register/start",
            post(webauthn::start_registration),
        )
        .route(
            "/two-factor/webauthn/register/finish",
            post(webauthn::finish_registration),
        )
        .route(
            "/two-factor/webauthn/{id}",
            delete(webauthn::disable_webauthn),
        )
}
