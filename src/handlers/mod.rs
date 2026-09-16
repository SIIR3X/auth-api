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
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    timeout::TimeoutLayer,
};

use crate::{
    middleware::{
        access_log, error_body,
        rate_limit::{self, Bucket, RateLimitState},
        request_id, security_headers,
    },
    state::AppState,
};

pub mod audit;
pub mod auth;
pub mod authorize;
pub mod device;
pub mod extractors;
pub mod session;
pub mod two_factor;
pub mod user;

#[utoipa::path(
    get,
    path = "/health",
    tag = "discovery",
    responses(
        (status = 200, description = "Serving", body = String, content_type = "text/plain"),
    ),
)]
pub async fn health() -> &'static str {
    "ok"
}

#[utoipa::path(
    get,
    path = "/live",
    tag = "discovery",
    responses(
        (status = 200, description = "The process serves requests; dependencies are not checked", body = String, content_type = "text/plain"),
    ),
)]
/// Liveness: answers as long as the process serves HTTP. Restarting the
/// container cannot fix a dependency, so this never checks one.
pub async fn live() -> &'static str {
    "ok"
}

/// What `/ready` found for each dependency.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ReadyResponse {
    /// `ready` when every dependency answered, `unavailable` otherwise.
    pub status: &'static str,
    /// `up` or `down`.
    pub database: &'static str,
    pub redis: &'static str,
    pub nats: &'static str,
}

/// How long a readiness check waits for one dependency.
const READY_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[utoipa::path(
    get,
    path = "/ready",
    tag = "discovery",
    responses(
        (status = 200, description = "Every dependency answered", body = ReadyResponse),
        (status = 503, description = "A dependency did not answer", body = ReadyResponse),
    ),
)]
/// Readiness: whether this instance can serve traffic now. The reverse proxy
/// and the rolling update send traffic only to a ready instance.
pub async fn ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (axum::http::StatusCode, axum::Json<ReadyResponse>) {
    let database = async {
        matches!(
            tokio::time::timeout(
                READY_PROBE_TIMEOUT,
                sqlx::query("SELECT 1").execute(&state.db)
            )
            .await,
            Ok(Ok(_))
        )
    };
    let redis = async {
        let ping = async {
            let mut conn = state.redis.get().await.ok()?;
            deadpool_redis::redis::cmd("PING")
                .query_async::<String>(&mut *conn)
                .await
                .ok()
        };
        matches!(
            tokio::time::timeout(READY_PROBE_TIMEOUT, ping).await,
            Ok(Some(_))
        )
    };
    let (database, redis) = tokio::join!(database, redis);
    let nats = state.nats.connection_state() == async_nats::connection::State::Connected;

    let up = |ok: bool| if ok { "up" } else { "down" };
    let all = database && redis && nats;
    (
        if all {
            axum::http::StatusCode::OK
        } else {
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        },
        axum::Json(ReadyResponse {
            status: if all { "ready" } else { "unavailable" },
            database: up(database),
            redis: up(redis),
            nats: up(nats),
        }),
    )
}

#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "discovery",
    responses(
        (status = 200, description = "JSON Web Key Set of the current and previous signing keys", body = Object),
    ),
)]
pub async fn jwks(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl axum::response::IntoResponse {
    // Public key material is safe to cache: a short max-age lets downstream
    // verifiers avoid refetching on every validation while still picking up
    // rotated keys quickly. The security-headers middleware only applies its
    // blanket `no-store` when the handler did not set cache-control itself.
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        axum::Json(state.jwt_jwks.as_ref().clone()),
    )
}

/// Build the main application router plus a separate `/metrics` router.
///
/// The metrics router MUST be served on an internal listener only (see
/// `MetricsConfig`): the Prometheus exposition reveals route-level traffic
/// patterns and must never sit behind the public reverse proxy.
///
/// Calling this installs the global Prometheus recorder, which can only
/// happen once per process: use it from `main` only. Tests use `router()`,
/// which records no metrics.
pub fn router_with_metrics(state: AppState) -> (Router, Router) {
    let (prometheus_layer, metric_handle) = axum_prometheus::PrometheusMetricLayer::pair();

    let app = build_router(state, Some(prometheus_layer));
    let metrics = Router::new().route(
        "/metrics",
        get(move || {
            let handle = metric_handle.clone();
            async move { handle.render() }
        }),
    );

    (app, metrics)
}

pub fn router(state: AppState) -> Router {
    build_router(state, None)
}

fn build_router(
    state: AppState,
    prometheus_layer: Option<axum_prometheus::PrometheusMetricLayer<'static>>,
) -> Router {
    // Every route passes exactly one rate-limit layer, which checks all of its
    // buckets in a single Redis call. Auth and reauth routes count against the
    // general bucket and a stricter one of their own.
    let general = Bucket {
        prefix: "rl",
        limit: state.config.rate_limit.requests_per_minute,
    };
    let strict = Bucket {
        prefix: "rl_auth",
        limit: state.config.rate_limit.auth_requests_per_minute,
    };
    let limiter = |buckets: Vec<Bucket>| RateLimitState {
        redis: state.redis.clone(),
        buckets,
        trusted_proxy_cidrs: state.config.server.trusted_proxy_cidrs.clone(),
        fail_open_on_redis_error: state.config.rate_limit.fail_open_on_redis_error,
        allow_requests_without_ip: state.config.rate_limit.allow_requests_without_ip,
    };
    let rl_general = limiter(vec![general]);
    let rl_auth = limiter(vec![general, strict]);
    let security_headers_state = security_headers::SecurityHeadersState {
        enable_hsts: state.config.is_production()
            && state.config.server.public_url.starts_with("https://"),
        is_production: state.config.is_production(),
    };

    let cors = build_cors(&state.config.cors);

    // Reauth shares the strict auth bucket to cap password-guessing attempts
    // made with a stolen access token. It is merged separately so that other
    // /users/me routes only consume from the larger general bucket.
    let me_with_strict_reauth = me_strict_router()
        .layer(middleware::from_fn_with_state(
            rl_auth.clone(),
            rate_limit::layer_with_state,
        ))
        .merge(me_router().layer(middleware::from_fn_with_state(
            rl_general.clone(),
            rate_limit::layer_with_state,
        )));

    // Probes skip the rate limiter: an orchestrator or the reverse proxy polls
    // them, and a Redis outage must not turn every instance unhealthy at once.
    let probes = Router::new()
        .route("/health", get(health))
        .route("/live", get(live))
        .route("/ready", get(ready));

    let public = Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        // Logout is authenticated (requires a valid JWT via AuthUser) but intentionally
        // placed outside the auth rate-limit bucket. Exhausting that bucket during a
        // brute-force attack must not prevent the legitimate user from ending their session.
        .route("/auth/logout", post(auth::logout))
        .layer(middleware::from_fn_with_state(
            rl_general,
            rate_limit::layer_with_state,
        ));

    let router = probes
        .merge(public)
        .nest(
            "/auth",
            auth_router().layer(middleware::from_fn_with_state(
                rl_auth,
                rate_limit::layer_with_state,
            )),
        )
        .nest("/users/me", me_with_strict_reauth)
        .layer(cors)
        .layer(middleware::from_fn(access_log::layer))
        // 64 KB is more than sufficient for any JSON payload this API accepts.
        // Overrides Axum's default 2 MB limit to reduce DoS exposure.
        .layer(DefaultBodyLimit::max(65_536))
        // Defence-in-depth: cap total handler time so a stalled dependency
        // (DB pool exhaustion, unresponsive SMTP relay) cannot pile up
        // connections indefinitely, even if the reverse proxy has no timeout.
        // 30 s comfortably covers the slowest legitimate path (Argon2 queueing
        // behind the concurrency semaphore under load). 503 (not 408) matches
        // the API's existing overload semantics (rate limiter unavailable).
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            std::time::Duration::from_secs(30),
        ))
        // Outside the timeout, the body limit and the rate limiters, whose
        // refusals are plain text: every error leaves with the documented body.
        .layer(middleware::from_fn(error_body::layer))
        .layer(middleware::from_fn_with_state(
            security_headers_state,
            security_headers::layer,
        ))
        .layer(middleware::from_fn(request_id::layer));

    // Outermost layer so HTTP metrics include time spent in every middleware.
    let router = match prometheus_layer {
        Some(layer) => router.layer(layer),
        None => router,
    };

    router.with_state(state)
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

// Public auth routes (all share the strict auth rate-limit bucket).
// /logout is registered separately in router() under the general bucket.

fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh))
        // Token delivered in the body (POST) to keep it out of access logs and
        // browser history. Switched from GET /verify-email?token= for this reason.
        .route("/verify-email", post(auth::verify_email))
        .route("/verify-email/resend", post(auth::resend_verification))
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
        // Device authorization flow (RFC 8628)
        .route("/device", post(device::authorize))
        .route("/device/token", post(device::token))
        .route("/device/verify", post(device::verify))
        .route("/device/{user_code}", get(device::describe))
        // Authorization Code with PKCE (RFC 7636, RFC 8252)
        .route("/authorize", post(authorize::approve))
        .route("/authorize/describe", post(authorize::describe))
        .route("/authorize/token", post(authorize::token))
}

// Sensitive authenticated routes placed under the strict auth rate-limit bucket.
// The email-change flow is included here because each step involves OTP dispatch
// or verification - the same threat model as the reauth endpoint.

fn me_strict_router() -> Router<AppState> {
    Router::new()
        .route("/reauth", post(user::reauthenticate))
        .route("/email/start", post(user::start_email_change))
        .route("/email/verify-current", post(user::verify_current_email))
        .route("/email/submit", post(user::submit_new_email))
        .route("/email/confirm", post(user::confirm_new_email))
}

// Protected routes under /users/me (all require a valid JWT).
// /reauth is registered in me_strict_router() with the tighter rate limit.

fn me_router() -> Router<AppState> {
    Router::new()
        // Profile
        .route("/", get(user::me))
        .route("/audit", get(audit::list))
        .route("/two-factor", get(two_factor::list))
        .route("/username", patch(user::change_username))
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
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn metrics_recorder_renders_business_counters() {
        // pair() installs the process-global Prometheus recorder (and spawns
        // its upkeep task, hence the Tokio runtime); this must stay the only
        // test doing so (router() never installs it, so the integration suite
        // is unaffected).
        let (_layer, handle) = axum_prometheus::PrometheusMetricLayer::pair();

        metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
        metrics::gauge!("argon2_queue_available_permits").set(4.0);

        let body = handle.render();
        assert!(
            body.contains("auth_logins_total"),
            "missing counter: {body}"
        );
        assert!(body.contains("argon2_queue_available_permits"));
    }
}
