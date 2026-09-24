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
    routing::{delete, get, patch, post, put},
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

pub mod admin;
pub mod audit;
pub mod auth;
pub mod external_identity;
pub mod extractors;
pub mod oauth;
pub mod passkey;
pub mod personal_access_token;
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

/// Whether this instance can serve traffic, as the public `/ready` says it.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ReadyResponse {
    /// `ready` when every dependency answered, `unavailable` otherwise.
    pub status: &'static str,
}

/// What a readiness check found for each dependency. Served on the internal
/// listener only: which dependency is down is operational detail.
#[derive(serde::Serialize)]
pub struct Readiness {
    /// `ready` when every dependency answered, `unavailable` otherwise.
    pub status: &'static str,
    /// `up` or `down`.
    pub database: &'static str,
    pub redis: &'static str,
    pub nats: &'static str,
}

impl Readiness {
    pub fn is_ready(&self) -> bool {
        self.status == "ready"
    }
}

/// How long a readiness check waits for one dependency.
const READY_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Check every dependency, each within [`READY_PROBE_TIMEOUT`].
pub async fn readiness(state: &AppState) -> Readiness {
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
    Readiness {
        status: if database && redis && nats {
            "ready"
        } else {
            "unavailable"
        },
        database: up(database),
        redis: up(redis),
        nats: up(nats),
    }
}

fn ready_status(readiness: &Readiness) -> axum::http::StatusCode {
    if readiness.is_ready() {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    }
}

#[utoipa::path(
    get,
    path = "/ready",
    tag = "discovery",
    responses(
        (status = 200, description = "Every dependency answered", body = ReadyResponse),
        (status = 503, description = "A dependency did not answer; the internal listener says which", body = ReadyResponse),
    ),
)]
/// Readiness: whether this instance can serve traffic now. The reverse proxy
/// and the rolling update send traffic only to a ready instance.
pub async fn ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (axum::http::StatusCode, axum::Json<ReadyResponse>) {
    // Anyone may poll it: the answer is reused for a second, so a flood costs
    // the dependencies one check per second and no pool connections.
    let ready = {
        let mut cached = state.readiness_cache.lock().await;
        match *cached {
            Some((taken, ready)) if taken.elapsed() < READY_CACHE_TTL => ready,
            _ => {
                let ready = readiness(&state).await.is_ready();
                *cached = Some((std::time::Instant::now(), ready));
                ready
            }
        }
    };
    let (status, word) = if ready {
        (axum::http::StatusCode::OK, "ready")
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    };
    (status, axum::Json(ReadyResponse { status: word }))
}

/// How long the public readiness answer is reused.
const READY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// The readiness of each dependency, on the internal listener.
async fn ready_detail(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (axum::http::StatusCode, axum::Json<Readiness>) {
    let readiness = readiness(&state).await;
    (ready_status(&readiness), axum::Json(readiness))
}

/// The internal listener answers only with `Authorization: Bearer
/// <METRICS_TOKEN>` when a token is configured (always, in production).
async fn internal_bearer(
    axum::extract::State(token): axum::extract::State<Option<String>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    if let Some(token) = token.as_deref() {
        let presented = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        if !crate::utils::crypto::constant_time_eq(presented.as_bytes(), token.as_bytes()) {
            return axum::response::IntoResponse::into_response(
                axum::http::StatusCode::UNAUTHORIZED,
            );
        }
    }
    next.run(request).await
}

/// The endpoint label of requests no route matched: the raw path would give
/// every scanned URL a series of its own.
fn unmatched_endpoint_label(_path: &str) -> String {
    "<unmatched>".to_owned()
}

/// The HTTP metrics layer and the handle that renders the exposition.
fn metrics_layer() -> (
    axum_prometheus::PrometheusMetricLayer<'static>,
    axum_prometheus::metrics_exporter_prometheus::PrometheusHandle,
) {
    axum_prometheus::PrometheusMetricLayerBuilder::new()
        .with_endpoint_label_type(axum_prometheus::EndpointLabel::MatchedPathWithFallbackFn(
            unmatched_endpoint_label,
        ))
        .with_default_metrics()
        .build_pair()
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

/// Build the main application router plus a separate internal router:
/// `/metrics` and the detailed `/ready`.
///
/// The internal router MUST be served on an internal listener only (see
/// `MetricsConfig`): the Prometheus exposition reveals route-level traffic
/// patterns and must never sit behind the public reverse proxy.
///
/// Calling this installs the global Prometheus recorder, which can only
/// happen once per process: use it from `main` only. Tests use `router()`,
/// which records no metrics.
pub fn router_with_metrics(state: AppState) -> (Router, Router) {
    let (prometheus_layer, metric_handle) = metrics_layer();

    let app = build_router(state.clone(), Some(prometheus_layer));
    let internal = Router::new()
        .route(
            "/metrics",
            get(move || {
                let handle = metric_handle.clone();
                async move { handle.render() }
            }),
        )
        .route("/ready", get(ready_detail))
        .layer(middleware::from_fn_with_state(
            state.config.metrics.token.clone(),
            internal_bearer,
        ))
        .with_state(state);

    (app, internal)
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

    // Requests no route matches spend the general budget too: a scan of
    // unknown paths is still traffic from one address.
    let unmatched = Router::new()
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            rl_general.clone(),
            rate_limit::layer_with_state,
        ));

    let admin = admin_router().layer(middleware::from_fn_with_state(
        rl_general.clone(),
        rate_limit::layer_with_state,
    ));

    let public = Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(oauth::openid_configuration),
        )
        // Logout is authenticated (requires a valid JWT via AuthUser) but intentionally
        // placed outside the auth rate-limit bucket. Exhausting that bucket during a
        // brute-force attack must not prevent the legitimate user from ending their session.
        .route("/auth/logout", post(auth::logout))
        .layer(middleware::from_fn_with_state(
            rl_general.clone(),
            rate_limit::layer_with_state,
        ));

    let router = probes
        .merge(public)
        .merge(unmatched)
        .nest(
            "/auth",
            auth_router().layer(middleware::from_fn_with_state(
                rl_auth.clone(),
                rate_limit::layer_with_state,
            )),
        )
        .nest(
            "/oauth",
            oauth_router()
                .layer(middleware::from_fn_with_state(
                    rl_auth,
                    rate_limit::layer_with_state,
                ))
                .merge(oauth_client_router().layer(middleware::from_fn_with_state(
                    rl_general,
                    rate_limit::layer_with_state,
                ))),
        )
        .nest("/users/me", me_with_strict_reauth)
        .nest("/admin", admin)
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

/// The router's own 404, which the error body layer documents.
async fn not_found() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_FOUND
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
            Method::PUT,
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
        .route("/magic-link", post(auth::request_magic_link))
        .route("/magic-link/complete", post(auth::complete_magic_link))
        .route("/external/providers", get(external_identity::providers))
        .route(
            "/external/complete",
            post(external_identity::complete_sign_in),
        )
        .route(
            "/external/{provider}/start",
            post(external_identity::start_sign_in),
        )
        .route(
            "/external/{provider}/callback",
            get(external_identity::callback),
        )
        .route("/passkeys/options", post(passkey::authentication_options))
        .route("/passkeys/sign-in", post(passkey::sign_in))
        .route(
            "/personal-access-tokens/exchange",
            post(personal_access_token::exchange),
        )
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
}

// Administration: every route checks its own permission.

fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/users", get(admin::users::search))
        .route("/users/{id}", get(admin::users::detail))
        .route("/users/{id}", delete(admin::users::delete))
        .route("/users/{id}/suspend", post(admin::users::suspend))
        .route("/users/{id}/reactivate", post(admin::users::reactivate))
        .route("/users/{id}/unlock", post(admin::users::unlock))
        .route(
            "/users/{id}/access-factors",
            delete(admin::users::remove_access_factors),
        )
        .route(
            "/users/{id}/sessions",
            delete(admin::users::revoke_sessions),
        )
        .route(
            "/users/{id}/password-reset",
            post(admin::users::force_password_reset),
        )
        .route("/users/{id}/roles", post(admin::roles::assign))
        .route("/users/{id}/roles/{name}", delete(admin::roles::unassign))
        .route("/permissions", get(admin::roles::permissions))
        .route("/roles", get(admin::roles::list))
        .route("/roles", post(admin::roles::create))
        .route("/roles/{name}", delete(admin::roles::delete))
        .route(
            "/roles/{name}/permissions",
            put(admin::roles::set_permissions),
        )
        .route("/clients", get(admin::clients::list))
        .route("/clients/{client_id}", put(admin::clients::save))
        .route("/clients/{client_id}", delete(admin::clients::delete))
        .route(
            "/clients/{client_id}/secret",
            post(admin::clients::rotate_secret),
        )
        .route(
            "/clients/{client_id}/secret",
            delete(admin::clients::remove_secret),
        )
        .route("/audit", get(admin::audit::list))
        .route("/webhooks", get(admin::webhooks::list))
        .route("/webhooks", post(admin::webhooks::create))
        .route("/webhooks/{id}", put(admin::webhooks::update))
        .route("/webhooks/{id}", delete(admin::webhooks::delete))
        .route(
            "/webhooks/{id}/secret",
            post(admin::webhooks::rotate_secret),
        )
        .route(
            "/webhooks/{id}/deliveries",
            get(admin::webhooks::deliveries),
        )
        .route(
            "/webhooks/{id}/deliveries/{delivery_id}/retry",
            post(admin::webhooks::retry),
        )
}

// OAuth 2.1 (RFC 6749, 7636, 8252, 8628). Every route shares the strict bucket:
// the token endpoint answers unauthenticated guesses, and the approval routes
// mint long-lived sessions.

fn oauth_router() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(oauth::authorize))
        .route("/device_authorization", post(oauth::device_authorization))
        .route("/userinfo", get(oauth::userinfo))
        .route("/device/verify", post(oauth::verify_device))
        .route("/device/{user_code}", get(oauth::describe_device))
        .route("/authorization-requests/{id}", get(oauth::describe_request))
        .route(
            "/authorization-requests/{id}/approve",
            post(oauth::approve_request),
        )
        .route(
            "/authorization-requests/{id}/deny",
            post(oauth::deny_request),
        )
}

// The endpoints a client application calls with its own credentials: under
// the general per-address bucket, with a per-client budget and a per-address
// budget of wrong secrets in `services::oauth::authenticate_client`. The strict
// bucket would cap a resource server introspecting from one address, or every
// client behind a NAT, at a handful of requests a minute.

fn oauth_client_router() -> Router<AppState> {
    Router::new()
        .route("/token", post(oauth::token))
        .route("/introspect", post(oauth::introspect))
        .route("/revoke", post(oauth::revoke))
}

// Sensitive authenticated routes placed under the strict auth rate-limit bucket.
// The email-change flow is included here because each step involves OTP dispatch
// or verification - the same threat model as the reauth endpoint.

fn me_strict_router() -> Router<AppState> {
    Router::new()
        .route("/reauth", post(user::reauthenticate))
        // A download of everything stored: as costly as it is sensitive.
        .route("/export", get(user::export_data))
        .route("/email/start", post(user::start_email_change))
        .route("/email/verify-current", post(user::verify_current_email))
        .route("/email/submit", post(user::submit_new_email))
        .route("/email/confirm", post(user::confirm_new_email))
        // Every route accepting `current_password` guesses the password like
        // `/reauth` does, so it shares its bucket: the general one would let a
        // stolen access token try passwords fifteen times faster.
        .route("/", delete(user::delete_account))
        .route("/username", patch(user::change_username))
        .route("/password", patch(user::change_password))
        .route("/sessions", delete(session::revoke_all))
        .route("/sessions/{id}", delete(session::revoke))
        .route("/passkeys/{id}", delete(passkey::remove))
        .route(
            "/external-identities/{id}",
            delete(external_identity::unlink),
        )
        .route("/two-factor/totp/setup", post(two_factor::setup_totp))
        .route("/two-factor/totp/{id}", delete(two_factor::disable_totp))
        .route(
            "/two-factor/recovery-codes",
            post(two_factor::regenerate_recovery_codes),
        )
        .route("/two-factor/email/setup", post(two_factor::setup_email_otp))
        .route(
            "/two-factor/email/{id}",
            delete(two_factor::disable_email_otp),
        )
}

// Protected routes under /users/me (all require a valid JWT).
// /reauth is registered in me_strict_router() with the tighter rate limit.

fn me_router() -> Router<AppState> {
    Router::new()
        // Profile
        .route("/", get(user::me))
        .route("/audit", get(audit::list))
        .route("/two-factor", get(two_factor::list))
        .route("/locale", patch(user::change_locale))
        // External identities
        .route("/external-identities", get(external_identity::list))
        .route(
            "/external-identities/complete",
            post(external_identity::complete_link),
        )
        .route(
            "/external-identities/{provider}/start",
            post(external_identity::start_link),
        )
        // Passkeys
        .route("/passkeys", get(passkey::list))
        .route("/passkeys", post(passkey::register))
        .route("/passkeys/options", post(passkey::registration_options))
        // Personal access tokens
        .route("/tokens", get(personal_access_token::list))
        .route("/tokens", post(personal_access_token::create))
        .route("/tokens/{id}", delete(personal_access_token::revoke))
        // Sessions
        .route("/sessions", get(session::list))
        // Two-factor: TOTP
        .route(
            "/two-factor/totp/{id}/verify",
            post(two_factor::verify_totp_setup),
        )
        .route(
            "/two-factor/recovery-codes/use",
            post(two_factor::use_recovery_code),
        )
        // Two-factor: Email OTP
        .route(
            "/two-factor/email/send",
            post(two_factor::send_email_otp_code),
        )
        .route(
            "/two-factor/email/{id}/verify",
            post(two_factor::verify_email_otp_setup),
        )
}

#[cfg(test)]
mod tests {
    use tower::ServiceExt;

    /// The internal listener answers only with its bearer token (SEC-65).
    #[tokio::test]
    async fn the_internal_listener_needs_its_token() {
        let app = axum::Router::new()
            .route("/ready", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                Some("metrics-token".to_owned()),
                super::internal_bearer,
            ));
        let status = |authorization: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut request = axum::http::Request::get("/ready");
                if let Some(value) = authorization {
                    request = request.header("authorization", value);
                }
                app.oneshot(request.body(axum::body::Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status()
                    .as_u16()
            }
        };
        assert_eq!(status(None).await, 401);
        assert_eq!(status(Some("Bearer wrong")).await, 401);
        assert_eq!(status(Some("Bearer metrics-token")).await, 200);
    }

    #[tokio::test]
    async fn metrics_recorder_renders_business_counters_and_folds_unmatched_paths() {
        // The builder installs the process-global Prometheus recorder (and
        // spawns its upkeep task, hence the Tokio runtime); this must stay the
        // only test doing so (router() never installs it, so the integration
        // suite is unaffected).
        let (layer, handle) = super::metrics_layer();

        metrics::counter!("auth_logins_total", "outcome" => "success").increment(1);
        metrics::gauge!("argon2_queue_available_permits").set(4.0);

        let app = axum::Router::new()
            .route("/known", axum::routing::get(|| async { "ok" }))
            .layer(layer);
        for path in ["/known", "/scan-a1b2c3", "/.env"] {
            app.clone()
                .oneshot(
                    axum::http::Request::get(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        let body = handle.render();
        assert!(
            body.contains("auth_logins_total"),
            "missing counter: {body}"
        );
        assert!(body.contains("argon2_queue_available_permits"));
        assert!(body.contains(r#"endpoint="/known""#), "{body}");
        assert!(body.contains(r#"endpoint="<unmatched>""#), "{body}");
        assert!(
            !body.contains("scan-a1b2c3") && !body.contains("/.env"),
            "an unmatched path became a label: {body}"
        );
    }
}
