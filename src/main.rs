use std::{future::IntoFuture, time::Duration};

use auth_api::{
    config::{Config, LogFormat},
    handlers,
    services::{cleanup, key_rotation},
    state::AppState,
};

/// Shutdown budget, inside the container's 40-second stop grace period: requests
/// get slightly more than the 30-second request timeout, then the background
/// tasks (notifications, cache invalidations), then the buffered NATS events.
const REQUEST_DRAIN_TIMEOUT: Duration = Duration::from_secs(32);
const BACKGROUND_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const NATS_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Healthcheck mode: hit the local /live endpoint and exit 0/1.
    // Designed for `HEALTHCHECK CMD ["./auth-api", "--healthcheck"]` in the
    // runtime image so we don't have to ship `curl`/`wget` in the slim base.
    // Handled BEFORE Config::from_env so a misconfigured env doesn't make the
    // healthcheck explode (it just talks HTTP to localhost).
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(run_healthcheck().await);
    }

    let config = Config::from_env().expect("failed to load config");

    init_tracing(&config.log);
    auth_api::utils::password::log_capacity(&config.crypto);

    // One-off command: re-encrypt all TOTP secrets with the new key.
    // Set PREVIOUS_ENCRYPTION_KEY=<old> ENCRYPTION_KEY=<new>, run, then remove PREVIOUS_ENCRYPTION_KEY.
    if std::env::args().any(|a| a == "--rotate-totp-keys") {
        let state = AppState::from_config(config).await?;
        let result = key_rotation::rotate_totp_encryption_key(&state).await?;
        tracing::info!(
            rotated = result.rotated,
            skipped = result.skipped,
            failed = result.failed,
            "TOTP key rotation complete"
        );
        if result.failed > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    // One-off command: create or update a registered client (device and
    // authorization code flows refuse unregistered clients). Needs only the
    // database, not Redis, NATS or SMTP.
    let args: Vec<String> = std::env::args().collect();

    // One-off command: grant a role, such as the first administrator.
    match auth_api::cli::parse_role_grant(&args) {
        Ok(Some(grant)) => {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&config.database.url)
                .await?;
            auth_api::cli::grant_role(&pool, &grant)
                .await
                .map_err(|message| anyhow::anyhow!("--grant-role: {message}"))?;
            tracing::info!(role = grant.role, "role granted");
            return Ok(());
        }
        Ok(None) => {}
        Err(message) => anyhow::bail!("--grant-role: {message}"),
    }

    match auth_api::cli::parse_client_registration(&args) {
        Ok(Some(registration)) => {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&config.database.url)
                .await?;
            let client =
                auth_api::repositories::registered_client::upsert(&pool, &registration.as_new())
                    .await?;
            tracing::info!(
                client_id = client.client_id,
                primary = client.is_primary,
                "registered client saved"
            );
            return Ok(());
        }
        Ok(None) => {}
        Err(message) => anyhow::bail!("--register-client: {message}"),
    }

    let addr = format!("{}:{}", config.server.host, config.server.port);

    let state = AppState::from_config(config).await?;

    // Rotate audit log partitions at startup: creates upcoming monthly partitions
    // and drops partitions older than retention_months.
    if let Err(e) = cleanup::rotate_audit_log(&state.db, state.config.audit.retention_months).await
    {
        tracing::warn!(error = ?e, "audit log partition rotation failed at startup");
    }

    cleanup::spawn_cleanup_task(state.db.clone(), state.config.clone());
    let _relay = auth_api::services::events::spawn_relay(state.db.clone(), state.nats.clone());
    let nats = state.nats.clone();
    auth_api::utils::container_metrics::spawn();
    auth_api::utils::pool_metrics::spawn(
        state.db.clone(),
        state.config.database.max_connections,
        state.redis.clone(),
    );

    // Serve Prometheus metrics on a separate internal listener so the
    // exposition endpoint never sits behind the public reverse proxy.
    // docker-compose publishes this port on loopback only.
    let app = if state.config.metrics.enabled {
        let metrics_addr = format!("{}:{}", state.config.server.host, state.config.metrics.port);
        let (app, metrics_app) = handlers::router_with_metrics(state);

        let metrics_listener = tokio::net::TcpListener::bind(&metrics_addr).await?;
        tracing::info!("metrics listening on {}", metrics_addr);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(metrics_listener, metrics_app).await {
                tracing::error!(error = %e, "metrics server exited");
            }
        });

        app
    } else {
        handlers::router(state)
    };

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {}", addr);

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop_tx.send(true);
    });
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|stopped| *stopped).await;
    };

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stop_rx.clone()));

    // Phase 1: in-flight requests, bounded. Axum alone would wait forever.
    let deadline_rx = stop_rx;
    tokio::select! {
        result = server.into_future() => result?,
        () = async move {
            stopped(deadline_rx).await;
            tokio::time::sleep(REQUEST_DRAIN_TIMEOUT).await;
        } => {
            tracing::warn!(timeout = ?REQUEST_DRAIN_TIMEOUT, "requests still running at the shutdown deadline");
        }
    }

    // Phase 2: notifications and cache invalidations started by requests.
    let left = auth_api::utils::background::drain(BACKGROUND_DRAIN_TIMEOUT).await;
    if left > 0 {
        tracing::warn!(left, "background tasks cut off at shutdown");
    }

    // Phase 3: events the NATS client still buffers.
    match tokio::time::timeout(NATS_FLUSH_TIMEOUT, nats.flush()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "NATS events not flushed at shutdown"),
        Err(_) => tracing::warn!("flushing NATS events timed out at shutdown"),
    }

    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received Ctrl+C, starting graceful shutdown"),
        () = terminate => tracing::info!("received SIGTERM, starting graceful shutdown"),
    }
}

/// Hit the local `/live` endpoint and return a process exit code.
/// Reads `SERVER_PORT` (defaults to 3000) so the healthcheck honours
/// custom port overrides without requiring a full Config load.
/// Returns 0 on a 2xx response, 1 otherwise (including timeouts and
/// connection errors).
async fn run_healthcheck() -> i32 {
    let port = std::env::var("SERVER_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(3000);
    let url = format!("http://127.0.0.1:{port}/live");

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return 1,
    };

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => 0,
        _ => 1,
    }
}

fn init_tracing(cfg: &auth_api::config::LogConfig) {
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

    let filter = EnvFilter::try_new(&cfg.level).unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(filter);

    match cfg.format {
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json())
            .init(),
        LogFormat::Pretty => registry
            .with(tracing_subscriber::fmt::layer().pretty())
            .init(),
    }
}
