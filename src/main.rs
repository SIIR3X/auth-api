use auth_api::{
    config::{Config, LogFormat},
    handlers,
    services::{cleanup, key_rotation},
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Healthcheck mode: hit the local /health endpoint and exit 0/1.
    // Designed for `HEALTHCHECK CMD ["./auth-api", "--healthcheck"]` in the
    // runtime image so we don't have to ship `curl`/`wget` in the slim base.
    // Handled BEFORE Config::from_env so a misconfigured env doesn't make the
    // healthcheck explode (it just talks HTTP to localhost).
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(run_healthcheck().await);
    }

    let config = Config::from_env().expect("failed to load config");

    init_tracing(&config.log);

    // One-off command: re-encrypt all TOTP secrets with the new key.
    // Set PREVIOUS_ENCRYPTION_KEY=<old> ENCRYPTION_KEY=<new>, run, then remove PREVIOUS_ENCRYPTION_KEY.
    if std::env::args().any(|a| a == "--rotate-totp-keys") {
        let state = AppState::from_config(config).await?;
        let result = key_rotation::rotate_totp_encryption_key(&state)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        tracing::info!(
            rotated = result.rotated,
            failed = result.failed,
            "TOTP key rotation complete"
        );
        if result.failed > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    let addr = format!("{}:{}", config.server.host, config.server.port);

    let state = AppState::from_config(config).await?;

    // Rotate audit log partitions at startup: creates upcoming monthly partitions
    // and drops partitions older than retention_months.
    if let Err(e) = rotate_audit_log(&state.db, state.config.audit.retention_months).await {
        tracing::warn!(error = ?e, "audit log partition rotation failed at startup");
    }

    cleanup::spawn_cleanup_task(state.db.clone(), state.config.clone());

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

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

async fn rotate_audit_log(db: &sqlx::PgPool, retention_months: u32) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT rotate_audit_log_partitions($1)")
        .bind(retention_months as i32)
        .execute(db)
        .await?;
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

/// Hit the local `/health` endpoint and return a process exit code.
/// Reads `SERVER_PORT` (defaults to 3000) so the healthcheck honours
/// custom port overrides without requiring a full Config load.
/// Returns 0 on a 2xx response, 1 otherwise (including timeouts and
/// connection errors).
async fn run_healthcheck() -> i32 {
    let port = std::env::var("SERVER_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(3000);
    let url = format!("http://127.0.0.1:{port}/health");

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
