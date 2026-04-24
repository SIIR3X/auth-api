use auth_api::{
    config::{Config, LogFormat},
    handlers,
    services::{cleanup, key_rotation},
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let app = handlers::router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn rotate_audit_log(db: &sqlx::PgPool, retention_months: u32) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT rotate_audit_log_partitions($1)")
        .bind(retention_months as i32)
        .execute(db)
        .await?;
    Ok(())
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
