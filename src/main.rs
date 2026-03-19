mod config;
mod domain;
mod error;
mod handlers;
mod middleware;
mod repositories;
mod services;
mod state;
mod utils;

use config::{Config, LogFormat};
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env().expect("failed to load config");

    init_tracing(&config.log);

    let addr = format!("{}:{}", config.server.host, config.server.port);

    let state = AppState::from_config(config).await?;
    let app = handlers::router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing(cfg: &config::LogConfig) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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
