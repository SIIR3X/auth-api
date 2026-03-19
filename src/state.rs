//! Application state shared across all request handlers.
//!
//! AppState is initialized once at startup and injected into every route
//! via Axum's State extractor. All fields are cheap to clone since they
//! are Arc-backed internally (PgPool, RedisPool, Mailer, Arc<Config>).
//! Tera is wrapped in Arc because it does not implement Clone.

use std::{sync::Arc, time::Duration};

use deadpool_redis::{Config as RedisPoolConfig, Pool as RedisPool, Runtime};
use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, Tokio1Executor,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tera::Tera;

use crate::config::{Config, DatabaseConfig, MailConfig, RedisConfig, SmtpConfig};

// Convenience alias used across services
pub type Mailer = AsyncSmtpTransport<Tokio1Executor>;

// Error

#[derive(Debug, thiserror::Error)]
pub enum AppStateError {
    #[error("database pool error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("redis pool error: {0}")]
    Redis(#[from] deadpool_redis::CreatePoolError),
    #[error("smtp transport error: {0}")]
    Smtp(#[from] lettre::transport::smtp::Error),
    #[error("template engine error: {0}")]
    Templates(#[from] tera::Error),
}

// State

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: RedisPool,
    pub mailer: Mailer,
    pub templates: Arc<Tera>,
    pub config: Arc<Config>,
}

impl AppState {
    /// Build the application state by initializing all connection pools and services.
    /// Fails fast if any dependency is unreachable or misconfigured.
    pub async fn from_config(config: Config) -> Result<Self, AppStateError> {
        let db = build_pg_pool(&config.database).await?;
        let redis = build_redis_pool(&config.redis)?;
        let mailer = build_mailer(&config.mail.smtp)?;
        let templates = Arc::new(build_templates(&config.mail)?);

        Ok(Self {
            db,
            redis,
            mailer,
            templates,
            config: Arc::new(config),
        })
    }

    /// Build the application state with an existing database pool.
    /// Used in integration tests where the pool is created and migrated externally.
    pub async fn from_config_with_pool(config: Config, db: PgPool) -> Result<Self, AppStateError> {
        let redis = build_redis_pool(&config.redis)?;
        let mailer = build_mailer(&config.mail.smtp)?;
        let templates = Arc::new(build_templates(&config.mail)?);

        Ok(Self {
            db,
            redis,
            mailer,
            templates,
            config: Arc::new(config),
        })
    }
}

// Builders

async fn build_pg_pool(cfg: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .connect(&cfg.url)
        .await
}

fn build_redis_pool(cfg: &RedisConfig) -> Result<RedisPool, deadpool_redis::CreatePoolError> {
    let mut pool_cfg = RedisPoolConfig::from_url(&cfg.url);

    pool_cfg.pool = Some(deadpool_redis::PoolConfig {
        max_size: cfg.pool_size as usize,
        ..Default::default()
    });

    pool_cfg.create_pool(Some(Runtime::Tokio1))
}

fn build_mailer(cfg: &SmtpConfig) -> Result<Mailer, lettre::transport::smtp::Error> {
    let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());

    // starttls_relay returns a Result; the final .build() returns the transport directly
    let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?
        .port(cfg.port)
        .credentials(creds)
        .build();

    Ok(transport)
}

/// Load all templates from `{templates_dir}/emails/**/*`.
/// Each template is addressable as "emails/{locale}/name.html".
fn build_templates(cfg: &MailConfig) -> Result<Tera, tera::Error> {
    // Pattern must start from templates_dir so Tera names templates relative to it.
    // e.g. with templates_dir="templates": "templates/**/*" -> "emails/en/verification.html"
    let pattern = format!("{}/**/*", cfg.templates_dir);
    Tera::new(&pattern)
}
