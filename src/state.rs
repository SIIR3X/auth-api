//! Application state shared across all request handlers.
//!
//! AppState is initialized once at startup and injected into every route
//! via Axum's State extractor. All fields are cheap to clone since they
//! are Arc-backed internally (PgPool, RedisPool, Mailer, Arc<Config>).
//! Tera is wrapped in Arc because it does not implement Clone.

use std::{sync::Arc, time::Duration};

use deadpool_redis::{Config as RedisPoolConfig, Pool as RedisPool, Runtime};
use lettre::{AsyncSmtpTransport, Tokio1Executor, transport::smtp::authentication::Credentials};
use reqwest::Client;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tera::Tera;

use crate::{
    config::{
        CaptchaConfig, Config, ConfigError, DatabaseConfig, MailConfig, RedisConfig, SmtpConfig,
    },
    utils::geoip::GeoIp,
};

// Convenience alias used across services
pub type Mailer = AsyncSmtpTransport<Tokio1Executor>;

// Error

#[derive(Debug, thiserror::Error)]
pub enum AppStateError {
    #[error("invalid configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("database pool error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("redis pool error: {0}")]
    Redis(#[from] deadpool_redis::CreatePoolError),
    #[error("smtp transport error: {0}")]
    Smtp(#[from] lettre::transport::smtp::Error),
    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("template engine error: {0}")]
    Templates(#[from] tera::Error),
}

// State

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: RedisPool,
    pub mailer: Mailer,
    pub http_client: Client,
    pub templates: Arc<Tera>,
    pub config: Arc<Config>,
    pub geoip: GeoIp,
}

impl AppState {
    /// Build the application state by initializing all connection pools and services.
    /// Fails fast if any dependency is unreachable or misconfigured.
    pub async fn from_config(config: Config) -> Result<Self, AppStateError> {
        config.validate()?;

        let db = build_pg_pool(&config.database).await?;
        let redis = build_redis_pool(&config.redis)?;
        let mailer = build_mailer(&config.mail.smtp)?;
        let http_client = build_http_client(&config.captcha)?;
        let templates = Arc::new(build_templates(&config.mail)?);
        let geoip = GeoIp::open(&config.risk.geoip_db_path);

        if config.risk.geoip_required && !geoip.is_available() {
            return Err(AppStateError::Config(ConfigError::Invalid {
                key: "GEOIP_DB_PATH".into(),
                reason: "GeoIP database is required but could not be loaded".into(),
            }));
        }

        Ok(Self {
            db,
            redis,
            mailer,
            http_client,
            templates,
            geoip,
            config: Arc::new(config),
        })
    }

    /// Build the application state with an existing database pool.
    /// Used in integration tests where the pool is created and migrated externally.
    pub async fn from_config_with_pool(config: Config, db: PgPool) -> Result<Self, AppStateError> {
        config.validate()?;

        let redis = build_redis_pool(&config.redis)?;
        let mailer = build_mailer(&config.mail.smtp)?;
        let http_client = build_http_client(&config.captcha)?;
        let templates = Arc::new(build_templates(&config.mail)?);
        let geoip = GeoIp::open(&config.risk.geoip_db_path);

        if config.risk.geoip_required && !geoip.is_available() {
            return Err(AppStateError::Config(ConfigError::Invalid {
                key: "GEOIP_DB_PATH".into(),
                reason: "GeoIP database is required but could not be loaded".into(),
            }));
        }

        Ok(Self {
            db,
            redis,
            mailer,
            http_client,
            templates,
            geoip,
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

    let mut pool_config = deadpool_redis::PoolConfig {
        max_size: cfg.pool_size as usize,
        ..Default::default()
    };
    pool_config.timeouts.wait = Some(Duration::from_millis(cfg.wait_timeout_ms));

    pool_cfg.pool = Some(pool_config);
    pool_cfg.create_pool(Some(Runtime::Tokio1))
}

fn build_mailer(cfg: &SmtpConfig) -> Result<Mailer, lettre::transport::smtp::Error> {
    let creds = Credentials::new(cfg.username.clone(), cfg.password.clone());

    // Use plain (no TLS) transport for local dev (e.g. Mailpit on port 1025)
    // and STARTTLS for production SMTP servers
    let transport = if cfg.username.is_empty() {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host)
            .port(cfg.port)
            .build()
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?
            .port(cfg.port)
            .credentials(creds)
            .build()
    };

    Ok(transport)
}

fn build_http_client(cfg: &CaptchaConfig) -> Result<Client, reqwest::Error> {
    Client::builder()
        .connect_timeout(Duration::from_secs(cfg.request_timeout_secs))
        .timeout(Duration::from_secs(cfg.request_timeout_secs))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_state_error_display_config_variant() {
        let err = AppStateError::Config(crate::config::ConfigError::Missing("MY_KEY".into()));
        let msg = err.to_string();
        assert!(
            msg.contains("MY_KEY"),
            "display must mention the missing key"
        );
    }

    #[test]
    fn app_state_error_display_database_variant() {
        let err = AppStateError::Database(sqlx::Error::RowNotFound);
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }
}

/// Load all templates from `{templates_dir}/emails/**/*`.
/// Each template is addressable as "emails/{locale}/name.html".
fn build_templates(cfg: &MailConfig) -> Result<Tera, tera::Error> {
    // Pattern must start from templates_dir so Tera names templates relative to it.
    // e.g. with templates_dir="templates": "templates/**/*" -> "emails/en/verification.html"
    let pattern = format!("{}/**/*", cfg.templates_dir);
    Tera::new(&pattern)
}
