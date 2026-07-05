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

use jsonwebtoken::{DecodingKey, EncodingKey};

use crate::{
    config::{
        CaptchaConfig, Config, ConfigError, DatabaseConfig, MailConfig, RedisConfig, SmtpConfig,
    },
    utils::{geoip::GeoIp, jwt},
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
    #[error("nats connection error: {0}")]
    Nats(#[from] async_nats::ConnectError),
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
    pub nats: async_nats::Client,
    pub mailer: Mailer,
    pub http_client: Client,
    pub templates: Arc<Tera>,
    pub config: Arc<Config>,
    pub geoip: GeoIp,
    pub jwt_signing_key: EncodingKey,
    pub jwt_verifying_key: DecodingKey,
    pub jwt_previous_verifying_key: Option<DecodingKey>,
    pub jwt_kid: String,
    /// JWKS document served at /.well-known/jwks.json, precomputed at startup
    /// (current key first, previous key appended during rotation windows).
    pub jwt_jwks: Arc<serde_json::Value>,
}

/// JWT key material parsed once at startup.
struct JwtKeys {
    signing_key: EncodingKey,
    verifying_key: DecodingKey,
    previous_verifying_key: Option<DecodingKey>,
    kid: String,
    jwks: Arc<serde_json::Value>,
}

impl AppState {
    /// Build the application state by initializing all connection pools and services.
    /// Fails fast if any dependency is unreachable or misconfigured.
    pub async fn from_config(mut config: Config) -> Result<Self, AppStateError> {
        // Auto-include auth-api's own public URL in the audience list so the
        // tokens it mints carry it. The `AuthenticatedUser` extractor then
        // pins `aud == public_url` defense-in-depth, rejecting tokens that
        // were addressed only to downstream resource servers.
        ensure_self_in_audience(&mut config);
        config.validate()?;

        let db = build_pg_pool(&config.database).await?;
        let redis = build_redis_pool(&config.redis)?;
        let nats = async_nats::connect(&config.nats.url).await?;
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

        let jwt_keys = parse_jwt_keys(&config)?;

        Ok(Self {
            db,
            redis,
            nats,
            mailer,
            http_client,
            templates,
            geoip,
            jwt_signing_key: jwt_keys.signing_key,
            jwt_verifying_key: jwt_keys.verifying_key,
            jwt_previous_verifying_key: jwt_keys.previous_verifying_key,
            jwt_kid: jwt_keys.kid,
            jwt_jwks: jwt_keys.jwks,
            config: Arc::new(config),
        })
    }

    /// Build the application state with an existing database pool.
    /// Used in integration tests where the pool is created and migrated externally.
    pub async fn from_config_with_pool(
        mut config: Config,
        db: PgPool,
    ) -> Result<Self, AppStateError> {
        ensure_self_in_audience(&mut config);
        config.validate()?;

        let redis = build_redis_pool(&config.redis)?;
        let nats = async_nats::connect(&config.nats.url).await?;
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

        let jwt_keys = parse_jwt_keys(&config)?;

        Ok(Self {
            db,
            redis,
            nats,
            mailer,
            http_client,
            templates,
            geoip,
            jwt_signing_key: jwt_keys.signing_key,
            jwt_verifying_key: jwt_keys.verifying_key,
            jwt_previous_verifying_key: jwt_keys.previous_verifying_key,
            jwt_kid: jwt_keys.kid,
            jwt_jwks: jwt_keys.jwks,
            config: Arc::new(config),
        })
    }
}

/// Make sure auth-api's own `public_url` is part of the JWT audience list.
///
/// auth-api emits `aud=[downstream_url, ...]` so tokens can be accepted by
/// downstream resource servers (core-api, billing-api, ...). But auth-api
/// also consumes its own tokens for `/users/me/*` routes, and we now pin
/// `aud == public_url` defense-in-depth in the `AuthenticatedUser` extractor.
/// Without this auto-injection the token wouldn't satisfy that check.
///
/// Idempotent: if `public_url` is already configured in `JWT_AUDIENCE`,
/// nothing changes.
fn ensure_self_in_audience(config: &mut Config) {
    let self_url = config.server.public_url.clone();
    if self_url.is_empty() {
        return;
    }
    if !config.jwt.audience.iter().any(|a| a == &self_url) {
        config.jwt.audience.push(self_url);
    }
}

// JWT key parsing

fn parse_jwt_keys(config: &Config) -> Result<JwtKeys, AppStateError> {
    let invalid = |key: &str, e: jwt::JwtError| {
        AppStateError::Config(ConfigError::Invalid {
            key: key.into(),
            reason: e.to_string(),
        })
    };

    let signing_key = jwt::parse_encoding_key(&config.jwt.private_key)
        .map_err(|e| invalid("JWT_PRIVATE_KEY", e))?;
    let verifying_key = jwt::parse_verifying_key(&config.jwt.public_key)
        .map_err(|e| invalid("JWT_PUBLIC_KEY", e))?;

    // The p256 representation is only needed at startup, to derive the kid and
    // build the JWKS document served at /.well-known/jwks.json.
    let p256_key = jwt::parse_p256_verifying_key(&config.jwt.public_key)
        .map_err(|e| invalid("JWT_PUBLIC_KEY", e))?;
    let kid = jwt::compute_kid(&p256_key);
    let mut jwks_keys = vec![jwt::public_key_to_jwk(&p256_key, &kid)];

    let previous_verifying_key = if let Some(ref prev_pem) = config.jwt.previous_public_key {
        let prev_key = jwt::parse_verifying_key(prev_pem)
            .map_err(|e| invalid("JWT_PREVIOUS_PUBLIC_KEY", e))?;
        let prev_p256 = jwt::parse_p256_verifying_key(prev_pem)
            .map_err(|e| invalid("JWT_PREVIOUS_PUBLIC_KEY", e))?;
        jwks_keys.push(jwt::public_key_to_jwk(
            &prev_p256,
            &jwt::compute_kid(&prev_p256),
        ));
        Some(prev_key)
    } else {
        None
    };

    Ok(JwtKeys {
        signing_key,
        verifying_key,
        previous_verifying_key,
        kid,
        jwks: Arc::new(serde_json::json!({ "keys": jwks_keys })),
    })
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

/// Load all templates from `{templates_dir}/emails/**/*`.
/// Each template is addressable as "emails/{locale}/name.html".
fn build_templates(cfg: &MailConfig) -> Result<Tera, tera::Error> {
    // Pattern must start from templates_dir so Tera names templates relative to it.
    // e.g. with templates_dir="templates": "templates/**/*" -> "emails/en/verification.html"
    let pattern = format!("{}/**/*", cfg.templates_dir);
    let mut tera = Tera::new();
    tera.load_from_glob(&pattern)?;
    Ok(tera)
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
