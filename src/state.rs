//! Application state shared across all request handlers.
//!
//! AppState is initialized once at startup and injected into every route
//! via Axum's State extractor. All fields are cheap to clone since they
//! are Arc-backed internally (PgPool, RedisPool, Mailer, Arc<Config>).
//! Tera is wrapped in Arc because it does not implement Clone.
//!
//! The clock and the mail transport are trait objects: the service runs with
//! the wall clock and SMTP, and the test suites replace both on a built state.

use std::{sync::Arc, time::Duration};

use reqwest::Client;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tera::Tera;

use jsonwebtoken::{DecodingKey, EncodingKey};

use crate::{
    config::{CaptchaConfig, Config, ConfigError, DatabaseConfig, MailConfig},
    services::mailer::SmtpMailer,
    utils::{
        crypto, jwt,
        redis_pool::{self, RedisPool},
        time::{Clock, SystemClock},
    },
};

pub use crate::services::mailer::Mailer;

// Error

#[derive(Debug, thiserror::Error)]
pub enum AppStateError {
    #[error("invalid configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("database pool error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("redis pool error: {0}")]
    Redis(String),
    #[error("smtp transport error: {0}")]
    Smtp(#[from] lettre::transport::smtp::Error),
    #[error("nats connection error: {0}")]
    Nats(#[from] async_nats::ConnectError),
    #[error("nats stream setup error: {0}")]
    NatsStream(String),
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
    pub clock: Arc<dyn Clock>,
    pub mailer: Mailer,
    pub http_client: Client,
    pub templates: Arc<Tera>,
    /// Keys for secrets encrypted at rest (TOTP seeds), decoded once.
    pub keyring: Arc<crypto::Keyring>,
    pub config: Arc<Config>,
    pub jwt_signing_key: EncodingKey,
    pub jwt_verifying_key: DecodingKey,
    /// Every key an access token may be verified with, by `kid`: current, next
    /// (published ahead of a rotation) and previous.
    pub jwt_verifying_keys: Arc<jwt::VerifyingKeys>,
    pub jwt_kid: String,
    /// JWKS document served at /.well-known/jwks.json, precomputed at startup
    /// (current key first, previous key appended during rotation windows).
    pub jwt_jwks: Arc<serde_json::Value>,
}

/// JWT key material parsed once at startup.
struct JwtKeys {
    signing_key: EncodingKey,
    verifying_key: DecodingKey,
    verifying_keys: jwt::VerifyingKeys,
    kid: String,
    jwks: Arc<serde_json::Value>,
}

impl AppState {
    /// Build the application state by initializing all connection pools and services.
    /// Fails fast if any dependency is unreachable or misconfigured.
    pub async fn from_config(mut config: Config) -> Result<Self, AppStateError> {
        prepare_config(&mut config)?;
        let db = build_pg_pool(&config.database).await?;
        Self::assemble(config, db).await
    }

    /// Build the application state with an existing database pool.
    /// Used in integration tests where the pool is created and migrated externally.
    pub async fn from_config_with_pool(
        mut config: Config,
        db: PgPool,
    ) -> Result<Self, AppStateError> {
        prepare_config(&mut config)?;
        Self::assemble(config, db).await
    }

    /// Connect every remaining dependency around a prepared, validated config.
    async fn assemble(config: Config, db: PgPool) -> Result<Self, AppStateError> {
        let redis = redis_pool::build(&config.redis).map_err(AppStateError::Redis)?;
        let nats = connect_nats(&config.nats.url).await?;
        // Declared now when the broker is up; otherwise before the first
        // durable publish (account deletion).
        match tokio::time::timeout(
            Duration::from_secs(5),
            crate::services::events::ensure_user_stream_once(&nats),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "user event stream not declared at startup"),
            Err(_) => tracing::warn!("user event stream declaration timed out at startup"),
        }
        let mailer = Mailer::new(SmtpMailer::from_config(&config.mail.smtp)?);
        let http_client = build_http_client(&config.captcha)?;
        let templates = Arc::new(build_templates(&config.mail)?);
        let jwt_keys = parse_jwt_keys(&config)?;
        let keyring = crypto::Keyring::from_base64(
            &config.crypto.encryption_key,
            config.crypto.previous_encryption_key.as_deref(),
        )
        .map(Arc::new)
        .map_err(|e| {
            AppStateError::Config(ConfigError::Invalid {
                key: "ENCRYPTION_KEY".into(),
                reason: e.to_string(),
            })
        })?;

        Ok(Self {
            db,
            redis,
            nats,
            clock: Arc::new(SystemClock),
            mailer,
            http_client,
            templates,
            keyring,
            jwt_signing_key: jwt_keys.signing_key,
            jwt_verifying_key: jwt_keys.verifying_key,
            jwt_verifying_keys: Arc::new(jwt_keys.verifying_keys),
            jwt_kid: jwt_keys.kid,
            jwt_jwks: jwt_keys.jwks,
            config: Arc::new(config),
        })
    }
}

/// Connect to NATS.
///
/// A broker that refuses the credentials stops the start: that is a
/// configuration error. A broker that cannot be reached does not: only account
/// deletion needs it, so the client keeps connecting in the background and
/// `/ready` reports it. async-nats ignores credentials inside the URL, so they
/// are given apart.
async fn connect_nats(url: &str) -> Result<async_nats::Client, AppStateError> {
    use crate::utils::nats;

    let (address, credentials) = nats::split_credentials(url).map_err(|reason| {
        AppStateError::Config(ConfigError::Invalid {
            key: "NATS_URL".into(),
            reason,
        })
    })?;

    match nats::connect_options(credentials.clone())
        .connect(address.as_str())
        .await
    {
        Ok(client) => Ok(client),
        Err(e)
            if matches!(
                e.kind(),
                async_nats::ConnectErrorKind::Authentication
                    | async_nats::ConnectErrorKind::AuthorizationViolation
            ) =>
        {
            Err(AppStateError::Nats(e))
        }
        Err(e) => {
            tracing::warn!(address, error = %e, "NATS unreachable at startup; connecting in the background");
            Ok(nats::connect_options(credentials)
                .retry_on_initial_connect()
                .connect(address.as_str())
                .await?)
        }
    }
}

/// Derive computed values, then validate the configuration exactly once.
///
/// auth-api's own public URL is added to the JWT audience before validation so
/// a production deployment without downstream audiences still boots.
fn prepare_config(config: &mut Config) -> Result<(), ConfigError> {
    config.ensure_self_in_audience();
    config.validate()
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
    // The JWKS lists the current key, then the next one (published ahead of a
    // rotation, before anything is signed with it), then the previous one
    // (until the tokens it signed have expired).
    let mut jwks_keys = vec![jwt::public_key_to_jwk(&p256_key, &kid)];
    let mut verifying = vec![(kid.clone(), verifying_key.clone())];
    for (variable, pem) in [
        ("JWT_NEXT_PUBLIC_KEY", config.jwt.next_public_key.as_deref()),
        (
            "JWT_PREVIOUS_PUBLIC_KEY",
            config.jwt.previous_public_key.as_deref(),
        ),
    ] {
        let Some(pem) = pem else { continue };
        let key = jwt::parse_verifying_key(pem).map_err(|e| invalid(variable, e))?;
        let p256 = jwt::parse_p256_verifying_key(pem).map_err(|e| invalid(variable, e))?;
        let extra_kid = jwt::compute_kid(&p256);
        if verifying.iter().any(|(held, _)| *held == extra_kid) {
            continue;
        }
        jwks_keys.push(jwt::public_key_to_jwk(&p256, &extra_kid));
        verifying.push((extra_kid, key));
    }

    Ok(JwtKeys {
        signing_key,
        verifying_key,
        verifying_keys: jwt::VerifyingKeys::new(verifying),
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
