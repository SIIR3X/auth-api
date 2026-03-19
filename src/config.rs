//! Application configuration.
//!
//! Loads all settings from environment variables at startup.
//! Required variables cause an early, explicit error if missing.
//! Optional variables fall back to safe, documented defaults.
//! Use `.env.example` as a reference for all available variables.

use std::{env, str::FromStr};

// Error

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(String),
    #[error("invalid value for '{key}': {reason}")]
    Invalid { key: String, reason: String },
}

// Environment

#[derive(Debug, Clone, PartialEq)]
pub enum Environment {
    Development,
    Production,
    Test,
}

impl FromStr for Environment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            "test" => Ok(Self::Test),
            _ => Err(format!("unknown environment: {s}")),
        }
    }
}

// Sub-configs

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Public-facing base URL used to build links in emails (e.g. "https://api.example.com").
    pub public_url: String,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Minimum idle connections kept alive.
    pub min_connections: u32,
    /// Seconds before a pending acquire is aborted.
    pub acquire_timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    /// Short-lived access token lifetime (default: 15 min).
    pub access_expiry_secs: u64,
    /// Long-lived refresh token lifetime (default: 30 days).
    pub refresh_expiry_secs: u64,
}

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    // Argon2id parameters, tune for your hardware
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    /// Issuer name shown in authenticator apps.
    pub totp_issuer: String,
    /// Base64-encoded 32-byte key used to encrypt TOTP secrets at rest with AES-256-GCM.
    pub encryption_key: String,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Max requests per window per IP.
    pub requests_per_second: u64,
    /// Burst allowance on top of the steady rate.
    pub burst_size: u32,
}

// Log

#[derive(Debug, Clone, PartialEq)]
pub enum LogFormat {
    /// Human-readable, coloured output for development.
    Pretty,
    /// Structured JSON output for production log aggregators.
    Json,
}

impl FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "pretty" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            _ => Err(format!("unknown log format: {s}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Directive passed to EnvFilter, e.g. "info" or "rust_api=debug,tower_http=info".
    pub level: String,
    pub format: LogFormat,
}

// Mail

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// Display name used in the From header.
    pub from_name: String,
    /// Email address used in the From header.
    pub from_address: String,
}

#[derive(Debug, Clone)]
pub struct MailConfig {
    pub smtp: SmtpConfig,
    /// Path to the templates directory, e.g. "templates".
    pub templates_dir: String,
    /// Locale used when no match is found for the user's preferred locale.
    pub default_locale: String,
}

// Root config

#[derive(Debug, Clone)]
pub struct Config {
    pub env: Environment,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub crypto: CryptoConfig,
    pub rate_limit: RateLimitConfig,
    pub mail: MailConfig,
    pub log: LogConfig,
}

impl Config {
    /// Load configuration from environment variables.
    /// Silently ignores a missing `.env` file; production relies on real env vars.
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        Ok(Self {
            env: env_parse("APP_ENV").unwrap_or(Environment::Development),
            server: ServerConfig {
                host: env_string("SERVER_HOST").unwrap_or_else(|| "0.0.0.0".into()),
                port: env_parse("SERVER_PORT").unwrap_or(3000u16),
                public_url: env_string("APP_PUBLIC_URL")
                    .unwrap_or_else(|| "http://localhost:3000".into()),
            },
            database: DatabaseConfig {
                url: env_require("DATABASE_URL")?,
                max_connections: env_parse("DB_MAX_CONNECTIONS").unwrap_or(20),
                min_connections: env_parse("DB_MIN_CONNECTIONS").unwrap_or(2),
                acquire_timeout_secs: env_parse("DB_ACQUIRE_TIMEOUT_SECS").unwrap_or(30),
            },
            redis: RedisConfig {
                url: env_require("REDIS_URL")?,
                pool_size: env_parse("REDIS_POOL_SIZE").unwrap_or(10),
            },
            jwt: JwtConfig {
                secret: env_require("JWT_SECRET")?,
                access_expiry_secs: env_parse("JWT_ACCESS_EXPIRY_SECS").unwrap_or(900),
                refresh_expiry_secs: env_parse("JWT_REFRESH_EXPIRY_SECS")
                    .unwrap_or(60 * 60 * 24 * 30),
            },
            crypto: CryptoConfig {
                argon2_memory_kib: env_parse("ARGON2_MEMORY_KIB").unwrap_or(65_536), // 64 MB
                argon2_iterations: env_parse("ARGON2_ITERATIONS").unwrap_or(3),
                argon2_parallelism: env_parse("ARGON2_PARALLELISM").unwrap_or(4),
                totp_issuer: env_string("TOTP_ISSUER").unwrap_or_else(|| "rust-api".into()),
                encryption_key: env_require("ENCRYPTION_KEY")?,
            },
            rate_limit: RateLimitConfig {
                requests_per_second: env_parse("RATE_LIMIT_RPS").unwrap_or(100),
                burst_size: env_parse("RATE_LIMIT_BURST").unwrap_or(50),
            },
            mail: MailConfig {
                smtp: SmtpConfig {
                    host: env_require("SMTP_HOST")?,
                    port: env_parse("SMTP_PORT").unwrap_or(587),
                    username: env_require("SMTP_USERNAME")?,
                    password: env_require("SMTP_PASSWORD")?,
                    from_name: env_string("SMTP_FROM_NAME")
                        .unwrap_or_else(|| "rust-api".into()),
                    from_address: env_require("SMTP_FROM_ADDRESS")?,
                },
                templates_dir: env_string("MAIL_TEMPLATES_DIR")
                    .unwrap_or_else(|| "templates".into()),
                default_locale: env_string("MAIL_DEFAULT_LOCALE")
                    .unwrap_or_else(|| "en".into()),
            },
            log: LogConfig {
                level: env_string("LOG_LEVEL").unwrap_or_else(|| "info".into()),
                format: env_parse("LOG_FORMAT").unwrap_or(LogFormat::Pretty),
            },
        })
    }

    pub fn is_production(&self) -> bool {
        self.env == Environment::Production
    }

    pub fn is_test(&self) -> bool {
        self.env == Environment::Test
    }
}

// Helpers

fn env_require(key: &str) -> Result<String, ConfigError> {
    env::var(key).map_err(|_| ConfigError::Missing(key.into()))
}

fn env_string(key: &str) -> Option<String> {
    env::var(key).ok()
}

// Parse an env var into any type that implements FromStr; returns None on missing or parse failure.
fn env_parse<T: FromStr>(key: &str) -> Option<T> {
    env::var(key).ok()?.parse().ok()
}
