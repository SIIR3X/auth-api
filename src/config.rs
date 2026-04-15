//! Application configuration.
//!
//! Loads all settings from environment variables at startup.
//! Required variables cause an early, explicit error if missing.
//! Optional variables fall back to safe, documented defaults.
//! Use `.env.example` as a reference for all available variables.

use std::{env, path::Path, str::FromStr};

use base64::{Engine, engine::general_purpose::STANDARD};
use ipnetwork::IpNetwork;

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
    /// Reverse-proxy CIDRs allowed to supply X-Forwarded-For / X-Real-IP.
    /// Requests coming from other peers use the socket address directly.
    pub trusted_proxy_cidrs: Vec<IpNetwork>,
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
    /// Maximum time in milliseconds to wait for a connection from the pool.
    /// Prevents unbounded queue buildup under Redis pressure. Default: 2000ms.
    pub wait_timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    /// Previous signing secret, accepted for token verification only (not used for signing).
    /// Set to the old JWT_SECRET value before rotating; remove after all old tokens expire.
    pub previous_secret: Option<String>,
    /// Short-lived access token lifetime (default: 15 min).
    pub access_expiry_secs: u64,
    /// Long-lived refresh token lifetime (default: 30 days).
    pub refresh_expiry_secs: u64,
    /// When true, the refresh endpoint rejects requests whose IP differs from the
    /// one recorded at session creation. Useful for high-security deployments but
    /// breaks clients that roam between networks (e.g. mobile).
    pub strict_session_binding: bool,
    /// Hard upper bound on session lifetime regardless of refresh activity (default: 90 days).
    pub max_session_lifetime_secs: u64,
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
    /// Previous encryption key used only during key rotation (`--rotate-totp-keys`).
    /// Set this to the old key value before running the rotation command, then remove it afterward.
    pub previous_encryption_key: Option<String>,
    /// Number of 30-second steps to accept before and after the current one.
    /// 1 = accept codes within +/- 30 seconds (recommended for clock skew tolerance).
    pub totp_skew: u8,
    /// Lifetime of recovery codes in days. 0 = no expiration.
    pub recovery_code_expiry_days: u32,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Max requests per 1-minute window per IP for general routes.
    pub requests_per_minute: u64,
    /// Stricter limit for authentication routes (login, register, forgot-password, 2FA).
    /// Defaults to 20 requests per minute.
    pub auth_requests_per_minute: u64,
    /// When true, Redis outages do not block traffic and the request is allowed through.
    pub fail_open_on_redis_error: bool,
    /// When true, requests with no resolved client IP are allowed through.
    pub allow_requests_without_ip: bool,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Number of consecutive login failures before the account is temporarily locked.
    pub lockout_threshold: u32,
    /// Duration of the account lockout in seconds (default: 1800 = 30 minutes).
    pub lockout_duration_secs: u64,
    /// TTL of the "recent re-authentication" window for sensitive actions.
    pub sensitive_action_reauth_secs: u64,
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

// Risk scoring

#[derive(Debug, Clone)]
pub struct RiskConfig {
    /// Path to the MaxMind GeoLite2-City.mmdb file.
    /// If empty or the file is absent, geolocation signals are skipped (fail open).
    pub geoip_db_path: String,
    /// When true, the API refuses to start unless the GeoIP database is available.
    pub geoip_required: bool,
    /// Score threshold above which an alert email is sent to the user (default: 30).
    pub alert_threshold: u32,
    /// Score threshold above which 2FA is enforced even without TOTP configured (default: 60).
    pub challenge_threshold: u32,
    /// Score threshold above which the login is blocked entirely (default: 80).
    pub block_threshold: u32,
    /// Number of days of location history to consider when computing "new country/city" (default: 90).
    pub history_days: u32,
}

// WebAuthn

#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Relying Party ID, usually the domain name (e.g. "example.com").
    pub rp_id: String,
    /// Relying Party origin, full URL (e.g. "https://example.com").
    pub rp_origin: String,
    /// Displayed name for the relying party in authenticator dialogs.
    pub rp_name: String,
}

// Audit

#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Number of months of audit log data to retain. Older monthly partitions are dropped.
    /// The database function rotate_audit_log_partitions() enforces this at startup and
    /// nightly via pg_cron (if available). 0 = keep forever.
    pub retention_months: u32,
}

// CAPTCHA

#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    /// hCaptcha secret key. If empty, captcha verification is skipped (development/test mode).
    pub secret: Option<String>,
    /// hCaptcha verify endpoint.
    pub verify_url: String,
    /// Request timeout for the verification call.
    pub request_timeout_secs: u64,
    /// When true, network/5xx errors from the CAPTCHA provider allow the request through.
    pub fail_open_on_error: bool,
}

// CORS

#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Comma-separated list of allowed origins, e.g. "https://app.example.com,https://admin.example.com".
    /// Use "*" to allow all origins (not recommended in production).
    pub allowed_origins: Vec<String>,
    /// Whether to allow credentials (cookies, Authorization header).
    pub allow_credentials: bool,
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
    pub security: SecurityConfig,
    pub mail: MailConfig,
    pub cors: CorsConfig,
    pub captcha: CaptchaConfig,
    pub audit: AuditConfig,
    pub risk: RiskConfig,
    pub webauthn: WebAuthnConfig,
    pub log: LogConfig,
}

impl Config {
    /// Load configuration from environment variables.
    /// Silently ignores a missing `.env` file; production relies on real env vars.
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let env = env_parse("APP_ENV").unwrap_or(Environment::Development);

        let is_production = matches!(env, Environment::Production);

        let config = Self {
            env: env.clone(),
            server: ServerConfig {
                host: env_string("SERVER_HOST").unwrap_or_else(|| "0.0.0.0".into()),
                port: env_parse("SERVER_PORT").unwrap_or(3000u16),
                public_url: env_string("APP_PUBLIC_URL")
                    .unwrap_or_else(|| "http://localhost:3000".into()),
                trusted_proxy_cidrs: env_ip_network_list("TRUSTED_PROXY_CIDRS")?,
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
                wait_timeout_ms: env_parse("REDIS_WAIT_TIMEOUT_MS").unwrap_or(2000),
            },
            jwt: JwtConfig {
                secret: env_require("JWT_SECRET")?,
                previous_secret: env_string("JWT_PREVIOUS_SECRET"),
                access_expiry_secs: env_parse("JWT_ACCESS_EXPIRY_SECS").unwrap_or(900),
                refresh_expiry_secs: env_parse("JWT_REFRESH_EXPIRY_SECS")
                    .unwrap_or(60 * 60 * 24 * 30),
                strict_session_binding: env_parse("JWT_STRICT_SESSION_BINDING").unwrap_or(false),
                max_session_lifetime_secs: env_parse("JWT_MAX_SESSION_LIFETIME_SECS")
                    .unwrap_or(60 * 60 * 24 * 90),
            },
            crypto: CryptoConfig {
                argon2_memory_kib: env_parse("ARGON2_MEMORY_KIB").unwrap_or(65_536), // 64 MB
                argon2_iterations: env_parse("ARGON2_ITERATIONS").unwrap_or(3),
                argon2_parallelism: env_parse("ARGON2_PARALLELISM").unwrap_or(4),
                totp_issuer: env_string("TOTP_ISSUER").unwrap_or_else(|| "rust-api".into()),
                encryption_key: env_require("ENCRYPTION_KEY")?,
                previous_encryption_key: env_string("PREVIOUS_ENCRYPTION_KEY"),
                totp_skew: env_parse("TOTP_SKEW").unwrap_or(1),
                recovery_code_expiry_days: env_parse("RECOVERY_CODE_EXPIRY_DAYS").unwrap_or(365),
            },
            rate_limit: RateLimitConfig {
                requests_per_minute: env_parse("RATE_LIMIT_RPM").unwrap_or(300),
                auth_requests_per_minute: env_parse("RATE_LIMIT_AUTH_RPM").unwrap_or(20),
                fail_open_on_redis_error: env_parse("RATE_LIMIT_FAIL_OPEN")
                    .unwrap_or(!is_production),
                allow_requests_without_ip: env_parse("RATE_LIMIT_ALLOW_MISSING_IP")
                    .unwrap_or(!is_production),
            },
            security: SecurityConfig {
                lockout_threshold: env_parse("LOCKOUT_THRESHOLD").unwrap_or(10),
                lockout_duration_secs: env_parse("LOCKOUT_DURATION_SECS").unwrap_or(1800),
                sensitive_action_reauth_secs: env_parse("SENSITIVE_ACTION_REAUTH_SECS")
                    .unwrap_or(600),
            },
            mail: MailConfig {
                smtp: SmtpConfig {
                    host: env_require("SMTP_HOST")?,
                    port: env_parse("SMTP_PORT").unwrap_or(587),
                    username: env_require("SMTP_USERNAME")?,
                    password: env_require("SMTP_PASSWORD")?,
                    from_name: env_string("SMTP_FROM_NAME").unwrap_or_else(|| "rust-api".into()),
                    from_address: env_require("SMTP_FROM_ADDRESS")?,
                },
                templates_dir: env_string("MAIL_TEMPLATES_DIR")
                    .unwrap_or_else(|| "templates".into()),
                default_locale: env_string("MAIL_DEFAULT_LOCALE").unwrap_or_else(|| "en".into()),
            },
            captcha: CaptchaConfig {
                secret: env_string("CAPTCHA_SECRET"),
                verify_url: env_string("CAPTCHA_VERIFY_URL")
                    .unwrap_or_else(|| "https://hcaptcha.com/siteverify".into()),
                request_timeout_secs: env_parse("CAPTCHA_TIMEOUT_SECS").unwrap_or(5),
                fail_open_on_error: env_parse("CAPTCHA_FAIL_OPEN").unwrap_or(!is_production),
            },
            cors: CorsConfig {
                allowed_origins: env_string("CORS_ALLOWED_ORIGINS")
                    .unwrap_or_else(|| "http://localhost:3000".into())
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .collect(),
                allow_credentials: env_parse("CORS_ALLOW_CREDENTIALS").unwrap_or(true),
            },
            audit: AuditConfig {
                retention_months: env_parse("AUDIT_LOG_RETENTION_MONTHS").unwrap_or(12),
            },
            risk: RiskConfig {
                geoip_db_path: env_string("GEOIP_DB_PATH").unwrap_or_default(),
                geoip_required: env_parse("GEOIP_REQUIRED").unwrap_or(false),
                alert_threshold: env_parse("RISK_ALERT_THRESHOLD").unwrap_or(30),
                challenge_threshold: env_parse("RISK_CHALLENGE_THRESHOLD").unwrap_or(60),
                block_threshold: env_parse("RISK_BLOCK_THRESHOLD").unwrap_or(80),
                history_days: env_parse("RISK_HISTORY_DAYS").unwrap_or(90),
            },
            webauthn: WebAuthnConfig {
                rp_id: env_string("WEBAUTHN_RP_ID").unwrap_or_else(|| "localhost".into()),
                rp_origin: env_string("WEBAUTHN_RP_ORIGIN")
                    .unwrap_or_else(|| "http://localhost:3000".into()),
                rp_name: env_string("WEBAUTHN_RP_NAME").unwrap_or_else(|| "rust-api".into()),
            },
            log: LogConfig {
                level: env_string("LOG_LEVEL").unwrap_or_else(|| "info".into()),
                format: env_parse("LOG_FORMAT").unwrap_or(LogFormat::Pretty),
            },
        };

        config.validate()?;

        Ok(config)
    }

    pub fn is_production(&self) -> bool {
        self.env == Environment::Production
    }

    pub fn is_test(&self) -> bool {
        self.env == Environment::Test
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_jwt_secret(&self.jwt.secret)?;
        validate_optional_jwt_secret(self.jwt.previous_secret.as_deref())?;
        validate_encryption_key("ENCRYPTION_KEY", &self.crypto.encryption_key)?;
        validate_optional_encryption_key(
            "PREVIOUS_ENCRYPTION_KEY",
            self.crypto.previous_encryption_key.as_deref(),
        )?;
        validate_cors(&self.cors, self.is_production())?;
        validate_risk(&self.risk)?;
        validate_webauthn(&self.webauthn)?;
        validate_security(&self.security)?;

        if self.is_production() {
            validate_https_url("APP_PUBLIC_URL", &self.server.public_url)?;
            validate_https_url("WEBAUTHN_RP_ORIGIN", &self.webauthn.rp_origin)?;

            if self.captcha.secret.is_some() {
                validate_https_url("CAPTCHA_VERIFY_URL", &self.captcha.verify_url)?;
            }

            if self.mail.smtp.username.is_empty() {
                return Err(ConfigError::Invalid {
                    key: "SMTP_USERNAME".into(),
                    reason: "must not be empty in production (unauthenticated/unencrypted SMTP is not allowed)".into(),
                });
            }
        }

        Ok(())
    }
}

// Helpers

fn env_require(key: &str) -> Result<String, ConfigError> {
    env::var(key).map_err(|_| ConfigError::Missing(key.into()))
}

fn env_string(key: &str) -> Option<String> {
    env::var(key).ok()
}

fn env_csv(key: &str) -> Option<Vec<String>> {
    let value = env::var(key).ok()?;
    let values = value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    Some(values)
}

fn env_ip_network_list(key: &str) -> Result<Vec<IpNetwork>, ConfigError> {
    env_csv(key)
        .unwrap_or_default()
        .into_iter()
        .map(|raw| {
            raw.parse::<IpNetwork>().map_err(|e| ConfigError::Invalid {
                key: key.into(),
                reason: format!("invalid CIDR '{raw}': {e}"),
            })
        })
        .collect()
}

// Parse an env var into any type that implements FromStr; returns None on missing or parse failure.
fn env_parse<T: FromStr>(key: &str) -> Option<T> {
    env::var(key).ok()?.parse().ok()
}

fn validate_jwt_secret(secret: &str) -> Result<(), ConfigError> {
    if secret.len() < 32 {
        return Err(ConfigError::Invalid {
            key: "JWT_SECRET".into(),
            reason: "must be at least 32 characters long".into(),
        });
    }

    let unique_chars = secret.chars().collect::<std::collections::HashSet<_>>().len();
    if unique_chars < 10 {
        return Err(ConfigError::Invalid {
            key: "JWT_SECRET".into(),
            reason: "secret has insufficient entropy: use a random value (e.g. openssl rand -hex 32)".into(),
        });
    }

    Ok(())
}

fn validate_optional_jwt_secret(secret: Option<&str>) -> Result<(), ConfigError> {
    if let Some(secret) = secret {
        validate_jwt_secret(secret)?;
    }

    Ok(())
}

fn validate_encryption_key(key_name: &str, value: &str) -> Result<(), ConfigError> {
    let decoded = STANDARD.decode(value).map_err(|e| ConfigError::Invalid {
        key: key_name.into(),
        reason: format!("must be valid base64: {e}"),
    })?;

    if decoded.len() != 32 {
        return Err(ConfigError::Invalid {
            key: key_name.into(),
            reason: "must decode to exactly 32 bytes".into(),
        });
    }

    Ok(())
}

fn validate_optional_encryption_key(
    key_name: &str,
    value: Option<&str>,
) -> Result<(), ConfigError> {
    if let Some(value) = value {
        validate_encryption_key(key_name, value)?;
    }

    Ok(())
}

fn validate_https_url(key: &str, value: &str) -> Result<(), ConfigError> {
    if !value.starts_with("https://") {
        return Err(ConfigError::Invalid {
            key: key.into(),
            reason: "must use https in production".into(),
        });
    }

    Ok(())
}

fn validate_security(security: &SecurityConfig) -> Result<(), ConfigError> {
    if security.sensitive_action_reauth_secs == 0 {
        return Err(ConfigError::Invalid {
            key: "SENSITIVE_ACTION_REAUTH_SECS".into(),
            reason: "must be greater than 0".into(),
        });
    }

    Ok(())
}

fn validate_cors(cors: &CorsConfig, is_production: bool) -> Result<(), ConfigError> {
    if cors.allowed_origins.is_empty() {
        return Err(ConfigError::Invalid {
            key: "CORS_ALLOWED_ORIGINS".into(),
            reason: "must not be empty".into(),
        });
    }

    let has_wildcard = cors.allowed_origins.iter().any(|origin| origin == "*");
    if has_wildcard && cors.allow_credentials {
        return Err(ConfigError::Invalid {
            key: "CORS_ALLOWED_ORIGINS".into(),
            reason: "cannot use '*' when CORS_ALLOW_CREDENTIALS=true".into(),
        });
    }

    if is_production && has_wildcard {
        return Err(ConfigError::Invalid {
            key: "CORS_ALLOWED_ORIGINS".into(),
            reason: "cannot use '*' in production".into(),
        });
    }

    for origin in cors
        .allowed_origins
        .iter()
        .filter(|origin| origin.as_str() != "*")
    {
        let parsed = reqwest::Url::parse(origin).map_err(|e| ConfigError::Invalid {
            key: "CORS_ALLOWED_ORIGINS".into(),
            reason: format!("invalid origin '{origin}': {e}"),
        })?;

        if is_production && parsed.scheme() != "https" {
            return Err(ConfigError::Invalid {
                key: "CORS_ALLOWED_ORIGINS".into(),
                reason: format!("origin '{origin}' must use https in production"),
            });
        }
    }

    Ok(())
}

fn validate_risk(risk: &RiskConfig) -> Result<(), ConfigError> {
    if !(risk.alert_threshold <= risk.challenge_threshold
        && risk.challenge_threshold <= risk.block_threshold)
    {
        return Err(ConfigError::Invalid {
            key: "RISK_*_THRESHOLD".into(),
            reason: "must satisfy alert <= challenge <= block".into(),
        });
    }

    if risk.geoip_required {
        if risk.geoip_db_path.is_empty() {
            return Err(ConfigError::Invalid {
                key: "GEOIP_DB_PATH".into(),
                reason: "is required when GEOIP_REQUIRED=true".into(),
            });
        }

        if !Path::new(&risk.geoip_db_path).exists() {
            return Err(ConfigError::Invalid {
                key: "GEOIP_DB_PATH".into(),
                reason: "file does not exist".into(),
            });
        }
    }

    Ok(())
}

fn validate_webauthn(webauthn: &WebAuthnConfig) -> Result<(), ConfigError> {
    let parsed = reqwest::Url::parse(&webauthn.rp_origin).map_err(|e| ConfigError::Invalid {
        key: "WEBAUTHN_RP_ORIGIN".into(),
        reason: format!("invalid URL: {e}"),
    })?;

    match parsed.host_str() {
        Some(host) if host == webauthn.rp_id => Ok(()),
        Some(host) => Err(ConfigError::Invalid {
            key: "WEBAUTHN_RP_ORIGIN".into(),
            reason: format!(
                "host '{host}' must match WEBAUTHN_RP_ID '{}'",
                webauthn.rp_id
            ),
        }),
        None => Err(ConfigError::Invalid {
            key: "WEBAUTHN_RP_ORIGIN".into(),
            reason: "must contain a host".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        Config {
            env: Environment::Production,
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 3000,
                public_url: "https://api.example.com".into(),
                trusted_proxy_cidrs: vec![],
            },
            database: DatabaseConfig {
                url: "postgres://user:pass@localhost/db".into(),
                max_connections: 10,
                min_connections: 1,
                acquire_timeout_secs: 5,
            },
            redis: RedisConfig {
                url: "redis://127.0.0.1:6379".into(),
                pool_size: 5,
                wait_timeout_ms: 2000,
            },
            jwt: JwtConfig {
                secret: "abcdefghijklmnopqrstuvwxyz123456".into(),
                previous_secret: None,
                access_expiry_secs: 900,
                refresh_expiry_secs: 3600,
                strict_session_binding: false,
                max_session_lifetime_secs: 86400,
            },
            crypto: CryptoConfig {
                argon2_memory_kib: 8192,
                argon2_iterations: 1,
                argon2_parallelism: 1,
                totp_issuer: "test".into(),
                encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                previous_encryption_key: None,
                totp_skew: 1,
                recovery_code_expiry_days: 365,
            },
            rate_limit: RateLimitConfig {
                requests_per_minute: 100,
                auth_requests_per_minute: 20,
                fail_open_on_redis_error: false,
                allow_requests_without_ip: false,
            },
            security: SecurityConfig {
                lockout_threshold: 5,
                lockout_duration_secs: 1800,
                sensitive_action_reauth_secs: 600,
            },
            mail: MailConfig {
                smtp: SmtpConfig {
                    host: "smtp.example.com".into(),
                    port: 587,
                    username: "user".into(),
                    password: "pass".into(),
                    from_name: "Example".into(),
                    from_address: "no-reply@example.com".into(),
                },
                templates_dir: "templates".into(),
                default_locale: "en".into(),
            },
            cors: CorsConfig {
                allowed_origins: vec!["https://app.example.com".into()],
                allow_credentials: true,
            },
            captcha: CaptchaConfig {
                secret: Some("captcha-secret".into()),
                verify_url: "https://hcaptcha.com/siteverify".into(),
                request_timeout_secs: 5,
                fail_open_on_error: false,
            },
            audit: AuditConfig {
                retention_months: 6,
            },
            risk: RiskConfig {
                geoip_db_path: String::new(),
                geoip_required: false,
                alert_threshold: 30,
                challenge_threshold: 60,
                block_threshold: 80,
                history_days: 90,
            },
            webauthn: WebAuthnConfig {
                rp_id: "api.example.com".into(),
                rp_origin: "https://api.example.com".into(),
                rp_name: "Example".into(),
            },
            log: LogConfig {
                level: "info".into(),
                format: LogFormat::Pretty,
            },
        }
    }

    #[test]
    fn validate_accepts_hardened_production_config() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn validate_rejects_wildcard_cors_with_credentials() {
        let mut config = valid_config();
        config.cors.allowed_origins = vec!["*".into()];

        let err = config
            .validate()
            .expect_err("wildcard CORS with credentials should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "CORS_ALLOWED_ORIGINS"));
    }

    #[test]
    fn validate_rejects_non_https_public_url_in_production() {
        let mut config = valid_config();
        config.server.public_url = "http://api.example.com".into();

        let err = config
            .validate()
            .expect_err("http public URL should fail in production");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "APP_PUBLIC_URL"));
    }

    #[test]
    fn validate_rejects_short_jwt_secret() {
        let mut config = valid_config();
        config.jwt.secret = "short-secret".into();

        let err = config.validate().expect_err("short JWT secret should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_SECRET"));
    }

    #[test]
    fn validate_rejects_invalid_encryption_key() {
        let mut config = valid_config();
        config.crypto.encryption_key = "not-base64".into();

        let err = config
            .validate()
            .expect_err("invalid encryption key should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "ENCRYPTION_KEY"));
    }

    #[test]
    fn validate_rejects_missing_geoip_database_when_required() {
        let mut config = valid_config();
        config.risk.geoip_required = true;

        let err = config
            .validate()
            .expect_err("missing GeoIP database should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "GEOIP_DB_PATH"));
    }

    #[test]
    fn validate_rejects_zero_sensitive_reauth_window() {
        let mut config = valid_config();
        config.security.sensitive_action_reauth_secs = 0;

        let err = config
            .validate()
            .expect_err("zero recent reauth window should fail");
        assert!(
            matches!(err, ConfigError::Invalid { key, .. } if key == "SENSITIVE_ACTION_REAUTH_SECS")
        );
    }
}
