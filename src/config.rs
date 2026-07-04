//! Application configuration.
//!
//! Loads all settings from environment variables at startup.
//! Required variables cause an early, explicit error if missing.
//! Optional variables fall back to safe, documented defaults.
//! Use `.env.dev` and `config.prod.env` as a reference for all available variables.

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
pub struct NatsConfig {
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// PEM-encoded ECDSA P-256 private key used to sign access tokens.
    pub private_key: String,
    /// PEM-encoded ECDSA P-256 public key used to verify access tokens.
    pub public_key: String,
    /// Previous public key, accepted for verification during key rotation.
    pub previous_public_key: Option<String>,
    /// Short-lived access token lifetime (default: 15 min).
    pub access_expiry_secs: u64,
    /// Long-lived refresh token lifetime used when remember_me is true (default: 30 days).
    pub refresh_expiry_secs: u64,
    /// Short-lived refresh token lifetime used when remember_me is false (default: 24 h).
    pub short_session_expiry_secs: u64,
    /// When true, the refresh endpoint rejects requests whose IP differs from the
    /// one recorded at session creation. Useful for high-security deployments but
    /// breaks clients that roam between networks (e.g. mobile).
    pub strict_session_binding: bool,
    /// Hard upper bound on session lifetime regardless of refresh activity (default: 90 days).
    pub max_session_lifetime_secs: u64,
    /// Audience values stamped into the `aud` claim of issued access tokens.
    /// Each entry is the public URL of a downstream resource server (core-api,
    /// billing-api, ...). Loaded from the `JWT_AUDIENCE` env var as a CSV.
    /// Required in production: an empty audience would emit tokens that
    /// downstream services pinning `aud` could not accept.
    pub audience: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    // Argon2id parameters, tune for your hardware
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    /// Maximum number of Argon2id operations allowed to run concurrently.
    /// Bounds worst-case memory usage (max_concurrency x argon2_memory_kib)
    /// and keeps the blocking threadpool from being flooded during a login
    /// storm; excess requests queue on a semaphore instead. Defaults to the
    /// number of available CPU cores.
    pub argon2_max_concurrency: u32,
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
    /// Directive passed to EnvFilter, e.g. "info" or "auth_api=debug,tower_http=info".
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

// Cleanup

#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Interval in seconds between application-side cleanup runs (fallback when pg_cron is unavailable). Default: 3600.
    pub interval_secs: u64,
    /// Grace period in days after session expiry/revocation before deletion. Default: 7.
    pub sessions_grace_days: u32,
    /// Grace period in days after token expiry before deletion
    /// (email_2fa_codes, password_reset_tokens, email_verification_tokens). Default: 1.
    pub tokens_grace_days: u32,
    /// Retention period in days for login_attempts records. Default: 90.
    pub login_attempts_retention_days: u32,
    /// Grace period in days after recovery code expiry before deletion. Default: 7.
    pub recovery_codes_grace_days: u32,
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

// Metrics

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// When true, Prometheus metrics are collected and served on `port`.
    pub enabled: bool,
    /// Port of the internal metrics listener (`/metrics`). Conventionally 9464
    /// (Prometheus exporter range). Must never be exposed publicly: publish it
    /// on loopback only in docker-compose, never through the reverse proxy.
    pub port: u16,
}

// Device authorization (RFC 8628)

#[derive(Debug, Clone)]
pub struct DeviceAuthConfig {
    /// How long a device authorization request remains valid (seconds).
    pub ttl_secs: u64,
    /// Recommended polling interval for clients (seconds).
    pub poll_interval_secs: u64,
    /// Base URL of the verification page shown to the user (auth frontend).
    pub verification_uri: String,
}

// Root config

#[derive(Debug, Clone)]
pub struct Config {
    pub env: Environment,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub nats: NatsConfig,
    pub jwt: JwtConfig,
    pub crypto: CryptoConfig,
    pub rate_limit: RateLimitConfig,
    pub security: SecurityConfig,
    pub mail: MailConfig,
    pub cors: CorsConfig,
    pub captcha: CaptchaConfig,
    pub cleanup: CleanupConfig,
    pub audit: AuditConfig,
    pub risk: RiskConfig,
    pub log: LogConfig,
    pub device_auth: DeviceAuthConfig,
    pub metrics: MetricsConfig,
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
            nats: NatsConfig {
                url: env_string("NATS_URL").unwrap_or_else(|| "nats://nats:4222".into()),
            },
            jwt: JwtConfig {
                private_key: env_require("JWT_PRIVATE_KEY")?.replace("\\n", "\n"),
                public_key: env_require("JWT_PUBLIC_KEY")?.replace("\\n", "\n"),
                previous_public_key: env_string("JWT_PREVIOUS_PUBLIC_KEY")
                    .map(|s| s.replace("\\n", "\n")),
                access_expiry_secs: env_parse("JWT_ACCESS_EXPIRY_SECS").unwrap_or(900),
                refresh_expiry_secs: env_parse("JWT_REFRESH_EXPIRY_SECS")
                    .unwrap_or(60 * 60 * 24 * 30),
                short_session_expiry_secs: env_parse("JWT_SHORT_SESSION_EXPIRY_SECS")
                    .unwrap_or(60 * 60 * 24),
                strict_session_binding: env_parse("JWT_STRICT_SESSION_BINDING").unwrap_or(false),
                max_session_lifetime_secs: env_parse("JWT_MAX_SESSION_LIFETIME_SECS")
                    .unwrap_or(60 * 60 * 24 * 90),
                audience: env_csv("JWT_AUDIENCE").unwrap_or_default(),
            },
            crypto: CryptoConfig {
                argon2_memory_kib: env_parse("ARGON2_MEMORY_KIB").unwrap_or(65_536), // 64 MB
                argon2_iterations: env_parse("ARGON2_ITERATIONS").unwrap_or(3),
                argon2_parallelism: env_parse("ARGON2_PARALLELISM").unwrap_or(4),
                argon2_max_concurrency: env_parse("ARGON2_MAX_CONCURRENCY")
                    .unwrap_or_else(default_argon2_max_concurrency),
                totp_issuer: env_string("TOTP_ISSUER").unwrap_or_else(|| "auth-api".into()),
                encryption_key: env_require("ENCRYPTION_KEY")?,
                previous_encryption_key: env_string("PREVIOUS_ENCRYPTION_KEY"),
                totp_skew: env_parse("TOTP_SKEW").unwrap_or(1),
                recovery_code_expiry_days: env_parse("RECOVERY_CODE_EXPIRY_DAYS").unwrap_or(365), // 0 = never
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
                    from_name: env_string("SMTP_FROM_NAME").unwrap_or_else(|| "auth-api".into()),
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
            cleanup: CleanupConfig {
                interval_secs: env_parse("CLEANUP_INTERVAL_SECS").unwrap_or(3600),
                sessions_grace_days: env_parse("CLEANUP_SESSIONS_GRACE_DAYS").unwrap_or(7),
                tokens_grace_days: env_parse("CLEANUP_TOKENS_GRACE_DAYS").unwrap_or(1),
                login_attempts_retention_days: env_parse("CLEANUP_LOGIN_ATTEMPTS_RETENTION_DAYS")
                    .unwrap_or(90),
                recovery_codes_grace_days: env_parse("CLEANUP_RECOVERY_CODES_GRACE_DAYS")
                    .unwrap_or(7),
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
            log: LogConfig {
                level: env_string("LOG_LEVEL").unwrap_or_else(|| "info".into()),
                format: env_parse("LOG_FORMAT").unwrap_or(LogFormat::Pretty),
            },
            device_auth: DeviceAuthConfig {
                ttl_secs: env_parse("DEVICE_AUTH_TTL_SECS").unwrap_or(300),
                poll_interval_secs: env_parse("DEVICE_AUTH_POLL_INTERVAL_SECS").unwrap_or(5),
                verification_uri: env_require("DEVICE_AUTH_VERIFICATION_URI")?,
            },
            metrics: MetricsConfig {
                enabled: env_parse("METRICS_ENABLED").unwrap_or(true),
                port: env_parse("METRICS_PORT").unwrap_or(9464),
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
        validate_jwt_keys(&self.jwt)?;
        validate_encryption_key("ENCRYPTION_KEY", &self.crypto.encryption_key)?;
        validate_optional_encryption_key(
            "PREVIOUS_ENCRYPTION_KEY",
            self.crypto.previous_encryption_key.as_deref(),
        )?;
        validate_cors(&self.cors, self.is_production())?;
        validate_risk(&self.risk)?;
        validate_security(&self.security)?;
        validate_crypto(&self.crypto)?;

        validate_jwt_audience(&self.jwt.audience, self.is_production())?;

        if self.is_production() {
            // The development key pair is committed in `.env.dev` and therefore
            // public: anyone can mint valid tokens for a deployment that uses
            // it. Refuse to boot rather than run with a known-compromised key.
            if self
                .jwt
                .public_key
                .replace(['\n', ' ', '\t'], "")
                .contains(DEV_JWT_PUBLIC_KEY_MARKER)
            {
                return Err(ConfigError::Invalid {
                    key: "JWT_PUBLIC_KEY".into(),
                    reason: "this is the committed development key from .env.dev -- it is public and must never be used in production".into(),
                });
            }

            validate_https_url("APP_PUBLIC_URL", &self.server.public_url)?;

            if self.captcha.secret.is_some() {
                validate_https_url("CAPTCHA_VERIFY_URL", &self.captcha.verify_url)?;
            } else {
                return Err(ConfigError::Invalid {
                    key: "CAPTCHA_SECRET".into(),
                    reason: "must be set in production -- CAPTCHA protection cannot be disabled in production".into(),
                });
            }

            if self.mail.smtp.username.is_empty() {
                return Err(ConfigError::Invalid {
                    key: "SMTP_USERNAME".into(),
                    reason: "must not be empty in production (unauthenticated/unencrypted SMTP is not allowed)".into(),
                });
            }

            // Hardened-default switches: in production these MUST be set to the
            // secure value, even if an env override re-enables the permissive
            // behaviour. Refuse to boot rather than start in a degraded state.
            if self.rate_limit.fail_open_on_redis_error {
                return Err(ConfigError::Invalid {
                    key: "RATE_LIMIT_FAIL_OPEN".into(),
                    reason: "must be false in production -- a Redis outage would otherwise disable rate limiting entirely".into(),
                });
            }

            if self.rate_limit.allow_requests_without_ip {
                return Err(ConfigError::Invalid {
                    key: "RATE_LIMIT_ALLOW_MISSING_IP".into(),
                    reason: "must be false in production -- requests without a resolved client IP must be rejected, not let through".into(),
                });
            }

            if self.captcha.fail_open_on_error {
                return Err(ConfigError::Invalid {
                    key: "CAPTCHA_FAIL_OPEN".into(),
                    reason: "must be false in production -- CAPTCHA upstream errors must not let traffic through".into(),
                });
            }

            if !self.jwt.strict_session_binding {
                return Err(ConfigError::Invalid {
                    key: "JWT_STRICT_SESSION_BINDING".into(),
                    reason: "must be true in production -- refresh tokens must be bound to the originating IP".into(),
                });
            }
        }

        Ok(())
    }
}

/// Unique fragment of the development JWT public key committed in `.env.dev`.
/// Used to refuse that key in production (the pair is public by definition).
const DEV_JWT_PUBLIC_KEY_MARKER: &str = "MEjIGO1563lSVOpDzgW6Y9aI20lH";

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

fn validate_jwt_keys(jwt: &JwtConfig) -> Result<(), ConfigError> {
    use crate::utils::jwt as jwt_util;

    let signing_key =
        jwt_util::parse_signing_key(&jwt.private_key).map_err(|e| ConfigError::Invalid {
            key: "JWT_PRIVATE_KEY".into(),
            reason: e.to_string(),
        })?;

    let verifying_key =
        jwt_util::parse_p256_verifying_key(&jwt.public_key).map_err(|e| ConfigError::Invalid {
            key: "JWT_PUBLIC_KEY".into(),
            reason: e.to_string(),
        })?;

    // Verify that the public key matches the private key.
    let derived = p256::ecdsa::VerifyingKey::from(&signing_key);
    if derived != verifying_key {
        return Err(ConfigError::Invalid {
            key: "JWT_PUBLIC_KEY".into(),
            reason: "public key does not match the private key".into(),
        });
    }

    if let Some(ref prev_pub) = jwt.previous_public_key {
        jwt_util::parse_p256_verifying_key(prev_pub).map_err(|e| ConfigError::Invalid {
            key: "JWT_PREVIOUS_PUBLIC_KEY".into(),
            reason: e.to_string(),
        })?;
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

    // Reject low-entropy keys using Shannon entropy over byte distribution.
    // A truly random 32-byte key typically has >= 3.5 bits of entropy per byte.
    let mut counts = [0u32; 256];
    for &b in &decoded {
        counts[b as usize] += 1;
    }
    let len = decoded.len() as f64;
    let shannon: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum();
    if shannon < 3.0 {
        return Err(ConfigError::Invalid {
            key: key_name.into(),
            reason: format!(
                "key has insufficient entropy ({shannon:.2} bits/byte, minimum 3.0): \
                 use a cryptographically random key (e.g. openssl rand -base64 32)"
            ),
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

/// `JWT_AUDIENCE` validation. In production we refuse to start without at
/// least one audience: emitting tokens with an empty `aud` would silently
/// break every downstream service that pins the audience claim. In dev we
/// only warn so local stacks (no resource server, scratch tests) keep
/// working.
fn validate_jwt_audience(audience: &[String], is_production: bool) -> Result<(), ConfigError> {
    if audience.is_empty() {
        if is_production {
            return Err(ConfigError::Invalid {
                key: "JWT_AUDIENCE".into(),
                reason: "must not be empty in production -- downstream services that pin `aud` would reject all tokens".into(),
            });
        }

        tracing::warn!(
            "JWT_AUDIENCE is empty: issued access tokens will not carry an `aud` claim, downstream services pinning audience will reject them"
        );
        return Ok(());
    }

    for value in audience {
        if value.trim().is_empty() {
            return Err(ConfigError::Invalid {
                key: "JWT_AUDIENCE".into(),
                reason: "entries must not be empty or whitespace-only".into(),
            });
        }
    }

    Ok(())
}

fn default_argon2_max_concurrency() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}

fn validate_crypto(crypto: &CryptoConfig) -> Result<(), ConfigError> {
    if crypto.argon2_max_concurrency == 0 {
        return Err(ConfigError::Invalid {
            key: "ARGON2_MAX_CONCURRENCY".into(),
            reason: "must be greater than 0".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgL+1qOaZ7C+H1mGbV\njUP83/W450N4GfOnZSrQ7P//4Y2hRANCAAR4BApTJy8Anvp+O7YNVlTeCbBZ+1YJ\nk+r5ELHGFIXciAEGSrCTOkCm3yChSYroYWLE3ZN4reh6JDbIMX/QnBGx\n-----END PRIVATE KEY-----";
    const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeAQKUycvAJ76fju2DVZU3gmwWftW\nCZPq+RCxxhSF3IgBBkqwkzpApt8goUmK6GFixN2TeK3oeiQ2yDF/0JwRsQ==\n-----END PUBLIC KEY-----";

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
            nats: NatsConfig {
                url: "nats://127.0.0.1:4222".into(),
            },
            jwt: JwtConfig {
                private_key: TEST_PRIVATE_KEY_PEM.into(),
                public_key: TEST_PUBLIC_KEY_PEM.into(),
                previous_public_key: None,
                access_expiry_secs: 900,
                refresh_expiry_secs: 3600,
                short_session_expiry_secs: 3600,
                strict_session_binding: true,
                max_session_lifetime_secs: 86400,
                audience: vec!["https://core.example.com".into()],
            },
            crypto: CryptoConfig {
                argon2_memory_kib: 8192,
                argon2_iterations: 1,
                argon2_parallelism: 1,
                argon2_max_concurrency: 4,
                totp_issuer: "test".into(),
                encryption_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
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
            cleanup: CleanupConfig {
                interval_secs: 3600,
                sessions_grace_days: 7,
                tokens_grace_days: 1,
                login_attempts_retention_days: 90,
                recovery_codes_grace_days: 7,
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
            log: LogConfig {
                level: "info".into(),
                format: LogFormat::Pretty,
            },
            device_auth: DeviceAuthConfig {
                ttl_secs: 300,
                poll_interval_secs: 5,
                verification_uri: "https://auth.example.com/device".into(),
            },
            metrics: MetricsConfig {
                enabled: true,
                port: 9464,
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
    fn validate_rejects_invalid_jwt_private_key() {
        let mut config = valid_config();
        config.jwt.private_key = "not-a-valid-pem".into();

        let err = config
            .validate()
            .expect_err("invalid JWT private key should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_PRIVATE_KEY"));
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

    #[test]
    fn validate_rejects_mismatched_jwt_keys() {
        let mut config = valid_config();
        // Use a different public key that doesn't match the private key.
        config.jwt.public_key = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMEjIGO1563lSVOpDzgW6Y9aI20lH\nSejuoGIZ4JxZldRlZnWft8qZWJ9CUqlfKW88z3sHs6WEbAWNxl0fqn+SYg==\n-----END PUBLIC KEY-----".into();

        let err = config
            .validate()
            .expect_err("mismatched JWT keys should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_PUBLIC_KEY"));
    }

    #[test]
    fn validate_rejects_committed_dev_key_in_production() {
        // The exact key pair committed in .env.dev: valid, matching, but public.
        let mut config = valid_config();
        config.jwt.private_key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2R2G2WSdQAzqkVz/\n03JHEWNczskciWsiIKpONSbyHs2hRANCAAQwSMgY7XnreVJU6kPOBbpj1ojbSUdJ\n6O6gYhngnFmV1GVmdZ+3yplYn0JSqV8pbzzPewezpYRsBY3GXR+qf5Ji\n-----END PRIVATE KEY-----".into();
        config.jwt.public_key = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMEjIGO1563lSVOpDzgW6Y9aI20lH\nSejuoGIZ4JxZldRlZnWft8qZWJ9CUqlfKW88z3sHs6WEbAWNxl0fqn+SYg==\n-----END PUBLIC KEY-----".into();

        let err = config
            .validate()
            .expect_err("committed dev key in production must be rejected");
        match err {
            ConfigError::Invalid { key, reason } => {
                assert_eq!(key, "JWT_PUBLIC_KEY");
                assert!(reason.contains("development"), "reason: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_committed_dev_key_outside_production() {
        let mut config = valid_config();
        config.env = Environment::Development;
        config.mail.smtp.username = String::new();
        config.server.public_url = "http://localhost:3000".into();
        config.cors.allowed_origins = vec!["http://localhost:5173".into()];
        config.cors.allow_credentials = false;
        config.captcha.secret = None;
        config.jwt.private_key = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2R2G2WSdQAzqkVz/\n03JHEWNczskciWsiIKpONSbyHs2hRANCAAQwSMgY7XnreVJU6kPOBbpj1ojbSUdJ\n6O6gYhngnFmV1GVmdZ+3yplYn0JSqV8pbzzPewezpYRsBY3GXR+qf5Ji\n-----END PRIVATE KEY-----".into();
        config.jwt.public_key = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMEjIGO1563lSVOpDzgW6Y9aI20lH\nSejuoGIZ4JxZldRlZnWft8qZWJ9CUqlfKW88z3sHs6WEbAWNxl0fqn+SYg==\n-----END PUBLIC KEY-----".into();

        assert!(
            config.validate().is_ok(),
            "dev key must remain usable in development"
        );
    }

    #[test]
    fn validate_rejects_encryption_key_wrong_decoded_length() {
        let mut config = valid_config();
        // Valid base64 but decodes to 16 bytes, not 32.
        config.crypto.encryption_key = "AAAAAAAAAAAAAAAAAAAAAA==".into(); // 16 bytes

        let err = config
            .validate()
            .expect_err("wrong-length encryption key should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "ENCRYPTION_KEY"));
    }

    #[test]
    fn validate_rejects_empty_cors_origins() {
        let mut config = valid_config();
        config.cors.allowed_origins = vec![];

        let err = config
            .validate()
            .expect_err("empty CORS origins should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "CORS_ALLOWED_ORIGINS"));
    }

    #[test]
    fn validate_rejects_wildcard_cors_in_production() {
        let mut config = valid_config();
        config.cors.allow_credentials = false;
        config.cors.allowed_origins = vec!["*".into()];

        let err = config
            .validate()
            .expect_err("wildcard CORS in production should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "CORS_ALLOWED_ORIGINS"));
    }

    #[test]
    fn validate_rejects_non_https_cors_origin_in_production() {
        let mut config = valid_config();
        config.cors.allow_credentials = false;
        config.cors.allowed_origins = vec!["http://app.example.com".into()];

        let err = config
            .validate()
            .expect_err("http CORS origin in production should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "CORS_ALLOWED_ORIGINS"));
    }

    #[test]
    fn validate_rejects_invalid_cors_url() {
        let mut config = valid_config();
        config.env = Environment::Development;
        config.cors.allowed_origins = vec!["not-a-url".into()];

        let err = config.validate().expect_err("invalid CORS URL should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "CORS_ALLOWED_ORIGINS"));
    }

    #[test]
    fn validate_rejects_inverted_risk_thresholds_alert_above_challenge() {
        let mut config = valid_config();
        config.risk.alert_threshold = 50;
        config.risk.challenge_threshold = 30; // alert > challenge -- invalid
        config.risk.block_threshold = 80;

        let err = config
            .validate()
            .expect_err("alert > challenge threshold should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "RISK_*_THRESHOLD"));
    }

    #[test]
    fn validate_rejects_inverted_risk_thresholds_challenge_above_block() {
        let mut config = valid_config();
        config.risk.alert_threshold = 10;
        config.risk.challenge_threshold = 90;
        config.risk.block_threshold = 50; // challenge > block -- invalid

        let err = config
            .validate()
            .expect_err("challenge > block threshold should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "RISK_*_THRESHOLD"));
    }

    #[test]
    fn validate_rejects_empty_smtp_username_in_production() {
        let mut config = valid_config();
        config.mail.smtp.username = String::new();

        let err = config
            .validate()
            .expect_err("empty SMTP username in production should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "SMTP_USERNAME"));
    }

    #[test]
    fn validate_rejects_non_https_captcha_url_in_production() {
        let mut config = valid_config();
        config.captcha.verify_url = "http://hcaptcha.com/siteverify".into();

        let err = config
            .validate()
            .expect_err("http captcha URL in production should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "CAPTCHA_VERIFY_URL"));
    }

    #[test]
    fn validate_accepts_development_config_without_smtp() {
        let mut config = valid_config();
        config.env = Environment::Development;
        config.mail.smtp.username = String::new();
        config.server.public_url = "http://localhost:3000".into();
        config.cors.allowed_origins = vec!["http://localhost:5173".into()];
        config.cors.allow_credentials = false;
        config.captcha.secret = None;

        assert!(
            config.validate().is_ok(),
            "development config without SMTP must be accepted"
        );
    }

    #[test]
    fn validate_accepts_valid_previous_public_key() {
        let mut config = valid_config();
        // Use the mismatched public key from dev as a valid "previous" key.
        config.jwt.previous_public_key = Some("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMEjIGO1563lSVOpDzgW6Y9aI20lH\nSejuoGIZ4JxZldRlZnWft8qZWJ9CUqlfKW88z3sHs6WEbAWNxl0fqn+SYg==\n-----END PUBLIC KEY-----".into());

        assert!(
            config.validate().is_ok(),
            "valid previous public key must be accepted"
        );
    }

    #[test]
    fn validate_rejects_invalid_previous_public_key() {
        let mut config = valid_config();
        config.jwt.previous_public_key = Some("not-a-valid-pem".into());

        let err = config
            .validate()
            .expect_err("invalid previous public key should fail");
        assert!(
            matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_PREVIOUS_PUBLIC_KEY")
        );
    }

    #[test]
    fn validate_accepts_valid_previous_encryption_key() {
        let mut config = valid_config();
        config.crypto.previous_encryption_key =
            Some("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=".into());

        assert!(
            config.validate().is_ok(),
            "valid previous encryption key must be accepted"
        );
    }

    #[test]
    fn validate_rejects_invalid_previous_encryption_key() {
        let mut config = valid_config();
        config.crypto.previous_encryption_key = Some("not-base64!".into());

        let err = config
            .validate()
            .expect_err("invalid previous encryption key should fail");
        assert!(
            matches!(err, ConfigError::Invalid { key, .. } if key == "PREVIOUS_ENCRYPTION_KEY")
        );
    }

    #[test]
    fn validate_rejects_geoip_required_when_file_missing() {
        let mut config = valid_config();
        config.risk.geoip_required = true;
        config.risk.geoip_db_path = "/nonexistent/path/to/GeoIP.mmdb".into();

        let err = config
            .validate()
            .expect_err("non-existent GeoIP file should fail when required");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "GEOIP_DB_PATH"));
    }

    // Environment / LogFormat FromStr

    #[test]
    fn environment_from_str_accepts_known_variants() {
        assert_eq!(
            "development".parse::<Environment>().unwrap(),
            Environment::Development
        );
        assert_eq!(
            "dev".parse::<Environment>().unwrap(),
            Environment::Development
        );
        assert_eq!(
            "production".parse::<Environment>().unwrap(),
            Environment::Production
        );
        assert_eq!(
            "prod".parse::<Environment>().unwrap(),
            Environment::Production
        );
        assert_eq!("test".parse::<Environment>().unwrap(), Environment::Test);
    }

    #[test]
    fn environment_from_str_rejects_unknown_value() {
        let err = "staging".parse::<Environment>();
        assert!(err.is_err(), "unknown environment should return Err");
        assert!(err.unwrap_err().contains("staging"));
    }

    #[test]
    fn log_format_from_str_accepts_known_variants() {
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
    }

    #[test]
    fn log_format_from_str_rejects_unknown_value() {
        let err = "xml".parse::<LogFormat>();
        assert!(err.is_err(), "unknown log format should return Err");
        assert!(err.unwrap_err().contains("xml"));
    }

    // is_production / is_test

    #[test]
    fn is_production_returns_true_only_for_production_env() {
        let mut config = valid_config();
        assert!(config.is_production());
        config.env = Environment::Development;
        assert!(!config.is_production());
        config.env = Environment::Test;
        assert!(!config.is_production());
    }

    #[test]
    fn is_test_returns_true_only_for_test_env() {
        let mut config = valid_config();
        config.env = Environment::Test;
        assert!(config.is_test());
        config.env = Environment::Production;
        assert!(!config.is_test());
        config.env = Environment::Development;
        assert!(!config.is_test());
    }

    // JWT_AUDIENCE: required in production, optional (warn-only) in dev.

    #[test]
    fn validate_rejects_production_config_with_empty_jwt_audience() {
        let mut config = valid_config();
        config.jwt.audience = vec![];

        let err = config
            .validate()
            .expect_err("empty JWT_AUDIENCE in production should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_AUDIENCE"));
    }

    #[test]
    fn validate_accepts_development_config_with_empty_jwt_audience() {
        let mut config = valid_config();
        config.env = Environment::Development;
        config.mail.smtp.username = String::new();
        config.server.public_url = "http://localhost:3000".into();
        config.cors.allowed_origins = vec!["http://localhost:5173".into()];
        config.cors.allow_credentials = false;
        config.captcha.secret = None;
        config.jwt.audience = vec![];

        assert!(
            config.validate().is_ok(),
            "development config with empty JWT_AUDIENCE must be accepted (warn-only)"
        );
    }

    #[test]
    fn validate_rejects_jwt_audience_with_blank_entry() {
        let mut config = valid_config();
        config.jwt.audience = vec!["https://core.example.com".into(), "   ".into()];

        let err = config
            .validate()
            .expect_err("blank JWT_AUDIENCE entry should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_AUDIENCE"));
    }

    // Production captcha: secret absent must be rejected

    #[test]
    fn validate_rejects_production_config_without_captcha_secret() {
        let mut config = valid_config();
        config.captcha.secret = None;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("CAPTCHA_SECRET"),
            "production config without CAPTCHA_SECRET must be rejected: {err}"
        );
    }

    // Hardened-default switches: production must refuse permissive overrides.

    #[test]
    fn validate_rejects_production_config_with_rate_limit_fail_open() {
        let mut config = valid_config();
        config.rate_limit.fail_open_on_redis_error = true;

        let err = config
            .validate()
            .expect_err("RATE_LIMIT_FAIL_OPEN=true in production should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "RATE_LIMIT_FAIL_OPEN"));
    }

    #[test]
    fn validate_rejects_production_config_with_rate_limit_allow_missing_ip() {
        let mut config = valid_config();
        config.rate_limit.allow_requests_without_ip = true;

        let err = config
            .validate()
            .expect_err("RATE_LIMIT_ALLOW_MISSING_IP=true in production should fail");
        assert!(
            matches!(err, ConfigError::Invalid { key, .. } if key == "RATE_LIMIT_ALLOW_MISSING_IP")
        );
    }

    #[test]
    fn validate_rejects_production_config_with_captcha_fail_open() {
        let mut config = valid_config();
        config.captcha.fail_open_on_error = true;

        let err = config
            .validate()
            .expect_err("CAPTCHA_FAIL_OPEN=true in production should fail");
        assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "CAPTCHA_FAIL_OPEN"));
    }

    #[test]
    fn validate_rejects_production_config_without_strict_session_binding() {
        let mut config = valid_config();
        config.jwt.strict_session_binding = false;

        let err = config
            .validate()
            .expect_err("JWT_STRICT_SESSION_BINDING=false in production should fail");
        assert!(
            matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_STRICT_SESSION_BINDING")
        );
    }

    #[test]
    fn validate_accepts_development_config_with_permissive_switches() {
        let mut config = valid_config();
        config.env = Environment::Development;
        config.mail.smtp.username = String::new();
        config.server.public_url = "http://localhost:3000".into();
        config.cors.allowed_origins = vec!["http://localhost:5173".into()];
        config.cors.allow_credentials = false;
        config.captcha.secret = None;
        // Permissive defaults must remain allowed in development.
        config.rate_limit.fail_open_on_redis_error = true;
        config.rate_limit.allow_requests_without_ip = true;
        config.captcha.fail_open_on_error = true;
        config.jwt.strict_session_binding = false;

        assert!(
            config.validate().is_ok(),
            "development config with permissive switches must be accepted"
        );
    }
}
