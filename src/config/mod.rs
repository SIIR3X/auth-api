//! Application configuration.
//!
//! Loads all settings from environment variables at startup.
//! Required variables cause an early, explicit error if missing.
//! Optional variables fall back to safe, documented defaults.
//! Use `.env.dev` and `config.prod.env` as a reference for all available variables.

use std::str::FromStr;

use ipnetwork::IpNetwork;

mod env_vars;
#[cfg(test)]
mod tests;
mod validate;

use env_vars::*;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(String),
    #[error("invalid value for '{key}': {reason}")]
    Invalid { key: String, reason: String },
}

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

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Public base URL of this API (e.g. "https://api.example.com"): token
    /// issuer, audience, and the JWKS location.
    pub public_url: String,
    /// Base URL of the web application whose pages emails link to
    /// (`/verify-email`, `/reset-password`). `FRONTEND_URL`, defaulting to
    /// `APP_PUBLIC_URL` when the API and the application share an origin.
    pub frontend_url: String,
    /// Reverse-proxy CIDRs allowed to supply X-Forwarded-For / X-Real-IP.
    /// Requests coming from other peers use the socket address directly.
    pub trusted_proxy_cidrs: Vec<IpNetwork>,
}

#[derive(Clone)]
pub struct DatabaseConfig {
    pub url: String,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Minimum idle connections kept alive.
    pub min_connections: u32,
    /// Seconds before a pending acquire is aborted. Short (5 s by default):
    /// an exhausted pool must answer fast and show in the metrics, not wait out
    /// the 30-second request timeout.
    pub acquire_timeout_secs: u64,
}

#[derive(Clone)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    /// Maximum time in milliseconds to wait for a connection from the pool.
    /// Prevents unbounded queue buildup under Redis pressure. Default: 2000ms.
    pub wait_timeout_ms: u64,
}

#[derive(Clone)]
pub struct NatsConfig {
    pub url: String,
}

#[derive(Clone)]
pub struct JwtConfig {
    /// PEM-encoded ECDSA P-256 private key used to sign access tokens.
    pub private_key: String,
    /// PEM-encoded ECDSA P-256 public key used to verify access tokens.
    pub public_key: String,
    /// Previous public key, accepted for verification during key rotation.
    pub previous_public_key: Option<String>,
    /// Public key of the next signing key, published in the JWKS and accepted
    /// ahead of a rotation, so resource servers know it before any token is
    /// signed with it.
    pub next_public_key: Option<String>,
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
    /// Each entry is the public URL of a downstream resource server that accepts
    /// these tokens. Loaded from the `JWT_AUDIENCE` env var as a CSV.
    /// Required in production: an empty audience would emit tokens that
    /// downstream services pinning `aud` could not accept.
    pub audience: Vec<String>,
}

impl JwtConfig {
    /// Lifetime of a refresh token: long with "remember me", short otherwise.
    pub fn session_ttl_secs(&self, remember_me: bool) -> u64 {
        if remember_me {
            self.refresh_expiry_secs
        } else {
            self.short_session_expiry_secs
        }
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Interval in seconds between cleanup runs (retention sweeps and audit partition rotation). Default: 3600.
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

#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Number of months of audit log data to retain. Older monthly partitions are dropped.
    /// The database function rotate_audit_log_partitions() enforces this at startup and
    /// on every cleanup run. 0 = keep forever.
    pub retention_months: u32,
}

#[derive(Clone)]
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

#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Comma-separated list of allowed origins, e.g. "https://app.example.com,https://admin.example.com".
    /// Use "*" to allow all origins (not recommended in production).
    pub allowed_origins: Vec<String>,
    /// Whether to allow credentials (cookies, Authorization header).
    pub allow_credentials: bool,
}

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// When true, Prometheus metrics are collected and served on `port`.
    pub enabled: bool,
    /// Port of the internal metrics listener (`/metrics`). Conventionally 9464
    /// (Prometheus exporter range). Must never be exposed publicly: publish it
    /// on loopback only in docker-compose, never through the reverse proxy.
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct DeviceAuthConfig {
    /// How long a device authorization request remains valid (seconds).
    pub ttl_secs: u64,
    /// Recommended polling interval for clients (seconds).
    pub poll_interval_secs: u64,
    /// Base URL of the verification page shown to the user (auth frontend).
    pub verification_uri: String,
}

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
    pub log: LogConfig,
    pub device_auth: DeviceAuthConfig,
    pub metrics: MetricsConfig,
}

impl Config {
    /// Load configuration from environment variables.
    /// Silently ignores a missing `.env` file; production relies on real env vars.
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Load configuration from `lookup`, which returns the value of a variable:
    /// the process environment for `from_env`, a map in tests.
    pub(crate) fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let vars = Env::new(lookup);

        // Required: a typo such as `APP_ENV=prd` must not silently start a
        // deployment with every development relaxation enabled.
        let env: Environment = vars
            .parse("APP_ENV")?
            .ok_or_else(|| ConfigError::Missing("APP_ENV".into()))?;

        let is_production = matches!(env, Environment::Production);

        let config = Self {
            env: env.clone(),
            server: ServerConfig {
                host: vars
                    .string("SERVER_HOST")
                    .unwrap_or_else(|| "0.0.0.0".into()),
                port: vars.parse("SERVER_PORT")?.unwrap_or(3000u16),
                public_url: vars
                    .string("APP_PUBLIC_URL")
                    .unwrap_or_else(|| "http://localhost:3000".into()),
                frontend_url: vars
                    .string("FRONTEND_URL")
                    .or_else(|| vars.string("APP_PUBLIC_URL"))
                    .unwrap_or_else(|| "http://localhost:3000".into())
                    .trim_end_matches('/')
                    .to_owned(),
                trusted_proxy_cidrs: vars.ip_network_list("TRUSTED_PROXY_CIDRS")?,
            },
            database: DatabaseConfig {
                url: vars.require("DATABASE_URL")?,
                max_connections: vars.parse("DB_MAX_CONNECTIONS")?.unwrap_or(20),
                min_connections: vars.parse("DB_MIN_CONNECTIONS")?.unwrap_or(2),
                acquire_timeout_secs: vars.parse("DB_ACQUIRE_TIMEOUT_SECS")?.unwrap_or(5),
            },
            redis: RedisConfig {
                url: vars.require("REDIS_URL")?,
                pool_size: vars.parse("REDIS_POOL_SIZE")?.unwrap_or(10),
                wait_timeout_ms: vars.parse("REDIS_WAIT_TIMEOUT_MS")?.unwrap_or(2000),
            },
            nats: NatsConfig {
                url: vars
                    .string("NATS_URL")
                    .unwrap_or_else(|| "nats://nats:4222".into()),
            },
            jwt: JwtConfig {
                private_key: vars.require("JWT_PRIVATE_KEY")?.replace("\\n", "\n"),
                public_key: vars.require("JWT_PUBLIC_KEY")?.replace("\\n", "\n"),
                previous_public_key: vars
                    .string("JWT_PREVIOUS_PUBLIC_KEY")
                    .map(|s| s.replace("\\n", "\n")),
                next_public_key: vars
                    .string("JWT_NEXT_PUBLIC_KEY")
                    .map(|s| s.replace("\\n", "\n")),
                access_expiry_secs: vars.parse("JWT_ACCESS_EXPIRY_SECS")?.unwrap_or(900),
                refresh_expiry_secs: vars
                    .parse("JWT_REFRESH_EXPIRY_SECS")?
                    .unwrap_or(60 * 60 * 24 * 30),
                short_session_expiry_secs: vars
                    .parse("JWT_SHORT_SESSION_EXPIRY_SECS")?
                    .unwrap_or(60 * 60 * 24),
                strict_session_binding: vars.parse("JWT_STRICT_SESSION_BINDING")?.unwrap_or(false),
                max_session_lifetime_secs: vars
                    .parse("JWT_MAX_SESSION_LIFETIME_SECS")?
                    .unwrap_or(60 * 60 * 24 * 90),
                audience: vars.csv("JWT_AUDIENCE").unwrap_or_default(),
            },
            crypto: CryptoConfig {
                argon2_memory_kib: vars.parse("ARGON2_MEMORY_KIB")?.unwrap_or(65_536), // 64 MB
                argon2_iterations: vars.parse("ARGON2_ITERATIONS")?.unwrap_or(3),
                argon2_parallelism: vars.parse("ARGON2_PARALLELISM")?.unwrap_or(4),
                argon2_max_concurrency: vars
                    .parse("ARGON2_MAX_CONCURRENCY")?
                    .unwrap_or_else(default_argon2_max_concurrency),
                totp_issuer: vars
                    .string("TOTP_ISSUER")
                    .unwrap_or_else(|| "auth-api".into()),
                encryption_key: vars.require("ENCRYPTION_KEY")?,
                previous_encryption_key: vars.string("PREVIOUS_ENCRYPTION_KEY"),
                totp_skew: vars.parse("TOTP_SKEW")?.unwrap_or(1),
                recovery_code_expiry_days: vars.parse("RECOVERY_CODE_EXPIRY_DAYS")?.unwrap_or(365), // 0 = never
            },
            rate_limit: RateLimitConfig {
                requests_per_minute: vars.parse("RATE_LIMIT_RPM")?.unwrap_or(300),
                auth_requests_per_minute: vars.parse("RATE_LIMIT_AUTH_RPM")?.unwrap_or(20),
                fail_open_on_redis_error: vars
                    .parse("RATE_LIMIT_FAIL_OPEN")?
                    .unwrap_or(!is_production),
                allow_requests_without_ip: vars
                    .parse("RATE_LIMIT_ALLOW_MISSING_IP")?
                    .unwrap_or(!is_production),
            },
            security: SecurityConfig {
                lockout_threshold: vars.parse("LOCKOUT_THRESHOLD")?.unwrap_or(10),
                lockout_duration_secs: vars.parse("LOCKOUT_DURATION_SECS")?.unwrap_or(1800),
                sensitive_action_reauth_secs: vars
                    .parse("SENSITIVE_ACTION_REAUTH_SECS")?
                    .unwrap_or(600),
            },
            mail: MailConfig {
                smtp: SmtpConfig {
                    host: vars.require("SMTP_HOST")?,
                    port: vars.parse("SMTP_PORT")?.unwrap_or(587),
                    username: vars.require("SMTP_USERNAME")?,
                    password: vars.require("SMTP_PASSWORD")?,
                    from_name: vars
                        .string("SMTP_FROM_NAME")
                        .unwrap_or_else(|| "auth-api".into()),
                    from_address: vars.require("SMTP_FROM_ADDRESS")?,
                },
                templates_dir: vars
                    .string("MAIL_TEMPLATES_DIR")
                    .unwrap_or_else(|| "templates".into()),
                default_locale: vars
                    .string("MAIL_DEFAULT_LOCALE")
                    .unwrap_or_else(|| "en".into()),
            },
            captcha: CaptchaConfig {
                secret: vars.string("CAPTCHA_SECRET"),
                verify_url: vars
                    .string("CAPTCHA_VERIFY_URL")
                    .unwrap_or_else(|| "https://hcaptcha.com/siteverify".into()),
                request_timeout_secs: vars.parse("CAPTCHA_TIMEOUT_SECS")?.unwrap_or(5),
                fail_open_on_error: vars.parse("CAPTCHA_FAIL_OPEN")?.unwrap_or(!is_production),
            },
            cors: CorsConfig {
                allowed_origins: vars
                    .string("CORS_ALLOWED_ORIGINS")
                    .unwrap_or_else(|| "http://localhost:3000".into())
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .collect(),
                allow_credentials: vars.parse("CORS_ALLOW_CREDENTIALS")?.unwrap_or(true),
            },
            cleanup: CleanupConfig {
                interval_secs: vars.parse("CLEANUP_INTERVAL_SECS")?.unwrap_or(3600),
                sessions_grace_days: vars.parse("CLEANUP_SESSIONS_GRACE_DAYS")?.unwrap_or(7),
                tokens_grace_days: vars.parse("CLEANUP_TOKENS_GRACE_DAYS")?.unwrap_or(1),
                login_attempts_retention_days: vars
                    .parse("CLEANUP_LOGIN_ATTEMPTS_RETENTION_DAYS")?
                    .unwrap_or(90),
                recovery_codes_grace_days: vars
                    .parse("CLEANUP_RECOVERY_CODES_GRACE_DAYS")?
                    .unwrap_or(7),
            },
            audit: AuditConfig {
                retention_months: vars.parse("AUDIT_LOG_RETENTION_MONTHS")?.unwrap_or(12),
            },
            log: LogConfig {
                level: vars.string("LOG_LEVEL").unwrap_or_else(|| "info".into()),
                format: vars.parse("LOG_FORMAT")?.unwrap_or(LogFormat::Pretty),
            },
            device_auth: DeviceAuthConfig {
                ttl_secs: vars.parse("DEVICE_AUTH_TTL_SECS")?.unwrap_or(300),
                poll_interval_secs: vars.parse("DEVICE_AUTH_POLL_INTERVAL_SECS")?.unwrap_or(5),
                verification_uri: vars.require("DEVICE_AUTH_VERIFICATION_URI")?,
            },
            metrics: MetricsConfig {
                enabled: vars.parse("METRICS_ENABLED")?.unwrap_or(true),
                port: vars.parse("METRICS_PORT")?.unwrap_or(9464),
            },
        };

        // Validation runs once, in `AppState::from_config`, after derived values
        // such as the self audience are in place.
        Ok(config)
    }

    pub fn is_production(&self) -> bool {
        self.env == Environment::Production
    }

    pub fn is_test(&self) -> bool {
        self.env == Environment::Test
    }

    /// Make sure auth-api's own `public_url` is part of the JWT audience list.
    ///
    /// Tokens are addressed to downstream resource servers, but auth-api also
    /// consumes its own tokens for `/users/me/*` and pins `aud == public_url`
    /// in the `AuthUser` extractor. Idempotent.
    pub fn ensure_self_in_audience(&mut self) {
        let self_url = self.server.public_url.clone();
        if self_url.is_empty() || self.jwt.audience.iter().any(|a| a == &self_url) {
            return;
        }
        self.jwt.audience.push(self_url);
    }
}

/// Unique fragment of the development JWT public key committed in `.env.dev`.
/// Used to refuse that key in production (the pair is public by definition).
const DEV_JWT_PUBLIC_KEY_MARKER: &str = "MEjIGO1563lSVOpDzgW6Y9aI20lH";

// Debug output of the settings that hold secrets. `Config` derives `Debug`, and a
// derived implementation would print URLs with their passwords, the signing key
// and the encryption keys into any log or panic message that formats it.

/// Printed in place of a secret.
const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &REDACTED)
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("acquire_timeout_secs", &self.acquire_timeout_secs)
            .finish()
    }
}

impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfig")
            .field("url", &REDACTED)
            .field("pool_size", &self.pool_size)
            .field("wait_timeout_ms", &self.wait_timeout_ms)
            .finish()
    }
}

impl std::fmt::Debug for NatsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsConfig")
            .field("url", &REDACTED)
            .finish()
    }
}

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("private_key", &REDACTED)
            .field("public_key", &self.public_key)
            .field("previous_public_key", &self.previous_public_key)
            .field("next_public_key", &self.next_public_key)
            .field("access_expiry_secs", &self.access_expiry_secs)
            .field("refresh_expiry_secs", &self.refresh_expiry_secs)
            .field("short_session_expiry_secs", &self.short_session_expiry_secs)
            .field("strict_session_binding", &self.strict_session_binding)
            .field("max_session_lifetime_secs", &self.max_session_lifetime_secs)
            .field("audience", &self.audience)
            .finish()
    }
}

impl std::fmt::Debug for CryptoConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoConfig")
            .field("argon2_memory_kib", &self.argon2_memory_kib)
            .field("argon2_iterations", &self.argon2_iterations)
            .field("argon2_parallelism", &self.argon2_parallelism)
            .field("argon2_max_concurrency", &self.argon2_max_concurrency)
            .field("totp_issuer", &self.totp_issuer)
            .field("encryption_key", &REDACTED)
            .field(
                "previous_encryption_key",
                &self.previous_encryption_key.as_ref().map(|_| REDACTED),
            )
            .field("totp_skew", &self.totp_skew)
            .field("recovery_code_expiry_days", &self.recovery_code_expiry_days)
            .finish()
    }
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &REDACTED)
            .field("from_name", &self.from_name)
            .field("from_address", &self.from_address)
            .finish()
    }
}

impl std::fmt::Debug for CaptchaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaConfig")
            .field("secret", &self.secret.as_ref().map(|_| REDACTED))
            .field("verify_url", &self.verify_url)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("fail_open_on_error", &self.fail_open_on_error)
            .finish()
    }
}
