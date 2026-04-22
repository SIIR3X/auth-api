#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Once,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use auth_api::{
    config::{
        AuditConfig, CaptchaConfig, Config, CorsConfig, CryptoConfig, DatabaseConfig, Environment,
        JwtConfig, LogConfig, LogFormat, MailConfig, RateLimitConfig, RedisConfig, RiskConfig,
        SecurityConfig, ServerConfig, SmtpConfig,
    },
    handlers,
    state::AppState,
};

static TRACING_INIT: Once = Once::new();

#[derive(Debug)]
pub struct EphemeralDatabase {
    admin_url: String,
    pub db_name: String,
    pub db_url: String,
    pub pool: PgPool,
}

impl EphemeralDatabase {
    pub async fn create(prefix: &str, admin_url: &str) -> Result<Self> {
        let db_name = format!("{prefix}_{}_{}", std::process::id(), unique_suffix());
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(admin_url)
            .await
            .context("failed to connect to admin database")?;

        sqlx::query(&format!("CREATE DATABASE \"{db_name}\" TEMPLATE template0"))
            .execute(&admin_pool)
            .await
            .with_context(|| format!("failed to create benchmark database `{db_name}`"))?;
        drop(admin_pool);

        let db_url = replace_db_name(admin_url, &db_name);
        let pool = PgPoolOptions::new()
            .max_connections(32)
            .connect(&db_url)
            .await
            .with_context(|| format!("failed to connect to benchmark database `{db_name}`"))?;

        let migrator = sqlx::migrate::Migrator::new(Path::new("./migrations"))
            .await
            .context("failed to load migrations")?;
        migrator
            .run(&pool)
            .await
            .with_context(|| format!("failed to apply migrations on `{db_name}`"))?;

        Ok(Self {
            admin_url: admin_url.to_string(),
            db_name,
            db_url,
            pool,
        })
    }
}

impl Drop for EphemeralDatabase {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let db_name = self.db_name.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build cleanup runtime");

            rt.block_on(async move {
                let Ok(admin_pool) = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&admin_url)
                    .await
                else {
                    return;
                };

                let _ = sqlx::query(&format!(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{db_name}' AND pid <> pg_backend_pid()"
                ))
                .execute(&admin_pool)
                .await;

                let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"))
                    .execute(&admin_pool)
                    .await;
            });
        });
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencySummary {
    pub samples: usize,
    pub min_ms: f64,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub throughput_per_sec: f64,
}

pub fn init_tracing_once() {
    TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("auth_api=error,sqlx=warn")),
            )
            .try_init();
    });
}

pub fn required_admin_database_url() -> Result<String> {
    dotenvy::dotenv().ok();

    env_string("BENCH_DATABASE_URL")
        .or_else(|| env_string("TEST_DATABASE_URL"))
        .context("BENCH_DATABASE_URL or TEST_DATABASE_URL must be set for HTTP/SQL benchmarks")
}

pub fn benchmark_redis_url() -> String {
    dotenvy::dotenv().ok();

    env_string("BENCH_REDIS_URL")
        .or_else(|| env_string("TEST_REDIS_URL"))
        .or_else(|| env_string("REDIS_URL"))
        .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string())
}

pub fn report_section_dir(section: &str) -> Result<PathBuf> {
    let root = env_string("BENCH_REPORT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("reports/bench/manual-{}", unique_suffix())));
    let section_dir = root.join(section);
    fs::create_dir_all(&section_dir).with_context(|| {
        format!(
            "failed to create report directory {}",
            section_dir.display()
        )
    })?;
    Ok(section_dir)
}

pub fn benchmark_config(db_url: &str, redis_url: &str) -> Config {
    dotenvy::dotenv().ok();

    let mut config = Config::from_env().unwrap_or_else(|_| fallback_config(db_url, redis_url));

    config.env = Environment::Test;
    config.server.host = "127.0.0.1".into();
    config.server.port = 0;
    config.server.public_url = "http://127.0.0.1".into();
    config.server.trusted_proxy_cidrs.clear();
    config.database.url = db_url.into();
    config.database.max_connections = config.database.max_connections.max(32);
    config.database.min_connections = config.database.min_connections.min(4);
    config.redis.url = redis_url.into();
    config.redis.pool_size = config.redis.pool_size.max(16);
    config.rate_limit.requests_per_minute = 1_000_000;
    config.rate_limit.auth_requests_per_minute = 1_000_000;
    config.rate_limit.fail_open_on_redis_error = true;
    config.rate_limit.allow_requests_without_ip = true;
    config.security.lockout_threshold = config.security.lockout_threshold.max(10_000);
    config.captcha.secret = None;
    config.mail.smtp = SmtpConfig {
        host: "127.0.0.1".into(),
        port: 1025,
        username: String::new(),
        password: String::new(),
        from_name: "Bench".into(),
        from_address: "bench@example.com".into(),
    };
    config.cors.allowed_origins = vec!["*".into()];
    config.cors.allow_credentials = false;
    config.log.level = "error".into();
    config.log.format = LogFormat::Pretty;

    config
}

pub async fn build_state(db_url: &str, redis_url: &str, pool: PgPool) -> Result<AppState> {
    let config = benchmark_config(db_url, redis_url);
    AppState::from_config_with_pool(config, pool)
        .await
        .context("failed to build benchmark app state")
}

pub async fn spawn_app(state: AppState) -> Result<(String, Client)> {
    let app = handlers::router(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind benchmark listener")?;
    let port = listener
        .local_addr()
        .context("failed to get benchmark listener address")?
        .port();

    tokio::spawn(async move {
        if let Err(error) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        {
            tracing::error!(error = ?error, "benchmark server stopped unexpectedly");
        }
    });

    let client = Client::builder()
        .pool_max_idle_per_host(64)
        .build()
        .context("failed to build benchmark HTTP client")?;

    Ok((format!("http://127.0.0.1:{port}"), client))
}

pub fn summarize_latencies(latencies: &[Duration], wall_time: Duration) -> LatencySummary {
    let mut samples = latencies
        .iter()
        .map(|value| value.as_secs_f64() * 1000.0)
        .collect::<Vec<_>>();
    samples.sort_by(|left, right| left.partial_cmp(right).unwrap());

    let count = samples.len();
    let min_ms = samples.first().copied().unwrap_or_default();
    let max_ms = samples.last().copied().unwrap_or_default();
    let mean_ms = if count == 0 {
        0.0
    } else {
        samples.iter().sum::<f64>() / count as f64
    };

    LatencySummary {
        samples: count,
        min_ms,
        mean_ms,
        p50_ms: percentile(&samples, 0.50),
        p95_ms: percentile(&samples, 0.95),
        p99_ms: percentile(&samples, 0.99),
        max_ms,
        throughput_per_sec: if wall_time.is_zero() {
            0.0
        } else {
            count as f64 / wall_time.as_secs_f64()
        },
    }
}

pub fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value).context("failed to serialize JSON report")?;
    fs::write(path, json)
        .with_context(|| format!("failed to write JSON report {}", path.display()))?;
    Ok(())
}

pub fn write_markdown(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content)
        .with_context(|| format!("failed to write Markdown report {}", path.display()))?;
    Ok(())
}

pub fn env_usize(key: &str, default: usize) -> usize {
    env_string(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

pub fn env_u64(key: &str, default: u64) -> u64 {
    env_string(key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

pub fn env_bool(key: &str, default: bool) -> bool {
    env_string(key)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn fallback_config(db_url: &str, redis_url: &str) -> Config {
    Config {
        env: Environment::Test,
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            public_url: "http://localhost".into(),
            trusted_proxy_cidrs: Vec::new(),
        },
        database: DatabaseConfig {
            url: db_url.into(),
            max_connections: 32,
            min_connections: 4,
            acquire_timeout_secs: 5,
        },
        redis: RedisConfig {
            url: redis_url.into(),
            pool_size: 16,
            wait_timeout_ms: 2000,
        },
        jwt: JwtConfig {
            secret: "bench-secret-that-is-long-enough-for-hs256".into(),
            previous_secret: None,
            access_expiry_secs: 900,
            refresh_expiry_secs: 86400,
            short_session_expiry_secs: 3600,
            strict_session_binding: false,
            max_session_lifetime_secs: 60 * 60 * 24 * 90,
        },
        crypto: CryptoConfig {
            argon2_memory_kib: 65_536,
            argon2_iterations: 3,
            argon2_parallelism: 1,
            totp_issuer: "bench".into(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            previous_encryption_key: None,
            totp_skew: 1,
            recovery_code_expiry_days: 365,
        },
        rate_limit: RateLimitConfig {
            requests_per_minute: 1_000_000,
            auth_requests_per_minute: 1_000_000,
            fail_open_on_redis_error: true,
            allow_requests_without_ip: true,
        },
        security: SecurityConfig {
            lockout_threshold: 10_000,
            lockout_duration_secs: 1800,
            sensitive_action_reauth_secs: 600,
        },
        captcha: CaptchaConfig {
            secret: None,
            verify_url: "https://hcaptcha.com/siteverify".into(),
            request_timeout_secs: 1,
            fail_open_on_error: true,
        },
        cors: CorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: false,
        },
        mail: MailConfig {
            smtp: SmtpConfig {
                host: "127.0.0.1".into(),
                port: 1025,
                username: String::new(),
                password: String::new(),
                from_name: "Bench".into(),
                from_address: "bench@example.com".into(),
            },
            templates_dir: "templates".into(),
            default_locale: "en".into(),
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
            level: "error".into(),
            format: LogFormat::Pretty,
        },
    }
}

fn percentile(sorted_samples: &[f64], percentile: f64) -> f64 {
    if sorted_samples.is_empty() {
        return 0.0;
    }

    let rank = ((sorted_samples.len() - 1) as f64 * percentile).round() as usize;
    sorted_samples[rank]
}

fn replace_db_name(url: &str, new_db: &str) -> String {
    if let Some(slash_pos) = url.rfind('/') {
        format!("{}/{}", &url[..slash_pos], new_db)
    } else {
        format!("{}/{}", url, new_db)
    }
}

fn unique_suffix() -> u128 {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH")
        .as_nanos();

    timestamp ^ ((std::process::id() as u128) << 32)
}

// Tooling compatibility shim: cargo-geiger treats every `src/bin/*.rs`
// as a binary entrypoint. Keeping a no-op main here preserves the shared
// bench module path without affecting the real benchmark binaries.
fn main() {}
