//! TestApp: real Axum server on a random port with an isolated database.

#![allow(dead_code)]

use deadpool_redis::{Pool as RedisPool, redis::AsyncCommands};
use reqwest::{Client, Response};
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{net::TcpListener, sync::OnceCell};
use tracing_subscriber::EnvFilter;

use rust_api::{config::Config, handlers, state::AppState};

// Environment variable names for test infrastructure
const TEST_DATABASE_URL: &str = "TEST_DATABASE_URL";
const TEST_REDIS_URL: &str = "TEST_REDIS_URL";
const TEST_JWT_SECRET: &str = "test-secret-that-is-long-enough-for-hs256";

static TEMPLATE_DB: OnceCell<String> = OnceCell::const_new();

pub struct TestApp {
    pub base_url: String,
    pub db: PgPool,
    pub db_url: String,
    pub redis: RedisPool,
    pub client: Client,
    pub state: AppState,
    db_name: String,
    admin_url: String,
    /// Set when the app was spawned with `spawn_with_mailpit()`.
    mailpit_api_port: Option<u16>,
}

impl TestApp {
    pub async fn spawn() -> Self {
        Self::spawn_with_config(|_| {}).await
    }

    pub async fn spawn_with_config<F>(configure: F) -> Self
    where
        F: FnOnce(&mut Config),
    {
        // Initialize tracing once - subsequent calls are no-ops.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("rust_api=error")),
            )
            .try_init();

        dotenvy::dotenv().ok();

        let admin_url = std::env::var(TEST_DATABASE_URL).expect("TEST_DATABASE_URL must be set");
        let redis_url =
            std::env::var(TEST_REDIS_URL).unwrap_or_else(|_| "redis://127.0.0.1:6379".into());

        let db_name = format!("rust_api_http_test_{}", uuid::Uuid::new_v4().simple());
        let template_db = ensure_template_database(&admin_url).await;

        // Create isolated test database
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .expect("failed to connect to admin database");

        sqlx::query(&format!(
            "CREATE DATABASE \"{db_name}\" TEMPLATE \"{template_db}\""
        ))
        .execute(&admin_pool)
        .await
        .expect("failed to create test database");
        drop(admin_pool);

        // Connect to the cloned database.
        let db_url = replace_db_name(&admin_url, &db_name);
        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("failed to connect to test database");

        // Build a minimal config pointing at the test database and Redis
        let mut config = test_config(&db_url, &redis_url);
        configure(&mut config);
        let state = AppState::from_config_with_pool(config, db.clone())
            .await
            .expect("failed to build app state");

        let redis = state.redis.clone();
        let state_clone = state.clone();
        let app = handlers::router(state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test listener");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            db,
            db_url,
            redis,
            client,
            state: state_clone,
            db_name,
            admin_url,
            mailpit_api_port: None,
        }
    }

    /// Spawn the app with SMTP wired to the shared Mailpit instance so that
    /// emails sent during the test can be inspected via `self.mailpit()`.
    pub async fn spawn_with_mailpit() -> Self {
        Self::spawn_with_mailpit_and_config(|_| {}).await
    }

    /// Spawn with both Mailpit wiring and a custom config closure.
    pub async fn spawn_with_mailpit_and_config<F>(configure: F) -> Self
    where
        F: FnOnce(&mut Config),
    {
        let ports = super::mailpit::mailpit_ports().await;

        let smtp_port = ports.smtp_port;
        let api_port = ports.api_port;

        let mut app = Self::spawn_with_config(move |c| {
            // Point SMTP at Mailpit.  Empty username triggers the plain
            // (no-TLS) transport branch in build_mailer().
            c.mail.smtp.host = "127.0.0.1".into();
            c.mail.smtp.port = smtp_port;
            c.mail.smtp.username = String::new();
            c.mail.smtp.password = String::new();
            configure(c);
        })
        .await;

        app.mailpit_api_port = Some(api_port);
        app
    }

    /// Return a Mailpit client for this app.
    ///
    /// Panics if the app was not spawned with `spawn_with_mailpit[_and_config]()`.
    pub fn mailpit(&self) -> super::mailpit::MailpitClient {
        let port = self
            .mailpit_api_port
            .expect("TestApp was not spawned with spawn_with_mailpit()");
        super::mailpit::MailpitClient::new(port)
    }

    pub async fn post<B: Serialize>(&self, path: &str, body: &B) -> Response {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn post_auth<B: Serialize>(&self, path: &str, token: &str, body: &B) -> Response {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn get_auth(&self, path: &str, token: &str) -> Response {
        self.client
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn patch_auth<B: Serialize>(&self, path: &str, token: &str, body: &B) -> Response {
        self.client
            .patch(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn delete_auth(&self, path: &str, token: &str) -> Response {
        self.client
            .delete(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .send()
            .await
            .expect("request failed")
    }

    /// Delete the Redis anti-spam cooldown key for email 2FA.
    /// Call this after setup verification so the next login can auto-dispatch an OTP.
    pub async fn clear_email_2fa_cooldown(&self, user_id: uuid::Uuid) {
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("email2fa_cd:{}", user_id);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    /// Read and brute-force the active OTP for an email-change flow token.
    /// The OTP is stored as a base64url-encoded SHA-256 hash inside the Redis flow state.
    pub async fn read_email_change_otp(&self, flow_token: &str) -> String {
        use base64::Engine;

        let mut conn = self.redis.get().await.expect("redis connection failed");
        let key = format!("email_change_flow:{}", flow_token);
        let raw: String = conn
            .get::<_, String>(&key)
            .await
            .expect("email_change flow state not found in Redis");

        let state: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let hash_b64 = state["otp_hash"]
            .as_str()
            .expect("otp_hash missing from flow state");
        let hash_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(hash_b64)
            .unwrap();

        brute_force_otp(&hash_bytes)
    }

    /// Clear the per-user email-change cooldown so tests can run a second flow immediately.
    pub async fn clear_email_change_cooldown(&self, user_id: uuid::Uuid) {
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("email_change_cd:{}", user_id);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    pub async fn clear_recent_reauth(&self, access_token: &str) {
        let claims = rust_api::utils::jwt::decode_token(access_token, TEST_JWT_SECRET)
            .expect("failed to decode test access token");

        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("reauth:{}", claims.sid);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    /// Clear the per-IP rate limit sorted set key (general bucket: `rl:{ip}`).
    pub async fn clear_rate_limit_key(&self, ip: &str) {
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("rl:{}", ip);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    /// Clear the per-IP auth rate limit sorted set key (auth bucket: `rl_auth:{ip}`).
    pub async fn clear_auth_rate_limit_key(&self, ip: &str) {
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("rl_auth:{}", ip);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    /// Clear the per-IP forgot-password rate limiter key (limit: 5/15 min).
    pub async fn clear_forgot_password_rate_limit(&self, ip: &str) {
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("fp_req:{}", ip);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    /// Clear the per-IP reset-password attempt counter (limit: 10/hour).
    pub async fn clear_reset_password_rate_limit(&self, ip: &str) {
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("rp_fail:{}", ip);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    /// Clear the per-IP email-verification attempt counter (limit: 10/hour).
    pub async fn clear_verify_email_rate_limit(&self, ip: &str) {
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("vf_fail:{}", ip);
            let _: Result<(), _> = conn.del(&key).await;
        }
    }

    pub async fn delete_auth_json<B: serde::Serialize>(
        &self,
        path: &str,
        token: &str,
        body: &B,
    ) -> Response {
        self.client
            .delete(format!("{}{}", self.base_url, path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .expect("request failed")
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let db_name = self.db_name.clone();

        // Best-effort cleanup - runs in a blocking context since Drop is sync.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                let Ok(pool) = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&admin_url)
                    .await
                else {
                    return;
                };

                let _ = sqlx::query(&format!(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{db_name}' AND pid <> pg_backend_pid()"
                ))
                .execute(&pool)
                .await;

                let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"))
                    .execute(&pool)
                    .await;
            });
        });
    }
}

// Build a test config without needing a full .env file.
fn test_config(db_url: &str, redis_url: &str) -> Config {
    #[allow(unused_imports)]
    use rust_api::config::*;

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
            max_connections: 10,
            min_connections: 1,
            acquire_timeout_secs: 30,
        },
        redis: RedisConfig {
            url: redis_url.into(),
            pool_size: 5,
            wait_timeout_ms: 2000,
        },
        jwt: JwtConfig {
            secret: TEST_JWT_SECRET.into(),
            previous_secret: None,
            access_expiry_secs: 900,
            refresh_expiry_secs: 86400,
            short_session_expiry_secs: 3600,
            strict_session_binding: false,
            max_session_lifetime_secs: 60 * 60 * 24 * 90,
        },
        crypto: CryptoConfig {
            argon2_memory_kib: 8192, // low for tests
            argon2_iterations: 1,
            argon2_parallelism: 1,
            totp_issuer: "test".into(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            previous_encryption_key: None,
            totp_skew: 1,
            recovery_code_expiry_days: 365,
        },
        rate_limit: RateLimitConfig {
            requests_per_minute: 10_000,
            auth_requests_per_minute: 10_000,
            fail_open_on_redis_error: true,
            allow_requests_without_ip: true,
        },
        security: SecurityConfig {
            lockout_threshold: 3, // low threshold so tests don't need 10 failures
            lockout_duration_secs: 1800,
            sensitive_action_reauth_secs: 600,
        },
        captcha: CaptchaConfig {
            secret: None, // disabled in tests
            verify_url: "https://hcaptcha.com/siteverify".into(),
            request_timeout_secs: 1,
            fail_open_on_error: false,
        },
        cors: CorsConfig {
            allowed_origins: vec!["*".into()],
            allow_credentials: false,
        },
        mail: MailConfig {
            smtp: SmtpConfig {
                host: String::new(), // empty → send() skips silently, no WARN
                port: 1025,
                username: String::new(),
                password: String::new(),
                from_name: "Test".into(),
                from_address: "test@example.com".into(),
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

/// Brute-force a 6-digit OTP from its SHA-256 hash (tries all 1 000 000 possibilities).
fn brute_force_otp(expected_hash: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    for n in 0u32..1_000_000 {
        let candidate = format!("{:06}", n);
        let h = Sha256::digest(candidate.as_bytes());
        if h.as_slice() == expected_hash {
            return candidate;
        }
    }
    panic!("OTP not found in 6-digit space - unexpected hash");
}

/// Return a Redis URL pointing at a specific logical DB number.
/// Strips any existing `/N` DB suffix before appending the new one.
pub fn redis_url_with_db(base: &str, db: u8) -> String {
    // Strip an existing numeric DB suffix (e.g. "redis://host:6379/1" → "redis://host:6379")
    let stripped = if let Some(pos) = base.rfind('/') {
        let suffix = &base[pos + 1..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            &base[..pos]
        } else {
            base
        }
    } else {
        base
    };
    format!("{}/{}", stripped, db)
}

// Replace the database name in a PostgreSQL connection URL.
fn replace_db_name(url: &str, new_db: &str) -> String {
    // postgres://user:pass@host:port/dbname
    if let Some(slash_pos) = url.rfind('/') {
        format!("{}/{}", &url[..slash_pos], new_db)
    } else {
        format!("{}/{}", url, new_db)
    }
}

async fn ensure_template_database(admin_url: &str) -> String {
    TEMPLATE_DB
        .get_or_init(|| async {
            let template_db = format!("rust_api_http_template_{}", std::process::id());

            let admin_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(admin_url)
                .await
                .expect("failed to connect to admin database for template setup");

            let _ = sqlx::query(&format!(
                "DROP DATABASE IF EXISTS \"{template_db}\" WITH (FORCE)"
            ))
            .execute(&admin_pool)
            .await;

            sqlx::query(&format!(
                "CREATE DATABASE \"{template_db}\" TEMPLATE template0"
            ))
            .execute(&admin_pool)
            .await
            .expect("failed to create template test database");
            drop(admin_pool);

            let template_url = replace_db_name(admin_url, &template_db);
            let template_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&template_url)
                .await
                .expect("failed to connect to template test database");

            let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("./migrations"))
                .await
                .expect("failed to load migrations for template test database");

            migrator
                .run(&template_pool)
                .await
                .expect("failed to run migrations on template test database");

            drop(template_pool);

            template_db
        })
        .await
        .clone()
}
