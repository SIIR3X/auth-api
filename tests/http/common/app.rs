//! TestApp: real Axum server on a random port with an isolated database.

#![allow(dead_code)]

use reqwest::{Client, Response};
use tracing_subscriber::EnvFilter;
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::net::TcpListener;

use rust_api::{config::Config, handlers, state::AppState};

// Environment variable names for test infrastructure
const TEST_DATABASE_URL: &str = "TEST_DATABASE_URL";
const TEST_REDIS_URL: &str = "TEST_REDIS_URL";

pub struct TestApp {
    pub base_url: String,
    pub db: PgPool,
    pub client: Client,
    db_name: String,
    admin_url: String,
}

impl TestApp {
    pub async fn spawn() -> Self {
        // Initialize tracing once — subsequent calls are no-ops.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("rust_api=debug")),
            )
            .try_init();

        dotenvy::dotenv().ok();

        let admin_url = std::env::var(TEST_DATABASE_URL)
            .expect("TEST_DATABASE_URL must be set");
        let redis_url = std::env::var(TEST_REDIS_URL)
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".into());

        let db_name = format!("rust_api_http_test_{}", uuid::Uuid::new_v4().simple());

        // Create isolated test database
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .expect("failed to connect to admin database");

        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin_pool)
            .await
            .expect("failed to create test database");
        drop(admin_pool);

        // Connect to the new database and run migrations
        let db_url = replace_db_name(&admin_url, &db_name);
        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("failed to connect to test database");

        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("failed to run migrations");

        // Build a minimal config pointing at the test database and Redis
        let config = test_config(&db_url, &redis_url);
        let state = AppState::from_config_with_pool(config, db.clone()).await
            .expect("failed to build app state");

        let app = handlers::router(state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test listener");
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            db,
            client,
            db_name,
            admin_url,
        }
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
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let db_name = self.db_name.clone();

        // Best-effort cleanup — runs in a blocking context since Drop is sync.
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
    use rust_api::config::*;

    Config {
        env: Environment::Test,
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            public_url: "http://localhost".into(),
        },
        database: DatabaseConfig {
            url: db_url.into(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout_secs: 5,
        },
        redis: RedisConfig {
            url: redis_url.into(),
            pool_size: 5,
        },
        jwt: JwtConfig {
            secret: "test-secret-that-is-long-enough-for-hs256".into(),
            access_expiry_secs: 900,
            refresh_expiry_secs: 86400,
        },
        crypto: CryptoConfig {
            argon2_memory_kib: 8192, // low for tests
            argon2_iterations: 1,
            argon2_parallelism: 1,
            totp_issuer: "test".into(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        },
        rate_limit: RateLimitConfig {
            requests_per_second: 1000,
            burst_size: 1000,
        },
        mail: MailConfig {
            smtp: SmtpConfig {
                host: "localhost".into(),
                port: 1025,
                username: "test".into(),
                password: "test".into(),
                from_name: "Test".into(),
                from_address: "test@example.com".into(),
            },
            templates_dir: "templates".into(),
            default_locale: "en".into(),
        },
        log: LogConfig {
            level: "error".into(),
            format: LogFormat::Pretty,
        },
    }
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
