//! TestApp: the real router on a random port, backed by its own database.
//!
//! Every app gets a fresh database cloned from the migrated template, a
//! [`TestClock`] installed as the application clock, and a [`MailOutbox`]
//! capturing what it sends. Its requests are attributed to a client address
//! unique to the app, so per-address budgets never leak between tests.

use std::sync::Arc;

use auth_api::{
    config::Config,
    handlers,
    services::mailer::Mailer,
    state::AppState,
    utils::{
        jwt::{self, Claims},
        redis_pool::RedisPool,
    },
};
use deadpool_redis::redis::AsyncCommands;
use reqwest::{Client, Response};
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{
    clock::TestClock,
    contract,
    db::TestDb,
    env,
    faults::FaultProxy,
    keys,
    mail::MailOutbox,
    mailpit::{self, MailpitClient},
};

type Configure = Box<dyn FnOnce(&mut Config) + Send>;

/// Options of a [`TestApp`] beyond its configuration.
#[derive(Default)]
pub struct TestAppBuilder {
    configure: Vec<Configure>,
    mailpit: bool,
    fault_proxies: bool,
    no_event_relay: bool,
}

impl TestAppBuilder {
    pub fn config(mut self, configure: impl FnOnce(&mut Config) + Send + 'static) -> Self {
        self.configure.push(Box::new(configure));
        self
    }

    /// Send mail over SMTP to the shared Mailpit instead of capturing it.
    pub fn smtp_to_mailpit(mut self) -> Self {
        self.mailpit = true;
        self
    }

    /// Reach PostgreSQL, Redis and NATS through [`FaultProxy`]s, available in
    /// [`TestApp::dependencies`]. The test's own `db` pool stays direct.
    pub fn fault_proxies(mut self) -> Self {
        self.fault_proxies = true;
        self
    }

    /// Leave the event relay off, for tests that drive `relay_once` themselves.
    pub fn without_event_relay(mut self) -> Self {
        self.no_event_relay = true;
        self
    }

    pub async fn spawn(self) -> TestApp {
        let Self {
            configure,
            mailpit,
            fault_proxies,
            no_event_relay,
        } = self;
        TestApp::spawn_inner(mailpit, fault_proxies, !no_event_relay, move |config| {
            for configure in configure {
                configure(config);
            }
        })
        .await
    }
}

/// The dependencies of an app spawned with [`TestAppBuilder::fault_proxies`].
pub struct Dependencies {
    pub postgres: FaultProxy,
    pub redis: FaultProxy,
    pub nats: FaultProxy,
}

pub struct TestApp {
    pub base_url: String,
    /// Client address this app's requests are attributed to (forwarded through
    /// the trusted loopback proxy).
    pub client_ip: String,
    /// Direct pool to the app's database, for setup and assertions.
    pub db: PgPool,
    pub db_url: String,
    pub redis: RedisPool,
    pub client: Client,
    pub state: AppState,
    pub clock: TestClock,
    pub mail: MailOutbox,
    pub dependencies: Option<Dependencies>,
    /// Responses outside the OpenAPI contract, checked when the app is dropped.
    pub contract: contract::Recorder,
    server: JoinHandle<()>,
    /// The event relay: stopped before the database is dropped, or a connection
    /// it opens while `DROP DATABASE ... WITH (FORCE)` runs holds the drop until
    /// PostgreSQL's 60-second authentication timeout.
    relay: Option<JoinHandle<()>>,
    mailpit_api_port: Option<u16>,
    // Declared last: dropped after everything holding a connection to it.
    _database: TestDb,
}

impl TestApp {
    pub fn builder() -> TestAppBuilder {
        TestAppBuilder::default()
    }

    pub async fn spawn() -> Self {
        Self::spawn_inner(false, false, true, |_| {}).await
    }

    pub async fn spawn_with_config<F>(configure: F) -> Self
    where
        F: FnOnce(&mut Config),
    {
        Self::spawn_inner(false, false, true, configure).await
    }

    /// Spawn the app with SMTP wired to the shared Mailpit instance, for the
    /// few tests covering the SMTP transport itself.
    pub async fn spawn_with_mailpit() -> Self {
        Self::spawn_inner(true, false, true, |_| {}).await
    }

    pub async fn spawn_with_mailpit_and_config<F>(configure: F) -> Self
    where
        F: FnOnce(&mut Config),
    {
        Self::spawn_inner(true, false, true, configure).await
    }

    async fn spawn_inner<F>(
        mailpit: bool,
        fault_proxies: bool,
        event_relay: bool,
        configure: F,
    ) -> Self
    where
        F: FnOnce(&mut Config),
    {
        crate::init_tracing();

        let database = TestDb::new().await;
        let redis_url = env::redis_url();
        let nats_url = env::nats_url();

        let dependencies = if fault_proxies {
            Some(Dependencies {
                postgres: FaultProxy::start(host_port(&database.url, 5432)).await,
                redis: FaultProxy::start(host_port(&redis_url, 6379)).await,
                nats: FaultProxy::start(host_port(&nats_url, 4222)).await,
            })
        } else {
            None
        };
        let (app_db_url, app_redis_url, app_nats_url) = match &dependencies {
            Some(d) => (
                through(&database.url, &d.postgres),
                through(&redis_url, &d.redis),
                through(&nats_url, &d.nats),
            ),
            None => (database.url.clone(), redis_url.clone(), nats_url.clone()),
        };

        let mut config = test_config(&app_db_url, &app_redis_url, &app_nats_url);
        let mailpit_ports = mailpit.then(mailpit::mailpit_ports);
        if let Some(ports) = &mailpit_ports {
            // An empty username selects the plain (no TLS) transport.
            config.mail.smtp.host = "127.0.0.1".into();
            config.mail.smtp.port = ports.smtp_port;
            config.mail.smtp.username = String::new();
            config.mail.smtp.password = String::new();
        }
        configure(&mut config);

        let app_pool = if dependencies.is_some() {
            PgPoolOptions::new()
                .max_connections(10)
                .acquire_timeout(std::time::Duration::from_secs(
                    config.database.acquire_timeout_secs,
                ))
                .connect(&app_db_url)
                .await
                .expect("connect to the test database through its proxy")
        } else {
            database.pool.clone()
        };

        let mut state = AppState::from_config_with_pool(config, app_pool)
            .await
            .expect("failed to build app state");
        let clock = TestClock::new();
        state.clock = Arc::new(clock.clone());
        let mail = MailOutbox::new();
        if !mailpit {
            state.mailer = Mailer::new(mail.clone());
        }

        // Events recorded by the requests reach NATS as in production.
        let relay = event_relay
            .then(|| auth_api::services::events::spawn_relay(state.db.clone(), state.nats.clone()));

        let contract = contract::Recorder::default();
        let router = handlers::router(state.clone()).layer(axum::middleware::from_fn_with_state(
            contract.clone(),
            contract::record,
        ));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test listener");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let id = uuid::Uuid::new_v4();
        let b = id.as_bytes();
        let client_ip = format!("10.{}.{}.{}", 100 + b[0] % 100, b[1], 1 + b[2] % 254);
        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(
            "x-forwarded-for",
            client_ip.parse().expect("valid client ip header"),
        );
        let client = Client::builder()
            .default_headers(default_headers)
            .build()
            .unwrap();

        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            client_ip,
            db: database.pool.clone(),
            db_url: database.url.clone(),
            redis: state.redis.clone(),
            client,
            state,
            clock,
            mail,
            dependencies,
            contract,
            server,
            relay,
            mailpit_api_port: mailpit_ports.map(|p| p.api_port),
            _database: database,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Mailpit client of an app spawned with `spawn_with_mailpit`.
    pub fn mailpit(&self) -> MailpitClient {
        let port = self
            .mailpit_api_port
            .expect("TestApp was not spawned with spawn_with_mailpit()");
        MailpitClient::new(port)
    }

    /// Claims of an access token issued by this app, checked like the API does.
    pub fn decode_access_token(&self, token: &str) -> Claims {
        jwt::decode_token(
            token,
            &self.state.jwt_verifying_key,
            self.state.clock.now().unix_timestamp(),
        )
        .expect("failed to decode test access token")
    }

    pub async fn get(&self, path: &str) -> Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("request failed")
    }

    pub async fn post<B: Serialize>(&self, path: &str, body: &B) -> Response {
        self.client
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn post_auth<B: Serialize>(&self, path: &str, token: &str, body: &B) -> Response {
        self.client
            .post(self.url(path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn get_auth(&self, path: &str, token: &str) -> Response {
        self.client
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn patch_auth<B: Serialize>(&self, path: &str, token: &str, body: &B) -> Response {
        self.client
            .patch(self.url(path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn delete_auth(&self, path: &str, token: &str) -> Response {
        self.client
            .delete(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .expect("request failed")
    }

    pub async fn delete_auth_json<B: Serialize>(
        &self,
        path: &str,
        token: &str,
        body: &B,
    ) -> Response {
        self.client
            .delete(self.url(path))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .expect("request failed")
    }

    async fn delete_redis_key(&self, key: &str) {
        if let Ok(mut conn) = self.redis.get().await {
            let _: Result<(), _> = conn.del(key).await;
        }
    }

    /// Delete the anti-spam cooldown of email 2FA, so the next login can send
    /// a code right away.
    pub async fn clear_email_2fa_cooldown(&self, user_id: uuid::Uuid) {
        self.delete_redis_key(&format!("email2fa_cd:{user_id}"))
            .await;
    }

    /// Recover the active OTP of an email-change flow from its hash in Redis.
    pub async fn read_email_change_otp(&self, flow_token: &str) -> String {
        use base64::Engine;

        let mut conn = self.redis.get().await.expect("redis connection failed");
        let raw: String = conn
            .get(format!("email_change_flow:{flow_token}"))
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

    /// Clear the per-user email-change cooldown so a second flow can start.
    pub async fn clear_email_change_cooldown(&self, user_id: uuid::Uuid) {
        self.delete_redis_key(&format!("email_change_cd:{user_id}"))
            .await;
    }

    pub async fn clear_recent_reauth(&self, access_token: &str) {
        let claims = self.decode_access_token(access_token);
        self.delete_redis_key(&format!("reauth:{}", claims.sid))
            .await;
    }

    /// Clear the general rate-limit window of `ip`.
    pub async fn clear_rate_limit_key(&self, ip: &str) {
        self.delete_redis_key(&format!("rl:{ip}")).await;
    }

    /// Clear the auth rate-limit window of `ip`.
    pub async fn clear_auth_rate_limit_key(&self, ip: &str) {
        self.delete_redis_key(&format!("rl_auth:{ip}")).await;
    }

    pub async fn clear_forgot_password_rate_limit(&self, ip: &str) {
        self.delete_redis_key(&format!("fp_req:{ip}")).await;
    }

    pub async fn clear_reset_password_rate_limit(&self, ip: &str) {
        self.delete_redis_key(&format!("rp_fail:{ip}")).await;
    }

    pub async fn clear_verify_email_rate_limit(&self, ip: &str) {
        self.delete_redis_key(&format!("vf_fail:{ip}")).await;
    }

    /// Clear the per-token budget of a verify-email token, so the same token
    /// can be submitted again.
    pub async fn clear_verify_email_token_hash_rate_limit(&self, raw_token: &str) {
        let hash = auth_api::utils::crypto::sha256(raw_token.as_bytes());
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        self.delete_redis_key(&format!("vf_tok:{hex}")).await;
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if let Some(relay) = &self.relay {
            relay.abort();
        }
        self.server.abort();
        contract::settle(&self.contract);
    }
}

/// Configuration of a test app: permissive rate limits, cheap Argon2, the
/// test keys, and no SMTP relay.
pub fn test_config(db_url: &str, redis_url: &str, nats_url: &str) -> Config {
    use auth_api::config::*;

    Config {
        env: Environment::Test,
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            public_url: "http://localhost".into(),
            frontend_url: "http://localhost".into(),
            // The test client talks to the server over loopback and forwards a
            // per-app address in X-Forwarded-For (see `TestApp::client_ip`).
            trusted_proxy_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
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
        nats: NatsConfig {
            url: nats_url.into(),
        },
        jwt: JwtConfig {
            private_key: keys::PRIVATE_KEY_PEM.into(),
            public_key: keys::PUBLIC_KEY_PEM.into(),
            previous_public_key: None,
            next_public_key: None,
            access_expiry_secs: 900,
            refresh_expiry_secs: 86400,
            short_session_expiry_secs: 3600,
            strict_session_binding: false,
            max_session_lifetime_secs: 60 * 60 * 24 * 90,
            audience: Vec::new(),
        },
        crypto: CryptoConfig {
            argon2_memory_kib: 8192,
            argon2_iterations: 1,
            argon2_parallelism: 1,
            argon2_max_concurrency: 4,
            totp_issuer: "test".into(),
            encryption_key: keys::ENCRYPTION_KEY.into(),
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
            lockout_threshold: 3,
            lockout_duration_secs: 1800,
            sensitive_action_reauth_secs: 600,
        },
        captcha: CaptchaConfig {
            secret: None,
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
                host: String::new(),
                port: 1025,
                username: String::new(),
                password: String::new(),
                from_name: "Test".into(),
                from_address: "test@example.com".into(),
            },
            templates_dir: crate::workspace_path("templates")
                .to_string_lossy()
                .into_owned(),
            default_locale: "en".into(),
        },
        cleanup: CleanupConfig {
            interval_secs: 3600,
            sessions_grace_days: 7,
            tokens_grace_days: 1,
            login_attempts_retention_days: 90,
            recovery_codes_grace_days: 7,
            unverified_accounts_retention_days: 7,
        },
        audit: AuditConfig {
            retention_months: 6,
            ip_retention_days: 90,
        },
        log: LogConfig {
            level: "error".into(),
            format: LogFormat::Pretty,
        },
        device_auth: DeviceAuthConfig {
            ttl_secs: 300,
            poll_interval_secs: 5,
            verification_uri: "http://localhost:5173/device".into(),
        },
        metrics: MetricsConfig {
            enabled: false,
            port: 9464,
        },
    }
}

/// Recover a 6-digit OTP from its SHA-256 digest.
pub fn brute_force_otp(expected_hash: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    (0u32..1_000_000)
        .map(|n| format!("{n:06}"))
        .find(|candidate| Sha256::digest(candidate.as_bytes()).as_slice() == expected_hash)
        .expect("OTP not found in the 6-digit space")
}

/// `base` with its logical database number replaced by `db`.
pub fn redis_url_with_db(base: &str, db: u8) -> String {
    let stripped = match base.rfind('/') {
        Some(pos)
            if !base[pos + 1..].is_empty()
                && base[pos + 1..].chars().all(|c| c.is_ascii_digit()) =>
        {
            &base[..pos]
        }
        _ => base,
    };
    format!("{stripped}/{db}")
}

fn host_port(url: &str, default_port: u16) -> String {
    let parsed = reqwest::Url::parse(url).expect("valid dependency URL");
    format!(
        "{}:{}",
        parsed.host_str().expect("dependency URL has a host"),
        parsed.port().unwrap_or(default_port)
    )
}

fn through(url: &str, proxy: &FaultProxy) -> String {
    let mut parsed = reqwest::Url::parse(url).expect("valid dependency URL");
    parsed.set_host(Some("127.0.0.1")).expect("settable host");
    parsed
        .set_port(Some(proxy.addr().port()))
        .expect("settable port");
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_url_with_db_replaces_only_a_numeric_suffix() {
        assert_eq!(redis_url_with_db("redis://h:6380", 2), "redis://h:6380/2");
        assert_eq!(redis_url_with_db("redis://h:6380/1", 3), "redis://h:6380/3");
    }

    #[test]
    fn dependency_urls_are_rewritten_to_the_proxy_port() {
        assert_eq!(host_port("redis://127.0.0.1:6380", 6379), "127.0.0.1:6380");
        assert_eq!(host_port("nats://localhost", 4222), "localhost:4222");
    }

    #[test]
    fn otp_is_recovered_from_its_digest() {
        use sha2::{Digest, Sha256};
        assert_eq!(brute_force_otp(&Sha256::digest(b"004217")), "004217");
    }
}
