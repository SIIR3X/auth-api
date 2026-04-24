//! TOTP encryption key rotation tests.
//!
//! Strategy:
//!   1. Spawn a TestApp with KEY_A (the default test encryption key).
//!   2. Set up TOTP for a user via HTTP → secret stored encrypted with KEY_A.
//!   3. Build a second AppState (same DB pool, no HTTP server) configured with
//!      previous_encryption_key = KEY_A and encryption_key = KEY_B.
//!   4. Call `rotate_totp_encryption_key` directly.
//!   5. Assertions:
//!      - RotationResult.rotated == 1, .failed == 0.
//!      - The DB secret can now be decrypted with KEY_B.
//!      - The DB secret can no longer be decrypted with KEY_A.
//!      - A second rotation with identical keys is rejected with an error.
//!      - Rotation without previous_encryption_key configured is rejected.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use uuid::Uuid;

use auth_api::{
    services::key_rotation::rotate_totp_encryption_key, state::AppState, utils::crypto,
};

use crate::common::{app::TestApp, fixtures};

// Key constants

/// The default test encryption key used by TestApp (32 zero bytes, base64-encoded).
const KEY_A_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// A distinct second key (32 bytes of value 1, base64-encoded).
const KEY_B_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

// helpers

/// Set up TOTP for `user` and return the method ID (UUID).
async fn setup_totp(app: &TestApp, access_token: &str) -> Uuid {
    use serde_json::Value;
    use totp_rs::{Algorithm, Secret, TOTP};

    let res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp setup failed");
    let body: Value = res.json().await.unwrap();
    let method_id_str = body["method_id"].as_str().unwrap().to_owned();
    let base32_secret = body["base32_secret"].as_str().unwrap().to_owned();

    let bytes = Secret::Encoded(base32_secret).to_bytes().unwrap();
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes).unwrap();
    let code = totp.generate_current().unwrap();

    let res = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{}/verify", method_id_str),
            access_token,
            &serde_json::json!({ "code": code }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200, "totp verify_setup failed");

    Uuid::parse_str(&method_id_str).unwrap()
}

/// Build an AppState that shares the TestApp's DB pool but uses new key config.
/// Redis URL is read from the test environment (same as TestApp).
async fn build_rotation_state(
    db: sqlx::PgPool,
    prev_key: Option<&str>,
    new_key: &str,
    redis_url: &str,
) -> AppState {
    #[allow(unused_imports)]
    use auth_api::config::*;

    let mut config = Config {
        env: Environment::Test,
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            public_url: "http://localhost".into(),
            trusted_proxy_cidrs: Vec::new(),
        },
        database: DatabaseConfig {
            url: "unused".into(),
            max_connections: 1,
            min_connections: 1,
            acquire_timeout_secs: 5,
        },
        redis: RedisConfig {
            url: redis_url.into(),
            pool_size: 2,
            wait_timeout_ms: 2000,
        },
        jwt: JwtConfig {
            secret: "test-secret-that-is-long-enough-for-hs256".into(),
            previous_secret: None,
            access_expiry_secs: 900,
            refresh_expiry_secs: 86400,
            short_session_expiry_secs: 3600,
            strict_session_binding: false,
            max_session_lifetime_secs: 60 * 60 * 24 * 90,
        },
        crypto: CryptoConfig {
            argon2_memory_kib: 8192,
            argon2_iterations: 1,
            argon2_parallelism: 1,
            totp_issuer: "test".into(),
            encryption_key: new_key.into(),
            previous_encryption_key: prev_key.map(|s| s.into()),
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
                host: "localhost".into(),
                port: 1025,
                username: "".into(), // empty → builder_dangerous (no TLS, no auth)
                password: "".into(),
                from_name: "Test".into(),
                from_address: "test@example.com".into(),
            },
            templates_dir: "templates".into(),
            default_locale: "en".into(),
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
            level: "error".into(),
            format: LogFormat::Pretty,
        },
    };

    // Disable config.validate()'s key-equality check by pointing database.url
    // at something that won't be opened (we supply the pool directly).
    config.database.url = "postgres://unused/unused".into();

    AppState::from_config_with_pool(config, db)
        .await
        .expect("failed to build rotation AppState")
}

fn redis_url() -> String {
    std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
}

// Tests

#[tokio::test]
async fn rotate_totp_key_re_encrypts_secret_successfully() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 400).await;
    let method_id = setup_totp(&app, &user.access_token).await;

    // Read the encrypted secret stored with KEY_A.
    let encrypted_before: String =
        sqlx::query_scalar("SELECT totp_secret FROM two_factor_methods WHERE id = $1")
            .bind(method_id)
            .fetch_one(&app.db)
            .await
            .expect("method not found");

    // Verify it decrypts with KEY_A.
    let key_a: [u8; 32] = B64.decode(KEY_A_B64).unwrap().try_into().unwrap();
    let plaintext_original = crypto::decrypt(&encrypted_before, &key_a)
        .expect("encrypted_before must decrypt with KEY_A");

    // Build rotation state: previous = KEY_A, current = KEY_B.
    let state =
        build_rotation_state(app.db.clone(), Some(KEY_A_B64), KEY_B_B64, &redis_url()).await;

    let result = rotate_totp_encryption_key(&state)
        .await
        .expect("rotation must succeed");

    assert_eq!(result.rotated, 1, "expected 1 rotated secret");
    assert_eq!(result.failed, 0, "expected 0 failures");

    // Read the secret again.
    let encrypted_after: String =
        sqlx::query_scalar("SELECT totp_secret FROM two_factor_methods WHERE id = $1")
            .bind(method_id)
            .fetch_one(&app.db)
            .await
            .expect("method not found after rotation");

    // Must differ (new nonce + new key).
    assert_ne!(
        encrypted_after, encrypted_before,
        "ciphertext must change after rotation"
    );

    // Must decrypt with KEY_B and yield the same plaintext.
    let key_b: [u8; 32] = B64.decode(KEY_B_B64).unwrap().try_into().unwrap();
    let plaintext_after =
        crypto::decrypt(&encrypted_after, &key_b).expect("encrypted_after must decrypt with KEY_B");
    assert_eq!(
        plaintext_after, plaintext_original,
        "plaintext must be preserved after rotation"
    );

    // Must NOT decrypt with KEY_A anymore.
    assert!(
        crypto::decrypt(&encrypted_after, &key_a).is_err(),
        "re-encrypted secret must not be readable with old key"
    );
}

#[tokio::test]
async fn rotate_totp_key_with_multiple_users_rotates_all() {
    let app = TestApp::spawn().await;

    // Set up TOTP for two separate users.
    let u1 = fixtures::authenticated_user(&app, 401).await;
    let u2 = fixtures::authenticated_user(&app, 402).await;
    setup_totp(&app, &u1.access_token).await;
    setup_totp(&app, &u2.access_token).await;

    let state =
        build_rotation_state(app.db.clone(), Some(KEY_A_B64), KEY_B_B64, &redis_url()).await;

    let result = rotate_totp_encryption_key(&state)
        .await
        .expect("rotation must succeed");

    assert_eq!(result.rotated, 2, "expected both secrets rotated");
    assert_eq!(result.failed, 0);
}

#[tokio::test]
async fn rotate_totp_key_fails_when_previous_key_not_configured() {
    let app = TestApp::spawn().await;

    let state = build_rotation_state(
        app.db.clone(),
        None, // no previous key
        KEY_A_B64,
        &redis_url(),
    )
    .await;

    let err = rotate_totp_encryption_key(&state).await;
    assert!(
        err.is_err(),
        "rotation must fail when previous_encryption_key is not set"
    );
}

#[tokio::test]
async fn rotate_totp_key_fails_when_keys_are_identical() {
    let app = TestApp::spawn().await;

    // previous = current = KEY_A → should be caught and rejected.
    let state =
        build_rotation_state(app.db.clone(), Some(KEY_A_B64), KEY_A_B64, &redis_url()).await;

    let err = rotate_totp_encryption_key(&state).await;
    assert!(
        err.is_err(),
        "rotation must fail when old and new keys are identical"
    );
}

#[tokio::test]
async fn rotate_totp_key_no_op_when_no_totp_methods_exist() {
    // No TOTP methods set up → rotated = 0, failed = 0, no error.
    let app = TestApp::spawn().await;
    // Just register but don't set up TOTP.
    let _user = fixtures::authenticated_user(&app, 403).await;

    let state =
        build_rotation_state(app.db.clone(), Some(KEY_A_B64), KEY_B_B64, &redis_url()).await;

    let result = rotate_totp_encryption_key(&state)
        .await
        .expect("rotation must not error");
    assert_eq!(result.rotated, 0);
    assert_eq!(result.failed, 0);
}
