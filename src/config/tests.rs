//! Configuration loading and validation tests.

use base64::{Engine, engine::general_purpose::STANDARD};

use super::*;
#[allow(unused_imports)]
use super::{env_vars::*, validate::*};

const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgL+1qOaZ7C+H1mGbV\njUP83/W450N4GfOnZSrQ7P//4Y2hRANCAAR4BApTJy8Anvp+O7YNVlTeCbBZ+1YJ\nk+r5ELHGFIXciAEGSrCTOkCm3yChSYroYWLE3ZN4reh6JDbIMX/QnBGx\n-----END PRIVATE KEY-----";
const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeAQKUycvAJ76fju2DVZU3gmwWftW\nCZPq+RCxxhSF3IgBBkqwkzpApt8goUmK6GFixN2TeK3oeiQ2yDF/0JwRsQ==\n-----END PUBLIC KEY-----";

fn valid_config() -> Config {
    Config {
        env: Environment::Production,
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 3000,
            public_url: "https://api.example.com".into(),
            frontend_url: "https://api.example.com".into(),
            trusted_proxy_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
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
            encryption_key: "VVKGNsojoT/vVMlGypXnqcCcJIbrPKbn/8DGfEs496k=".into(),
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
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_PREVIOUS_PUBLIC_KEY"));
}

#[test]
fn validate_accepts_valid_previous_encryption_key() {
    let mut config = valid_config();
    config.crypto.previous_encryption_key =
        Some("6QoHPPjm9EnjsuRmj7OXQrYh98XIvrWYbI5KQyglMNc=".into());

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
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "PREVIOUS_ENCRYPTION_KEY"));
}

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
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_STRICT_SESSION_BINDING"));
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

// Production hardening added with strict configuration loading.

#[test]
fn validate_rejects_empty_trusted_proxies_in_production() {
    let mut config = valid_config();
    config.server.trusted_proxy_cidrs = vec![];

    let err = config.validate().expect_err("empty proxies must fail");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "TRUSTED_PROXY_CIDRS"));
}

#[test]
fn validate_rejects_committed_dev_encryption_key_in_production() {
    let mut config = valid_config();
    config.crypto.encryption_key = DEV_ENCRYPTION_KEYS[0].into();

    let err = config.validate().expect_err("dev AES key must fail");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "ENCRYPTION_KEY"));
}

#[test]
fn validate_rejects_arithmetic_encryption_key_in_production() {
    let mut config = valid_config();
    let counted: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(3)).collect();
    config.crypto.previous_encryption_key = Some(STANDARD.encode(counted));

    let err = config.validate().expect_err("counted key must fail");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "PREVIOUS_ENCRYPTION_KEY"));
}

#[test]
fn validate_accepts_dev_encryption_key_outside_production() {
    let mut config = valid_config();
    config.env = Environment::Development;
    config.crypto.encryption_key = DEV_ENCRYPTION_KEYS[0].into();

    assert!(config.validate().is_ok());
}

#[test]
fn env_string_treats_blank_as_unset() {
    // SAFETY: key names are unique to this test; no other thread reads them.
    unsafe { std::env::set_var("AUTH_API_TEST_BLANK_STRING", "   ") };
    assert_eq!(env_string("AUTH_API_TEST_BLANK_STRING"), None);
}

#[test]
fn env_parse_rejects_unparsable_values() {
    // SAFETY: key names are unique to this test; no other thread reads them.
    unsafe { std::env::set_var("AUTH_API_TEST_BAD_NUMBER", "1O") };
    let parsed: Result<Option<u32>, _> = env_parse("AUTH_API_TEST_BAD_NUMBER");

    assert!(
        matches!(parsed, Err(ConfigError::Invalid { key, .. }) if key == "AUTH_API_TEST_BAD_NUMBER")
    );
}

#[test]
fn env_parse_accepts_absent_and_valid_values() {
    // SAFETY: key names are unique to this test; no other thread reads them.
    unsafe { std::env::set_var("AUTH_API_TEST_GOOD_NUMBER", " 42 ") };
    let absent: Option<u32> = env_parse("AUTH_API_TEST_ABSENT_NUMBER").unwrap();
    let present: Option<u32> = env_parse("AUTH_API_TEST_GOOD_NUMBER").unwrap();

    assert_eq!(absent, None);
    assert_eq!(present, Some(42));
}

#[test]
fn ensure_self_in_audience_is_idempotent() {
    let mut config = valid_config();
    config.ensure_self_in_audience();
    config.ensure_self_in_audience();

    let own = config.server.public_url.clone();
    assert_eq!(config.jwt.audience.iter().filter(|a| **a == own).count(), 1);
}

#[test]
fn validate_rejects_non_https_frontend_url_in_production() {
    let mut config = valid_config();
    config.server.frontend_url = "http://app.example.com".into();

    let err = config.validate().unwrap_err();

    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "FRONTEND_URL"));
}
