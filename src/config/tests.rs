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
            url: "nats://broker-token@127.0.0.1:4222".into(),
        },
        jwt: JwtConfig {
            private_key: TEST_PRIVATE_KEY_PEM.into(),
            public_key: TEST_PUBLIC_KEY_PEM.into(),
            previous_public_key: None,
            next_public_key: None,
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
            unverified_accounts_retention_days: 7,
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
fn validate_rejects_a_production_broker_without_credentials() {
    let mut config = valid_config();
    config.nats.url = "nats://127.0.0.1:4222".into();

    let err = config
        .validate()
        .expect_err("an unauthenticated broker must be refused in production");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "NATS_URL"));

    config.env = Environment::Development;
    assert!(
        config.validate().is_ok(),
        "development may use an open broker"
    );
}

#[test]
fn validate_rejects_an_unreadable_broker_url() {
    let mut config = valid_config();
    config.env = Environment::Development;
    config.nats.url = "nats://:password-without-user@127.0.0.1:4222".into();

    let err = config
        .validate()
        .expect_err("an unreadable NATS_URL must be refused");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "NATS_URL"));
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
fn validate_rejects_invalid_next_public_key() {
    let mut config = valid_config();
    config.jwt.next_public_key = Some("not-a-valid-pem".into());

    let err = config
        .validate()
        .expect_err("an unreadable next key must be refused");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_NEXT_PUBLIC_KEY"));
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

fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let map: std::collections::HashMap<String, String> = pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    move |key| map.get(key).cloned()
}

#[test]
fn env_string_treats_blank_as_unset() {
    let env = Env::new(lookup(&[("BLANK", "   "), ("SET", " x ")]));
    assert_eq!(env.string("BLANK"), None);
    assert_eq!(env.string("ABSENT"), None);
    assert_eq!(env.string("SET").as_deref(), Some(" x "));
}

#[test]
fn env_parse_rejects_unparsable_values() {
    let env = Env::new(lookup(&[("BAD_NUMBER", "1O")]));
    let parsed: Result<Option<u32>, _> = env.parse("BAD_NUMBER");

    assert!(matches!(parsed, Err(ConfigError::Invalid { key, .. }) if key == "BAD_NUMBER"));
}

#[test]
fn env_parse_accepts_absent_and_valid_values() {
    let env = Env::new(lookup(&[("GOOD_NUMBER", " 42 ")]));
    assert_eq!(env.parse::<u32>("ABSENT").unwrap(), None);
    assert_eq!(env.parse::<u32>("GOOD_NUMBER").unwrap(), Some(42));
}

/// Load a configuration from the variables every deployment sets, with
/// `overrides` applied and `removed` unset.
fn load(overrides: &[(&str, &str)], removed: &[&str]) -> Result<Config, ConfigError> {
    let private_key = TEST_PRIVATE_KEY_PEM.replace('\n', "\\n");
    let public_key = TEST_PUBLIC_KEY_PEM.replace('\n', "\\n");
    let mut vars: Vec<(&str, &str)> = vec![
        ("APP_ENV", "development"),
        ("DATABASE_URL", "postgres://db/auth"),
        ("REDIS_URL", "redis://redis"),
        ("JWT_PRIVATE_KEY", &private_key),
        ("JWT_PUBLIC_KEY", &public_key),
        ("ENCRYPTION_KEY", "key"),
        ("SMTP_HOST", "smtp.example.com"),
        ("SMTP_USERNAME", "user"),
        ("SMTP_PASSWORD", "password"),
        ("SMTP_FROM_ADDRESS", "no-reply@example.com"),
        ("DEVICE_AUTH_VERIFICATION_URI", "https://example.com/device"),
    ];
    vars.retain(|(key, _)| !removed.contains(key) && !overrides.iter().any(|(k, _)| k == key));
    vars.extend_from_slice(overrides);
    Config::from_lookup(lookup(&vars))
}

#[test]
fn loading_applies_the_documented_defaults() {
    let config = load(&[], &[]).unwrap();

    assert_eq!(config.env, Environment::Development);
    assert_eq!(config.server.port, 3000);
    assert_eq!(config.server.public_url, "http://localhost:3000");
    assert_eq!(config.server.frontend_url, "http://localhost:3000");
    assert!(config.server.trusted_proxy_cidrs.is_empty());
    assert_eq!(config.nats.url, "nats://nats:4222");
    assert_eq!(config.jwt.access_expiry_secs, 900);
    assert_eq!(config.jwt.refresh_expiry_secs, 30 * 86_400);
    assert_eq!(config.jwt.short_session_expiry_secs, 86_400);
    assert_eq!(config.jwt.max_session_lifetime_secs, 90 * 86_400);
    assert!(!config.jwt.strict_session_binding);
    assert_eq!(
        config.jwt.private_key, TEST_PRIVATE_KEY_PEM,
        "escaped newlines are restored"
    );
    assert_eq!(config.security.lockout_threshold, 10);
    assert_eq!(config.security.lockout_duration_secs, 1800);
    assert_eq!(config.cors.allowed_origins, vec!["http://localhost:3000"]);
    assert_eq!(config.captcha.secret, None);
    assert_eq!(config.mail.default_locale, "en");
    assert_eq!(config.device_auth.poll_interval_secs, 5);
    assert_eq!(config.database.acquire_timeout_secs, 5);
    assert_eq!(config.jwt.next_public_key, None);
    assert!(
        config.rate_limit.fail_open_on_redis_error,
        "development fails open"
    );
    assert!(config.rate_limit.allow_requests_without_ip);
    assert!(config.captcha.fail_open_on_error);
}

#[test]
fn debug_output_never_prints_a_secret() {
    let mut config = valid_config();
    config.crypto.previous_encryption_key = Some(config.crypto.encryption_key.clone());
    config.captcha.secret = Some("captcha-secret-value".into());
    config.mail.smtp.password = "smtp-password-value".into();
    let printed = format!("{config:?}");

    for secret in [
        config.database.url.as_str(),
        config.redis.url.as_str(),
        config.nats.url.as_str(),
        config.jwt.private_key.as_str(),
        config.crypto.encryption_key.as_str(),
        "captcha-secret-value",
        "smtp-password-value",
    ] {
        assert!(!printed.contains(secret), "Debug printed {secret:?}");
    }
    assert!(printed.contains("<redacted>"));
    assert!(
        printed.contains("acquire_timeout_secs"),
        "non-secret settings stay visible"
    );
}

#[test]
fn production_defaults_fail_closed() {
    let config = load(&[("APP_ENV", "production")], &[]).unwrap();

    assert!(config.is_production());
    assert!(!config.rate_limit.fail_open_on_redis_error);
    assert!(!config.rate_limit.allow_requests_without_ip);
    assert!(!config.captcha.fail_open_on_error);
}

#[test]
fn loading_reads_lists_flags_and_urls() {
    let config = load(
        &[
            ("SERVER_PORT", " 8080 "),
            ("APP_PUBLIC_URL", "https://auth.example.com"),
            ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 192.168.1.1/32"),
            (
                "JWT_AUDIENCE",
                "https://api.example.com, ,https://files.example.com",
            ),
            ("JWT_STRICT_SESSION_BINDING", "true"),
            (
                "CORS_ALLOWED_ORIGINS",
                "https://a.example.com, https://b.example.com",
            ),
            ("CAPTCHA_SECRET", "   "),
        ],
        &[],
    )
    .unwrap();

    assert_eq!(config.server.port, 8080);
    assert_eq!(
        config.server.frontend_url, "https://auth.example.com",
        "the frontend defaults to the public URL"
    );
    assert_eq!(config.server.trusted_proxy_cidrs.len(), 2);
    assert_eq!(
        config.jwt.audience,
        vec!["https://api.example.com", "https://files.example.com"]
    );
    assert!(config.jwt.strict_session_binding);
    assert_eq!(
        config.cors.allowed_origins,
        vec!["https://a.example.com", "https://b.example.com"]
    );
    assert_eq!(config.captcha.secret, None, "a blank secret is no secret");

    let config = load(&[("FRONTEND_URL", "https://app.example.com/")], &[]).unwrap();
    assert_eq!(config.server.frontend_url, "https://app.example.com");
}

#[test]
fn loading_names_the_variable_at_fault() {
    for key in [
        "APP_ENV",
        "DATABASE_URL",
        "REDIS_URL",
        "JWT_PRIVATE_KEY",
        "JWT_PUBLIC_KEY",
        "ENCRYPTION_KEY",
        "SMTP_HOST",
        "SMTP_FROM_ADDRESS",
        "DEVICE_AUTH_VERIFICATION_URI",
    ] {
        assert!(
            matches!(load(&[], &[key]), Err(ConfigError::Missing(missing)) if missing == key),
            "{key} must be required"
        );
    }

    for (key, value) in [
        ("APP_ENV", "prd"),
        ("SERVER_PORT", "70000"),
        ("LOCKOUT_THRESHOLD", "1O"),
        ("TRUSTED_PROXY_CIDRS", "10.0.0.0/33"),
        ("JWT_STRICT_SESSION_BINDING", "yes"),
    ] {
        assert!(
            matches!(load(&[(key, value)], &[]), Err(ConfigError::Invalid { key: invalid, .. }) if invalid == key),
            "{key}={value} must be refused"
        );
    }
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

#[test]
fn validate_rejects_zero_lockout_threshold() {
    let mut config = valid_config();
    config.security.lockout_threshold = 0;

    let err = config
        .validate()
        .expect_err("a zero lockout threshold should fail");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "LOCKOUT_THRESHOLD"));
}

#[test]
fn validate_rejects_zero_device_poll_interval() {
    let mut config = valid_config();
    config.device_auth.poll_interval_secs = 0;

    let err = config
        .validate()
        .expect_err("a zero poll interval should fail");
    assert!(
        matches!(err, ConfigError::Invalid { key, .. } if key == "DEVICE_AUTH_POLL_INTERVAL_SECS")
    );
}

#[test]
fn validate_rejects_poll_interval_not_below_device_ttl() {
    let mut config = valid_config();
    config.device_auth.ttl_secs = 60;
    config.device_auth.poll_interval_secs = 60;

    let err = config
        .validate()
        .expect_err("a poll interval as long as the code lifetime should fail");
    assert!(
        matches!(err, ConfigError::Invalid { key, .. } if key == "DEVICE_AUTH_POLL_INTERVAL_SECS")
    );
}

#[test]
fn validate_rejects_zero_session_lifetime() {
    let mut config = valid_config();
    config.jwt.max_session_lifetime_secs = 0;

    let err = config
        .validate()
        .expect_err("a zero absolute session lifetime should fail");
    assert!(
        matches!(err, ConfigError::Invalid { key, .. } if key == "JWT_MAX_SESSION_LIFETIME_SECS")
    );
}

/// The production checks also reject most malformed keys, which hid this
/// validator from the tests: it is exercised on its own here.
#[test]
fn encryption_keys_are_checked_for_shape_in_every_environment() {
    let reason = |value: &str| match validate_encryption_key("ENCRYPTION_KEY", value) {
        Err(ConfigError::Invalid { key, reason }) => {
            assert_eq!(key, "ENCRYPTION_KEY");
            reason
        }
        other => panic!("{value:?} was not refused: {other:?}"),
    };

    assert!(reason("not-base64").contains("base64"));
    assert!(reason(&STANDARD.encode([0x5a_u8; 16])).contains("32 bytes"));
    assert!(
        validate_encryption_key(
            "ENCRYPTION_KEY",
            "VVKGNsojoT/vVMlGypXnqcCcJIbrPKbn/8DGfEs496k="
        )
        .is_ok()
    );
}

#[test]
fn a_well_formed_key_with_little_entropy_is_refused() {
    // 32 bytes alternating two values: not an arithmetic sequence, so only the
    // entropy floor (1 bit per byte here) can refuse it.
    let weak = STANDARD.encode([0xab_u8, 0x13].repeat(16));
    match validate_encryption_key("ENCRYPTION_KEY", &weak) {
        Err(ConfigError::Invalid { reason, .. }) => assert!(reason.contains("entropy"), "{reason}"),
        other => panic!("a low-entropy key was accepted: {other:?}"),
    }
}

#[test]
fn a_key_at_exactly_the_entropy_floor_is_accepted() {
    // Eight distinct bytes, four times each: exactly 3.0 bits per byte.
    let bytes = [0x10_u8, 0x9c, 0x2e, 0xf1, 0x47, 0x83, 0x5d, 0xb6].repeat(4);
    assert!(validate_encryption_key("ENCRYPTION_KEY", &STANDARD.encode(bytes)).is_ok());
}

#[test]
fn the_previous_encryption_key_is_optional_but_checked_when_set() {
    assert!(validate_optional_encryption_key("PREVIOUS_ENCRYPTION_KEY", None).is_ok());
    let err = validate_optional_encryption_key("PREVIOUS_ENCRYPTION_KEY", Some("not-base64"))
        .expect_err("a malformed previous key should fail");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "PREVIOUS_ENCRYPTION_KEY"));
}

#[test]
fn argon2_needs_at_least_one_concurrent_hash() {
    let mut crypto = valid_config().crypto;
    crypto.argon2_max_concurrency = 0;
    let err = validate_crypto(&crypto).expect_err("zero concurrency should fail");
    assert!(matches!(err, ConfigError::Invalid { key, .. } if key == "ARGON2_MAX_CONCURRENCY"));
    crypto.argon2_max_concurrency = 1;
    assert!(validate_crypto(&crypto).is_ok());
}

#[test]
fn remember_me_selects_the_long_session_lifetime() {
    let mut jwt = valid_config().jwt;
    jwt.refresh_expiry_secs = 30;
    jwt.short_session_expiry_secs = 1;
    assert_eq!(jwt.session_ttl_secs(true), 30);
    assert_eq!(jwt.session_ttl_secs(false), 1);
}
