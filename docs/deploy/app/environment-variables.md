# Application Server Environment Variables

This document lists the non-sensitive environment variables used by the application server.

Sensitive values must not be stored in `runtime.env`.
They must be stored in `pass` and exported before starting the service.

See:
- [pass-store.md](pass-store.md)
- [secrets.md](secrets.md)

## Runtime File

The application server uses a local runtime file such as:

```text
/srv/rust-api/env/runtime.env
```

## Non-Sensitive Variables

| Variable | Purpose |
| --- | --- |
| `APP_ENV` | Selects the application environment |
| `SERVER_HOST` | Bind address inside the container |
| `SERVER_PORT` | Internal application port |
| `APP_PUBLIC_URL` | Public base URL used for links and security-sensitive flows |
| `TRUSTED_PROXY_CIDRS` | Lists reverse proxies allowed to forward client IP headers |
| `DB_MAX_CONNECTIONS` | Maximum PostgreSQL connections for the application pool |
| `DB_MIN_CONNECTIONS` | Minimum PostgreSQL connections kept ready |
| `DB_ACQUIRE_TIMEOUT_SECS` | Connection acquisition timeout for PostgreSQL |
| `REDIS_POOL_SIZE` | Redis connection pool size |
| `JWT_ACCESS_EXPIRY_SECS` | Access token lifetime |
| `JWT_REFRESH_EXPIRY_SECS` | Refresh token lifetime |
| `JWT_MAX_SESSION_LIFETIME_SECS` | Maximum session lifetime |
| `JWT_STRICT_SESSION_BINDING` | Enables strict session binding checks |
| `ARGON2_MEMORY_KIB` | Memory cost for password hashing |
| `ARGON2_ITERATIONS` | Iteration count for password hashing |
| `ARGON2_PARALLELISM` | Parallelism parameter for password hashing |
| `TOTP_ISSUER` | Issuer label used for TOTP enrollment |
| `TOTP_SKEW` | Accepted TOTP clock drift |
| `RECOVERY_CODE_EXPIRY_DAYS` | Recovery code validity duration |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | Global request rate limit |
| `RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE` | Authentication request rate limit |
| `RATE_LIMIT_FAIL_OPEN` | Controls behavior when Redis-based rate limiting fails |
| `RATE_LIMIT_ALLOW_MISSING_IP` | Controls behavior when the client IP is unavailable |
| `LOCKOUT_THRESHOLD` | Number of failures before lockout |
| `LOCKOUT_DURATION_SECS` | Lockout duration |
| `SENSITIVE_ACTION_REAUTH_SECS` | Fresh reauthentication window for sensitive actions |
| `RISK_GEOIP_DB_PATH` | GeoIP database path used by risk analysis |
| `RISK_GEOIP_REQUIRED` | Fails startup if GeoIP is enabled but missing |
| `RISK_ALERT_THRESHOLD` | Threshold for risk alerts |
| `RISK_CHALLENGE_THRESHOLD` | Threshold for additional user challenge |
| `RISK_BLOCK_THRESHOLD` | Threshold for blocking risky activity |
| `RISK_HISTORY_DAYS` | Number of days of login history used for risk evaluation |
| `CORS_ALLOWED_ORIGINS` | Allowed origins for browser clients |
| `CORS_ALLOW_CREDENTIALS` | Controls credential support in CORS |
| `SMTP_HOST` | SMTP server hostname |
| `SMTP_PORT` | SMTP server port |
| `SMTP_FROM_NAME` | Sender display name |
| `SMTP_FROM_ADDRESS` | Sender email address |
| `MAIL_TEMPLATES_DIR` | Mail template directory |
| `MAIL_DEFAULT_LOCALE` | Default mail locale |
| `CAPTCHA_VERIFY_URL` | CAPTCHA verification endpoint |
| `CAPTCHA_REQUEST_TIMEOUT_SECS` | CAPTCHA verification timeout |
| `CAPTCHA_FAIL_OPEN_ON_ERROR` | Controls CAPTCHA failure behavior on provider error |
| `AUDIT_RETENTION_MONTHS` | Audit log retention period |
| `WEBAUTHN_RP_ID` | WebAuthn relying party ID |
| `WEBAUTHN_RP_ORIGIN` | WebAuthn relying party origin |
| `WEBAUTHN_RP_NAME` | WebAuthn relying party display name |
| `LOG_LEVEL` | Application log verbosity |
| `LOG_FORMAT` | Application log format |
