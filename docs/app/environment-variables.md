# Application Server Environment Variables

Sensitive values must not be placed in `runtime.env`.

Put secrets in:
- [pass-store.md](./pass-store.md)

## Non-Sensitive Variables

| Variable | Purpose |
| --- | --- |
| `APP_ENV` | Selects the runtime environment. |
| `SERVER_HOST` | Bind address used by the application inside the container. |
| `SERVER_PORT` | Port used by the application inside the container. |
| `APP_PUBLIC_URL` | Public base URL used in links and callbacks. |
| `TRUSTED_PROXY_CIDRS` | Proxy CIDRs allowed to supply forwarded client IP headers. |
| `DB_MAX_CONNECTIONS` | Maximum size of the PostgreSQL connection pool. |
| `DB_MIN_CONNECTIONS` | Minimum number of idle PostgreSQL connections kept ready. |
| `DB_ACQUIRE_TIMEOUT_SECS` | Timeout when waiting for a PostgreSQL connection. |
| `REDIS_POOL_SIZE` | Size of the Redis connection pool. |
| `JWT_ACCESS_EXPIRY_SECS` | Access token lifetime. |
| `JWT_REFRESH_EXPIRY_SECS` | Refresh token lifetime. |
| `JWT_MAX_SESSION_LIFETIME_SECS` | Maximum session lifetime regardless of refresh activity. |
| `JWT_STRICT_SESSION_BINDING` | Enables strict session IP binding on refresh. |
| `ARGON2_MEMORY_KIB` | Argon2 memory cost. |
| `ARGON2_ITERATIONS` | Argon2 time cost. |
| `ARGON2_PARALLELISM` | Argon2 parallelism factor. |
| `TOTP_ISSUER` | Label shown by authenticator apps. |
| `TOTP_SKEW` | Accepted TOTP clock skew window. |
| `RECOVERY_CODE_EXPIRY_DAYS` | Lifetime of recovery codes. |
| `RATE_LIMIT_RPM` | General per-IP request limit. |
| `RATE_LIMIT_AUTH_RPM` | Stricter per-IP limit for authentication routes. |
| `RATE_LIMIT_FAIL_OPEN` | Controls whether Redis failures allow traffic through. |
| `RATE_LIMIT_ALLOW_MISSING_IP` | Controls whether requests with no resolved IP are accepted. |
| `LOCKOUT_THRESHOLD` | Number of failures before account lockout. |
| `LOCKOUT_DURATION_SECS` | Duration of an account lockout. |
| `SENSITIVE_ACTION_REAUTH_SECS` | Recent re-authentication window for sensitive actions. |
| `GEOIP_DB_PATH` | In-container path to the GeoIP database file. |
| `GEOIP_REQUIRED` | Requires the GeoIP file to exist at startup. |
| `RISK_ALERT_THRESHOLD` | Risk score threshold that triggers alerting. |
| `RISK_CHALLENGE_THRESHOLD` | Risk score threshold that triggers a challenge. |
| `RISK_BLOCK_THRESHOLD` | Risk score threshold that blocks login. |
| `RISK_HISTORY_DAYS` | Number of days of location history used by risk scoring. |
| `SMTP_HOST` | SMTP server hostname. |
| `SMTP_PORT` | SMTP server port. |
| `SMTP_FROM_NAME` | Display name used in outgoing emails. |
| `SMTP_FROM_ADDRESS` | Sender email address used in outgoing emails. |
| `MAIL_TEMPLATES_DIR` | In-container path to email templates. |
| `MAIL_DEFAULT_LOCALE` | Fallback locale for email rendering. |
| `CAPTCHA_VERIFY_URL` | CAPTCHA provider verification endpoint. |
| `CAPTCHA_TIMEOUT_SECS` | Timeout for CAPTCHA verification requests. |
| `CAPTCHA_FAIL_OPEN` | Controls whether CAPTCHA provider failures allow requests through. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated list of allowed frontend origins. |
| `CORS_ALLOW_CREDENTIALS` | Controls whether credentialed cross-origin requests are allowed. |
| `AUDIT_LOG_RETENTION_MONTHS` | Retention window for audit partitions. |
| `LOG_LEVEL` | Application log verbosity. |
| `LOG_FORMAT` | Log output format. |
| `WEBAUTHN_RP_ID` | WebAuthn relying party ID. |
| `WEBAUTHN_RP_ORIGIN` | WebAuthn relying party origin. |
| `WEBAUTHN_RP_NAME` | WebAuthn relying party display name. |
