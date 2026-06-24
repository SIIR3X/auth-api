# Configuration Reference

## Environment files

| File | Committed | Used in |
|------|-----------|---------|
| `.env.dev` | Yes | Development (`make dev`) |
| `config.prod.env` | Yes | Production (non-sensitive values only) |

Sensitive production values are never stored in files — they are exported from `pass` before deployment.

## Secrets (production only)

These variables must be exported from `pass` on the VPS before running `docker compose`:

| Variable | Description | Generate with |
|----------|-------------|---------------|
| `DATABASE_URL` | PostgreSQL connection string including credentials | — |
| `REDIS_URL` | Redis connection string including password | — |
| `JWT_SECRET` | HS256 signing key for access tokens | `openssl rand -hex 32` |
| `JWT_PREVIOUS_SECRET` | Previous JWT signing key — set only during JWT key rotation | — |
| `ENCRYPTION_KEY` | AES-256-GCM key for TOTP secret encryption (base64, 32 bytes) | `openssl rand -base64 32` |
| `PREVIOUS_ENCRYPTION_KEY` | Previous encryption key — set only during key rotation | — |
| `SMTP_USERNAME` | SMTP authentication username | — |
| `SMTP_PASSWORD` | SMTP authentication password | — |
| `CAPTCHA_SECRET` | hCaptcha secret key | — |

## Non-sensitive variables

These variables are committed in `config.prod.env` and can be adjusted without any security concern.

### Server

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `APP_ENV` | `production` | Environment name |
| `SERVER_HOST` | `0.0.0.0` | Bind address |
| `SERVER_PORT` | `3000` | Bind port |
| `APP_PUBLIC_URL` | — | Public-facing URL of the API |
| `TRUSTED_PROXY_CIDRS` | — | Comma-separated CIDRs of trusted reverse proxies |

### Database

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `DB_MAX_CONNECTIONS` | `20` | Maximum PostgreSQL pool size |
| `DB_MIN_CONNECTIONS` | `2` | Minimum PostgreSQL pool size |
| `DB_ACQUIRE_TIMEOUT_SECS` | `30` | Timeout to acquire a connection |

### Redis

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `REDIS_POOL_SIZE` | `10` | Redis connection pool size |
| `REDIS_WAIT_TIMEOUT_MS` | `2000` | Max wait time to acquire a Redis connection |

### JWT

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `JWT_ACCESS_EXPIRY_SECS` | `900` | Access token lifetime (15 minutes) |
| `JWT_REFRESH_EXPIRY_SECS` | `2592000` | Refresh token lifetime when "remember me" is on (30 days) |
| `JWT_SHORT_SESSION_EXPIRY_SECS` | `86400` | Refresh token lifetime when "remember me" is off (24 hours) |
| `JWT_MAX_SESSION_LIFETIME_SECS` | `7776000` | Absolute session lifetime cap regardless of refresh activity (90 days) |
| `JWT_STRICT_SESSION_BINDING` | `false` | Bind refresh tokens to the login IP (breaks mobile roaming) |

### Argon2id

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `ARGON2_MEMORY_KIB` | `65536` | Memory cost in KiB — tune for your hardware |
| `ARGON2_ITERATIONS` | `3` | Iteration count |
| `ARGON2_PARALLELISM` | `4` | Parallelism factor |

### TOTP / 2FA

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `TOTP_ISSUER` | `MyApp` | Issuer name shown in authenticator apps |
| `TOTP_SKEW` | `1` | Accepted time-step skew (±1 window) |
| `RECOVERY_CODE_EXPIRY_DAYS` | `365` | Recovery code validity in days |

### Rate limiting

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `RATE_LIMIT_RPM` | `300` | Max requests per minute per IP |
| `RATE_LIMIT_AUTH_RPM` | `20` | Max auth requests per minute per IP |
| `RATE_LIMIT_FAIL_OPEN` | `false` | Allow requests if Redis is unavailable — must be `false` in production |
| `RATE_LIMIT_ALLOW_MISSING_IP` | `false` | Allow requests without a resolved IP — must be `false` in production |

### Account lockout

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `LOCKOUT_THRESHOLD` | `10` | Failed attempts before lockout |
| `LOCKOUT_DURATION_SECS` | `1800` | Lockout duration in seconds (30 minutes) |
| `SENSITIVE_ACTION_REAUTH_SECS` | `600` | Recent authentication window for sensitive actions |

### GeoIP & risk scoring

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `GEOIP_DB_PATH` | — | Path to the MaxMind GeoLite2-City `.mmdb` file |
| `GEOIP_REQUIRED` | `false` | Fail on startup if the GeoIP database is missing |
| `RISK_ALERT_THRESHOLD` | `30` | Risk score above which an alert is triggered |
| `RISK_CHALLENGE_THRESHOLD` | `60` | Risk score above which a challenge is required |
| `RISK_BLOCK_THRESHOLD` | `80` | Risk score above which the request is blocked |
| `RISK_HISTORY_DAYS` | `90` | Days of login history used for risk evaluation |

### SMTP

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `SMTP_HOST` | — | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_FROM_NAME` | `MyApp` | Sender display name |
| `SMTP_FROM_ADDRESS` | — | Sender email address |

### Mail

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `MAIL_TEMPLATES_DIR` | `templates` | Path to email templates directory |
| `MAIL_DEFAULT_LOCALE` | `en` | Default locale for email templates |

### CAPTCHA

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `CAPTCHA_VERIFY_URL` | hCaptcha URL | Verification endpoint |
| `CAPTCHA_TIMEOUT_SECS` | `5` | Request timeout for CAPTCHA verification |
| `CAPTCHA_FAIL_OPEN` | `false` | Allow requests if CAPTCHA provider is unavailable — must be `false` in production |

### CORS

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated list of allowed origins |
| `CORS_ALLOW_CREDENTIALS` | `true` | Allow credentials in cross-origin requests |

### Audit log

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `AUDIT_LOG_RETENTION_MONTHS` | `12` | Retention period in months — `0` keeps forever |

### Cleanup

Expired-data cleanup runs nightly via pg_cron when available; otherwise the application background task enforces these settings.

| Variable | Default | Description |
|----------|---------|-------------|
| `CLEANUP_INTERVAL_SECS` | `3600` | Interval between application-side cleanup runs (fallback when pg_cron is unavailable) |
| `CLEANUP_SESSIONS_GRACE_DAYS` | `7` | Grace period after session expiry/revocation before deletion |
| `CLEANUP_TOKENS_GRACE_DAYS` | `1` | Grace period after token expiry before deletion (email 2FA, password reset, email verification) |
| `CLEANUP_LOGIN_ATTEMPTS_RETENTION_DAYS` | `90` | Retention period for `login_attempts` records |
| `CLEANUP_RECOVERY_CODES_GRACE_DAYS` | `7` | Grace period after recovery code expiry before deletion |

### Logging

| Variable | Default (prod) | Description |
|----------|----------------|-------------|
| `LOG_LEVEL` | `info` | Log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `LOG_FORMAT` | `json` | Log format — `json` for production, `pretty` for development |
