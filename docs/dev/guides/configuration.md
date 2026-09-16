# Configuration Reference

Every setting is an environment variable, read once at startup. A variable
that is present but does not parse is an error, never a silent fallback to its
default (`LOCKOUT_THRESHOLD=1O` refuses to start). A blank value counts as
unset.

In `APP_ENV=production` the configuration is validated before the server
accepts traffic; the checks are listed under [Production checks](#production-checks).

## Environment files

| File | Committed | Used in |
|------|-----------|---------|
| `.env.dev` | Yes | Development (`make dev`) - development keys only, refused in production |
| `config.prod.env` | Yes | Production, non-sensitive values only |

Production secrets are never written to files: they are exported from `pass`
before `docker compose` runs (see [Secrets](../../deploy/api/secrets.md)).

## Secrets

| Variable | Description | Generate with |
|----------|-------------|---------------|
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string, password included | - |
| `JWT_PRIVATE_KEY` | EC P-256 private key, PEM (signs access tokens) | `openssl ecparam -genkey -name prime256v1 -noout \| openssl pkcs8 -topk8 -nocrypt` |
| `JWT_PUBLIC_KEY` | Matching public key, PEM | `openssl ec -pubout < private.pem` |
| `JWT_PREVIOUS_PUBLIC_KEY` | Previous public key, only during a signing key rotation | - |
| `JWT_NEXT_PUBLIC_KEY` | Next public key, only while a signing key rotation is being announced | - |
| `ENCRYPTION_KEY` | AES-256-GCM key for TOTP secrets at rest, base64 of 32 bytes | `openssl rand -base64 32` |
| `PREVIOUS_ENCRYPTION_KEY` | Previous encryption key, only during a rotation | - |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | SMTP credentials | - |
| `CAPTCHA_SECRET` | hCaptcha secret | - |
| `NATS_URL` | NATS URL embedding the broker token (`nats://<token>@nats:4222`) | - |
| `NATS_AUTH_TOKEN` | Token the bundled broker requires (read by `docker-compose.api.yml`) | `openssl rand -hex 32` |

## Variables

"Required" variables have no default and stop the startup when missing.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | required | `development`, `test` or `production`. Required so a typo cannot start a deployment with development relaxations |
| `SERVER_HOST` | `0.0.0.0` | Bind address |
| `SERVER_PORT` | `3000` | Bind port |
| `APP_PUBLIC_URL` | `http://localhost:3000` | Public URL of this API: token issuer, audience, JWKS location |
| `FRONTEND_URL` | `APP_PUBLIC_URL` | Web application whose pages emails link to (`/verify-email`, `/reset-password`) |
| `TRUSTED_PROXY_CIDRS` | empty | Comma-separated CIDRs allowed to set `X-Forwarded-For` / `X-Real-IP`. Behind the bundled compose file this is the network gateway, `172.30.0.1/32` |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | required | PostgreSQL connection string |
| `DB_MAX_CONNECTIONS` | `20` | Pool size |
| `DB_MIN_CONNECTIONS` | `2` | Connections kept open |
| `DB_ACQUIRE_TIMEOUT_SECS` | `5` | Wait for a pooled connection |

### Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | required | Redis connection string |
| `REDIS_POOL_SIZE` | `10` | Pool size |
| `REDIS_WAIT_TIMEOUT_MS` | `2000` | Wait for a pooled connection before failing |

### NATS

Domain events (`user.created`, `user.email_verified`, `user.email_changed`,
`user.password_changed`, `user.sessions_revoked`, `user.deleted`) are recorded in
the `event_outbox` table with the change they announce, then published to NATS
JetStream by a background relay. They carry the user id only, with `event_id`
and `occurred_at`. The broker ships in the compose files.

| Variable | Default | Description |
|----------|---------|-------------|
| `NATS_URL` | `nats://nats:4222` | Broker URL |

### Access tokens (ES256)

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_PRIVATE_KEY` | required | Signing key, PEM (`\n` escapes accepted) |
| `JWT_PUBLIC_KEY` | required | Verification key, PEM |
| `JWT_PREVIOUS_PUBLIC_KEY` | unset | Still accepted and published in the JWKS during a rotation |
| `JWT_NEXT_PUBLIC_KEY` | unset | Published in the JWKS and accepted before the signing key switches to it |
| `JWT_AUDIENCE` | empty | Comma-separated audiences stamped in `aud`; `APP_PUBLIC_URL` is always added |
| `JWT_ACCESS_EXPIRY_SECS` | `900` | Access token lifetime |
| `JWT_REFRESH_EXPIRY_SECS` | `2592000` | Refresh token lifetime with "remember me" (30 days) |
| `JWT_SHORT_SESSION_EXPIRY_SECS` | `86400` | Refresh token lifetime without "remember me" (24 hours) |
| `JWT_MAX_SESSION_LIFETIME_SECS` | `7776000` | Absolute lifetime of a sign-in, whatever the refresh activity (90 days) |
| `JWT_STRICT_SESSION_BINDING` | `false` | Refuse a refresh from another address than the sign-in |

### Passwords and second factors

| Variable | Default | Description |
|----------|---------|-------------|
| `ARGON2_MEMORY_KIB` | `65536` | Argon2id memory cost |
| `ARGON2_ITERATIONS` | `3` | Argon2id iterations |
| `ARGON2_PARALLELISM` | `4` | Argon2id lanes |
| `ARGON2_MAX_CONCURRENCY` | CPU cores | Hashes computed at once; the rest queue |
| `ENCRYPTION_KEY` | required | Current key for TOTP secrets |
| `PREVIOUS_ENCRYPTION_KEY` | unset | Previous key, readable during a rotation |
| `TOTP_ISSUER` | `auth-api` | Issuer shown in authenticator apps |
| `TOTP_SKEW` | `1` | Accepted 30-second steps before and after the current one |
| `RECOVERY_CODE_EXPIRY_DAYS` | `365` | Recovery code lifetime; `0` never expires |

### Abuse protection

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_RPM` | `300` | Requests per minute per client, every route |
| `RATE_LIMIT_AUTH_RPM` | `20` | Additional per-minute budget of credential-bearing routes |
| `RATE_LIMIT_FAIL_OPEN` | `true` outside production | Serve requests when Redis is unreachable |
| `RATE_LIMIT_ALLOW_MISSING_IP` | `true` outside production | Serve requests whose client address cannot be resolved |
| `LOCKOUT_THRESHOLD` | `10` | Consecutive wrong passwords before a lockout |
| `LOCKOUT_DURATION_SECS` | `1800` | Lockout duration |
| `SENSITIVE_ACTION_REAUTH_SECS` | `600` | How long a re-authentication (`POST /users/me/reauth`) covers sensitive actions |
| `CAPTCHA_SECRET` | unset | hCaptcha secret; unset disables the check, which production refuses |
| `CAPTCHA_VERIFY_URL` | `https://hcaptcha.com/siteverify` | Verification endpoint |
| `CAPTCHA_TIMEOUT_SECS` | `5` | Verification timeout |
| `CAPTCHA_FAIL_OPEN` | `true` outside production | Accept the request when the provider cannot be reached |

IPv6 clients are limited per `/64`, the prefix a subscriber is usually given.

### Mail

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | required | SMTP server; empty skips sending (tests) |
| `SMTP_PORT` | `587` | STARTTLS port |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | required | Credentials; an empty username sends without TLS or authentication (Mailpit), which production refuses |
| `SMTP_FROM_NAME` | `auth-api` | Sender name |
| `SMTP_FROM_ADDRESS` | required | Sender address |
| `MAIL_TEMPLATES_DIR` | `templates` | Holds `emails/{locale}/{name}.html` and `{name}.subject` |
| `MAIL_DEFAULT_LOCALE` | `en` | Locale used when the user's has no template |

### Client applications

| Variable | Default | Description |
|----------|---------|-------------|
| `DEVICE_AUTH_VERIFICATION_URI` | required | Page where a user enters a device code (RFC 8628 `verification_uri`) |
| `DEVICE_AUTH_TTL_SECS` | `300` | Lifetime of a device code |
| `DEVICE_AUTH_POLL_INTERVAL_SECS` | `5` | Minimum polling interval; faster polls get `slow_down` |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated origins allowed to call the API from a browser |
| `CORS_ALLOW_CREDENTIALS` | `true` | Allow credentialed cross-origin requests |

Registered clients (device and authorization code flows) live in the database
and are managed with `auth-api --register-client` (see [Commands](commands.md)).

### Retention

The application is the only scheduler: every `CLEANUP_INTERVAL_SECS`, one
instance (advisory lock) deletes expired rows in bounded batches and rotates
the audit log partitions.

| Variable | Default | Description |
|----------|---------|-------------|
| `CLEANUP_INTERVAL_SECS` | `3600` | Interval between runs |
| `CLEANUP_SESSIONS_GRACE_DAYS` | `7` | Kept after expiry or revocation |
| `CLEANUP_TOKENS_GRACE_DAYS` | `1` | Kept after expiry: email codes, verification and reset tokens |
| `CLEANUP_LOGIN_ATTEMPTS_RETENTION_DAYS` | `90` | Login attempt ledger retention |
| `CLEANUP_RECOVERY_CODES_GRACE_DAYS` | `7` | Kept after expiry |
| `CLEANUP_UNVERIFIED_ACCOUNT_DAYS` | `7` | Accounts whose address was never verified are deleted after this many days (audited, `user.deleted` published); `0` keeps them |
| `AUDIT_LOG_RETENTION_MONTHS` | `12` | Monthly audit partitions kept; `0` keeps every partition |
| `AUDIT_IP_RETENTION_DAYS` | `90` | Client addresses of older audit entries keep only their network (/24, /48); `0` keeps full addresses |

Authorization codes are kept one hour past expiry (so a replay still finds the
session it produced) and TOTP replay records 90 seconds; neither is configurable.

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug`, `trace` |
| `LOG_FORMAT` | `pretty` | `json` in production |
| `METRICS_ENABLED` | `true` | Serve Prometheus metrics on a separate listener |
| `METRICS_PORT` | `9464` | Metrics listener port; publish on loopback only |

## Production checks

With `APP_ENV=production` the service refuses to start when:

- `APP_PUBLIC_URL`, `FRONTEND_URL` or `CAPTCHA_VERIFY_URL` is not HTTPS;
- `TRUSTED_PROXY_CIDRS` is empty (every client would share the proxy's address);
- the JWT keys do not form a pair, or are the committed development pair;
- `ENCRYPTION_KEY` is not 32 bytes, is a committed development key, or is an
  arithmetic sequence;
- `JWT_AUDIENCE` is empty or has a blank entry;
- `CORS_ALLOWED_ORIGINS` contains `*` or a non-HTTPS origin;
- `SMTP_USERNAME` or `CAPTCHA_SECRET` is empty;
- `RATE_LIMIT_FAIL_OPEN`, `RATE_LIMIT_ALLOW_MISSING_IP` or `CAPTCHA_FAIL_OPEN`
  is `true`, or `JWT_STRICT_SESSION_BINDING` is `false`;
- `SENSITIVE_ACTION_REAUTH_SECS` or `ARGON2_MAX_CONCURRENCY` is `0`.
