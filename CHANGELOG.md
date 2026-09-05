# Changelog

All notable changes. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0.0, a minor version may break compatibility.

## [Unreleased]

A hardening, performance and cleanup release. It changes the HTTP contract and
the configuration: read **Breaking changes** and **Upgrading** before deploying.

### Breaking changes

**API**

- `POST /auth/register` answers `202` with `{ "status", "message" }` for every
  request, whether or not the address is taken; the owner of a taken address is
  emailed. The response no longer carries the account.
- Signing in no longer grants a re-authentication. Changing the password,
  username or email, deleting the account, revoking sessions, and adding or
  removing a second factor need `POST /users/me/reauth` within
  `SENSITIVE_ACTION_REAUTH_SECS`, or `current_password` in the body. The
  `DELETE` routes accept an optional JSON body for it.
- A pre-auth token completes only the method it was issued for
  (`/auth/two-factor/complete` for TOTP, `/auth/two-factor/email/complete` for
  email codes).
- Validation errors return their message; conflicts return a specific `code`
  (`email_taken`, `username_taken`, ...).
- Tokens issued to a registered client carry only the permissions consented for
  it, and no roles.
- The device flow requires a registered client (`--register-client`); a flow
  without `client_id` uses the primary client.
- `429` responses carry a computed `Retry-After` instead of a fixed 60.
- Email links point at `FRONTEND_URL` (defaults to `APP_PUBLIC_URL`).

**Configuration**

- `APP_ENV` is required; a present but unparsable value is an error instead of
  falling back to the default.
- Production refuses to start without `TRUSTED_PROXY_CIDRS`, with an HTTP
  `FRONTEND_URL`, or with a committed or arithmetic `ENCRYPTION_KEY`.
- Removed with risk scoring: `GEOIP_DB_PATH`, `GEOIP_REQUIRED`, `RISK_*`, the
  `login_locations` table, and the new-device and suspicious-login emails.
- `docker-compose.api.yml` runs `auth-api:${AUTH_API_VERSION}` built by
  `make release`; no image is published to a registry.
- Behind the compose file, `TRUSTED_PROXY_CIDRS` must be `172.30.0.1/32`.

**Data**

- New TOTP secrets are written in a versioned format (`v1:{key id}:...`) that
  earlier versions cannot read: once this version has written secrets, rolling
  back breaks TOTP for those accounts.
- The pg_cron jobs are unscheduled (migration 0024); the application is the
  only retention scheduler.

### Added

- Authorization code flow with PKCE: `POST /auth/authorize/describe`,
  `POST /auth/authorize`, `POST /auth/authorize/token`.
- Client registry: scopes, redirect URIs, loopback redirects, default session
  limit; `auth-api --register-client`.
- `GET /auth/device/{user_code}`: what the signed-in user is about to approve.
- `GET /users/me/audit`: the caller's security history, cursor-paginated.
- `GET /users/me/two-factor`: configured methods and remaining recovery codes.
- Events `user.password_changed` and `user.sessions_revoked`.
- Emails: account already exists, email address changed (to the previous
  address), two-factor enabled; subjects translated in English and French.
- Encryption keyring: `PREVIOUS_ENCRYPTION_KEY` stays readable during a
  rotation; `--rotate-totp-keys` is resumable and audited as
  `encryption_key_rotated`.
- Access log (route template, status, latency, request id), nextest
  configuration, `make ci`, `make release`, OpenAPI document generated from the
  code, security model, this changelog.
- The OpenAPI document lists the responses every operation can return (`400`,
  `401`, `413`, `415`, `422`, `429`, `503`) with their error body.
- Test suites by layer (`make test-unit`, `test-integration`, `test-security`,
  `test-sim`), a shared harness (`crates/testkit`), every test response checked
  against the OpenAPI document, an authorization matrix over every operation,
  a control catalog in the security model, fuzz targets (`make fuzz`) replayed
  on stable in `make ci`, and `migrations/SHA256SUMS` freezing released
  migrations. See `docs/dev/guides/testing.md`.

### Security

- Second factors: pre-auth tokens bound to their method; failure budgets per
  challenge and per account for TOTP, email and recovery codes; second-factor
  failures no longer lock the account out.
- No account oracle: the lockout answers the same whatever the password,
  unknown identifiers pay a full hash, registration and forgot-password answer
  identically; forgot-password is capped per account.
- Sessions: an absolute lifetime measured from the sign-in; concurrent refreshes
  within 2 seconds no longer revoke a legitimate family; email change keeps the
  account status and records no addresses in the audit log.
- Attempt budgets are consumed atomically before the check they guard.
- IPv6 clients are rate limited per `/64`.
- Device flow: user codes reserved atomically, approvals collected once, polling
  paced, account status and session limits checked at issue.
- `user.deleted` is acknowledged by JetStream before the account is deleted.
- Nginx served `403` for `/.well-known/jwks.json` (hidden-file rule), appended
  client-supplied `X-Forwarded-For` hops, and duplicated security headers.
- Behind Docker's port proxy the trusted proxy never matched, so every client
  shared one rate-limit bucket.
- `AUDIT_LOG_RETENTION_MONTHS=0` deleted every past audit partition instead of
  keeping them, and the pg_cron job deleted audit months beyond six whatever the
  configuration.
- Base images pinned by digest; OpenSSL removed from the images; development
  ports bound to loopback.
- Passwords need at least 10 characters, not 10 bytes: an accented password of
  ten bytes could hold seven characters (found by fuzzing). The upper bound
  stays 128 bytes so every accepted password remains usable at sign-in.
- A loopback redirect on port 0 is refused.
- TOTP verification refuses a time within the skew of the epoch instead of
  panicking.
- Every error response carries the documented `{ "code", "message" }` body:
  rate limiter and timeout refusals, unknown routes and malformed or oversized
  JSON no longer answer in plain text, and no longer quote the JSON parser.

### Reliability

- An unreachable PostgreSQL or Redis answers `503 service_unavailable` instead
  of `500`, including connections dropped while being set up.
- The Redis pool replaces a connection whose transport failed. Before, a Redis
  restart under traffic was never recovered from: each request failed on a dead
  connection and counted as a use, so the connection never went idle long
  enough to be checked.

### Performance

- Indexes matched to the queries: unused ones dropped, expiry and referencing
  columns indexed (migration 0024).
- A sign-in writes its session, account stamp, ledger entry and audit record in
  one transaction; roles and permissions load in one query.
- Cleanups run in bounded batches under an advisory lock.
- Redis: recycled connections are pinged only after 5 seconds idle; the rate
  limiter is O(1) and checks every bucket in one script; token checks read the
  blocklist and session cache in one pipeline. Profile reads went from 1.05 ms to
  0.71 ms at p50 in the HTTP benchmark.
- Retention batches select their rows through a TID scan (migration 0026):
  a session purge batch at 1 million accounts went from 950 ms (the old query
  gathered the whole backlog) to about 20 ms.
- Indexes no query uses are dropped: `idx_sessions_family_active` and the
  audit log's request id index (755 MB at 1 million accounts); the internal
  `audit::find_by_request_id`, which no route called, is removed.
- The audit history page skips the empty partitions created for future months.
- The API logs its Argon2 capacity at startup and warns when the container
  memory limit cannot hold it; Argon2 saturation alerts at 5 and 15 minutes.
- Measurement campaign and report: `make perf`, `docs/perf/performance-report.md`.

### Upgrading

1. Back up the database.
2. Run migrations 0020 to 0026. Migration 0024 builds indexes in a transaction:
   on large tables, create them `CONCURRENTLY` by hand first (the migration then
   skips them).
3. Set `APP_ENV`, `FRONTEND_URL`, `DEVICE_AUTH_VERIFICATION_URI` and
   `TRUSTED_PROXY_CIDRS=172.30.0.1/32`; remove `GEOIP_*` and `RISK_*`.
4. Register the primary client, and any device or authorization code client,
   with `auth-api --register-client`.
5. Update client applications: re-authenticate before sensitive actions, and
   stop reading the account from the registration response.
