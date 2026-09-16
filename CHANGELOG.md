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
- Startup refuses `LOCKOUT_THRESHOLD=0`, `DEVICE_AUTH_TTL_SECS=0`, a
  `DEVICE_AUTH_POLL_INTERVAL_SECS` of 0 or not shorter than the device code
  lifetime, and `JWT_MAX_SESSION_LIFETIME_SECS=0`.

**Data**

- New TOTP secrets are written in a versioned format (`v1:{key id}:...`) that
  earlier versions cannot read: once this version has written secrets, rolling
  back breaks TOTP for those accounts.
- Retention runs only in the application: the migrations install no pg_cron
  job, which ran with the SQL defaults instead of the configured retention.
- The migrations are consolidated into one file per domain, each creating its
  tables in their final form. A database created by an earlier development
  version is created again rather than upgraded.

### Added

- Simulations of random account lifecycles checked against a model, a timing
  test comparing existing and unknown accounts, and `make soak`: an hour of
  mixed traffic that fails on any error or on growing memory.
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
  migrations. Property tests pit the validators against the database
  constraints; `make mutants` runs mutation testing over the security-relevant
  pure code. `make coverage` fails under 90 % of lines, 85 % of regions and 79 %
  of functions. See `docs/dev/guides/testing.md`.

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
- `LOCKOUT_THRESHOLD=0` is refused at startup: it locked an account on every
  wrong password instead of disabling the lockout.
- The re-authentication budget is consumed atomically before the password is
  hashed, and fails closed: parallel guesses could all pass a count read
  before any of them was recorded.
- Failed sign-ins are capped per IPv6 /64, like every other per-address
  budget: rotating addresses inside one /64 reset the cap.
- Device flow approvals check the client's session limit under the same lock
  as code redemptions: concurrent polls could each count the same sessions and
  exceed the limit.
- A refresh no longer dates the new session past the absolute lifetime of its
  sign-in, so session listings and revocation lifetimes match the real end.
- Confirming a TOTP method records its code in the durable replay table shared
  with sign-in (it could complete a sign-in in the same window, and the Redis
  guard was skipped without Redis), under a budget of 5 wrong codes per 15
  minutes.
- Recovery codes have one per-account budget (10 per 24 hours) shared by the
  sign-in challenge and `POST /users/me/two-factor/recovery-codes/use`, which
  had its own; purging a user's challenges also clears their email-code
  budgets.
- Second factors and client flows answer `account_inactive` and
  `email_not_verified` like the password sign-in, instead of
  `account_suspended` for every status other than active.
- An authorization code redirect keeps the query of its registered URI.
- The API never authenticated to NATS: async-nats ignores the credentials of
  a URL, so the documented `NATS_URL=nats://<token>@nats:4222` against the
  token-protected broker of `docker-compose.api.yml` was refused and the service
  could not start. The credentials are now read from `NATS_URL` and presented
  to the broker, production refuses a `NATS_URL` without them, and the test
  broker requires a token so every suite exercises it.
- The deployment docs said `CAPTCHA_SECRET` could be left unset and redeployed
  a TOTP key rotation before storing the new key; production requires the
  secret, and the rotation now stores both keys first.
- The production image runs on distroless (no shell, no package manager): the
  Debian runtime carried two HIGH vulnerabilities in `libpcre2`. The binary and
  templates belong to root, the service runs as a numeric non-root user, and the
  image carries its version and commit as OCI labels.
- `make release` builds the image from the commit rather than the working tree,
  refuses a dirty tree, a version that differs from `Cargo.toml` or an untagged
  commit, stops on a HIGH or CRITICAL vulnerability, records the image
  identifier and signs the checksums with an SSH key. `make docker-refresh-pins`
  moves every pinned base image to its current digest; the development and test
  compose files are pinned too.
- `GET /live` (liveness, dependencies unchecked) and `GET /ready` (database,
  Redis and NATS, one second each, 503 when one is down) sit outside the rate
  limiter; `/health` stays as an alias of `/live`. The image health check calls
  `/live`: a rate-limited `/health` turned every instance unhealthy during a
  Redis outage.
- A database failure while checking a token answers 503 instead of 401, which
  signed users out during an outage and hid it from the server-error alerts.
- Domain events go through a transactional outbox: each event is recorded in
  the transaction of the change it announces and a background relay publishes
  it to JetStream in order, with its id as message id (deduplication) and
  `event_id` and `occurred_at` in the payload. An event is no longer lost when
  NATS is down, requests never wait for the broker, and a rolled-back change
  announces nothing. Registration, email verification, password changes and
  resets, session revocation and email changes now commit their writes in one
  transaction. `AuthApiEventsStalled` replaces `AuthApiEventsDropped`. The
  acknowledged `user.deleted` waits at most 5 seconds. An unreachable broker no longer stops
  the start (a refused token still does): the client reconnects in the
  background, the stream is declared before the first acknowledged event, and
  `/ready` reports NATS.
- Stopping the service drains in bounded phases that fit a 40-second stop:
  in-flight requests (32 s), then notifications and cache invalidations started
  by requests (5 s, counted in `auth_background_tasks`), then events the NATS
  client still buffers (2 s). Before, the drain had no deadline and background
  tasks and buffered events were lost at every restart.
- Notifications are capped at 1 000 pending (`auth_notifications_pending`;
  `auth_notifications_failed_total` and `auth_notifications_dropped_total` by
  task). The SMTP relay is reached through a connection pool with a 10-second
  timeout instead of a new connection per message and lettre's one-minute
  default, and a temporary refusal is retried twice (after 2 and 8 seconds).
- New metrics for the alerts: pool saturation (`auth_db_pool_connections`,
  `auth_redis_pool_connections`, `auth_redis_pool_waiting`), Redis failures by
  operation (`auth_redis_errors_total`) and cleanup results
  (`auth_cleanup_deleted_rows_total`, `auth_cleanup_failures_total`).
- Every log line of a request carries its `request_id` through a span. A
  client-supplied `X-Request-Id` is kept only when it has at most 64 letters,
  digits or `-_.:`; otherwise a new identifier replaces it.
- The `Debug` output of the configuration masks connection URLs, the JWT
  private key, the encryption keys and the SMTP and CAPTCHA secrets.
- `DB_ACQUIRE_TIMEOUT_SECS` defaults to 5 seconds instead of 30: an exhausted
  pool answers fast instead of waiting out the request timeout.
- A signing key rotation no longer makes resource servers refuse new tokens
  for up to 5 minutes. `JWT_NEXT_PUBLIC_KEY` publishes the next key in the JWKS
  and has it accepted before the signing key switches to it, and the API
  verifies a token with the key its `kid` names (a token without a known `kid`
  is tried against every key). The runbook rotation now runs in three phases.
- The API VPS runs two API instances (`api-a` and `api-b`, on loopback ports
  3001 and 3002) sized by a profile: `deploy/profiles/s.env`, `m.env` or
  `l.env`, passed with `--env-file` (`docker-compose.api.l.yml` adds two
  instances for profile L). Each instance has CPU, memory and process limits, a
  40-second stop grace period and rotated logs, and its health check calls
  `/live` every 10 seconds. `scripts/rolling-update.sh` replaces the instances
  one at a time and waits for `/ready`, so an update no longer stops the
  service. The NATS token moves to `nats-auth.conf`, mounted as a secret instead
  of a command-line argument, and JetStream storage is capped in `nats.conf`.
  Pool sizes and Argon2 concurrency leave `config.prod.env` for the profiles.
- nginx balances the API instances: an instance that refuses or fails is
  skipped for 10 seconds and the request goes to the other one, while a
  request an instance already received is never resent. Proxy timeouts are 35
  seconds (credential routes cut at 10 while a sign-in queued behind Argon2 may
  take up to 30), HEAD is allowed for uptime probes, every request is logged as
  one JSON line with the `request_id` passed on to the API, and the nginx rate
  limits sit at twice the API's so clients see the API's 429 and `Retry-After`.
- The DB VPS ships its settings in `deploy/db/`: PostgreSQL sized per profile
  (memory, connections, WAL, `pg_stat_statements`, slow statement logs) with
  session limits for the `auth_api` role (25-second statements, 10-second lock
  waits, 60 seconds idle in a transaction); Redis with `maxmemory` and
  `noeviction`, append-only persistence, the default user disabled and an
  `auth_api` ACL user without administrative or dangerous commands
  (`REDIS_URL` becomes `redis://auth_api:<password>@10.0.0.2:6379`); kernel
  settings (overcommit, swappiness, no transparent huge pages). Migration 0027
  vacuums `sessions` and `login_attempts` once 2 % of their rows changed
  instead of 20 %. The API VPS no longer opens a WireGuard port it never
  listened on.
- Backups fail loudly and restore safely. `backup-db.sh` reads
  `/etc/auth-api/backup.env` instead of being edited, refuses the placeholder
  key, writes through a temporary file so a failed run leaves nothing that looks
  like a backup, fails when the offsite copy fails, and writes
  `auth_backup_last_success_timestamp`, the size and the duration for
  node_exporter after a complete run only: `AuthBackupMissing` could never fire
  before, since nothing wrote its metric, and it now also fires when the metric
  is absent. `AuthBackupShrunk` warns of a backup half the size of the previous
  ones. `restore-db.sh` restores in a single transaction and `--force` empties
  the target first. The drill restores as the non-superuser owner, checks that a
  failed backup leaves nothing, that an overwrite without `--force` is refused,
  and compares every table. Profiles M and L get point-in-time recovery with
  pgBackRest (`deploy/db/pgbackrest.conf`, `postgresql.pitr.conf`).
- Monitoring moves to its own host (`deploy/monitoring/`): Prometheus,
  Alertmanager with a dead man's switch, and a blackbox probe of the public
  `/ready` and its certificate. Exporters listen on WireGuard addresses only;
  the API compose adds a NATS exporter and publishes the metrics listeners on
  `METRICS_BIND_ADDRESS`. `rules/infrastructure.yml` alerts on hosts, disks,
  PostgreSQL, Redis (including refused writes under `noeviction`), NATS, pool
  saturation, dropped events and e-mails and failing retention jobs, each with
  a promtool test. Each API instance publishes its container's memory against
  its limit, CPU throttling and start time from its cgroup
  (`auth_container_*`, `auth_process_start_time_seconds`), so the container
  alerts need no host exporter.
- The operations runbook covers a full Redis, NATS and SMTP outages and adding
  an instance; its addresses match the two-instance deployment. The
  `config.prod.env` comment no longer calls `JWT_AUDIENCE` required:
  `APP_PUBLIC_URL` is always part of the audience.
- GitHub Actions: `ci.yml` checks pull requests to `main` with one required
  check, `ci-ok`, and runs only the jobs a change concerns (formatting, clippy,
  dependency policy and every suite; deployment files; the image and Trivy);
  `scheduled.yml` runs advisories, the image scan, coverage and the long
  simulations weekly, the backup drill and fuzzing monthly, and tracks failures
  in an issue; `backmerge.yml` fast-forwards `staging` after a merge; Dependabot
  opens grouped pull requests monthly. Actions are pinned by commit, the token is
  read-only by default, and the toolchain is pinned in `rust-toolchain.toml`.
  `scripts/infra-check.sh` gains check families (`CHECKS=hygiene|static|image`),
  actionlint, a repository secret scan and an image size limit.
- `make stack-test` (`scripts/stack-smoke.sh`) runs the production compose
  with profile M behind the repository's nginx configuration and checks the
  container limits, balancing, a sign-in flow, failover, a rolling update under
  load with no failed request, the deletion event through the authenticated
  broker and a clean stop. `make sizing` (`perf/sizing.sh`) checks the profiles
  under real container quotas: sign-ins per CPU, peak memory and overload,
  Redis, NATS and PostgreSQL footprint at 100 000 and 1 million accounts, the
  restore time, and a soak at a chosen profile.
- The OpenAPI document said a password change and `DELETE /users/me/sessions`
  revoke the other sessions; both revoke every session, the current one
  included.
- `X-Forwarded-For` is read across every header line, and a hop that is not an
  address stops the walk at the trusted proxy instead of letting the value to
  its left through. `X-Real-IP` only counts without `X-Forwarded-For`. The
  bundled nginx configuration was not affected: it overwrites both headers.
- A recovery code no longer completes a pre-auth state that names no method
  (the format written before challenges were bound to their method).

### Reliability

- An unreachable PostgreSQL or Redis answers `503 service_unavailable` instead
  of `500`, including connections dropped while being set up.
- The Redis pool replaces a connection whose transport failed. Before, a Redis
  restart under traffic was never recovered from: each request failed on a dead
  connection and counted as a use, so the connection never went idle long
  enough to be checked.
- A refresh no longer fails when the Redis pool is unavailable: its per-address
  budget fails open and the database decides, as documented.

### Performance

- Indexes matched to the queries: unused ones dropped, expiry and referencing
  columns indexed.
- A sign-in writes its session, account stamp, ledger entry and audit record in
  one transaction; roles and permissions load in one query.
- Cleanups run in bounded batches under an advisory lock.
- Redis: recycled connections are pinged only after 5 seconds idle; the rate
  limiter is O(1) and checks every bucket in one script; token checks read the
  blocklist and session cache in one pipeline. Profile reads went from 1.05 ms to
  0.71 ms at p50 in the HTTP benchmark.
- Retention batches select their rows through a TID scan:
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
2. Create the database from the migrations (see the note under **Data**).
3. Set `APP_ENV`, `FRONTEND_URL`, `DEVICE_AUTH_VERIFICATION_URI` and
   `TRUSTED_PROXY_CIDRS=172.30.0.1/32`; remove `GEOIP_*` and `RISK_*`.
4. Register the primary client, and any device or authorization code client,
   with `auth-api --register-client`.
5. Update client applications: re-authenticate before sensitive actions, and
   stop reading the account from the registration response.
