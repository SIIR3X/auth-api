# Operations Runbook

[Index](../README.md)

Procedures for planned maintenance (key rotations, backups) and incident
response (Redis outage, account interventions). Every command block states
where it runs (API VPS or DB VPS).

## 1. JWT Signing Key Rotation (ES256)

Access tokens are signed with the private key and verified against the JWKS
served at `/.well-known/jwks.json`, which resource servers may cache for 5
minutes (`Cache-Control: max-age=300`). The rotation takes three redeploys so
that no valid token is ever refused, by the API or by a resource server: a key
is published before anything is signed with it, and kept until every token it
signed has expired. The API picks the verification key named by a token's
`kid`.

**On a secure machine** - generate the new key pair:

```bash
openssl ecparam -genkey -name prime256v1 -noout \
  | openssl pkcs8 -topk8 -nocrypt -out jwt-private-new.pem
openssl ec -in jwt-private-new.pem -pubout -out jwt-public-new.pem
```

**On the API VPS:**

1. **Publish the next key.**

   ```bash
   pass insert -m prod/auth-api/jwt-next-private-key < jwt-private-new.pem
   pass insert -m prod/auth-api/jwt-next-public-key  < jwt-public-new.pem
   export JWT_NEXT_PUBLIC_KEY=$(pass show prod/auth-api/jwt-next-public-key)
   ```

   Redeploy ([Deploying a New Release](update.md#4-start-the-new-version)).
   The JWKS lists both `kid`s; nothing is signed with the new key yet. **Wait at
   least 5 minutes**, or the longest JWKS cache of your resource servers.

2. **Sign with the next key.**

   ```bash
   pass show prod/auth-api/jwt-public-key      | pass insert -m -f prod/auth-api/jwt-previous-public-key
   pass show prod/auth-api/jwt-next-private-key | pass insert -m -f prod/auth-api/jwt-private-key
   pass show prod/auth-api/jwt-next-public-key  | pass insert -m -f prod/auth-api/jwt-public-key
   pass rm prod/auth-api/jwt-next-private-key prod/auth-api/jwt-next-public-key
   unset JWT_NEXT_PUBLIC_KEY
   ```

   Redeploy. New tokens carry the new `kid`; tokens signed with the old key
   still verify through `JWT_PREVIOUS_PUBLIC_KEY`. **Wait at least
   `JWT_ACCESS_EXPIRY_SECS`** (15 minutes by default).

3. **Retire the old key.** `pass rm prod/auth-api/jwt-previous-public-key`,
   then redeploy. Verify that the JWKS lists a single key:

   ```bash
   curl -s https://api.example.com/.well-known/jwks.json | jq '.keys | length'
   ```

Refresh tokens are opaque (not JWT) and are unaffected by this rotation.

## 2. TOTP Encryption Key Rotation (AES-256-GCM)

TOTP secrets are encrypted at rest. Each ciphertext names its key
(`v1:{key id}:...`) and the service reads with `ENCRYPTION_KEY` and, when set,
`PREVIOUS_ENCRYPTION_KEY`. A rotation needs no downtime and can be interrupted
and resumed.

**On the API VPS:**

1. Store both keys before anything else, so no key ever lives only in a shell:

   ```bash
   pass show prod/auth-api/encryption-key | pass insert -m prod/auth-api/previous-encryption-key
   openssl rand -base64 32 | pass insert -m -f prod/auth-api/encryption-key
   ```

2. Redeploy with the exports of the [update guide](update.md#4-start-the-new-version):
   they read `ENCRYPTION_KEY` (the new key) and `PREVIOUS_ENCRYPTION_KEY` (the
   old one) from `pass`. Existing secrets stay readable; new ones are written
   under the new key.
3. Re-encrypt the stored secrets:

   ```bash
   docker compose -f docker-compose.api.yml run --rm api ./auth-api --rotate-totp-keys
   ```

   The command logs `rotated`, `skipped` and `failed`, exits non-zero when a
   secret failed, and is recorded in the audit log as `encryption_key_rotated`.
   Run it until it reports `rotated=0 failed=0`: secrets already under the new
   key are skipped, and a secret changed during the run is left as the service
   wrote it.
4. Remove the previous key and redeploy:
   `pass rm prod/auth-api/previous-encryption-key`, then the update guide's
   exports again (the previous key is now unset).

Keep the old key in `pass` history until the run reported no failures.

## 3. Backup and Restore

Nightly encrypted backups run on the DB VPS via cron
(`scripts/backup-db.sh`): `pg_dump | gzip | age`, written to
`/var/backups/auth-api/`, 7-day retention. The age **private** key lives
offline, never on the VPS.

**Offsite copy:** set `OFFSITE_REMOTE` (an rclone remote, e.g.
`b2:auth-backups`) in the cron entry and install rclone; each backup is then
uploaded after being written (30-day remote retention). Backups that only live
on the DB VPS die with it - configure this for production.

**Restore** (DB VPS, or any machine with `psql` access):

```bash
scripts/restore-db.sh -i /path/to/backup.key \
  -f auth_api_YYYYMMDD_HHMMSS.sql.gz.age \
  -d postgres://auth_api:...@10.0.0.2:5432/auth_api
```

The script refuses to restore into a non-empty database unless `--force` is
passed (a restore is destructive: restore into a fresh database, verify, then
switch the API over).

**Drills** - two levels:

- **Mechanism (monthly):** run `scripts/backup-drill.sh` (it needs Docker):
  seed -> backup -> restore into a fresh Postgres -> verify row counts. It
  validates the pipeline, not your data.
- **Data (manual, quarterly):** decrypt a real production backup with the
  offline key and restore it into a scratch database. This is the only test
  that proves the actual backups are usable. Log the date and outcome below.

| Date | Backup file | Outcome |
|------|-------------|---------|
| _-_  | _-_         | _-_     |

## 4. Redis Outage - Behaviour Matrix

The API degrades predictably during a Redis outage. **Do not disable any
guard to "restore service"** - the fail-closed behaviours below are
deliberate.

| Subsystem | Behaviour without Redis |
|-----------|------------------------|
| Rate limiting (prod) | **Fail-closed: 503** on all routes (`RATE_LIMIT_FAIL_OPEN=false` enforced in prod) |
| Token checks (logout blocklist and session cache, one Redis read) | **Fail-closed: 503** on authenticated routes - revocation cannot be proven |
| Refresh-token blocklist | Falls back to the DB `sessions.revoked_at` check (durable source of truth) |
| TOTP replay guard | Redis is only a fast-path: the `used_totp_codes` table remains authoritative (**fail-closed**, no replay window) |
| Pre-auth (2FA challenge) tokens | Stored in Redis: in-flight 2FA logins fail; users retry after recovery |
| CAPTCHA / lockout counters | Various counters degrade fail-open; account lockout (DB-based) still works |

**Response:** restart/restore Redis, then verify `curl -f 127.0.0.1:3001/ready`
and `curl -f 127.0.0.1:3002/ready` on the API VPS and watch `auth_logins_total` on the metrics endpoint resume. No application
restart is needed - pools reconnect automatically.

**Redis full.** Redis runs with `maxmemory-policy noeviction`: evicting a
budget or blocklist key would silently reset an attempt budget or forget a
revoked token. When `maxmemory` is reached, Redis refuses writes and the API
answers 503 as during an outage (`RedisRejectingWrites`, `AuthApiRedisErrors`,
warned earlier by `RedisMemoryHigh`). Raise the limit on the DB VPS
(`CONFIG SET maxmemory 2gb`, then the same value in the Redis configuration);
never switch to an evicting policy. The measured footprint is in section 9.

## 5. Manual Interventions

**On the DB VPS** (`sudo -u postgres psql auth_api`):

Unlock an account locked out by failed logins:

```sql
UPDATE users SET locked_until = NULL WHERE email = 'user@example.com';
```

Revoke every session of a user (compromised account). Takes effect within
5 seconds (session-cache TTL):

```sql
UPDATE sessions SET revoked_at = NOW()
WHERE user_id = (SELECT id FROM users WHERE email = 'user@example.com')
  AND revoked_at IS NULL;
```

Suspend an account entirely:

```sql
UPDATE users SET status = 'suspended' WHERE email = 'user@example.com';
```

## 6. Metrics

Prometheus metrics are exposed on an internal listener
(`10.0.0.1:9465/metrics` and `10.0.0.1:9466/metrics` on the API VPS - WireGuard
only, never behind nginx). Key series:

- `auth_logins_total{outcome=...}` - success / invalid_credentials / locked / two_factor_required
- `auth_lockouts_total`, `auth_session_replays_total`, `auth_2fa_failures_total{method=...}`
- `argon2_queue_available_permits` - **0 while login latency climbs = login storm**; capacity is `ARGON2_MAX_CONCURRENCY` (defaults to CPU cores)
- `axum_http_requests_duration_seconds` - per-route latency histograms
- `auth_db_pool_connections{state=max|open|idle|in_use}`, `auth_redis_pool_connections{state=max|open|available}`, `auth_redis_pool_waiting` - pool saturation, refreshed every 10 s; `in_use` at `max` with requests timing out = pool too small or a slow query
- `auth_redis_errors_total{operation=budget|rate_limit|token_state}` - Redis failures, each refused with a 503 (fail closed)
- `auth_events_publish_failures_total{reason=error|timeout}` - best-effort events dropped because NATS did not take them within 500 ms
- `auth_notifications_pending`, `auth_notifications_failed_total{task}`, `auth_notifications_dropped_total{task}` - e-mails in flight, failed after retries, dropped past 1 000 pending
- `auth_background_tasks` - notifications and cache invalidations still running (drained for 5 s at shutdown)
- `auth_cleanup_deleted_rows_total{job}`, `auth_cleanup_failures_total{job}` - retention jobs
- `auth_container_memory_working_set_bytes`, `auth_container_memory_limit_bytes` (0 without a limit), `auth_container_cpu_periods_total`, `auth_container_cpu_throttled_periods_total`, `auth_process_start_time_seconds` - the instance's own container, read from its cgroup every 10 s; the container alerts of the [monitoring guide](monitoring.md) use them

Prometheus runs on a separate monitoring host and scrapes each instance over
WireGuard (`10.0.0.1:9465` and `9466`).

**Alert rules:** [`prometheus-alerts.yml`](prometheus-alerts.yml) (API down, 5xx
ratio, Argon2 saturation, p95 latency, missing backups) and
`deploy/monitoring/rules/infrastructure.yml` (probe, hosts, containers,
dependencies, pools); installation in the [monitoring guide](monitoring.md).

## 7. Release Bundle Verification

`make release` writes a `SHA256SUMS` file into the bundle. Record its own
checksum when the bundle is built, then verify on the server before loading
anything:

```bash
cd /srv/auth-api/releases/auth-api-X.Y.Z
sha256sum SHA256SUMS      # must match the value recorded at build time
sha256sum -c SHA256SUMS   # every file of the bundle
```

## 8. Measured Capacity

End-to-end HTTP benchmark (`make bench-http`, 16 workers x 64 iterations)
against PostgreSQL, Redis and NATS. Argon2 at production parameters dominates
every credential path, by design.

| Path | p50 | p95 | Notes |
|------|-----|-----|-------|
| Login (success) | ~319 ms | ~332 ms | Argon2 verify |
| Login (wrong password) | ~1082 ms | ~1088 ms | Deliberate backoff on failure |
| Register | ~321 ms | ~337 ms | Argon2 hash |
| Change password | ~653 ms | ~678 ms | Argon2 verify and hash |
| TOTP / email 2FA completion | ~330 ms | ~347 ms | Includes the password step |
| Refresh token | ~2.8 ms | ~5.2 ms | No Argon2 |
| Get profile (authenticated) | ~0.7 ms | ~1.7 ms | JWT and one Redis read |
| List sessions | ~0.8 ms | ~1.6 ms | |

**Reading:** credential endpoints are slow on purpose (Argon2 is what makes a
leaked hash expensive to crack); token and session paths stay around a
millisecond. Login throughput scales with `ARGON2_MAX_CONCURRENCY` and CPU
cores. Watch `argon2_queue_available_permits`: a sustained 0 means logins are
queueing.

_Recorded 2026-09-15 on the development machine; re-run per environment before
capacity planning._

## 9. Capacity Planning

Measured in [the performance campaign](../../perf/performance-report.md)
(3 API cores, PostgreSQL on 3 cores, 1 million accounts) and a one-hour soak
test (213 MiB of resident memory per instance, stable):

| Traffic | Measured capacity | Limiting factor |
|---------|------------------:|-----------------|
| Sign-ins and registrations | 33 per second | Argon2id, about 90 ms of CPU per hash |
| Refreshes | 5 000 per second | PostgreSQL write transaction |
| Authenticated reads | 11 000 to 12 600 per second | API CPU |

**Size the API on sign-ins**: they saturate first, by two orders of magnitude.

| Setting | Rule |
|---------|------|
| API cores | Peak sign-ins per second / 11, rounded up, plus one of headroom, spread over at least two instances |
| `ARGON2_MAX_CONCURRENCY` | The CPU limit of the instance |
| Memory per instance | 64 MiB x Argon2 concurrency + 256 MiB, rounded up to a multiple of 128 MiB; reservation half of it |
| `DB_MAX_CONNECTIONS`, `REDIS_POOL_SIZE` | 4 x the cores of the instance, at least 8. The sum over every instance, plus 10, stays under PostgreSQL's `max_connections` |
| PostgreSQL memory | Twice the indexes that sign-ins and refreshes update, about 4 KB per account (see [Database Deployment](../database/deployment.md#26-size-postgresqls-memory)) |

These rules give the three profiles shipped in `deploy/profiles/`, passed to
compose with `--env-file`:

| | S | M | L |
|---|---|---|---|
| Accounts | up to 100 000 | up to 1 million | up to 5 million |
| Peak sign-ins per second | 10 | 56 | 150 |
| API instances x CPU | 2 x 1 | 2 x 3 | 4 x 4 (`docker-compose.api.l.yml`) |
| Memory per instance (limit / reservation) | 384 / 192 MiB | 512 / 256 MiB | 512 / 256 MiB |
| `DB_MAX_CONNECTIONS` per instance | 8 | 12 | 16 |
| NATS (CPU / memory) | 0.25 / 128 MiB | 0.5 / 192 MiB | 1 / 256 MiB |
| API VPS (vCPU / RAM) | 3 / 2 GB | 8 / 4 GB | 20 / 8 GB |
| DB VPS (vCPU / RAM), PostgreSQL memory | 2 / 4 GB, 2 GB | 4 / 16 GB, 8 GB | 8 / 48 GB, 32 GB |

The API VPS keeps about 600 MiB beside the containers for nginx and the
system. Beyond profile L, PostgreSQL writes become the limit (connection
pooling, read replicas, shorter retention), which these profiles do not cover.

The figures come from dedicated, pinned cores; a container CPU limit is a quota
that behaves differently under bursts. Before relying on a profile, run
`make soak` on the target machine and watch the capacity alerts.

Each instance logs its Argon2 budget at startup (`argon2: at most N concurrent
hashes`) and warns when its memory limit is below it.

**Alerts**: `AuthApiArgon2Saturated` fires when no Argon2 slot was free for
5 minutes, `AuthApiArgon2SaturatedLong` after 15 (see
[`prometheus-alerts.yml`](prometheus-alerts.yml)). Either means sign-ins are
queueing: each waits for the ones ahead of it (8 seconds at 256 concurrent
sign-ins on 3 cores). Move to the next profile, or add an instance.

## 10. Bulk Imports

`login_attempts` is purged through a BRIN index on `attempted_at`. BRIN is
selective only while rows sit on disk in time order, which is the case for rows
the API writes. After loading attempts in another order (a migration from
another system, a reordered restore), check **on the DB VPS**:

```sql
SELECT correlation FROM pg_stats
WHERE tablename = 'login_attempts' AND attname = 'attempted_at';
```

Close to 1: nothing to do. Close to 0: every purge batch reads the whole table
(1.1 s at 10 million rows, whatever it deletes). Rewrite the table in time order
during a maintenance window - `CLUSTER` locks the table while it runs:

```sql
CREATE INDEX CONCURRENTLY tmp_login_attempts_order ON login_attempts (attempted_at);
CLUSTER login_attempts USING tmp_login_attempts_order;
DROP INDEX tmp_login_attempts_order;
ANALYZE login_attempts;
```

## 11. NATS and SMTP Outages

Neither stops the service. Docker checks `/live`, which does not depend on
them, so it never restarts the instances because of them.

| Path | Without NATS |
|------|--------------|
| Every event except `user.deleted` | Published with a 500 ms timeout, then dropped and counted in `auth_events_publish_failures_total{reason}` (`AuthApiEventsDropped`); the request succeeds |
| Account deletion | Waits up to 5 seconds for JetStream to store `user.deleted`, then answers 503 without deleting the account; the user retries later |
| `/ready` | 503 with `"nats": "down"` (`NatsDown` alerts) |
| Instance start | Starts and connects in the background; only a wrong token stops the start |

**Response:** restart the broker (`docker compose -f docker-compose.api.yml
restart nats`); the instances reconnect by themselves. Dropped events are not
replayed: a downstream service that missed one reconciles from the API.

**SMTP relay down.** E-mails are sent in the background, never inside the
request: each attempt has a 10-second timeout and is retried after 2 then
8 seconds, unless the relay refused it permanently. A notification that still
fails is counted in `auth_notifications_failed_total{task}`
(`AuthApiNotificationsFailing`). Past 1 000 notifications in flight, new ones
are dropped and counted in `auth_notifications_dropped_total{task}`
(`AuthApiNotificationsDropped`). Verification, password reset and e-mail codes
sent meanwhile are lost: users request a new reset or code once the relay is
back. There is no route to resend a verification e-mail yet.

## 12. Adding an Instance

Profile L shows the pattern (`docker-compose.api.l.yml`). For each new instance:

1. A service extending `x-api` in an overlay file, with the next loopback port
   (`127.0.0.1:3003:3000`) and metrics port (`${METRICS_BIND_ADDRESS:-10.0.0.1}:9467:9464`).
2. Its port in the nginx upstream (`server 127.0.0.1:3003 max_fails=3 fail_timeout=10s;`),
   then `sudo nginx -t && sudo systemctl reload nginx`.
3. Its metrics target in `prometheus.yml` on the monitoring host, and the port
   in the API VPS firewall rule for `10.0.0.3`.
4. Check the connection budget: `DB_MAX_CONNECTIONS` times the instances, plus
   10, stays under PostgreSQL's `max_connections` (section 9).
5. Its `service:port` in the `INSTANCES` list of `rolling-update.sh`, which
   otherwise replaces only `api-a` and `api-b`, plus `api-c` and `api-d` when
   `docker-compose.api.l.yml` is present.
6. Start it with `docker compose ... up -d --wait <service>`; it takes traffic
   as soon as nginx is reloaded.
