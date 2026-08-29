# Operations Runbook

[Index](../README.md)

Procedures for planned maintenance (key rotations, backups) and incident
response (Redis outage, account interventions). Every command block states
where it runs (API VPS or DB VPS).

## 1. JWT Signing Key Rotation (ES256)

Access tokens are signed with the private key and verified against the JWKS
served at `/.well-known/jwks.json`. Rotation is zero-downtime because the API
accepts tokens signed with the previous key for as long as
`JWT_PREVIOUS_PUBLIC_KEY` is set.

**On a secure machine** - generate the new key pair:

```bash
openssl ecparam -genkey -name prime256v1 -noout \
  | openssl pkcs8 -topk8 -nocrypt -out jwt-private-new.pem
openssl ec -in jwt-private-new.pem -pubout -out jwt-public-new.pem
```

**On the API VPS:**

1. Store the new keys and keep the old public key as "previous":

   ```bash
   pass show prod/auth-api/jwt-public-key > /dev/shm/jwt-public-old.pem
   pass insert -m prod/auth-api/jwt-private-key      < jwt-private-new.pem
   pass insert -m prod/auth-api/jwt-public-key       < jwt-public-new.pem
   pass insert -m prod/auth-api/jwt-previous-public-key < /dev/shm/jwt-public-old.pem
   rm /dev/shm/jwt-public-old.pem
   ```

2. Redeploy with `JWT_PREVIOUS_PUBLIC_KEY` exported (see
   [Deploying a New Release](update.md)). The JWKS now lists both `kid`s;
   tokens signed with either key are accepted.

3. **Wait at least `JWT_ACCESS_EXPIRY_SECS` (default 15 min) plus the JWKS
   cache window (5 min)** so every token signed with the old key has expired
   and downstream resource servers have refreshed their JWKS.

4. Remove `prod/auth-api/jwt-previous-public-key` from `pass`, unset the
   variable, and redeploy. Verify the JWKS lists a single key:

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

1. Generate the new key: `openssl rand -base64 32`.
2. Redeploy with the new key as `ENCRYPTION_KEY` and the old one as
   `PREVIOUS_ENCRYPTION_KEY`. Existing secrets stay readable; new ones are
   written under the new key.
3. Re-encrypt the stored secrets:

   ```bash
   docker compose -f docker-compose.api.yml run --rm api ./auth-api --rotate-totp-keys
   ```

   The command logs `rotated`, `skipped` and `failed`, exits non-zero when a
   secret failed, and is recorded in the audit log as `encryption_key_rotated`.
   Run it until it reports `rotated=0 failed=0`: secrets already under the new
   key are skipped, and a secret changed during the run is left as the service
   wrote it.
4. Store the new key in `pass`, remove `PREVIOUS_ENCRYPTION_KEY`, redeploy.

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

**Response:** restart/restore Redis, then verify `curl -f localhost:3000/health`
and watch `auth_logins_total` on the metrics endpoint resume. No application
restart is needed - pools reconnect automatically.

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
(`127.0.0.1:9464/metrics` on the API VPS - loopback only, never behind
nginx). Key series:

- `auth_logins_total{outcome=...}` - success / invalid_credentials / locked / two_factor_required
- `auth_lockouts_total`, `auth_session_replays_total`, `auth_2fa_failures_total{method=...}`
- `argon2_queue_available_permits` - **0 while login latency climbs = login storm**; capacity is `ARGON2_MAX_CONCURRENCY` (defaults to CPU cores)
- `axum_http_requests_duration_seconds` - per-route latency histograms

Scrape config (host Prometheus): `static_configs: [{targets: ['127.0.0.1:9464']}]`.

**Alert rules:** [`prometheus-alerts.yml`](prometheus-alerts.yml) ships ready
to install (API down, 5xx ratio, Argon2 saturation, p95 latency, missing
backups). Copy it into `/etc/prometheus/rules/` on the API VPS - installation
notes are in the file header.

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
