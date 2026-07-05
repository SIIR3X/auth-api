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
   and downstream services (core-api, billing-api) have refreshed their JWKS.

4. Remove `prod/auth-api/jwt-previous-public-key` from `pass`, unset the
   variable, and redeploy. Verify the JWKS lists a single key:

   ```bash
   curl -s https://api.example.com/.well-known/jwks.json | jq '.keys | length'
   ```

Refresh tokens are opaque (not JWT) and are unaffected by this rotation.

## 2. TOTP Encryption Key Rotation (AES-256-GCM)

TOTP secrets are encrypted at rest with `ENCRYPTION_KEY`. The binary ships a
one-off re-encryption command.

**On the API VPS:**

```bash
# 1. Generate the new key
openssl rand -base64 32   # -> becomes the new ENCRYPTION_KEY

# 2. Run the rotation with BOTH keys set (one-off container)
export PREVIOUS_ENCRYPTION_KEY=$(pass prod/auth-api/encryption-key)
export ENCRYPTION_KEY=<new key>
docker compose -f docker-compose.api.yml run --rm api ./auth-api --rotate-totp-keys
```

The command logs `rotated` / `failed` counts and exits non-zero if any secret
failed (in which case nothing is lost: re-run after fixing the cause). Then:

```bash
# 3. Persist the new key, drop the previous one, redeploy
pass insert prod/auth-api/encryption-key   # paste the new key
unset PREVIOUS_ENCRYPTION_KEY
docker compose -f docker-compose.api.yml up -d
```

Never delete the old key from `pass` history until a user with TOTP enabled
has successfully logged in after the rotation.

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

- **Mechanism (automated):** the `backup-drill` GitHub workflow runs
  `scripts/backup-drill.sh` monthly: seed -> backup -> restore into a fresh
  Postgres -> verify row counts. It validates the pipeline, not your data.
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
| JTI blocklist (logout revocation) | **Fail-closed: 503** on authenticated routes - revocation cannot be proven |
| Refresh-token blocklist | Falls back to the DB `sessions.revoked_at` check (durable source of truth) |
| Session validity cache | Falls back to a direct DB query per request (slower, correct) |
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

- `auth_logins_total{outcome=...}` - success / invalid_credentials / locked / blocked / two_factor_required
- `auth_lockouts_total`, `auth_session_replays_total`, `auth_2fa_failures_total{method=...}`
- `argon2_queue_available_permits` - **0 while login latency climbs = login storm**; capacity is `ARGON2_MAX_CONCURRENCY` (defaults to CPU cores)
- `axum_http_requests_duration_seconds` - per-route latency histograms

Scrape config (host Prometheus): `static_configs: [{targets: ['127.0.0.1:9464']}]`.

**Alert rules:** [`prometheus-alerts.yml`](prometheus-alerts.yml) ships ready
to install (API down, 5xx ratio, Argon2 saturation, p95 latency, missing
backups). Copy it into `/etc/prometheus/rules/` on the API VPS - installation
notes are in the file header.

## 7. Release Verification (cosign)

Every published image is signed keyless (GitHub OIDC) and carries SBOM +
provenance attestations. Before deploying a new tag, verify the signature:

```bash
cosign verify \
  --certificate-identity-regexp 'github.com/SIIR3X/auth-api' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/siir3x/auth-api:latest
```

A failed verification means the image was not produced by this repository's
`docker-publish` workflow - do not deploy it.

## 8. Measured Capacity

End-to-end HTTP load benchmark (`scripts/bench-http.sh`, concurrency 8), run
against Postgres + Redis + NATS. Argon2 at production parameters (64 MiB, 3
iterations) dominates every credential path - this is by design.

| Path | p50 | p99 | Notes |
|------|-----|-----|-------|
| Login (success) | ~195 ms | ~210 ms | Argon2 verify-bound (~33 logins/s/worker) |
| Login (wrong password) | ~1100 ms | ~1110 ms | Deliberate backoff on failure |
| Register | ~195 ms | ~210 ms | Argon2 hash-bound |
| Change password | ~380 ms | ~410 ms | Two Argon2 ops (verify + hash) |
| Refresh token | ~8 ms | ~15 ms | No Argon2 |
| Get profile (authed) | ~3 ms | ~4 ms | JWT + Redis session cache |
| TOTP / email 2FA complete | ~200 ms | ~220 ms | Argon2 on the pre-auth login step |

**Reading:** credential endpoints are intentionally slow (Argon2 is the cost of
offline-crack resistance); everything token- or session-based is single-digit
milliseconds. Login throughput scales linearly with `ARGON2_MAX_CONCURRENCY`
and CPU cores. Watch `argon2_queue_available_permits`: sustained 0 means logins
are queueing - scale cores or raise the concurrency bound.

_Baseline recorded 2026-07-04 on the development machine; re-run per environment
before capacity planning._
