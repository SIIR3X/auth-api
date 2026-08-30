#!/usr/bin/env bash
# Performance campaign: data volume x load, for the database and the HTTP API.
#
# For each volume of VOLUMES (users), the data set is grown to that size, then:
#   1. query plans, relation and index sizes         (perf_load explain)
#   2. the application's queries at DB_CONCURRENCY    (perf_load db)
#   3. every HTTP scenario at each CONCURRENCY level  (perf_load http)
#   4. pg_stat_statements over the mixed scenario, retention batches
#
# Everything lands in $OUT/results.jsonl; perf/report.py writes the report.
# The infrastructure is started by perf/infra.sh (see it for CPU pinning).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VOLUMES=${VOLUMES:-"10000 100000 1000000"}
CONCURRENCY=${CONCURRENCY:-"1 4 16 64 256"}
HTTP_SCENARIOS=${HTTP_SCENARIOS:-"profile sessions audit two_factor refresh login register mixed"}
DB_SCENARIOS=${DB_SCENARIOS:-"user_by_email session_by_token session_validation active_sessions failures_by_identifier failures_by_ip consecutive_failures rbac audit_page two_factor_overview sign_in_write"}
DB_CONCURRENCY=${DB_CONCURRENCY:-"1 8 32"}
DURATION=${DURATION:-20}
WARMUP=${WARMUP:-5}
DB_DURATION=${DB_DURATION:-10}
DB_WARMUP=${DB_WARMUP:-3}
STATEMENTS_CONCURRENCY=${STATEMENTS_CONCURRENCY:-64}
SEED_CHUNK=${SEED_CHUNK:-50000}
PG_PORT=${PG_PORT:-5434}
REDIS_PORT=${REDIS_PORT:-6381}
NATS_PORT=${NATS_PORT:-4225}
API_PORT=${API_PORT:-3100}
SMTP_PORT=${SMTP_PORT:-1026}
API_DB_POOL=${API_DB_POOL:-32}
PG_CPUS=${PG_CPUS:-0-2}
CACHE_CPUS=${CACHE_CPUS:-3}
API_CPUS=${API_CPUS:-4-6}
LOAD_CPUS=${LOAD_CPUS:-7}
PG_BIN=${PG_BIN:-$(dirname "$(command -v postgres)")}
REDIS_CLI=${REDIS_CLI:-$(command -v redis-cli)}
OUT=${OUT:-reports/perf/$(date +%Y%m%d-%H%M%S)}
export PG_BIN REDIS_CLI PG_PORT REDIS_PORT NATS_PORT PG_CPUS CACHE_CPUS

export PERF_PASSWORD=${PERF_PASSWORD:-Perf-Password-2026!}
export PERF_CPU_GROUPS="postgres=$PG_CPUS;cache=$CACHE_CPUS;api=$API_CPUS;load=$LOAD_CPUS"
export DATABASE_URL="postgres://postgres@127.0.0.1:$PG_PORT/auth_perf"
export BASE_URL="http://127.0.0.1:$API_PORT"
export APP_PUBLIC_URL="$BASE_URL"
JWT_PRIVATE_KEY=$(grep '^JWT_PRIVATE_KEY=' .env.dev | cut -d= -f2-)
JWT_PUBLIC_KEY=$(grep '^JWT_PUBLIC_KEY=' .env.dev | cut -d= -f2-)
export JWT_PRIVATE_KEY JWT_PUBLIC_KEY

PSQL=("$PG_BIN/psql" -h 127.0.0.1 -p "$PG_PORT" -U postgres -X -q -v ON_ERROR_STOP=1)
LOAD=(taskset -c "$LOAD_CPUS" "$ROOT/target/release/perf_load")

mkdir -p "$OUT/api"
OUT=$(cd "$OUT" && pwd)
RESULTS="$OUT/results.jsonl"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }

API_PID=""
start_api() {
  (cd "$OUT/api" && exec taskset -c "$API_CPUS" "$ROOT/target/release/auth-api" >>api.log 2>&1) &
  API_PID=$!
  for _ in $(seq 1 60); do
    curl -fsS "$BASE_URL/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  log "API did not start; see $OUT/api/api.log"
  exit 1
}
stop_api() {
  if [ -n "$API_PID" ]; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
    API_PID=""
  fi
}
trap stop_api EXIT

log "building"
cargo build --release --quiet --bin auth-api --bin perf_load

log "infrastructure"
perf/infra.sh start | tee -a "$OUT/run.log"

log "fresh database"
"${PSQL[@]}" -d postgres -c "DROP DATABASE IF EXISTS auth_perf WITH (FORCE)" -c "CREATE DATABASE auth_perf"
"${PSQL[@]}" -d auth_perf -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"
"${LOAD[@]}" migrate
HASH=$("${LOAD[@]}" hash)

# Every value single-quoted: dotenvy stops at the first line it cannot parse
# (the PEM keys contain spaces) and silently leaves the rest unset.
sed -E "s/^([A-Z0-9_]+)=(.*)$/\1='\2'/" > "$OUT/api/.env" <<ENV
APP_ENV=development
SERVER_HOST=127.0.0.1
SERVER_PORT=$API_PORT
APP_PUBLIC_URL=$BASE_URL
FRONTEND_URL=http://127.0.0.1:5173
TRUSTED_PROXY_CIDRS=127.0.0.1/32
DATABASE_URL=$DATABASE_URL
DB_MAX_CONNECTIONS=$API_DB_POOL
DB_MIN_CONNECTIONS=8
REDIS_URL=redis://127.0.0.1:$REDIS_PORT
REDIS_POOL_SIZE=32
NATS_URL=nats://127.0.0.1:$NATS_PORT
$(grep -E '^(JWT_PRIVATE_KEY|JWT_PUBLIC_KEY|ENCRYPTION_KEY)=' .env.dev)
JWT_ACCESS_EXPIRY_SECS=900
ARGON2_MEMORY_KIB=65536
ARGON2_ITERATIONS=3
ARGON2_PARALLELISM=4
RATE_LIMIT_RPM=1000000000
RATE_LIMIT_AUTH_RPM=1000000000
RATE_LIMIT_FAIL_OPEN=false
RATE_LIMIT_ALLOW_MISSING_IP=false
LOCKOUT_THRESHOLD=1000000
SMTP_HOST=127.0.0.1
SMTP_PORT=$SMTP_PORT
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_ADDRESS=perf@example.com
MAIL_TEMPLATES_DIR=$ROOT/templates
DEVICE_AUTH_VERIFICATION_URI=http://127.0.0.1:5173/device
LOG_LEVEL=warn
LOG_FORMAT=json
METRICS_ENABLED=true
METRICS_PORT=$((API_PORT + 1000))
CLEANUP_INTERVAL_SECS=86400
ENV

python3 - "$OUT/environment.json" <<PY
import json, os, platform, subprocess, sys
def sh(cmd):
    try: return subprocess.check_output(cmd, shell=True, text=True).strip()
    except Exception: return None
json.dump({
    "cpu_model": sh("LC_ALL=C lscpu | sed -n 's/^Model name: *//p'"),
    "cpus": os.cpu_count(),
    "memory_gb": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1),
    "kernel": platform.release(),
    "disk_rotational": sh("cat /sys/block/sda/queue/rotational"),
    "postgres": sh("'$PG_BIN/postgres' --version"),
    "commit": sh("git rev-parse --short HEAD"),
    "volumes": "$VOLUMES".split(),
    "concurrency": "$CONCURRENCY".split(),
    "db_concurrency": "$DB_CONCURRENCY".split(),
    "duration_secs": $DURATION, "warmup_secs": $WARMUP,
    "db_duration_secs": $DB_DURATION, "db_warmup_secs": $DB_WARMUP,
    "cpu_groups": "$PERF_CPU_GROUPS",
    "api_db_pool": $API_DB_POOL,
    "argon2": "m=65536 KiB, t=3, p=4",
}, open(sys.argv[1], "w"), indent=2)
PY

seeded=0
for volume in $VOLUMES; do
  label="users=$volume"
  log "seeding users $((seeded + 1))..$volume"
  started=$(date +%s)
  from=$((seeded + 1))
  while [ "$from" -le "$volume" ]; do
    to=$((from + SEED_CHUNK - 1))
    [ "$to" -gt "$volume" ] && to=$volume
    "${PSQL[@]}" -d auth_perf -v from="$from" -v to="$to" -v hash="$HASH" -f perf/seed.sql
    from=$((to + 1))
  done
  "${PSQL[@]}" -d auth_perf -c "VACUUM (ANALYZE)" -c "CHECKPOINT"
  printf '{"kind":"seed","label":"%s","users":%s,"added":%s,"seconds":%s}\n' \
    "$label" "$volume" "$((volume - seeded))" "$(( $(date +%s) - started ))" >> "$RESULTS"
  seeded=$volume

  log "$label: plans and sizes"
  "${LOAD[@]}" explain --users "$volume" --label "$label" --out "$RESULTS"

  log "$label: database queries"
  for scenario in $DB_SCENARIOS; do
    for c in $DB_CONCURRENCY; do
      "${LOAD[@]}" db --scenario "$scenario" --concurrency "$c" --duration "$DB_DURATION" \
        --warmup "$DB_WARMUP" --users "$volume" --label "$label" --out "$RESULTS" \
        | tee -a "$OUT/run.log" || log "db $scenario c=$c failed"
    done
  done

  log "$label: HTTP scenarios"
  start_api
  for scenario in $HTTP_SCENARIOS; do
    for c in $CONCURRENCY; do
      "$REDIS_CLI" -p "$REDIS_PORT" FLUSHALL >/dev/null
      statements=0
      [ "$scenario" = mixed ] && [ "$c" = "$STATEMENTS_CONCURRENCY" ] && statements=1
      [ "$statements" = 1 ] && "${LOAD[@]}" statements reset
      "${LOAD[@]}" http --scenario "$scenario" --concurrency "$c" --duration "$DURATION" \
        --warmup "$WARMUP" --users "$volume" --label "$label" --out "$RESULTS" \
        | tee -a "$OUT/run.log" || log "http $scenario c=$c failed"
      [ "$statements" = 1 ] && "${LOAD[@]}" statements dump --users "$volume" --label "$label" \
        --context "mixed, $c virtual users" --out "$RESULTS"
    done
  done
  stop_api

  log "$label: retention batches"
  "${LOAD[@]}" cleanup --users "$volume" --label "$label" --out "$RESULTS"
  "${PSQL[@]}" -d auth_perf -c "VACUUM (ANALYZE)"
done

log "done: $RESULTS"
