#!/usr/bin/env bash
# Sizing validation: the production image under the CPU and memory limits of
# the profiles (deploy/profiles), against PostgreSQL and Redis started with the
# settings of deploy/db and NATS with nats.conf, each container on its own
# cores with real cgroup quotas.
#
# Phases (PHASES, in this order):
#   signin     sign-ins per second, latency, CPU throttling and peak memory with
#              1 to 4 CPUs at the memory limit of the matching profile, then an
#              overload of 64 clients the instance must survive
#   footprint  the mixed scenario at profile M on each volume: Redis memory and
#              key families, NATS memory and CPU, PostgreSQL cache ratio, pool
#              saturation
#   restore    dump and restore time of the largest volume (the RTO)
#   soak       SOAK_SECS of mixed traffic at SOAK_PROFILE: no error, no restart,
#              stable memory
#
# The load generator is target/release/perf_load (perf/README.md). Results go to
# $OUT/results.jsonl, the verdicts to $OUT/summary.md.
#
# Usage: perf/sizing.sh   (make sizing). Hours with the default volumes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

PHASES=${PHASES:-"signin footprint restore soak"}
VOLUMES=${VOLUMES:-"100000 1000000"}
SIGNIN_CPUS=${SIGNIN_CPUS:-"1 2 3 4"}
SIGNIN_SECS=${SIGNIN_SECS:-60}
OVERLOAD_SECS=${OVERLOAD_SECS:-30}
FOOTPRINT_SECS=${FOOTPRINT_SECS:-180}
FOOTPRINT_CONCURRENCY=${FOOTPRINT_CONCURRENCY:-64}
SOAK_PROFILE=${SOAK_PROFILE:-m}
SOAK_SECS=${SOAK_SECS:-3600}
SOAK_CONCURRENCY=${SOAK_CONCURRENCY:-32}
SOAK_MAX_GROWTH_PCT=${SOAK_MAX_GROWTH_PCT:-20}
WARMUP=${WARMUP:-10}
SEED_CHUNK=${SEED_CHUNK:-50000}
PG_CPUS=${PG_CPUS:-0-2}
PG_MEMORY=${PG_MEMORY:-8g}
CACHE_CPUS=${CACHE_CPUS:-3}
LOAD_CPUS=${LOAD_CPUS:-7}
# Kept after the run when 1, so a later run does not seed a million accounts again.
KEEP_DATA=${KEEP_DATA:-0}
OUT=${OUT:-reports/perf/sizing-$(date +%Y%m%d-%H%M%S)}

PG_IMAGE=${PG_IMAGE:-$(sed -n 's/^ *image: *\(postgres:.*\)$/\1/p' docker-compose.test.yml | head -1)}
REDIS_IMAGE=${REDIS_IMAGE:-$(sed -n 's/^ *image: *\(redis:.*\)$/\1/p' docker-compose.test.yml | head -1)}
NATS_IMAGE=${NATS_IMAGE:-$(sed -n 's/^ *image: *\(nats:.*\)$/\1/p' docker-compose.api.yml | head -1)}
API_IMAGE=auth-api:sizing
NET=auth-sizing
SUBNET=172.31.250.0/24
PG_PORT=55440
API_PORT=3200
METRICS_PORT=3201
DB=auth_sizing

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
RESULTS="$OUT/results.jsonl"
SAMPLER=""

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
psql_db() { docker exec -i auth-sizing-pg psql -U postgres -d "$DB" -X -q -v ON_ERROR_STOP=1 "$@"; }
redis() { docker exec auth-sizing-redis redis-cli "$@" | tr -d '\r'; }
dev_env() { grep "^$1=" .env.dev | cut -d= -f2-; }
profile_value() { sed -n "s/^$2=//p" "deploy/profiles/$1.env"; }

# One JSON object per line: emit KIND key=value...; numbers stay numbers.
emit() {
  python3 - "$RESULTS" "$@" <<'PY'
import json, sys
out, kind, *pairs = sys.argv[1:]
record = {"kind": kind}
for pair in pairs:
    key, value = pair.split("=", 1)
    for cast in (int, float):
        try:
            value = cast(value)
            break
        except ValueError:
            pass
    record[key] = value
with open(out, "a") as f:
    f.write(json.dumps(record) + "\n")
PY
}

# rps, p95 and failed requests of the last HTTP run in results.jsonl.
last_http() {
  python3 - "$RESULTS" <<'PY'
import json, sys
runs = [r for r in map(json.loads, filter(str.strip, open(sys.argv[1]))) if r.get("kind") == "http"]
run = runs[-1]
errors = run.get("errors") or 0
errors = sum(errors.values()) if isinstance(errors, dict) else int(errors)
print(run["rps"], run["latency_ms"]["p95"], errors)
PY
}

cgroup_dir() {
  local id
  id=$(docker inspect -f '{{.Id}}' "$1")
  for dir in "/sys/fs/cgroup/system.slice/docker-$id.scope" "/sys/fs/cgroup/docker/$id"; do
    [ -d "$dir" ] && { echo "$dir"; return; }
  done
  echo "no cgroup v2 directory for $1" >&2
  return 1
}
cpu_stat() { awk -v key="$2" '$1 == key { print $2 }' "$1/cpu.stat"; }

teardown() {
  if [ -n "$SAMPLER" ]; then kill "$SAMPLER" 2>/dev/null || true; fi
  docker rm -f auth-sizing-api auth-sizing-nats auth-sizing-redis auth-sizing-pg >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  if [ "$KEEP_DATA" != 1 ]; then
    docker volume rm auth-sizing-pgdata auth-sizing-dump >/dev/null 2>&1 || true
  fi
}
trap teardown EXIT

# --- Dependencies -------------------------------------------------------------

start_dependencies() {
  docker network create --subnet "$SUBNET" "$NET" >/dev/null

  # PostgreSQL with the DB VPS settings (profile M), minus the listen address.
  local pg_args=() line key value
  while IFS= read -r line; do
    line=${line%%#*}
    [[ $line =~ ^[[:space:]]*([a-z_.]+)[[:space:]]*=[[:space:]]*(.*[^[:space:]])[[:space:]]*$ ]] || continue
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    value=${value#\'}
    value=${value%\'}
    [ "$key" = listen_addresses ] && continue
    pg_args+=(-c "$key=$value")
  done < deploy/db/postgresql.auth-api.conf
  docker run -d --name auth-sizing-pg --network "$NET" --cpuset-cpus "$PG_CPUS" \
    --memory "$PG_MEMORY" --shm-size 1g -p "127.0.0.1:$PG_PORT:5432" \
    -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB="$DB" \
    -v auth-sizing-pgdata:/var/lib/postgresql/data -v auth-sizing-dump:/dump \
    "$PG_IMAGE" postgres "${pg_args[@]}" >/dev/null
  for _ in $(seq 1 60); do
    docker exec auth-sizing-pg pg_isready -U postgres -d "$DB" >/dev/null 2>&1 && break
    sleep 1
  done
  # The entrypoint restarts the server once after creating the database.
  sleep 3
  docker exec auth-sizing-pg pg_isready -U postgres -d "$DB" >/dev/null

  # Redis with the DB VPS settings, minus the address, port and ACL file.
  local redis_args=()
  while read -r key value; do
    case "$key" in "" | \#* | bind | port | aclfile | protected-mode) continue ;; esac
    redis_args+=("--$key" "$value")
  done < deploy/db/redis.auth-api.conf
  docker run -d --name auth-sizing-redis --network "$NET" --cpuset-cpus "$CACHE_CPUS" \
    "$REDIS_IMAGE" redis-server "${redis_args[@]}" >/dev/null

  # NATS with nats.conf and the limits of profile M.
  printf 'authorization { token: "sizing-token" }\n' > "$OUT/nats-auth.conf"
  chmod 644 "$OUT/nats-auth.conf"
  docker run -d --name auth-sizing-nats --network "$NET" --cpuset-cpus "$CACHE_CPUS" \
    --cpus "$(profile_value m NATS_CPUS)" --memory "$(profile_value m NATS_MEMORY)" \
    -e GOMEMLIMIT="$(profile_value m NATS_GOMEMLIMIT)" \
    -v "$ROOT/nats.conf:/etc/nats/nats.conf:ro" -v "$OUT/nats-auth.conf:/etc/nats/auth.conf:ro" \
    "$NATS_IMAGE" --config /etc/nats/nats.conf >/dev/null
}

# --- API ----------------------------------------------------------------------

# start_api CPUS MEMORY RESERVATION ARGON2 DB_POOL REDIS_POOL
start_api() {
  local cpus=$1 cpuset=4-6
  [ "$cpus" -gt 3 ] && cpuset=4-7
  docker rm -f auth-sizing-api >/dev/null 2>&1 || true
  docker run -d --name auth-sizing-api --network "$NET" \
    --cpuset-cpus "$cpuset" --cpus "$cpus" --memory "$2" --memory-reservation "$3" \
    --pids-limit 256 --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    -p "127.0.0.1:$API_PORT:3000" -p "127.0.0.1:$METRICS_PORT:9464" \
    -e APP_ENV=development -e SERVER_HOST=0.0.0.0 -e SERVER_PORT=3000 \
    -e APP_PUBLIC_URL="http://127.0.0.1:$API_PORT" -e FRONTEND_URL=http://127.0.0.1:5173 \
    -e TRUSTED_PROXY_CIDRS="$SUBNET" \
    -e DATABASE_URL="postgres://postgres@auth-sizing-pg:5432/$DB" \
    -e DB_MAX_CONNECTIONS="$5" -e REDIS_URL=redis://auth-sizing-redis:6379 -e REDIS_POOL_SIZE="$6" \
    -e NATS_URL=nats://sizing-token@auth-sizing-nats:4222 \
    -e JWT_PRIVATE_KEY="$(dev_env JWT_PRIVATE_KEY)" -e JWT_PUBLIC_KEY="$(dev_env JWT_PUBLIC_KEY)" \
    -e ENCRYPTION_KEY="$(dev_env ENCRYPTION_KEY)" \
    -e ARGON2_MEMORY_KIB="$ARGON2_MEMORY_KIB" -e ARGON2_ITERATIONS="$ARGON2_ITERATIONS" \
    -e ARGON2_PARALLELISM="$ARGON2_PARALLELISM" -e ARGON2_MAX_CONCURRENCY="$4" \
    -e RATE_LIMIT_RPM=1000000000 -e RATE_LIMIT_AUTH_RPM=1000000000 \
    -e RATE_LIMIT_FAIL_OPEN=false -e RATE_LIMIT_ALLOW_MISSING_IP=false -e LOCKOUT_THRESHOLD=1000000 \
    -e SMTP_HOST=127.0.0.1 -e SMTP_PORT=1 -e SMTP_USERNAME= -e SMTP_PASSWORD= \
    -e SMTP_FROM_ADDRESS=perf@example.com \
    -e DEVICE_AUTH_VERIFICATION_URI=http://127.0.0.1:5173/device \
    -e LOG_LEVEL=warn -e LOG_FORMAT=json -e METRICS_ENABLED=true -e METRICS_PORT=9464 \
    -e CLEANUP_INTERVAL_SECS=86400 \
    "$API_IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$API_PORT/ready")" = 200 ] && return 0
    sleep 1
  done
  docker logs auth-sizing-api > "$OUT/api-failed.log" 2>&1
  log "the API did not become ready; see $OUT/api-failed.log"
  exit 1
}

# start_profile NAME: the API with a profile's limits.
start_profile() {
  start_api "$(profile_value "$1" API_CPUS)" "$(profile_value "$1" API_MEMORY)" \
    "$(profile_value "$1" API_MEMORY_RESERVATION)" "$(profile_value "$1" ARGON2_MAX_CONCURRENCY)" \
    "$(profile_value "$1" DB_MAX_CONNECTIONS)" "$(profile_value "$1" REDIS_POOL_SIZE)"
}

load() {
  taskset -c "$LOAD_CPUS" "$ROOT/target/release/perf_load" "$@" >> "$OUT/run.log"
}

# Pool, queue and memory gauges of the API and Redis memory, every 2 seconds.
sampler_start() {
  local file=$1
  echo "secs,db_in_use,db_max,redis_waiting,argon2_free,working_set,redis_used" > "$file"
  (
    started=$(date +%s)
    while :; do
      metrics=$(curl -s --max-time 2 "http://127.0.0.1:$METRICS_PORT/metrics" || true)
      gauge() { printf '%s\n' "$metrics" | awk -v name="$1" 'index($0, name " ") == 1 { printf "%d", $2 }'; }
      used=$(redis INFO memory 2>/dev/null | sed -n 's/^used_memory://p')
      echo "$(( $(date +%s) - started )),$(gauge 'auth_db_pool_connections{state="in_use"}'),$(gauge 'auth_db_pool_connections{state="max"}'),$(gauge auth_redis_pool_waiting),$(gauge argon2_queue_available_permits),$(gauge auth_container_memory_working_set_bytes),$used" >> "$file"
      sleep 2
    done
  ) &
  SAMPLER=$!
}
sampler_stop() {
  kill "$SAMPLER" 2>/dev/null || true
  wait "$SAMPLER" 2>/dev/null || true
  SAMPLER=""
}
column_max() {
  python3 -c "import csv,sys; print(max([int(r[sys.argv[2]]) for r in csv.DictReader(open(sys.argv[1])) if r[sys.argv[2]]] or [0]))" "$1" "$2"
}

# --- Data set -----------------------------------------------------------------

seed_to() {
  local volume=$1 from to seeded started
  seeded=$(psql_db -tAc "SELECT count(*) FROM users WHERE email LIKE 'perf%@example.com'")
  [ "$seeded" -ge "$volume" ] && { log "users: $seeded already seeded"; return; }
  log "seeding users $((seeded + 1))..$volume"
  started=$(date +%s)
  from=$((seeded + 1))
  while [ "$from" -le "$volume" ]; do
    to=$((from + SEED_CHUNK - 1))
    [ "$to" -gt "$volume" ] && to=$volume
    psql_db -v from="$from" -v to="$to" -v hash="$HASH" -f - < perf/seed.sql
    from=$((to + 1))
  done
  psql_db -c "VACUUM (ANALYZE)" -c "CHECKPOINT"
  emit seed users="$volume" seconds=$(( $(date +%s) - started ))
}

# --- Phases -------------------------------------------------------------------

phase_signin() {
  local volume=$1 cpus profile memory reservation pool cg periods throttled rps p95 errors
  for cpus in $SIGNIN_CPUS; do
    profile=$(grep -l "^API_CPUS=$cpus\$" deploy/profiles/*.env | head -1 | xargs -r basename | cut -d. -f1)
    memory=$( [ -n "$profile" ] && profile_value "$profile" API_MEMORY || echo 512M)
    reservation=$( [ -n "$profile" ] && profile_value "$profile" API_MEMORY_RESERVATION || echo 256M)
    pool=$( [ -n "$profile" ] && profile_value "$profile" DB_MAX_CONNECTIONS || echo $((4 * cpus)))
    log "signin: $cpus CPU, memory $memory (profile ${profile:-none})"
    start_api "$cpus" "$memory" "$reservation" "$cpus" "$pool" "$pool"
    cg=$(cgroup_dir auth-sizing-api)
    periods=$(cpu_stat "$cg" nr_periods)
    throttled=$(cpu_stat "$cg" nr_throttled)
    load http --scenario login --concurrency $((4 * cpus)) --duration "$SIGNIN_SECS" \
      --warmup "$WARMUP" --users "$volume" --label "signin cpus=$cpus" --out "$RESULTS"
    read -r rps p95 errors < <(last_http)
    periods=$(( $(cpu_stat "$cg" nr_periods) - periods ))
    throttled=$(( $(cpu_stat "$cg" nr_throttled) - throttled ))
    local peak limit
    peak=$(cat "$cg/memory.peak")
    limit=$(cat "$cg/memory.max")

    log "signin: overload, 64 clients"
    load http --scenario login --concurrency 64 --duration "$OVERLOAD_SECS" \
      --warmup 2 --users "$volume" --label "signin-overload cpus=$cpus" --out "$RESULTS"
    local overload_p95 overload_errors overload_peak running oom
    read -r _ overload_p95 overload_errors < <(last_http)
    overload_peak=$(cat "$cg/memory.peak")
    running=$(docker inspect -f '{{.State.Running}}' auth-sizing-api)
    oom=$(docker inspect -f '{{.State.OOMKilled}}' auth-sizing-api)
    emit signin cpus="$cpus" profile="${profile:-none}" memory_limit_bytes="$limit" \
      rps="$rps" p95_ms="$p95" errors="$errors" throttled_periods="$throttled" periods="$periods" \
      peak_bytes="$peak" overload_p95_ms="$overload_p95" overload_errors="$overload_errors" \
      overload_peak_bytes="$overload_peak" running="$running" oom_killed="$oom"
  done
}

phase_footprint() {
  local volume=$1 cg_nats nats_usage hit read rps p95 errors started
  log "footprint: users=$volume, profile M, mixed at $FOOTPRINT_CONCURRENCY clients"
  start_profile m
  redis FLUSHALL >/dev/null
  cg_nats=$(cgroup_dir auth-sizing-nats)
  nats_usage=$(cpu_stat "$cg_nats" usage_usec)
  read -r hit read < <(psql_db -tA -F ' ' -c "SELECT blks_hit, blks_read FROM pg_stat_database WHERE datname = '$DB'")
  sampler_start "$OUT/footprint-$volume.csv"
  started=$(date +%s)
  load http --scenario mixed --concurrency "$FOOTPRINT_CONCURRENCY" --duration "$FOOTPRINT_SECS" \
    --warmup "$WARMUP" --users "$volume" --label "footprint users=$volume" --out "$RESULTS"
  local elapsed=$(( $(date +%s) - started ))
  sampler_stop
  read -r rps p95 errors < <(last_http)
  local hit2 read2
  read -r hit2 read2 < <(psql_db -tA -F ' ' -c "SELECT blks_hit, blks_read FROM pg_stat_database WHERE datname = '$DB'")
  local cache_ratio families
  cache_ratio=$(python3 -c "h=$hit2-$hit; r=$read2-$read; print(round(h/(h+r), 4) if h+r else 1)")
  families=$(redis --scan --count 1000 | sed 's/:.*//' | sort | uniq -c | sort -rn | awk '{printf "%s%s=%s", sep, $2, $1; sep=","}')
  emit footprint users="$volume" rps="$rps" p95_ms="$p95" errors="$errors" \
    redis_used_peak_bytes="$(column_max "$OUT/footprint-$volume.csv" redis_used)" \
    redis_used_end_bytes="$(redis INFO memory | sed -n 's/^used_memory://p')" \
    redis_keys="$(redis DBSIZE)" redis_key_families="$families" \
    nats_peak_bytes="$(cat "$cg_nats/memory.peak")" nats_limit_bytes="$(cat "$cg_nats/memory.max")" \
    nats_cpu_cores="$(python3 -c "print(round(($(cpu_stat "$cg_nats" usage_usec) - $nats_usage) / 1e6 / $elapsed, 3))")" \
    pg_cache_ratio="$cache_ratio" \
    db_pool_in_use_max="$(column_max "$OUT/footprint-$volume.csv" db_in_use)" \
    db_pool_max="$(column_max "$OUT/footprint-$volume.csv" db_max)" \
    redis_pool_waiting_max="$(column_max "$OUT/footprint-$volume.csv" redis_waiting)" \
    api_working_set_max_bytes="$(column_max "$OUT/footprint-$volume.csv" working_set)" \
    api_limit_bytes="$(cat "$(cgroup_dir auth-sizing-api)/memory.max")"
}

phase_restore() {
  local volume=$1 started dump_secs restore_secs size source restored
  docker rm -f auth-sizing-api >/dev/null 2>&1 || true
  log "restore: dump of users=$volume (pg_dump | gzip, as backup-db.sh)"
  started=$(date +%s)
  docker exec auth-sizing-pg sh -c "pg_dump -U postgres --no-owner $DB | gzip > /dump/auth.sql.gz"
  dump_secs=$(( $(date +%s) - started ))
  size=$(docker exec auth-sizing-pg stat -c %s /dump/auth.sql.gz)
  log "restore: into a fresh database (psql --single-transaction, as restore-db.sh)"
  docker exec auth-sizing-pg createdb -U postgres auth_restored
  started=$(date +%s)
  docker exec auth-sizing-pg sh -c \
    "gunzip -c /dump/auth.sql.gz | psql -U postgres -d auth_restored -X -q -v ON_ERROR_STOP=1 --single-transaction > /dev/null"
  restore_secs=$(( $(date +%s) - started ))
  source=$(psql_db -tAc "SELECT count(*) FROM users")
  restored=$(docker exec auth-sizing-pg psql -U postgres -d auth_restored -tAc "SELECT count(*) FROM users")
  docker exec auth-sizing-pg dropdb -U postgres auth_restored
  docker exec auth-sizing-pg rm -f /dump/auth.sql.gz
  emit restore users="$volume" database_bytes="$(psql_db -tAc "SELECT pg_database_size('$DB')")" \
    dump_bytes="$size" dump_secs="$dump_secs" restore_secs="$restore_secs" \
    users_source="$source" users_restored="$restored"
}

phase_soak() {
  local volume=$1
  log "soak: profile $SOAK_PROFILE, users=$volume, mixed at $SOAK_CONCURRENCY clients for $SOAK_SECS s"
  start_profile "$SOAK_PROFILE"
  sampler_start "$OUT/soak.csv"
  load http --scenario mixed --concurrency "$SOAK_CONCURRENCY" --duration "$SOAK_SECS" \
    --warmup 60 --users "$volume" --label "soak profile=$SOAK_PROFILE" --out "$RESULTS"
  sampler_stop
  local rps p95 errors
  read -r rps p95 errors < <(last_http)
  local verdict
  verdict=$(python3 - "$OUT/soak.csv" "$SOAK_MAX_GROWTH_PCT" <<'PY'
import csv, statistics, sys
rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["working_set"] and int(r["secs"]) >= 60]
memory = [int(r["working_set"]) for r in rows]
tenth = max(1, len(memory) // 10)
first, last = statistics.median(memory[:tenth]), statistics.median(memory[-tenth:])
print(first, last, round((last - first) / first * 100, 1))
PY
)
  local first last growth
  read -r first last growth <<< "$verdict"
  emit soak profile="$SOAK_PROFILE" users="$volume" secs="$SOAK_SECS" rps="$rps" p95_ms="$p95" \
    errors="$errors" working_set_first_bytes="$first" working_set_last_bytes="$last" \
    growth_pct="$growth" max_growth_pct="$SOAK_MAX_GROWTH_PCT" \
    restarts="$(docker inspect -f '{{.RestartCount}}' auth-sizing-api)" \
    running="$(docker inspect -f '{{.State.Running}}' auth-sizing-api)" \
    oom_killed="$(docker inspect -f '{{.State.OOMKilled}}' auth-sizing-api)"
}

# --- Run ----------------------------------------------------------------------

has_phase() { [[ " $PHASES " == *" $1 "* ]]; }

read -r ARGON2_MEMORY_KIB ARGON2_ITERATIONS ARGON2_PARALLELISM < <(
  for key in ARGON2_MEMORY_KIB ARGON2_ITERATIONS ARGON2_PARALLELISM; do
    sed -n "s/^$key=//p" config.prod.env
  done | paste -sd ' ')
export PERF_PASSWORD=${PERF_PASSWORD:-Perf-Password-2026!}
export PERF_CPU_GROUPS="postgres=$PG_CPUS;cache=$CACHE_CPUS;api=4-7;load=$LOAD_CPUS"
export DATABASE_URL="postgres://postgres@127.0.0.1:$PG_PORT/$DB"
export BASE_URL="http://127.0.0.1:$API_PORT"
export APP_PUBLIC_URL="$BASE_URL"
JWT_PRIVATE_KEY=$(dev_env JWT_PRIVATE_KEY)
JWT_PUBLIC_KEY=$(dev_env JWT_PUBLIC_KEY)
export JWT_PRIVATE_KEY JWT_PUBLIC_KEY

log "building the image and the load generator"
docker build -q -t "$API_IMAGE" . >/dev/null
cargo build --release --quiet --bin perf_load
docker rm -f auth-sizing-api auth-sizing-nats auth-sizing-redis auth-sizing-pg >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
start_dependencies
load migrate
HASH=$(taskset -c "$LOAD_CPUS" "$ROOT/target/release/perf_load" hash)
emit environment cpus="$(nproc)" commit="$(git rev-parse --short HEAD)" \
  argon2="m=$ARGON2_MEMORY_KIB,t=$ARGON2_ITERATIONS,p=$ARGON2_PARALLELISM" \
  pg_cpus="$PG_CPUS" pg_memory="$PG_MEMORY" cache_cpus="$CACHE_CPUS" load_cpus="$LOAD_CPUS"

first=1
largest=""
for volume in $VOLUMES; do
  seed_to "$volume"
  if [ "$first" = 1 ] && has_phase signin; then phase_signin "$volume"; fi
  first=0
  if has_phase footprint; then phase_footprint "$volume"; fi
  largest=$volume
done
if has_phase restore; then phase_restore "$largest"; fi
if has_phase soak; then phase_soak "$largest"; fi
docker rm -f auth-sizing-api >/dev/null 2>&1 || true

python3 perf/sizing_report.py "$RESULTS" | tee "$OUT/summary.md"
