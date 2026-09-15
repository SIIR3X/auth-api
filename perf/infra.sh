#!/usr/bin/env bash
# Dedicated, disk-backed infrastructure for performance runs.
#
# PostgreSQL runs with production durability (fsync, synchronous commit, full
# page writes) on the local disk, never on tmpfs. Each service is pinned to its
# own CPUs so the load generator and the API do not steal time from the
# database, and so per-CPU utilization can be attributed to one component:
#
#   PG_CPUS (default 0-2)     PostgreSQL
#   CACHE_CPUS (default 3)    Redis and NATS
#   API_CPUS (default 4-6)    auth-api (see run.sh)
#   LOAD_CPUS (default 7)     load generator (see run.sh)
#
# Usage: perf/infra.sh start|stop|status
set -euo pipefail

PERF_HOME=${PERF_HOME:-$HOME/.cache/auth-api-perf}
PG_BIN=${PG_BIN:-$(dirname "$(command -v postgres)")}
REDIS_SERVER=${REDIS_SERVER:-$(command -v redis-server)}
REDIS_CLI=${REDIS_CLI:-$(command -v redis-cli)}
NATS_SERVER=${NATS_SERVER:-$(command -v nats-server)}
PG_PORT=${PG_PORT:-5434}
REDIS_PORT=${REDIS_PORT:-6381}
NATS_PORT=${NATS_PORT:-4225}
PG_CPUS=${PG_CPUS:-0-2}
CACHE_CPUS=${CACHE_CPUS:-3}

listening() { ss -ltn | grep -q ":$1 "; }

start() {
  mkdir -p "$PERF_HOME/run" "$PERF_HOME/js"
  if [ ! -d "$PERF_HOME/pgdata" ]; then
    "$PG_BIN/initdb" -D "$PERF_HOME/pgdata" -U postgres --auth=trust >/dev/null
  fi
  if ! listening "$PG_PORT"; then
    taskset -c "$PG_CPUS" "$PG_BIN/pg_ctl" -D "$PERF_HOME/pgdata" -l "$PERF_HOME/run/pg.log" -w start -o "\
      -p $PG_PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories='' \
      -c max_connections=200 \
      -c shared_buffers=4GB -c effective_cache_size=12GB \
      -c work_mem=16MB -c maintenance_work_mem=1GB \
      -c random_page_cost=1.1 -c effective_io_concurrency=200 \
      -c fsync=on -c synchronous_commit=on -c full_page_writes=on -c wal_compression=on \
      -c max_wal_size=8GB -c min_wal_size=1GB \
      -c checkpoint_timeout=15min -c checkpoint_completion_target=0.9 \
      -c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track=top \
      -c track_io_timing=on" >/dev/null
  fi
  "$PG_BIN/psql" -h 127.0.0.1 -p "$PG_PORT" -U postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname = 'auth_perf'" | grep -q 1 \
    || "$PG_BIN/createdb" -h 127.0.0.1 -p "$PG_PORT" -U postgres auth_perf
  "$PG_BIN/psql" -h 127.0.0.1 -p "$PG_PORT" -U postgres -d auth_perf -qc \
    "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"

  if ! listening "$REDIS_PORT"; then
    taskset -c "$CACHE_CPUS" "$REDIS_SERVER" --port "$REDIS_PORT" --bind 127.0.0.1 \
      --save '' --appendonly no --maxmemory 2gb --maxmemory-policy noeviction \
      --daemonize yes --dir "$PERF_HOME/run" --logfile "$PERF_HOME/run/redis.log" \
      --pidfile "$PERF_HOME/run/redis.pid"
  fi
  if ! listening "$NATS_PORT"; then
    nohup taskset -c "$CACHE_CPUS" "$NATS_SERVER" -a 127.0.0.1 -p "$NATS_PORT" \
      -js -sd "$PERF_HOME/js" -P "$PERF_HOME/run/nats.pid" \
      > "$PERF_HOME/run/nats.log" 2>&1 &
  fi
  sleep 1
  status
}

stop() {
  "$PG_BIN/pg_ctl" -D "$PERF_HOME/pgdata" -m fast stop >/dev/null 2>&1 || true
  "$REDIS_CLI" -p "$REDIS_PORT" shutdown nosave >/dev/null 2>&1 || true
  if [ -f "$PERF_HOME/run/nats.pid" ]; then
    kill "$(cat "$PERF_HOME/run/nats.pid")" 2>/dev/null || true
  fi
  status
}

status() {
  for port in "$PG_PORT" "$REDIS_PORT" "$NATS_PORT"; do
    if listening "$port"; then echo "port $port: up"; else echo "port $port: down"; fi
  done
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
