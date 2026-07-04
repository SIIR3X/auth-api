#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
REPORT_ROOT="${BENCH_REPORT_DIR:-$ROOT_DIR/reports/bench/$TIMESTAMP}"
SECTION_DIR="$REPORT_ROOT/http"
LOG_FILE="$SECTION_DIR/run.log"

mkdir -p "$SECTION_DIR"

export BENCH_REPORT_DIR="$REPORT_ROOT"
export BENCH_DATABASE_URL="${BENCH_DATABASE_URL:-${TEST_DATABASE_URL:-}}"
export BENCH_REDIS_URL="${BENCH_REDIS_URL:-${TEST_REDIS_URL:-${REDIS_URL:-redis://127.0.0.1:6379}}}"
export BENCH_NATS_URL="${BENCH_NATS_URL:-${TEST_NATS_URL:-${NATS_URL:-nats://127.0.0.1:4222}}}"
export BENCH_HTTP_CONCURRENCY="${BENCH_HTTP_CONCURRENCY:-8}"
export BENCH_HTTP_ITERATIONS="${BENCH_HTTP_ITERATIONS:-16}"
export BENCH_HTTP_WARMUP="${BENCH_HTTP_WARMUP:-3}"

if [[ -z "$BENCH_DATABASE_URL" ]]; then
  echo "BENCH_DATABASE_URL or TEST_DATABASE_URL must be set." >&2
  exit 1
fi

pushd "$ROOT_DIR" >/dev/null
cargo run --release --bin bench_http 2>&1 | tee "$LOG_FILE"
popd >/dev/null

printf 'HTTP benchmark artifacts written to %s\n' "$SECTION_DIR"
printf 'Markdown report: %s\n' "$SECTION_DIR/http_report.md"
printf 'JSON report: %s\n' "$SECTION_DIR/http_report.json"
