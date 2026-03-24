#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
REPORT_ROOT="${BENCH_REPORT_DIR:-$ROOT_DIR/reports/bench/$TIMESTAMP}"
SECTION_DIR="$REPORT_ROOT/sql"
LOG_FILE="$SECTION_DIR/run.log"

mkdir -p "$SECTION_DIR"

export BENCH_REPORT_DIR="$REPORT_ROOT"
export BENCH_DATABASE_URL="${BENCH_DATABASE_URL:-${TEST_DATABASE_URL:-}}"
export BENCH_SQL_ITERATIONS="${BENCH_SQL_ITERATIONS:-200}"
export BENCH_SQL_WARMUP="${BENCH_SQL_WARMUP:-25}"

if [[ -z "$BENCH_DATABASE_URL" ]]; then
  echo "BENCH_DATABASE_URL or TEST_DATABASE_URL must be set." >&2
  exit 1
fi

pushd "$ROOT_DIR" >/dev/null
cargo run --release --bin bench_sql 2>&1 | tee "$LOG_FILE"
popd >/dev/null

printf 'SQL benchmark artifacts written to %s\n' "$SECTION_DIR"
printf 'Markdown report: %s\n' "$SECTION_DIR/sql_report.md"
printf 'JSON report: %s\n' "$SECTION_DIR/sql_report.json"
