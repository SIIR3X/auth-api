#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
REPORT_ROOT="${BENCH_REPORT_DIR:-$ROOT_DIR/reports/bench/$TIMESTAMP}"
SUMMARY_FILE="$REPORT_ROOT/summary.md"

mkdir -p "$REPORT_ROOT"

export BENCH_REPORT_DIR="$REPORT_ROOT"

"$ROOT_DIR/scripts/bench-rust.sh" "$@"
"$ROOT_DIR/scripts/bench-http.sh"
"$ROOT_DIR/scripts/bench-sql.sh"

cat >"$SUMMARY_FILE" <<EOF
# Benchmark Run Summary

- Generated at: \`$TIMESTAMP\`
- Report root: \`$REPORT_ROOT\`

## Artifacts

- Rust micro-benchmarks: [rust/summary.md](./rust/summary.md)
- HTTP integration benchmarks: [http/http_report.md](./http/http_report.md)
- SQL database benchmarks: [sql/sql_report.md](./sql/sql_report.md)

## Environment

- BENCH_DATABASE_URL: \`${BENCH_DATABASE_URL:-<unset>}\`
- BENCH_REDIS_URL: \`${BENCH_REDIS_URL:-${TEST_REDIS_URL:-${REDIS_URL:-redis://127.0.0.1:6379}}}\`
- BENCH_HTTP_CONCURRENCY: \`${BENCH_HTTP_CONCURRENCY:-8}\`
- BENCH_HTTP_ITERATIONS: \`${BENCH_HTTP_ITERATIONS:-16}\`
- BENCH_SQL_ITERATIONS: \`${BENCH_SQL_ITERATIONS:-200}\`

## Next Step

Use the three generated sections together when writing a global performance report:
- Rust for pure CPU and algorithmic costs
- HTTP for end-to-end API latency and throughput
- SQL for query plans, index usage, and hot-path database timings
EOF

printf 'Combined benchmark report written to %s\n' "$SUMMARY_FILE"
