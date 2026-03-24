#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
REPORT_ROOT="${BENCH_REPORT_DIR:-$ROOT_DIR/reports/bench/$TIMESTAMP}"
SECTION_DIR="$REPORT_ROOT/rust"
LOG_FILE="$SECTION_DIR/criterion.log"
SUMMARY_FILE="$SECTION_DIR/summary.md"

mkdir -p "$SECTION_DIR"

CRITERION_ARGS=()
if [[ -n "${BENCH_CRITERION_SAVE_BASELINE:-}" ]]; then
  CRITERION_ARGS+=(--save-baseline "$BENCH_CRITERION_SAVE_BASELINE")
fi
if [[ -n "${BENCH_CRITERION_BASELINE:-}" ]]; then
  CRITERION_ARGS+=(--baseline "$BENCH_CRITERION_BASELINE")
fi

pushd "$ROOT_DIR" >/dev/null
cargo bench --bench core_benches -- "${CRITERION_ARGS[@]}" "$@" 2>&1 | tee "$LOG_FILE"

if [[ -d "$ROOT_DIR/target/criterion" ]]; then
  rm -rf "$SECTION_DIR/criterion"
  cp -a "$ROOT_DIR/target/criterion" "$SECTION_DIR/criterion"
fi
popd >/dev/null

cat >"$SUMMARY_FILE" <<EOF
# Rust Micro-Benchmarks

- Generated at: \`$TIMESTAMP\`
- Command: \`cargo bench --bench core_benches\`
- Criterion log: [criterion.log](./criterion.log)
- Criterion report: [criterion/report/index.html](./criterion/report/index.html)

## Coverage

- JWT encoding and decoding, including previous-secret fallback
- Pre-auth serialization and deserialization
- Risk-score computation over multiple history sizes
- TOTP secret generation, QR URI building, and code verification
- Argon2 hashing and verification

## Notes

- Use \`BENCH_CRITERION_SAVE_BASELINE=name\` to capture a named baseline.
- Use \`BENCH_CRITERION_BASELINE=name\` to compare against a saved baseline.
- Criterion HTML reports are copied into this run folder for archival and later reporting.
EOF

printf 'Rust benchmark artifacts written to %s\n' "$SECTION_DIR"
