#!/usr/bin/env bash
# Soak test: one API process under the mixed scenario for an hour, watching for
# errors and for resident memory that keeps growing.
#
# perf/run.sh does the work (release build, infrastructure, a data set of
# SOAK_USERS accounts in its own database) with a single long HTTP run; this
# script samples the API's memory meanwhile. It fails when a request errored,
# or when the API's memory over the last tenth of the run exceeds its memory
# over the first tenth, after warm-up, by more than SOAK_MAX_GROWTH_PCT.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

SOAK_SECS=${SOAK_SECS:-3600}
SOAK_USERS=${SOAK_USERS:-10000}
SOAK_CONCURRENCY=${SOAK_CONCURRENCY:-32}
SOAK_WARMUP=${SOAK_WARMUP:-60}
SOAK_MAX_GROWTH_PCT=${SOAK_MAX_GROWTH_PCT:-20}
SAMPLE_SECS=${SAMPLE_SECS:-15}
export OUT=${OUT:-reports/perf/soak-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
MEMORY="$OUT/memory.csv"

VOLUMES=$SOAK_USERS CONCURRENCY=$SOAK_CONCURRENCY HTTP_SCENARIOS=mixed DB_SCENARIOS="" \
  DURATION=$SOAK_SECS WARMUP=$SOAK_WARMUP STATEMENTS_CONCURRENCY=0 PERF_DB=auth_soak \
  perf/run.sh &
RUN_PID=$!
trap 'kill "$RUN_PID" 2>/dev/null || true' INT TERM

# Resident memory of the API, sampled while it runs.
echo "elapsed_secs,rss_kib" > "$MEMORY"
started=$(date +%s)
while kill -0 "$RUN_PID" 2>/dev/null; do
  pid=$(pgrep -n -f "^$ROOT/target/release/auth-api\$" || true)
  if [ -n "$pid" ]; then
    rss=$(awk '/^VmRSS:/ { print $2 }' "/proc/$pid/status" 2>/dev/null || true)
    [ -n "$rss" ] && echo "$(( $(date +%s) - started )),$rss" >> "$MEMORY"
  fi
  sleep "$SAMPLE_SECS"
done
wait "$RUN_PID"

python3 - "$OUT" "$SOAK_WARMUP" "$SAMPLE_SECS" "$SOAK_MAX_GROWTH_PCT" <<'PY'
import csv, json, statistics, sys

out, warmup, sample_secs, max_growth = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
results = [json.loads(line) for line in open(f"{out}/results.jsonl") if line.strip()]
http = [r for r in results if r.get("kind") == "http"]
if not http:
    sys.exit("soak: no HTTP result in results.jsonl")
run = http[-1]
errors = run.get("errors") or {}
error_count = sum(errors.values()) if isinstance(errors, dict) else int(errors)

rows = [row for row in csv.reader(open(f"{out}/memory.csv")) if row[0].isdigit()]
rss = [int(row[1]) for row in rows][max(1, warmup // sample_secs):]
if len(rss) < 10:
    sys.exit(f"soak: {len(rss)} memory samples after warm-up, too few to judge")
tenth = max(1, len(rss) // 10)
first, last = statistics.median(rss[:tenth]), statistics.median(rss[-tenth:])
growth = (last - first) / first * 100

summary = {
    "duration_secs": run.get("duration_secs"),
    "concurrency": run.get("concurrency"),
    "rps": run.get("rps"),
    "errors": errors,
    "rss_first_tenth_kib": first,
    "rss_last_tenth_kib": last,
    "rss_growth_pct": round(growth, 1),
    "max_growth_pct": max_growth,
}
json.dump(summary, open(f"{out}/soak.json", "w"), indent=2)
print(json.dumps(summary, indent=2))
if error_count:
    sys.exit(f"soak: {error_count} requests failed")
if growth > max_growth:
    sys.exit(f"soak: memory grew {growth:.1f}% (limit {max_growth}%)")
print("soak: no error, memory stable")
PY
