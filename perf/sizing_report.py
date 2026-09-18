"""Verdicts of perf/sizing.sh: a Markdown summary of results.jsonl.

Criteria (docs/deploy/guides/operations.md, section 9):
- sign-ins: 11 per second per CPU within 15 %, no error, peak memory under 90 %
  of the limit, the instance survives an overload without being killed;
- footprint: no error, NATS under 70 % of its memory limit, database pool
  never full, no Redis pool wait. PostgreSQL's buffer hit ratio is shown, not
  judged: it counts only shared_buffers, and the load reads accounts uniformly
  across the whole database (below 0.99 at 1 million accounts with 8 or 14 GB);
- soak: no error, no restart, working set growth under the tolerance.

Usage: python3 perf/sizing_report.py <results.jsonl>
"""

import json
import sys

MIB = 1024 * 1024
SIGNINS_PER_CPU = 11
TOLERANCE = 0.15


def mib(value):
    return f"{value / MIB:.0f} MiB"


def verdict(ok):
    return "PASS" if ok else "FAIL"


def main(path):
    records = [json.loads(line) for line in open(path) if line.strip()]
    by_kind = {}
    for record in records:
        by_kind.setdefault(record["kind"], []).append(record)
    failures = 0
    out = ["# Sizing validation", ""]

    for env in by_kind.get("environment", []):
        out.append(
            f"Commit {env['commit']}, {env['cpus']} host CPUs, Argon2 {env['argon2']}; "
            f"PostgreSQL on CPUs {env['pg_cpus']} with {env['pg_memory']}, Redis and NATS "
            f"on {env['cache_cpus']}, load generator on {env['load_cpus']}."
        )
        out.append("")

    if "signin" in by_kind:
        out += [
            "## Sign-ins under CPU quota",
            "",
            "| CPUs | Profile | Sign-ins/s | Per CPU | p95 | Throttled | Peak memory | Overload peak | Overload p95 | Verdict |",
            "|-----:|---------|-----------:|--------:|----:|----------:|------------:|--------------:|-------------:|---------|",
        ]
        for r in by_kind["signin"]:
            per_cpu = r["rps"] / r["cpus"]
            limit = r["memory_limit_bytes"]
            peak = max(r["peak_bytes"], r["overload_peak_bytes"])
            ok = (
                abs(per_cpu - SIGNINS_PER_CPU) / SIGNINS_PER_CPU <= TOLERANCE
                or per_cpu > SIGNINS_PER_CPU
            )
            ok = ok and r["errors"] == 0 and r["overload_errors"] == 0
            ok = ok and peak < 0.9 * limit and r["running"] == "true" and r["oom_killed"] == "false"
            failures += not ok
            throttled = r["throttled_periods"] / r["periods"] if r["periods"] else 0
            out.append(
                f"| {r['cpus']} | {r['profile']} | {r['rps']:.1f} | {per_cpu:.1f} | {r['p95_ms']:.0f} ms "
                f"| {throttled:.0%} | {mib(r['peak_bytes'])} / {mib(limit)} | {mib(r['overload_peak_bytes'])} "
                f"| {r['overload_p95_ms']:.0f} ms | {verdict(ok)} |"
            )
        out.append("")

    if "footprint" in by_kind:
        out += [
            "## Footprint at profile M (mixed scenario)",
            "",
            "| Accounts | Req/s | p95 | Errors | Redis peak | Redis keys | NATS peak | NATS CPU | PG cache | DB pool max in use | Redis pool wait | API working set | Verdict |",
            "|---------:|------:|----:|-------:|-----------:|-----------:|----------:|---------:|---------:|-------------------:|----------------:|----------------:|---------|",
        ]
        for r in by_kind["footprint"]:
            ok = (
                r["errors"] == 0
                and r["nats_peak_bytes"] < 0.7 * r["nats_limit_bytes"]
                and r["db_pool_in_use_max"] < r["db_pool_max"]
                and r["redis_pool_waiting_max"] == 0
                and r["api_working_set_max_bytes"] < 0.9 * r["api_limit_bytes"]
            )
            failures += not ok
            out.append(
                f"| {r['users']:,} | {r['rps']:.0f} | {r['p95_ms']:.0f} ms | {r['errors']} "
                f"| {mib(r['redis_used_peak_bytes'])} | {r['redis_keys']:,} "
                f"| {mib(r['nats_peak_bytes'])} / {mib(r['nats_limit_bytes'])} | {r['nats_cpu_cores']} "
                f"| {r['pg_cache_ratio']} | {r['db_pool_in_use_max']} / {r['db_pool_max']} "
                f"| {r['redis_pool_waiting_max']} | {mib(r['api_working_set_max_bytes'])} | {verdict(ok)} |"
            )
        out.append("")
        for r in by_kind["footprint"]:
            out.append(f"Redis key families at {r['users']:,} accounts: {r['redis_key_families']}.")
        out.append("")

    for r in by_kind.get("restore", []):
        ok = r["users_source"] == r["users_restored"]
        failures += not ok
        out += [
            "## Restore",
            "",
            f"{r['users']:,} accounts, database {r['database_bytes'] / 1024**3:.1f} GiB: dump "
            f"{r['dump_secs']} s ({r['dump_bytes'] / 1024**3:.2f} GiB compressed), restore "
            f"{r['restore_secs']} s in one transaction, {r['users_restored']:,} accounts restored. "
            f"{verdict(ok)}",
            "",
        ]

    for r in by_kind.get("soak", []):
        ok = (
            r["errors"] == 0
            and r["restarts"] == 0
            and r["running"] == "true"
            and r["growth_pct"] <= r["max_growth_pct"]
        )
        failures += not ok
        out += [
            "## Soak",
            "",
            f"Profile {r['profile'].upper()}, {r['users']:,} accounts, {r['secs']} s: {r['rps']:.0f} req/s, "
            f"p95 {r['p95_ms']:.0f} ms, {r['errors']} errors, {r['restarts']} restarts; working set "
            f"{mib(r['working_set_first_bytes'])} then {mib(r['working_set_last_bytes'])} "
            f"({r['growth_pct']:+.1f} %, tolerance {r['max_growth_pct']} %). {verdict(ok)}",
            "",
        ]

    out.append(f"**{'All criteria met' if failures == 0 else f'{failures} verdict(s) failed'}.**")
    print("\n".join(out))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
