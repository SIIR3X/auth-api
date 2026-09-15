# Performance campaign

Measures the database and the HTTP API as a function of data volume (number of
accounts) and load (concurrent clients). The latest report is
[`docs/perf/performance-report.md`](../docs/perf/performance-report.md).

## Running it

```bash
make perf                                         # hours: 10k, 100k, 1M accounts
make perf-report RUN=reports/perf/<run>           # tables and charts into docs/perf/
```

`perf/run.sh` builds the release binaries, starts the dedicated infrastructure
(`perf/infra.sh`), then for each volume grows the data set and runs every
measurement. It needs `postgres`, `psql`, `redis-server`, `redis-cli` and
`nats-server`, found in `PATH` or through `PG_BIN`, `REDIS_SERVER`,
`REDIS_CLI` and `NATS_SERVER`.

Nothing else CPU-intensive may run on the machine meanwhile: the components
share it and are pinned to separate cores.

| Variable | Default | Meaning |
|----------|---------|---------|
| `VOLUMES` | `10000 100000 1000000` | Accounts, cumulative |
| `CONCURRENCY` | `1 4 16 64 256` | Concurrent HTTP clients |
| `HTTP_SCENARIOS` | all eight | `profile sessions audit two_factor refresh login register mixed` |
| `DB_SCENARIOS` | all eleven | Application queries, see `perf_load db` |
| `DB_CONCURRENCY` | `1 8 32` | Database connections |
| `DURATION` / `WARMUP` | `20` / `5` | Seconds per HTTP point |
| `DB_DURATION` / `DB_WARMUP` | `10` / `3` | Seconds per database point |
| `PG_CPUS`, `CACHE_CPUS`, `API_CPUS`, `LOAD_CPUS` | `0-2`, `3`, `4-6`, `7` | CPU pinning |
| `OUT` | `reports/perf/<timestamp>` | Results directory |

A smoke run takes a few minutes:

```bash
VOLUMES="2000 4000" CONCURRENCY="1 8" DB_CONCURRENCY=2 DURATION=3 WARMUP=1 \
  DB_DURATION=2 DB_WARMUP=1 STATEMENTS_CONCURRENCY=8 SEED_CHUNK=1500 \
  OUT=reports/perf/smoke perf/run.sh
```

## Pieces

| File | Role |
|------|------|
| `infra.sh` | PostgreSQL 17 on disk with production durability, Redis, NATS; pinned |
| `seed.sql` | Deterministic, incremental data set (identifiers derive from the account index) |
| `run.sh` | The campaign |
| `../src/bin/perf_load.rs` | Load generator, database benchmark, plans, sizes, statement statistics |
| `report.py` | Tables and SVG charts from `results.jsonl` |

## What the load generator does

- **Closed loop:** each virtual client sends its next request as soon as the
  previous one answers. Throughput is the maximum the system sustains at that
  concurrency; latency is what a waiting client sees. It is not a fixed-rate
  test.
- **Tokens:** up to 100 000 access tokens are signed before the run for
  accounts drawn uniformly, so session-cache misses are realistic.
- **Client addresses:** each request comes from a random address among 262 144
  (`X-Forwarded-For`, trusted from 127.0.0.1), so per-address budgets behave as
  with real traffic.
- **Refresh chains:** each virtual client signs in once before the clock starts
  and then follows its own rotation chain.
- **Measurements:** a 1 %-resolution histogram per operation, CPU per pinned
  core group from `/proc/stat`, and `pg_stat_database` counters over the
  measurement window.

## Sizing validation

`make sizing` (`perf/sizing.sh`) checks the profiles of `deploy/profiles/` the
way production runs them: the production image in a container with the
profile's CPU quota and memory limit, PostgreSQL and Redis started with the
settings of `deploy/db/`, NATS with `nats.conf` and the profile's limits, each
on its own cores. It needs only Docker and the release build of `perf_load`.

| Phase | Measures | Criterion |
|-------|----------|-----------|
| `signin` | Sign-ins per second with 1 to 4 CPUs, p95, CPU throttling, peak memory; then 64 clients at once | 11 per CPU or more (within 15 %), no error, peak under 90 % of the limit, the instance survives the overload |
| `footprint` | Mixed scenario at profile M on each volume: Redis memory and key families, NATS memory and CPU, PostgreSQL buffer hit ratio, pool saturation | No error, NATS under 70 % of its limit, database pool never full, no Redis pool wait |
| `restore` | `pg_dump \| gzip` then `psql --single-transaction` of the largest volume, as `backup-db.sh` and `restore-db.sh` | Every account restored; the times are the RTO |
| `soak` | `SOAK_SECS` of mixed traffic at `SOAK_PROFILE` | No error, no restart, working set growth under `SOAK_MAX_GROWTH_PCT` |

| Variable | Default | |
|----------|---------|-|
| `PHASES` | `signin footprint restore soak` | Phases to run |
| `VOLUMES` | `100000 1000000` | Accounts, cumulative; sign-ins run on the first |
| `SIGNIN_CPUS` | `1 2 3 4` | CPU quotas tried |
| `SIGNIN_SECS` / `OVERLOAD_SECS` | `60` / `30` | |
| `FOOTPRINT_SECS` / `FOOTPRINT_CONCURRENCY` | `180` / `64` | |
| `SOAK_PROFILE` / `SOAK_SECS` / `SOAK_CONCURRENCY` | `m` / `3600` / `32` | |
| `PG_CPUS`, `PG_MEMORY`, `CACHE_CPUS`, `LOAD_CPUS` | `0-2`, `8g`, `3`, `7` | The API gets CPUs 4-6 (4-7 with 4 CPUs) |
| `KEEP_DATA` | `0` | `1` keeps the seeded database volume for the next run |

The verdicts are written to `summary.md` next to `results.jsonl`, and the script
fails when one fails.

## Soak test

`make soak` (`perf/soak.sh`) runs the mixed scenario for an hour against one API
process, on a data set of 10 000 accounts in its own `auth_soak` database, and
samples the API's resident memory every 15 seconds into `memory.csv`. It fails
when a request errors, or when memory over the last tenth of the run exceeds
memory over the first tenth, after warm-up, by more than 20 %.

| Variable | Default | |
|----------|--------:|-|
| `SOAK_SECS` | 3600 | Measured duration |
| `SOAK_USERS` | 10000 | Accounts seeded |
| `SOAK_CONCURRENCY` | 32 | Virtual users |
| `SOAK_WARMUP` | 60 | Seconds excluded before measuring |
| `SOAK_MAX_GROWTH_PCT` | 20 | Memory growth tolerated |

The verdict and its figures are written to `soak.json` next to the run's
results.

First run, 2026-09-15 (same machine and CPU pinning as the campaign, production
Argon2 parameters): 1 239 760 requests in 3 600 s at 32 virtual users, 344
requests per second, no error. Resident memory went from 213.3 MiB over the
first tenth to 213.6 MiB over the last (+0.2 %). Latency: p50 3.4 ms, p95 894 ms,
p99 940 ms. The throughput is the ceiling the campaign measured for the same mix
at 10 000 accounts (356 requests per second at 64 clients, p95 1 795 ms): the
sign-ins and registrations of the mix each pay a full Argon2 hash on three API
cores. The soak judges errors and memory only; it does not record latency over
time.
