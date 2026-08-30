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
