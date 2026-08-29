# Quality Gate

There is no hosted CI: the gate runs locally, and nothing is merged or released
without it passing.

```bash
make test-infra-up   # once: PostgreSQL, Redis, NATS, Mailpit on loopback ports
make ci
```

## What `make ci` runs

| Step | Tool | Fails on |
|------|------|----------|
| `fmt-check` | `cargo fmt --check` | Any formatting difference |
| `clippy` | `cargo clippy --all-targets -- -D warnings` | Any warning in the library, binaries, tests or benches |
| `deny` | `cargo deny check` | Advisories (RUSTSEC), disallowed licenses, banned or duplicated crates |
| tests | `cargo nextest run --profile ci` | Any failing test; every failure is reported in one run |

The test suite covers the HTTP API end to end (one database per test, cloned
from a migrated template), the SQL layer (constraints, query plans, migrations
applied from scratch), and unit tests. The OpenAPI test fails when
`docs/dev/api/openapi.yaml` differs from what the code generates, or when a
route is missing from it.

## Before a release

In addition to `make ci`:

| Command | Checks |
|---------|--------|
| `make docker-check` | Hadolint on the Dockerfile, Trivy CVE and secret scans of the image |
| `make bench-http` | Latency of every scenario; compare with the figures in the [operations runbook](../../deploy/guides/operations.md#8-measured-capacity) |

## Regenerating the OpenAPI document

```bash
cargo run --quiet --bin openapi > docs/dev/api/openapi.yaml
```

Commit the result with the change that caused it.
