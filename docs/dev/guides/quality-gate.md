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
| `clippy` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Any warning in the library, binaries, tests, benches, the test harness or the fuzzing entry points |
| `deny` | `cargo deny check` | Advisories (RUSTSEC), disallowed licenses, banned or duplicated crates |
| tests | `cargo nextest run --workspace --profile ci` | Any failing test of the unit, integration, security and simulation suites; every failure is reported in one run |
| fuzz corpus | `cargo nextest run --test fuzz_corpus --features fuzzing` | A fuzz seed or recorded crash that breaks its property again |

Every response a test receives is checked against `docs/dev/api/openapi.yaml`,
and a unit test fails when that document differs from what the code generates.
The security suite attacks every documented operation and fails when a control
of the [security model](../security-model.md) loses its tests. The
[testing guide](testing.md) describes the suites and the harness.

JUnit results are written to `target/nextest/ci/junit.xml`.

## Before a release

In addition to `make ci`:

| Command | Checks |
|---------|--------|
| `make fuzz FUZZ_SECS=600` | Every fuzz target for ten minutes (nightly); a crash is fixed and its input added to `fuzz/regressions/` |
| `make test-sim` | The simulation suite, long scenarios included |
| `make mutants` | Mutation testing of the security-relevant pure code; every surviving mutant in `reports/mutants.out/missed.txt` is a fault no unit test notices, unless the testing guide lists it as accepted |
| `make coverage` | Coverage of every suite; fails under 90 % of lines, 85 % of regions or 79 % of functions |
| `make docker-check` | Hadolint on the Dockerfile, Trivy CVE and secret scans of the image |
| `make bench-http` | Latency of every scenario; compare with the figures in the [operations runbook](../../deploy/guides/operations.md#8-measured-capacity) |

## Regenerating the OpenAPI document

```bash
cargo run --quiet --bin openapi > docs/dev/api/openapi.yaml
```

Commit the result with the change that caused it.
