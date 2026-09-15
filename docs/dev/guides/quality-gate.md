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

In addition to `make ci`. `make release` runs `infra-check` and `stack-test`
itself and stops if either fails.

| Command | Checks |
|---------|--------|
| `make fuzz FUZZ_SECS=600` | Every fuzz target for ten minutes (nightly); a crash is fixed and its input added to `fuzz/regressions/` |
| `make test-sim` | The simulation suite, long scenarios included |
| `make mutants` | Mutation testing of the security-relevant pure code; every surviving mutant in `reports/mutants.out/missed.txt` is a fault no unit test notices, unless the testing guide lists it as accepted |
| `make coverage` | Coverage of every suite; fails under 93 % of lines, 89 % of regions or 83 % of functions |
| `make soak` | An hour of mixed traffic against one API process: no failed request, and resident memory growing less than 20 % between the first and last tenth of the run |
| `make docker-check` | Hadolint on the Dockerfile, Trivy CVE and secret scans of the image |
| `make infra-check` | The deployment files: `docker compose config` for every compose file and profile, Hadolint, `nginx -t`, promtool on the Prometheus configuration, alert rules and their unit tests, amtool, shellcheck on every script, Trivy on the image |
| `make stack-test` | The production compose with profile M behind nginx in TLS: container limits, balancing, sign-in flow, failover, a rolling update under load with no failed request, the deletion event through the authenticated broker, a clean stop. Needs ports 80 and 443 free and outbound HTTPS to hcaptcha.com |
| `make sizing` | After a change to the profiles, the Argon2 parameters or the hot paths: the profiles under real container quotas at 100 000 and 1 million accounts (hours, see [perf/README.md](../../../perf/README.md#sizing-validation)) |
| `make bench-http` | Latency of every scenario; compare with the figures in the [operations runbook](../../deploy/guides/operations.md#8-measured-capacity) |

## Regenerating the OpenAPI document

```bash
cargo run --quiet --bin openapi > docs/dev/api/openapi.yaml
```

Commit the result with the change that caused it.
