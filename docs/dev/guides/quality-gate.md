# Quality Gate

The gate runs on every pull request to `main` in GitHub Actions and locally
with the same Makefile targets: nothing is merged or released without it
passing.

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

## Hosted CI

`staging` is the draft branch: pushes to it run nothing. Pushes to `main` are
refused; every change reaches it through a pull request, merged with a merge
commit (not squash or rebase) so the back-merge can fast-forward `staging`.

`.github/workflows/ci.yml` runs on pull requests to `main` and on `main` after a
merge. Branch protection requires a single check, `ci-ok`: a job the change does
not concern is skipped without blocking. A draft pull request fails `ci-ok`
until it is marked ready for review.

| Job | Runs when | Runs | Time |
|-----|-----------|------|------|
| `changes` | always | classifies the changed files | seconds |
| `hygiene` | always | `CHECKS=hygiene scripts/infra-check.sh`: actionlint, repository secret scan | ~1 min |
| `rust` | Rust, migrations, templates, `Cargo.*`, `openapi.yaml` or the test compose changed | `make fmt-check`, `make clippy`, `make deny`, `make test-infra-up`, `make ci-test` | ~10 min with the cache |
| `infra` | Dockerfiles, compose, nginx, `deploy/`, scripts changed | `CHECKS=static scripts/infra-check.sh` | ~2 min |
| `image` | a Dockerfile, `.dockerignore`, `Cargo.lock` or the toolchain changed | `CHECKS=image scripts/infra-check.sh`: build, size under 100 MiB, Trivy | ~15 min |
| `ci-ok` | always | fails if a job failed or was cancelled | seconds |

Only `main` writes the Rust cache; pull requests read it. A documentation-only
pull request runs `changes` and `hygiene`. The repository-wide English guard is
a Rust test: a documentation change that breaks it is caught by the next Rust
pull request or the weekly run.

`.github/workflows/scheduled.yml` opens an issue when a task fails and closes it
when every task passes again; run any task by hand from the Actions tab.

| When | Task |
|------|------|
| Mondays | `cargo deny check advisories`, image build and Trivy, `make coverage`, `make test-sim` |
| The first of the month | `scripts/backup-drill.sh`, `make fuzz FUZZ_SECS=60` |

`.github/workflows/backmerge.yml` fast-forwards `staging` to `main` after a
merge, and leaves it alone when draft commits were pushed meanwhile.
Dependabot opens grouped pull requests to `staging` once a month (Cargo,
actions, Dockerfile and compose images).

The toolchain is pinned in `rust-toolchain.toml`, locally and in the CI: bump it
deliberately, since a new clippy brings new lints. The CI never builds, signs or
publishes a release ([release guide](release.md)).

To reproduce a job locally, run its command from the table; `make ci` is the
`rust` job and `make infra-check` covers `hygiene`, `infra` and `image`.

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
