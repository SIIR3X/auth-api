# Commands

All commands are available via `make`. Run `make help` to list them.

## Development

| Command | Description |
|---------|-------------|
| `make dev` | Build and start the development stack (API, PostgreSQL, Redis, NATS, Mailpit) |
| `make dev-detach` | Same as `make dev`, in the background |
| `make dev-stop` | Stop the development stack |
| `make dev-reset` | Stop the development stack and delete its volumes (resets the database) |
| `make dev-logs` | Stream logs from every development service |

Every port of the development stack is published on `127.0.0.1` only.

## Quality gate

| Command | Description |
|---------|-------------|
| `make ci` | The full gate, run before every merge: `quality`, every suite with the nextest `ci` profile, then the fuzz corpus replay |
| `make quality` | `fmt-check`, `clippy` and `deny` |
| `make fmt` | Format the code |
| `make fmt-check` | Check formatting without modifying files |
| `make clippy` | Clippy on every target and feature of the workspace, warnings as errors |
| `make deny` | Dependency policy and security advisories (`cargo-deny`) |

## Tests

| Command | Description |
|---------|-------------|
| `make test` | Start the test infrastructure, run every suite, stop the infrastructure |
| `make test-local` | Run every suite against infrastructure already running |
| `make test-unit` | Unit tests of the service and of the harness, no infrastructure |
| `make test-integration` | API end to end, repositories, services, schema and migrations |
| `make test-security` | Security suite, then the fuzz corpus replay |
| `make test-sim` | Simulation suite, long scenarios included |
| `make test-verbose` | `make test` with test output shown |
| `make test-infra-up` / `make test-infra-down` | Start / stop PostgreSQL (5433), Redis (6380), NATS (4224) and Mailpit (1026) |
| `make fuzz` | Every fuzz target for `FUZZ_SECS` seconds (default 60; nightly toolchain and `cargo-fuzz`) |
| `make mutants` | Mutation testing of the domain, crypto, token, client address and configuration code (`cargo-mutants`, unit tests); report in `reports/mutants.out/` |
| `make coverage` | Coverage of every suite (`cargo-llvm-cov`), HTML report in `reports/coverage/` |

Each test runs in its own process against its own database, cloned from a
migrated template. The nextest configuration (`.config/nextest.toml`) kills a
test hung for two minutes (simulations get longer) and never retries a failure.
See the [testing guide](testing.md) for where a test belongs and what the
harness provides.

## Benchmarks

| Command | Description |
|---------|-------------|
| `make bench` | Criterion micro-benchmarks (JWT, TOTP, Argon2), no infrastructure |
| `make bench-http` | End-to-end HTTP scenarios against a real server, PostgreSQL and Redis |
| `make bench-sql` | Query benchmarks |

`bench-http` reads `BENCH_HTTP_CONCURRENCY` (default 8) and
`BENCH_HTTP_ITERATIONS` (default 16) and writes a report to `reports/bench/`.

## Build and images

| Command | Description |
|---------|-------------|
| `make build` | Release build |
| `make docker-build` | Production image |
| `make docker-build-dev` | Development image (runs migrations at start) |
| `make docker-lint` | Hadolint on the Dockerfile |
| `make docker-scan` / `make docker-scan-dev` | Trivy CVE scan of an image |
| `make docker-scan-secrets` | Trivy secret scan of the production image |
| `make docker-check` | Lint and both scans |

## Maintenance

| Command | Description |
|---------|-------------|
| `make clean` | Remove `target/` |
| `make clean-reports` | Remove benchmark and coverage reports |
| `make clean-all` | Remove build artifacts, reports and local images |
| `make docker-clean` | Remove local project images |

## Binary commands

The `auth-api` binary also runs one-off operational commands instead of the
server. In production, run them in a one-off container:
`docker compose -f docker-compose.api.yml run --rm api ./auth-api <command>`.

| Command | Description |
|---------|-------------|
| `--healthcheck` | Call the local `/health` and exit 0 or 1 (the image's health check) |
| `--register-client <id> --name <name> [options]` | Create or update a registered client (needs only `DATABASE_URL`) |
| `--rotate-totp-keys` | Re-encrypt TOTP secrets under `ENCRYPTION_KEY` (see the [operations runbook](../../deploy/guides/operations.md)) |

`--register-client` options:

| Option | Description |
|--------|-------------|
| `--primary` | The application this instance owns: used when a device flow names no client, exempt from session limits and from re-authentication on consent |
| `--scopes a:b,c:d` | Permissions its tokens may carry; omitted, tokens carry every permission of the user |
| `--redirect-uri <uri>` | Exact redirect URI for the authorization code flow; repeatable |
| `--loopback-redirect` | Also accept `http://127.0.0.1` / `http://[::1]` on any port for a registered loopback path (native apps) |
| `--max-sessions <n>` | Concurrent sessions per user when no quota row overrides it |

```bash
auth-api --register-client desktop-app --name "Desktop app" \
  --redirect-uri http://127.0.0.1/callback --loopback-redirect \
  --scopes profile:read --max-sessions 3
```
