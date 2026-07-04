# Commands

All commands are available via `make`. Run `make help` to list them.

## Development

| Command | Description |
|---------|-------------|
| `make dev` | Build and start the full development stack (API, PostgreSQL, Redis, Mailpit) |
| `make dev-detach` | Same as `make dev` but runs in the background |
| `make dev-stop` | Stop the development stack |
| `make dev-reset` | Stop the development stack and delete all volumes (resets the database) |
| `make dev-logs` | Stream logs from all development services |
| `make dev-admin` | Start the development stack with the Appsmith admin panel (`http://localhost:8080`) |
| `make dev-admin-stop` | Stop the development stack including Appsmith |

## Code Quality

| Command | Description |
|---------|-------------|
| `make fmt` | Format the code with `rustfmt` |
| `make fmt-check` | Check formatting without modifying files |
| `make clippy` | Run the Clippy linter (warnings treated as errors) |
| `make deny` | Enforce dependency policy and security audit via `cargo-deny` |
| `make quality` | Run all of the above checks in sequence |

## Tests

| Command | Description |
|---------|-------------|
| `make test` | Start test infrastructure, run all tests via `cargo-nextest`, then stop infrastructure |
| `make test-verbose` | Same as `make test` with full output (`--no-capture`) |
| `make test-infra-up` | Start PostgreSQL and Redis for tests (ports 5433 / 6380) |
| `make test-infra-down` | Stop the test infrastructure |
| `make coverage` | Run tests with coverage report (HTML + JSON in `reports/coverage/`) |

## Benchmarks

| Command | Description |
|---------|-------------|
| `make bench` | Run Criterion benchmarks (CPU only - no infrastructure required) |
| `make bench-http` | Run HTTP integration benchmarks (requires infrastructure) |
| `make bench-sql` | Run SQL integration benchmarks (requires infrastructure) |

## Build

| Command | Description |
|---------|-------------|
| `make build` | Compile the project in release mode |
| `make docker-build` | Build the production Docker image (`auth-api:local`) |
| `make docker-build-dev` | Build the development Docker image (`auth-api:dev`) |

## Docker Security

| Command | Description |
|---------|-------------|
| `make docker-lint` | Lint the `Dockerfile` with Hadolint |
| `make docker-scan` | Scan the production image for CVEs with Trivy |
| `make docker-scan-dev` | Scan the development image for CVEs with Trivy |
| `make docker-scan-secrets` | Scan the production image for leaked secrets with Trivy |
| `make docker-check` | Run lint + CVE scan + secret scan in sequence |

## Utilities

| Command | Description |
|---------|-------------|
| `make clean` | Remove compilation artifacts (`target/`) |
| `make clean-reports` | Remove generated reports (`reports/bench/manual-*`, `reports/coverage/`) |
| `make clean-all` | Remove all artifacts, reports and local Docker images |
| `make docker-clean` | Remove local project Docker images |
