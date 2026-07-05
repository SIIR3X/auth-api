# GitHub Actions Workflows

All workflows are located in `.github/workflows/`. They run automatically on
pull requests targeting `main` and on pushes to `staging`, except the publish
workflow (git tags) and the scheduled jobs.

## code-quality.yml - Code Quality

**Trigger:** pull request -> `main`, push -> `staging`

Three jobs running in parallel:

| Job | Tool | What it checks |
|-----|------|----------------|
| fmt | `cargo fmt --check` | Code style compliance |
| clippy | `cargo clippy` | Code correctness and best practices (warnings as errors) |
| deny | `cargo deny` | License compliance, duplicate dependencies, banned crates, CVEs |

`cargo-deny` is installed via `taiki-e/install-action` (pre-compiled binary, ~2s). It covers both dependency policy and security auditing - `cargo-audit` is not needed separately.

Fails the PR if any job does not pass.

## tests.yml - Tests & Coverage

**Trigger:** pull request -> `main`, push -> `staging`

A single job with PostgreSQL 17, Redis 7, NATS and Mailpit as services.

The suite runs under `cargo llvm-cov nextest` with an **80% line-coverage
gate** (binary entrypoints and the bench harness are excluded); the lcov
report is uploaded as an artifact.

Each test gets an isolated PostgreSQL database cloned from a shared template - created once, dropped after the test. No test state leaks between runs.

Fails the PR if tests fail or coverage drops below the gate.

## docker-checks.yml - Docker Checks

**Trigger:** pull request -> `main`

```
lint -> build -> scan
```

| Job | Tool | What it checks |
|-----|------|----------------|
| lint | Hadolint + port guard | Dockerfile best practices; compose ports stay loopback-only |
| build | Docker Buildx | Image builds; **fails above the 200 MB size threshold** |
| scan | Trivy (pinned) | CVEs in OS packages and Cargo dependencies (CRITICAL/HIGH, fixed only), leaked secrets |

## security-audit.yml - Security Audit

**Trigger:** weekly schedule, pull request -> `main`, manual

- **advisories** (scheduled only): `cargo deny check advisories` catches new
  RUSTSEC advisories between PRs.
- **secrets**: Gitleaks scans the repository history (allowlist in
  `.gitleaks.toml` for the committed test keys and `.env.dev`).

## docker-publish.yml - Publish Docker Image

**Trigger:** git tag matching `v*`

Builds the production image and pushes it to GitHub Container Registry (`ghcr.io/siir3x/auth-api`).

Tags applied to the image:

| Tag | Example | When |
|-----|---------|------|
| `latest` | `latest` | Always on tag push |
| semver full | `1.2.3` | When tag is `v1.2.3` |
| semver minor | `1.2` | When tag is `v1.2.3` |

Builds for `linux/amd64`. Uses GitHub Actions cache to avoid recompiling
unchanged dependencies. The image is cosign-signed (keyless) with SBOM +
provenance attestations.

See [Creating a Release](release.md) for the full release process.

## Scheduled maintenance

- **backup-drill.yml** (monthly): seeds a database, backs it up through the
  real `pg_dump | gzip | age` pipeline, restores it with `restore-db.sh` and
  verifies witness rows.
- **backmerge.yml**: after a PR merges into `main`, fast-forwards `staging`
  back onto `main` so the branches never drift.
- **Dependabot** (weekly): grouped cargo updates, GitHub Actions and Docker
  base-image bumps, each going through the full PR gauntlet.
