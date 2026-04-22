# GitHub Actions Workflows

All workflows are located in `.github/workflows/`. They run automatically on pull requests targeting `main`, except the publish workflow which runs on git tags.

## code-quality.yml — Code Quality

**Trigger:** pull request → `main`

Runs the following checks in sequence:

| Step | Tool | What it checks |
|------|------|----------------|
| Formatting | `cargo fmt --check` | Code style compliance |
| Linting | `cargo clippy` | Code correctness and best practices (warnings as errors) |
| Security audit | `cargo audit` | Known CVEs in Cargo dependencies |
| Dependency policy | `cargo deny` | License compliance, duplicate dependencies, banned crates |

Fails the PR if any check does not pass.

## tests.yml — Tests & Coverage

**Trigger:** pull request → `main`

Two jobs run in parallel, both with PostgreSQL 17 and Redis 7 as services.

### Tests job

Installs Mailpit locally (tests spawn it as a process on random ports), then runs `cargo test`.

Each test gets an isolated PostgreSQL database cloned from a shared template — created once, dropped after the test. No test state leaks between runs.

---

### Coverage job

Runs `cargo-tarpaulin` on the test suite, excluding `src/main.rs` and `src/bin/*`. Produces a JSON report and posts a comment on the PR with the coverage percentage.

Coverage thresholds (informational only, does not block the PR):

| Threshold | Icon |
|-----------|------|
| ≥ 80% | ✅ |
| 60–79% | ⚠️ |
| < 60% | ❌ |

## docker-checks.yml — Docker Checks

**Trigger:** pull request → `main`

Four jobs running in order:

```
lint → build → scan → report
```

| Job | Tool | What it checks |
|-----|------|----------------|
| lint | Hadolint | Dockerfile best practices |
| build | Docker Buildx | Image builds successfully, reports image size |
| scan | Trivy | CVEs in OS packages and Cargo dependencies (CRITICAL/HIGH, fixed only), leaked secrets |
| report | GitHub Script | Posts a summary comment on the PR |

The scan job uploads results in SARIF format to the GitHub Security tab.

## docker-publish.yml — Publish Docker Image

**Trigger:** git tag matching `v*`

Builds the production image and pushes it to GitHub Container Registry (`ghcr.io/siir3x/rust-api`).

Tags applied to the image:

| Tag | Example | When |
|-----|---------|------|
| `latest` | `latest` | Always on tag push |
| semver full | `v1.2.3` | When tag is `v1.2.3` |
| semver minor | `v1.2` | When tag is `v1.2.3` |

Builds for both `linux/amd64` and `linux/arm64`. Uses GitHub Actions cache to avoid recompiling unchanged dependencies.

See [Creating a Release](release.md) for the full release process.
