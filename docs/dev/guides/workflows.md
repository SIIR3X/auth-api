# GitHub Actions Workflows

All workflows are located in `.github/workflows/`. They run automatically on pull requests targeting `main`, except the publish workflow which runs on git tags.

## code-quality.yml — Code Quality

**Trigger:** pull request → `main`

Three jobs running in parallel, followed by a report:

| Job | Tool | What it checks |
|-----|------|----------------|
| fmt | `cargo fmt --check` | Code style compliance |
| clippy | `cargo clippy` | Code correctness and best practices (warnings as errors) |
| deny | `cargo deny` | License compliance, duplicate dependencies, banned crates, CVEs |

`cargo-deny` is installed via `taiki-e/install-action` (pre-compiled binary, ~2s). It covers both dependency policy and security auditing — `cargo-audit` is not needed separately.

A report comment is posted on the PR with the result of each check. Fails the PR if any job does not pass.

## tests.yml — Tests & Coverage

**Trigger:** pull request → `main`

A single job with PostgreSQL 17 and Redis 7 as services.

- **cargo-nextest** runs the full test suite — faster than `cargo test`, better output
- **cargo-tarpaulin** instruments the code and measures line coverage

Both are installed via `taiki-e/install-action` (pre-compiled binaries, ~2s each).

Each test gets an isolated PostgreSQL database cloned from a shared template — created once, dropped after the test. No test state leaks between runs.

A report comment is posted on the PR with:
- Number of tests passed / failed / skipped
- Line coverage percentage against 60% and 80% thresholds

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

Builds the production image and pushes it to GitHub Container Registry (`ghcr.io/siir3x/auth-api`).

Tags applied to the image:

| Tag | Example | When |
|-----|---------|------|
| `latest` | `latest` | Always on tag push |
| semver full | `v1.2.3` | When tag is `v1.2.3` |
| semver minor | `v1.2` | When tag is `v1.2.3` |

Builds for both `linux/amd64` and `linux/arm64`. Uses GitHub Actions cache to avoid recompiling unchanged dependencies.

See [Creating a Release](release.md) for the full release process.
