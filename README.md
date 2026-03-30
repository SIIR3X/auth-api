# Rust API

![Version](https://img.shields.io/badge/version-0.1.0-blue)
![Language](https://img.shields.io/badge/language-Rust-orange)
![Edition](https://img.shields.io/badge/edition-2024-orange)
![Framework](https://img.shields.io/badge/framework-Axum-black)
![Database](https://img.shields.io/badge/database-PostgreSQL-blue)
![Cache](https://img.shields.io/badge/cache-Redis-red)
![License](https://img.shields.io/badge/license-All%20rights%20reserved-lightgrey)

Security-focused Rust authentication API with PostgreSQL, Redis, Docker-based deployment, and CI workflows for code, Docker, and security checks.

## Overview

This repository contains a production-oriented Rust API built with `axum` and `tokio`.
It focuses on authentication and account security, with support for:
- JWT-based sessions
- password hashing with Argon2
- reauthentication for sensitive actions
- email and TOTP-based 2FA
- WebAuthn support
- risk scoring and GeoIP-aware signals
- audit logging and session management

The project also includes:
- SQL migrations and a dedicated migrations image
- Docker deployment assets for the application server and data server
- optional observability assets with Grafana, Loki, and Alloy
- benchmark tooling for Rust, HTTP, and SQL hot paths
- GitHub Actions workflows for code checks, Docker checks, security checks, and image publication

## Stack

| Area | Technology |
| --- | --- |
| Language | Rust |
| Web framework | Axum |
| Async runtime | Tokio |
| Database | PostgreSQL |
| Cache / rate limit backing | Redis |
| Templates | Tera |
| Mail transport | Lettre |
| Password hashing | Argon2 |
| 2FA / auth | TOTP, Email OTP, WebAuthn |
| Containerization | Docker |
| Observability | Grafana, Loki, Alloy |
| CI / CD | GitHub Actions + GHCR |

## Repository Layout

| Path | Purpose |
| --- | --- |
| [`src`](src) | Application code |
| [`migrations`](migrations) | PostgreSQL schema migrations |
| [`deploy`](deploy) | Deployment assets for app, data, and proxy |
| [`docs/deploy`](docs/deploy) | Deployment documentation |
| [`docs/dev`](docs/dev) | Development, analysis, and workflow documentation |
| [`benches`](benches) | Criterion micro-benchmarks |
| [`tests`](tests) | Database and HTTP test suites |
| [`.github/workflows`](.github/workflows) | CI, security, Docker, and publish workflows |

## Local Development

Install the Rust toolchain, then run:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Useful development documentation:
- [`docs/dev/rust-code-analysis.md`](docs/dev/rust-code-analysis.md)
- [`docs/dev/docker-code-analysis.md`](docs/dev/docker-code-analysis.md)
- [`docs/dev/workflows.md`](docs/dev/workflows.md)
- [`docs/report/rust-api-technical-report.pdf`](docs/report/rust-api-technical-report.pdf)

## Docker

Build the application image:

```bash
docker build -t rust-api:local .
```

Build the migrations image:

```bash
docker build --target migrations -t rust-api-migrations:local .
```

## Deployment

Deployment is split between:
- an application server
- a data server

Main deployment guides:
- [`docs/deploy/app/setup.md`](docs/deploy/app/setup.md)
- [`docs/deploy/data/setup.md`](docs/deploy/data/setup.md)
- [`docs/deploy/shared/image-release.md`](docs/deploy/shared/image-release.md)

Additional deployment references:
- [`deploy/app/docker-compose.yml`](deploy/app/docker-compose.yml)
- [`deploy/app/nginx.conf`](deploy/app/nginx.conf)
- [`deploy/app/alloy/docker-compose.yml`](deploy/app/alloy/docker-compose.yml)
- [`deploy/data/docker-compose.yml`](deploy/data/docker-compose.yml)
- [`deploy/data/alloy/docker-compose.yml`](deploy/data/alloy/docker-compose.yml)
- [`deploy/data/grafana/datasources/rust-api-postgresql.yml`](deploy/data/grafana/datasources/rust-api-postgresql.yml)

## CI and Release Flow

The repository currently uses four main workflows:

| Workflow | Purpose |
| --- | --- |
| [`code-checks.yml`](.github/workflows/code-checks.yml) | Rust formatting, linting, and tests on PRs to `main` |
| [`docker-checks.yml`](.github/workflows/docker-checks.yml) | Docker linting, builds, and image scanning on PRs to `main` |
| [`security.yml`](.github/workflows/security.yml) | Dependency and secret-oriented security checks on PRs to `main` |
| [`docker-publish.yml`](.github/workflows/docker-publish.yml) | Builds and publishes images to GHCR on version tags |

## Benchmarks

The repository includes:
- Rust micro-benchmarks
- HTTP benchmark runners
- SQL benchmark runners

These are intended to measure:
- authentication hot paths
- session-related flows
- database query plans and latencies

## License

This repository is proprietary and distributed under an "All rights reserved" license.

See [`LICENSE`](LICENSE).
