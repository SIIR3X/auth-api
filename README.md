# auth-api

A production-ready authentication and authorization API built with Rust.

![code quality](https://github.com/SIIR3X/auth-api/actions/workflows/code-quality.yml/badge.svg)
![tests](https://github.com/SIIR3X/auth-api/actions/workflows/tests.yml/badge.svg)
![docker](https://github.com/SIIR3X/auth-api/actions/workflows/docker-checks.yml/badge.svg)
![version](https://img.shields.io/badge/version-1.0.2-blue)
![rust](https://img.shields.io/badge/rust-2024_edition-orange)
![license](https://img.shields.io/badge/license-Proprietary-red)

## Features

- Registration, login, logout, email verification
- JWT access and refresh tokens with rotation and replay detection
- Two-factor authentication — TOTP and email OTP
- Recovery codes for 2FA backup access
- RBAC with roles and permissions
- Session management — per-device visibility, revocation, family compromise detection
- Password reset flow
- Email change flow with OTP verification at each step
- Risk scoring on login — GeoIP, new device detection, behavioral history
- Account lockout after repeated failures
- Per-IP rate limiting with separate auth bucket
- CAPTCHA support on sensitive endpoints
- Append-only audit log partitioned by month
- AES-256-GCM encryption for TOTP secrets at rest

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Rust |
| Framework | Axum |
| Database | PostgreSQL |
| Cache / sessions | Redis |
| Migrations | sqlx-cli |
| Containerization | Docker |
| CI/CD | GitHub Actions |
| Registry | GitHub Container Registry (GHCR) |

## Getting Started

**Prerequisites:** Docker and Docker Compose. See [prerequisites](docs/dev/guides/prerequisites.md) for the full list.

```bash
make dev
```

The API is available at `http://localhost:3000`. A Mailpit instance for catching emails is available at `http://localhost:8025`.

For all available commands see [commands](docs/dev/guides/commands.md).

## Documentation

- [Developer Guide](docs/dev/README.md) — prerequisites, commands, workflows, configuration, API routes, database schema
- [Deployment Guide](docs/deploy/README.md) — secrets, database setup, API deployment, release process

## License

Copyright © 2026 Lucas Fagioli. All rights reserved. See [LICENSE](LICENSE).
