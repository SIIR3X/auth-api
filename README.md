# auth-api

<p align="center">
  <img src="docs/assets/auth-api-banner.svg" alt="auth-api" width="780">
</p>

<p align="center">
  <a href="https://github.com/SIIR3X/auth-api/releases/latest"><img src="https://img.shields.io/github/v/release/SIIR3X/auth-api?color=blue&label=version" alt="Latest release"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/rust-2024%20edition-orange.svg" alt="Rust 2024 edition">
  <img src="https://img.shields.io/badge/framework-Axum-1793d1.svg" alt="Framework: Axum">
  <img src="https://img.shields.io/badge/datastores-PostgreSQL%20%7C%20Redis-1f3b4d.svg" alt="Datastores: PostgreSQL / Redis">
  <img src="https://img.shields.io/badge/container-Docker-2496ed.svg" alt="Container: Docker">
</p>

**Production-ready authentication and authorization API for Rust services - JWT
access and refresh tokens, two-factor auth, RBAC, per-device sessions and
risk-based login, built on Axum, PostgreSQL and Redis.**

## Description

auth-api is a complete authentication and authorization backend for production
services. It covers the full account lifecycle - registration, email
verification, login, logout, password reset and email change - and issues
short-lived JWT access tokens backed by rotating refresh tokens with replay and
family-compromise detection.

Security is built in rather than bolted on: two-factor authentication (TOTP and
email OTP) with recovery codes, role-based access control, per-device session
management, risk scoring on every login (GeoIP, new-device detection,
behavioral history), account lockout, per-IP rate limiting and CAPTCHA on
sensitive endpoints. Sensitive data is protected at rest - TOTP secrets are
encrypted with AES-256-GCM - and every security-relevant action is written to an
append-only audit log partitioned by month.

### What it provides

| Area | Capabilities |
|------|--------------|
| Account lifecycle | registration, login, logout, email verification, password reset, email change with OTP at each step |
| Tokens | JWT access + refresh, rotation, replay detection |
| Two-factor | TOTP and email OTP, recovery codes for backup access |
| Authorization | RBAC with roles and permissions |
| Sessions | per-device visibility, revocation, family compromise detection |
| Threat protection | risk scoring (GeoIP, new device, behavioral history), account lockout, per-IP rate limiting with a separate auth bucket, CAPTCHA |
| Audit & crypto | append-only audit log partitioned by month, AES-256-GCM encryption for TOTP secrets at rest |

## Requirements

**To run locally:**

- **Docker** and **Docker Compose**
- **GNU Make**

See [prerequisites](docs/dev/guides/prerequisites.md) for the full list.

**To deploy:** PostgreSQL, Redis and the shared infrastructure (NATS, API
Gateway) - see the [Deployment Guide](docs/deploy/README.md).

## Installation

### From source (development)

```bash
git clone https://github.com/SIIR3X/auth-api.git
cd auth-api
make dev
```

The API is available at `http://localhost:3000`. A Mailpit instance for catching
emails is available at `http://localhost:8025`.

### Container image

Released images are published to the GitHub Container Registry, tagged `latest`,
the full version and `major.minor`:

```bash
docker pull ghcr.io/siir3x/auth-api:latest
```

## Usage

`make dev` brings up the full stack (API, PostgreSQL, Redis, Mailpit) with
migrations applied. The API then serves at `http://localhost:3000`.

For all available commands see [commands](docs/dev/guides/commands.md). API
routes and the database schema are documented in the
[Developer Guide](docs/dev/README.md).

## Documentation

| Document | Contents |
|----------|----------|
| [Developer Guide](docs/dev/README.md) | Prerequisites, commands, workflows, configuration, API routes, database schema |
| [Deployment Guide](docs/deploy/README.md) | Secrets, database setup, API deployment, release process |
| [`LICENSE`](LICENSE) | MIT license terms |

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

Copyright (c) 2026 Lucas Fagioli.
