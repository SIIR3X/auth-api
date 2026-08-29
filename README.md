# Auth API

<p align="center">
  <img src="docs/assets/auth-api-banner.svg" alt="Auth API" width="780">
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/rust-2024%20edition-orange.svg" alt="Rust 2024 edition">
  <img src="https://img.shields.io/badge/framework-Axum-1793d1.svg" alt="Framework: Axum">
  <img src="https://img.shields.io/badge/datastores-PostgreSQL%20%7C%20Redis-1f3b4d.svg" alt="Datastores: PostgreSQL / Redis">
  <img src="https://img.shields.io/badge/container-Docker-2496ed.svg" alt="Container: Docker">
</p>

**A dedicated authentication API: accounts, sessions, second factors and
client applications, with ES256 tokens other services verify through a JWKS.
Built on Axum, PostgreSQL, Redis and NATS.**

## Description

Auth API owns the whole account lifecycle - registration, email verification,
sign-in, password reset and email change - and issues short-lived ES256 access
tokens backed by rotating refresh tokens. Resource servers verify tokens
offline with the published JWKS; nothing else needs to call it on every request.

Security is the design constraint rather than a feature list: sign-in answers
never reveal whether an account exists, sensitive changes require a recent
re-authentication, second factors cannot be bypassed or brute-forced, a replayed
refresh token revokes its whole session, and production refuses to start with a
configuration that disables any of it. The [security model](docs/dev/security-model.md)
describes each control and the tests that pin it.

### What it provides

| Area | Capabilities |
|------|--------------|
| Accounts | Registration, email verification, sign-in by email or username, password reset, email change confirmed on both addresses, account deletion |
| Tokens | ES256 access tokens, rotating refresh tokens with replay detection, absolute session lifetime, JWKS with zero-downtime key rotation |
| Second factors | TOTP and email codes, recovery codes, replay guard, per-challenge and per-account budgets |
| Client applications | Registered clients, device authorization (RFC 8628), authorization code with PKCE (RFC 7636, RFC 8252), per-client scopes and session limits |
| Sessions | Per-device listing and revocation, re-authentication for sensitive actions |
| Protection | Sliding-window rate limits per client (IPv6 per /64), account lockout, CAPTCHA, trusted-proxy address resolution |
| Records | Append-only audit log partitioned by month, readable by each user; durable domain events on NATS JetStream |
| Localization | English and French emails |

## Requirements

**To develop:** Rust (2024 edition), Docker with Compose, GNU Make - see
[prerequisites](docs/dev/guides/prerequisites.md).

**To deploy:** a server with Docker and a PostgreSQL and Redis reachable from
it - see the [Deployment Guide](docs/deploy/README.md). NATS ships in the
compose file.

## Installation

```bash
git clone <repository-url> auth-api
cd auth-api
make dev
```

The API serves at `http://localhost:3000`, and Mailpit catches emails at
`http://localhost:8025`. Every port is bound to loopback.

## Usage

| Task | Command |
|------|---------|
| Run the full quality gate | `make test-infra-up && make ci` |
| Register a client application | `auth-api --register-client <id> --name <name> [--primary]` |
| Build a release bundle | `make release VERSION=x.y.z` |

All commands are in [commands](docs/dev/guides/commands.md); routes in
[routes](docs/dev/api/routes.md) and the generated [OpenAPI document](docs/dev/api/openapi.yaml).

## Documentation

| Document | Contents |
|----------|----------|
| [Developer Guide](docs/dev/README.md) | Prerequisites, commands, quality gate, release, configuration, routes, schema, security model |
| [Deployment Guide](docs/deploy/README.md) | Secrets, database, API and Nginx deployment, updates, operations runbook |
| [`CHANGELOG.md`](CHANGELOG.md) | Changes per release, breaking changes and upgrade notes |
| [`LICENSE`](LICENSE) | MIT license terms |

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

Copyright (c) 2026 Lucas Fagioli.
