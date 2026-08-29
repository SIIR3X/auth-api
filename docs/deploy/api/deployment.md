# API Deployment

Previous: [Database Deployment](../database/deployment.md) | [Index](../README.md) | Next: [Nginx](nginx.md)

## Overview

The API runs from a release bundle built with `make release` (see
[Creating a Release](../../dev/guides/release.md)). The server needs Docker and
`sqlx-cli` for migrations - no source code and no registry.

```
trusted machine: make ci && make release VERSION=X.Y.Z
    |
scp dist/auth-api-X.Y.Z -> API VPS
    |
API VPS: verify checksums, docker load, migrate, docker compose up -d
```

The NATS event broker ships in `docker-compose.api.yml` and starts with the
API. Nginx runs on the host as the reverse proxy (see [Nginx](nginx.md)); the
API and its metrics listener are published on loopback only.

## 1. Initial Setup

### 1.1 Open the firewall

**On the API VPS** - WireGuard (database tunnel) and HTTP/HTTPS for Nginx:

```bash
sudo ufw allow 51820/udp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

---

### 1.2 Install Docker and sqlx-cli

```bash
curl -fsSL https://get.docker.com | sh
```

Build `sqlx` on a machine with Rust and copy the binary to the server:

```bash
cargo install sqlx-cli --no-default-features --features rustls,postgres --locked
scp ~/.cargo/bin/sqlx api-vps:/usr/local/bin/sqlx
```

---

### 1.3 Copy and verify the bundle

```bash
# On the trusted machine
scp -r dist/auth-api-X.Y.Z api-vps:/srv/auth-api/releases/

# On the API VPS
cd /srv/auth-api/releases/auth-api-X.Y.Z
sha256sum SHA256SUMS          # compare with the value recorded at build time
sha256sum -c SHA256SUMS
gunzip -c auth-api-X.Y.Z.image.tar.gz | docker load
```

---

### 1.4 Configure

Copy the deployment files next to each other and fill in the non-sensitive
values:

```bash
mkdir -p /srv/auth-api && cd /srv/auth-api
cp releases/auth-api-X.Y.Z/docker-compose.api.yml releases/auth-api-X.Y.Z/config.prod.env .
nano config.prod.env
```

Values to set:

- `APP_PUBLIC_URL`, `FRONTEND_URL`, `CORS_ALLOWED_ORIGINS`, `JWT_AUDIENCE`
- `DEVICE_AUTH_VERIFICATION_URI`
- `SMTP_HOST`, `SMTP_FROM_ADDRESS`, `TOTP_ISSUER`
- `ARGON2_*` for the server's memory and cores
- `TRUSTED_PROXY_CIDRS` stays `172.30.0.1/32` (the compose network gateway, see [Nginx](nginx.md#trusted-proxy))

---

### 1.5 Run the migrations

```bash
DATABASE_URL=$(pass prod/auth-api/database-url) \
  sqlx migrate run --source /srv/auth-api/releases/auth-api-X.Y.Z/migrations
```

---

### 1.6 Export secrets and start

```bash
cd /srv/auth-api
export AUTH_API_VERSION=X.Y.Z
export DATABASE_URL=$(pass prod/auth-api/database-url)
export REDIS_URL=$(pass prod/auth-api/redis-url)
export JWT_PRIVATE_KEY=$(pass prod/auth-api/jwt-private-key)
export JWT_PUBLIC_KEY=$(pass prod/auth-api/jwt-public-key)
export ENCRYPTION_KEY=$(pass prod/auth-api/encryption-key)
export SMTP_USERNAME=$(pass prod/auth-api/smtp-username)
export SMTP_PASSWORD=$(pass prod/auth-api/smtp-password)
export CAPTCHA_SECRET=$(pass prod/auth-api/captcha-secret)
export NATS_URL=$(pass prod/auth-api/nats-url)
export NATS_AUTH_TOKEN=$(pass prod/auth-api/nats-auth-token)

docker compose -f docker-compose.api.yml up -d
```

---

### 1.7 Register the client applications

Device and authorization code flows only serve registered clients. Register the
application this instance owns as primary, then any other client:

```bash
docker compose -f docker-compose.api.yml run --rm api \
  ./auth-api --register-client web-app --name "Web app" --primary \
  --redirect-uri https://app.example.com/callback
```

Options are listed in [Commands](../../dev/guides/commands.md#binary-commands).
