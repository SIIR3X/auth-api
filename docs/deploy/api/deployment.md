# API Deployment

Previous: [Database Deployment](../database/deployment.md) | [Index](../README.md) | Next: [Nginx](nginx.md)

## Overview

The API is distributed as a Docker image published to GitHub Container Registry (GHCR). The production server only needs Docker - no Rust, no source code.

```
git tag v1.2.3
    |
GitHub Actions builds the image
    |
Image pushed to ghcr.io/siir3x/auth-api:latest
    |
VPS: docker compose pull && docker compose up -d
```

## Prerequisites

The NATS event broker ships in `docker-compose.api.yml` and starts with the
API - no external infrastructure is required. Nginx runs directly on this VPS
as the reverse proxy (see [Nginx](nginx.md)); the API and its metrics endpoint
are published on loopback only and are reachable exclusively through it.

## 1. Initial Setup

### 1.1 Open the firewall

**On the API VPS** - allow WireGuard (database tunnel) and HTTP/HTTPS for
the local Nginx, which terminates TLS on this VPS:

```bash
sudo ufw allow 51820/udp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

---

### 1.2 Install Docker

```bash
curl -fsSL https://get.docker.com | sh
```

---

### 1.3 Authenticate to GHCR

A GitHub Personal Access Token with `read:packages` scope is required.

```bash
echo "<YOUR_GITHUB_TOKEN>" | docker login ghcr.io -u SIIR3X --password-stdin
```

---

### 1.4 Fetch the deployment files

Only two files are needed on the VPS - no need to clone the full repository.

```bash
mkdir -p /srv/auth-api && cd /srv/auth-api

curl -O https://raw.githubusercontent.com/SIIR3X/auth-api/main/docker-compose.api.yml
curl -O https://raw.githubusercontent.com/SIIR3X/auth-api/main/config.prod.env
```

---

### 1.5 Edit non-sensitive configuration

Open `config.prod.env` and fill in the values specific to your environment:

```bash
nano config.prod.env
```

Key values to update:

- `APP_PUBLIC_URL` - public URL of the API
- `CORS_ALLOWED_ORIGINS` - frontend origin(s)
- `SMTP_HOST`, `SMTP_FROM_ADDRESS` - email provider
- `TOTP_ISSUER` - name shown in authenticator apps
- `ARGON2_*` - tune for your server hardware

---

### 1.6 Export secrets and deploy

```bash
export DATABASE_URL=$(pass prod/auth-api/database-url)
export REDIS_URL=$(pass prod/auth-api/redis-url)
export JWT_PRIVATE_KEY=$(pass prod/auth-api/jwt-private-key)
export JWT_PUBLIC_KEY=$(pass prod/auth-api/jwt-public-key)
export ENCRYPTION_KEY=$(pass prod/auth-api/encryption-key)
export SMTP_USERNAME=$(pass prod/auth-api/smtp-username)
export SMTP_PASSWORD=$(pass prod/auth-api/smtp-password)
export CAPTCHA_SECRET=$(pass prod/auth-api/captcha-secret)
# NATS runs in the same compose file; NATS_URL defaults to nats://nats:4222.

docker compose -f docker-compose.api.yml up -d
```
