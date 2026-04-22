# API Deployment

Previous: [Database Deployment](../database/deployment.md) | [Index](../README.md)

## Overview

The API is distributed as a Docker image published to GitHub Container Registry (GHCR). The production server only needs Docker — no Rust, no source code.

```
git tag v1.2.3
    ↓
GitHub Actions builds the image
    ↓
Image pushed to ghcr.io/siir3x/auth-api:latest
    ↓
VPS: docker compose pull && docker compose up -d
```

## 1. Initial Setup

### 1.1 Install Docker

```bash
curl -fsSL https://get.docker.com | sh
```

---

### 1.2 Authenticate to GHCR

A GitHub Personal Access Token with `read:packages` scope is required.

```bash
echo "<YOUR_GITHUB_TOKEN>" | docker login ghcr.io -u SIIR3X --password-stdin
```

---

### 1.3 Fetch the deployment files

Only two files are needed on the VPS — no need to clone the full repository.

```bash
mkdir -p /srv/auth-api && cd /srv/auth-api

curl -O https://raw.githubusercontent.com/SIIR3X/auth-api/main/docker-compose.prod.yml
curl -O https://raw.githubusercontent.com/SIIR3X/auth-api/main/config.prod.env
```

---

### 1.4 Edit non-sensitive configuration

Open `config.prod.env` and fill in the values specific to your environment:

```bash
nano config.prod.env
```

Key values to update:

- `APP_PUBLIC_URL` — public URL of the API
- `CORS_ALLOWED_ORIGINS` — frontend origin(s)
- `SMTP_HOST`, `SMTP_FROM_ADDRESS` — email provider
- `TOTP_ISSUER` — name shown in authenticator apps
- `ARGON2_*` — tune for your server hardware

---

### 1.5 Export secrets and deploy

```bash
export DATABASE_URL=$(pass prod/auth-api/database-url)
export REDIS_URL=$(pass prod/auth-api/redis-url)
export JWT_SECRET=$(pass prod/auth-api/jwt-secret)
export ENCRYPTION_KEY=$(pass prod/auth-api/encryption-key)
export SMTP_USERNAME=$(pass prod/auth-api/smtp-username)
export SMTP_PASSWORD=$(pass prod/auth-api/smtp-password)
export CAPTCHA_SECRET=$(pass prod/auth-api/captcha-secret)

docker compose -f docker-compose.prod.yml up -d
```

