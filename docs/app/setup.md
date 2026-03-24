# Application Server Setup Guide

This guide explains how to prepare the server that runs the application container.

This server is responsible for:
- running the application container
- reading non-secret runtime configuration
- reading local encrypted secrets from `pass`

This server does not host PostgreSQL or Redis.

## Prerequisite

Before starting this setup, install and initialize `pass`:
- [pass-installation.md](../shared/pass-installation.md)

If you want `/srv/rust-api` to live on encrypted storage, install `cryptsetup` first:
- [cryptsetup-installation.md](../shared/cryptsetup-installation.md)

If you want to actually create and mount the encrypted volume:
- [cryptsetup-volumes.md](../shared/cryptsetup-volumes.md)

## Server Layout

| Path | Purpose |
| --- | --- |
| `/srv/rust-api/compose/docker-compose.yml` | Application Compose file |
| `/srv/rust-api/env/runtime.env` | Non-secret application runtime configuration |
| `/srv/rust-api/data/` | Runtime files mounted into the container |

Create the directories:

```bash
mkdir -p /srv/rust-api/compose
mkdir -p /srv/rust-api/env
mkdir -p /srv/rust-api/data
```

If `/srv/rust-api` is encrypted, do this only after the encrypted volume is mounted on `/srv/rust-api`.

## Step 1: Prepare GeoIP Data

If GeoIP is enabled, download the GeoLite2 City database from MaxMind and place it at:

```bash
/srv/rust-api/data/GeoLite2-City.mmdb
```

Keep this path in `runtime.env`:

```dotenv
GEOIP_DB_PATH=/app/data/GeoLite2-City.mmdb
```

Rules:
- if `GEOIP_REQUIRED=true`, the file must exist before the container starts
- if you do not want GeoIP yet, set `GEOIP_REQUIRED=false`

## Step 2: Create `runtime.env`

Create `/srv/rust-api/env/runtime.env` directly on the server.

Reference template:
- [runtime.env.example](../../deploy/app/runtime.env.example)
- [environment-variables.md](./environment-variables.md)

## Step 3: Create the `pass` Entries

Create the application secrets in `pass`:
- [pass-store.md](./pass-store.md)
- [secrets.md](./secrets.md)

## Step 4: Create the Compose File

Create `/srv/rust-api/compose/docker-compose.yml` on the server.

Reference template:
- [docker-compose.yml](../../deploy/app/docker-compose.yml)

## Step 5: Install and Configure Nginx

Install and configure Nginx before exposing the application publicly:
- [nginx-setup.md](./nginx-setup.md)

## Step 6: Add Final Service URLs to `pass`

After the data server is ready, insert these final client URLs:
- `DATABASE_URL`
- `REDIS_URL`

## Step 7: Start the Application

Export the deployment-time variables:

```bash
export RUST_API_IMAGE=ghcr.io/your-org/rust-api:latest
export RUST_API_RUNTIME_ENV_FILE=/srv/rust-api/env/runtime.env

export DATABASE_URL="$(pass show rust-api/app/DATABASE_URL)"
export REDIS_URL="$(pass show rust-api/app/REDIS_URL)"
export JWT_SECRET="$(pass show rust-api/app/JWT_SECRET)"
export ENCRYPTION_KEY="$(pass show rust-api/app/ENCRYPTION_KEY)"
export SMTP_USERNAME="$(pass show rust-api/app/SMTP_USERNAME)"
export SMTP_PASSWORD="$(pass show rust-api/app/SMTP_PASSWORD)"

export JWT_PREVIOUS_SECRET="$(pass show rust-api/app/JWT_PREVIOUS_SECRET 2>/dev/null || true)"
export PREVIOUS_ENCRYPTION_KEY="$(pass show rust-api/app/PREVIOUS_ENCRYPTION_KEY 2>/dev/null || true)"
export CAPTCHA_SECRET="$(pass show rust-api/app/CAPTCHA_SECRET 2>/dev/null || true)"
```

Then deploy:

```bash
docker compose \
  --env-file "$RUST_API_RUNTIME_ENV_FILE" \
  -f /srv/rust-api/compose/docker-compose.yml \
  pull

docker compose \
  --env-file "$RUST_API_RUNTIME_ENV_FILE" \
  -f /srv/rust-api/compose/docker-compose.yml \
  up -d
```

Image publishing and release tags are documented in:
- [image-release.md](../shared/image-release.md)
