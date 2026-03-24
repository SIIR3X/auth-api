# Application Server Setup

This guide explains how to prepare the application server.

The application server is responsible for:
- running the application container
- holding the local runtime configuration
- holding the local encrypted secret store with `pass`
- exposing the service through Nginx

The server is not expected to contain the full Git repository.
Repository files are references only.

## Prerequisites

Before starting, prepare the shared local tooling:
- [pass-installation.md](../shared/pass-installation.md)
- [cryptsetup-installation.md](../shared/cryptsetup-installation.md)
- [cryptsetup-volumes.md](../shared/cryptsetup-volumes.md)

## Server Layout

Recommended layout on the application server:

```text
/srv/rust-api/
├── compose/
│   └── docker-compose.yml
├── env/
│   └── runtime.env
└── data/
```

If you use encrypted storage, mount the decrypted LUKS volume directly on:

```text
/srv/rust-api
```

## Step 1. Prepare GeoIP Data

If GeoIP is enabled for risk analysis, download the MaxMind GeoLite2 City database and place the extracted `GeoLite2-City.mmdb` file in:

```text
/srv/rust-api/data/GeoLite2-City.mmdb
```

The runtime configuration must then point to:

```text
/app/data/GeoLite2-City.mmdb
```

If GeoIP is enabled:
- `RISK_GEOIP_REQUIRED=true` means the file must be present
- `RISK_GEOIP_REQUIRED=false` allows startup without the file

## Step 2. Create `runtime.env`

Create the runtime file directly on the server:

```text
/srv/rust-api/env/runtime.env
```

Use this repository file as the reference:
- [runtime.env.example](../../../deploy/app/runtime.env.example)

Variable descriptions are documented in:
- [environment-variables.md](environment-variables.md)

Only put non-sensitive values in this file.

## Step 3. Create the Local Secret Store

Create the required application secrets locally with `pass`.

Use:
- [pass-store.md](pass-store.md)
- [secrets.md](secrets.md)

The database and Redis URLs inserted here are the final application-side URLs.

## Step 4. Create the Compose File

Create the compose file directly on the server:

```text
/srv/rust-api/compose/docker-compose.yml
```

Use this repository file as the reference:
- [docker-compose.yml](../../../deploy/app/docker-compose.yml)

## Step 5. Configure Nginx

Install and configure Nginx using:
- [nginx-setup.md](nginx-setup.md)

## Step 6. Start the Application

Export the required secrets from `pass`:

```bash
export DATABASE_URL="$(pass show rust-api/app/DATABASE_URL)"
export REDIS_URL="$(pass show rust-api/app/REDIS_URL)"
export JWT_SECRET="$(pass show rust-api/app/JWT_SECRET)"
export ENCRYPTION_KEY="$(pass show rust-api/app/ENCRYPTION_KEY)"
export SMTP_USERNAME="$(pass show rust-api/app/SMTP_USERNAME 2>/dev/null || true)"
export SMTP_PASSWORD="$(pass show rust-api/app/SMTP_PASSWORD 2>/dev/null || true)"
export CAPTCHA_SECRET="$(pass show rust-api/app/CAPTCHA_SECRET 2>/dev/null || true)"
export JWT_PREVIOUS_SECRET="$(pass show rust-api/app/JWT_PREVIOUS_SECRET 2>/dev/null || true)"
export PREVIOUS_ENCRYPTION_KEY="$(pass show rust-api/app/PREVIOUS_ENCRYPTION_KEY 2>/dev/null || true)"
```

Set the image to deploy:

```bash
export RUST_API_IMAGE=ghcr.io/<owner>/rust-api:<tag>
```

Start the service:

```bash
docker compose \
  --env-file /srv/rust-api/env/runtime.env \
  -f /srv/rust-api/compose/docker-compose.yml \
  pull

docker compose \
  --env-file /srv/rust-api/env/runtime.env \
  -f /srv/rust-api/compose/docker-compose.yml \
  up -d
```

## Image Publication

Image publication is documented in:
- [image-release.md](../shared/image-release.md)
