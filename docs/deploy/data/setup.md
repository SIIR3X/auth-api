# Data Server Setup

This guide explains how to prepare the data server.

The data server is responsible for:
- running PostgreSQL
- running Redis
- holding the local runtime configuration
- holding the local encrypted secret store with `pass`
- running database migrations
- optionally hosting the observability stack

The server is not expected to contain the full Git repository.
Repository files are references only.

## Prerequisites

Before starting, prepare the shared local tooling:
- [pass-installation.md](../shared/pass-installation.md)
- [cryptsetup-installation.md](../shared/cryptsetup-installation.md)
- [cryptsetup-volumes.md](../shared/cryptsetup-volumes.md)

## Server Layout

Recommended layout on the data server:

```text
/srv/rust-api-data/
├── compose/
│   └── docker-compose.yml
├── env/
│   └── runtime.env
├── postgres/
└── redis/
```

If you use encrypted storage, mount the decrypted LUKS volume directly on:

```text
/srv/rust-api-data
```

## Step 1. Create `runtime.env`

Create the runtime file directly on the server:

```text
/srv/rust-api-data/env/runtime.env
```

Use this repository file as the reference:
- [runtime.env.example](../../../deploy/data/runtime.env.example)

Variable descriptions are documented in:
- [environment-variables.md](environment-variables.md)

Only put non-sensitive values in this file.

## Step 2. Create the Local Secret Store

Create the required local secrets with `pass`.

Use:
- [pass-store.md](pass-store.md)
- [secrets.md](secrets.md)

## Step 3. Create the Compose File

Create the compose file directly on the server:

```text
/srv/rust-api-data/compose/docker-compose.yml
```

Use this repository file as the reference:
- [docker-compose.yml](../../../deploy/data/docker-compose.yml)

## Step 4. Start PostgreSQL and Redis

Export the required secrets from `pass`:

```bash
export POSTGRES_DB="$(pass show rust-api/data/POSTGRES_DB)"
export POSTGRES_USER="$(pass show rust-api/data/POSTGRES_USER)"
export POSTGRES_PASSWORD="$(pass show rust-api/data/POSTGRES_PASSWORD)"
export REDIS_PASSWORD="$(pass show rust-api/data/REDIS_PASSWORD)"
```

Start the services:

```bash
docker compose \
  --env-file /srv/rust-api-data/env/runtime.env \
  -f /srv/rust-api-data/compose/docker-compose.yml \
  pull

docker compose \
  --env-file /srv/rust-api-data/env/runtime.env \
  -f /srv/rust-api-data/compose/docker-compose.yml \
  up -d
```

## Step 5. Prepare PostgreSQL

Initialize PostgreSQL using:
- [database-setup.md](database-setup.md)

## Step 6. Prepare Redis

Initialize Redis using:
- [redis-setup.md](redis-setup.md)

## Step 7. Run Migrations

Load the local runtime variables:

```bash
set -a
. /srv/rust-api-data/env/runtime.env
set +a
```

Export the migration credentials:

```bash
export POSTGRES_DB="$(pass show rust-api/data/POSTGRES_DB)"
export POSTGRES_USER="$(pass show rust-api/data/POSTGRES_USER)"
export POSTGRES_PASSWORD="$(pass show rust-api/data/POSTGRES_PASSWORD)"
```

Run the migrations image:

```bash
DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}" \
docker run --rm \
  -e DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}" \
  ghcr.io/<owner>/rust-api-migrations:<tag>
```

## Step 8. Prepare Final Application URLs

After PostgreSQL and Redis are ready, create the final application-side URLs and insert them on the application server:

```bash
pass insert rust-api/app/DATABASE_URL
pass insert rust-api/app/REDIS_URL
```

## Optional Step 9. Start Observability

If this server also hosts Grafana, Loki, and Alloy, use:
- [../observability/setup.md](../observability/setup.md)
- [../observability/environment-variables.md](../observability/environment-variables.md)
- [../observability/ports.md](../observability/ports.md)
