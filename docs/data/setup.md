# Data Server Setup Guide

This guide explains how to prepare the server that hosts PostgreSQL and Redis.

This server is responsible for:
- running PostgreSQL
- running Redis
- storing their persistent data
- exposing both services only on a private network or private IP
- reading local encrypted secrets from `pass`

## Prerequisite

Before starting this setup, install and initialize `pass`:
- [pass-installation.md](../shared/pass-installation.md)

If you want `/srv/rust-api-data` to live on encrypted storage, install `cryptsetup` first:
- [cryptsetup-installation.md](../shared/cryptsetup-installation.md)

If you want to actually create and mount the encrypted volume:
- [cryptsetup-volumes.md](../shared/cryptsetup-volumes.md)

## Server Layout

| Path | Purpose |
| --- | --- |
| `/srv/rust-api-data/compose/docker-compose.yml` | Data services Compose file |
| `/srv/rust-api-data/env/runtime.env` | Non-secret data server configuration |
| `/srv/rust-api-data/postgres/` | PostgreSQL persistent data |
| `/srv/rust-api-data/redis/` | Redis persistent data |

Create the directories:

```bash
mkdir -p /srv/rust-api-data/compose
mkdir -p /srv/rust-api-data/env
mkdir -p /srv/rust-api-data/postgres
mkdir -p /srv/rust-api-data/redis
chmod 700 /srv/rust-api-data/env
chmod 700 /srv/rust-api-data/postgres
chmod 700 /srv/rust-api-data/redis
```

If `/srv/rust-api-data` is encrypted, do this only after the encrypted volume is mounted on `/srv/rust-api-data`.

## Step 1: Create `runtime.env`

Create `/srv/rust-api-data/env/runtime.env` on the data server.

Reference template:
- [runtime.env.example](../../deploy/data/runtime.env.example)
- [environment-variables.md](./environment-variables.md)
- [database-setup.md](./database-setup.md)

## Step 2: Create the `pass` Entries

Create the data server secrets in `pass`:
- [pass-store.md](./pass-store.md)
- [secrets.md](./secrets.md)

## Step 3: Create the Compose File

Create `/srv/rust-api-data/compose/docker-compose.yml` on the data server.

Reference template:
- [docker-compose.yml](../../deploy/data/docker-compose.yml)

## Step 4: Start PostgreSQL and Redis

```bash
docker compose \
  --env-file /srv/rust-api-data/env/runtime.env \
  -f /srv/rust-api-data/compose/docker-compose.yml \
  pull

export POSTGRES_DB="$(pass show rust-api/data/POSTGRES_DB)"
export POSTGRES_USER="$(pass show rust-api/data/POSTGRES_USER)"
export POSTGRES_PASSWORD="$(pass show rust-api/data/POSTGRES_PASSWORD)"
export REDIS_PASSWORD="$(pass show rust-api/data/REDIS_PASSWORD)"

docker compose \
  --env-file /srv/rust-api-data/env/runtime.env \
  -f /srv/rust-api-data/compose/docker-compose.yml \
  up -d
```

## Step 5: Run the Migration Image

```bash
set -a
source /srv/rust-api-data/env/runtime.env
set +a

export POSTGRES_DB="$(pass show rust-api/data/POSTGRES_DB)"
export POSTGRES_USER="$(pass show rust-api/data/POSTGRES_USER)"
export POSTGRES_PASSWORD="$(pass show rust-api/data/POSTGRES_PASSWORD)"

DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT:-5432}/${POSTGRES_DB}" \
docker run --rm \
  -e DATABASE_URL="$DATABASE_URL" \
  ghcr.io/your-org/rust-api-migrations:latest
```

## Step 6: Build Final Client URLs

```dotenv
DATABASE_URL=postgres://POSTGRES_USER:POSTGRES_PASSWORD@PRIVATE_DB_HOST:5432/POSTGRES_DB
REDIS_URL=redis://:REDIS_PASSWORD@PRIVATE_REDIS_HOST:6379
```

Insert those values into `pass` on the application server.

For role creation, database ownership, and runtime grants, use:
- [database-setup.md](./database-setup.md)

For Redis password, bind settings, and final runtime URL, use:
- [redis-setup.md](./redis-setup.md)
