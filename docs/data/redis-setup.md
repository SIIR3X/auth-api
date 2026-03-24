# Redis Setup

This guide explains how to prepare Redis for the project.

Service startup is handled in:
- [setup.md](./setup.md)

This document focuses on:
- how Redis is installed in this deployment model
- which settings should be used at initialization time
- how to prepare the final runtime URL for the application server

The recommended model is:
- one dedicated Redis password for this deployment
- one Redis instance bound to a private IP only
- one final runtime URL inserted into `pass` on the application server

## Recommended Settings

| Item | Recommended value |
| --- | --- |
| Redis port | `6379` |
| Bind address | Private server IP only |
| Authentication | `requirepass` enabled |
| Persistence | `appendonly yes` |
| Max memory policy | `noeviction` |

## Step 1: Install Redis

In this project, Redis is installed through the data server Compose file:
- [docker-compose.yml](../../deploy/data/docker-compose.yml)

The Redis service is created from the official `redis` image and uses:
- `REDIS_VERSION`
- `REDIS_BIND_IP`
- `REDIS_PORT`
- `REDIS_DATA_DIR`

The Compose definition already initializes Redis with:
- `requirepass`
- `appendonly yes`
- `protected-mode yes`
- `maxmemory-policy noeviction`

The actual start command is run later from:
- [setup.md](./setup.md)

## Step 2: Choose a Strong Password

Generate a strong password for Redis and place it in `pass` on the data server.

Reference template:
- [pass-store.md](./pass-store.md)

The variable used by the data server is:

```dotenv
rust-api/data/REDIS_PASSWORD
```

## Step 3: Bind Redis to a Private Interface

Redis must not be exposed to the public internet.

Keep it reachable only on a private IP through:
- `REDIS_BIND_IP`
- the server firewall

Reference template:
- [runtime.env.example](../../deploy/data/runtime.env.example)

Typical runtime values:

```dotenv
REDIS_BIND_IP=10.0.0.10
REDIS_PORT=6379
REDIS_DATA_DIR=/srv/rust-api-data/redis
```

## Step 4: Validate Redis Locally

After the data stack has been started from:
- [setup.md](./setup.md)

From the data server, validate that Redis answers with authentication:

```bash
export REDIS_PASSWORD="$(pass show rust-api/data/REDIS_PASSWORD)"

redis-cli -h 127.0.0.1 -p 6379 -a "$REDIS_PASSWORD" ping
```

Expected result:

```text
PONG
```

## Step 5: Build the Final Runtime URL

The application server should use the final client URL only:

```dotenv
REDIS_URL=redis://:REDIS_PASSWORD@PRIVATE_REDIS_HOST:6379
```

Example:

```dotenv
REDIS_URL=redis://:super-secret-password@10.0.0.10:6379
```

Insert that final URL into `pass` on the application server.

## Summary

| Stage | Value used |
| --- | --- |
| Data server secret | `REDIS_PASSWORD` |
| Data server bind | `REDIS_BIND_IP` and `REDIS_PORT` |
| Application runtime secret | `REDIS_URL` |
