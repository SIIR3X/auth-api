# Redis Setup

This guide explains how Redis is initialized for this project on the data server.

The actual service start is handled by:
- [setup.md](setup.md)

The repository compose file is:
- [docker-compose.yml](../../../deploy/data/docker-compose.yml)

## Redis Authentication

Redis should be protected with a dedicated password.

Store it in the local encrypted store on the data server:

```bash
pass insert rust-api/data/REDIS_PASSWORD
```

## Redis Binding

Redis should listen only on a private interface.

The recommended bind address is configured in:
- [runtime.env.example](../../../deploy/data/runtime.env.example)

Typical examples:
- `127.0.0.1` when the application runs on the same host
- a private LAN address when the application runs on another server

## Redis Persistence

The compose file is configured to use append-only persistence.

The host directory should point to a persistent path such as:

```text
/srv/rust-api-data/redis
```

## Validate Redis After Startup

After the data server is started, verify Redis with:

```bash
export REDIS_PASSWORD="$(pass show rust-api/data/REDIS_PASSWORD)"
redis-cli -h 127.0.0.1 -p 6379 -a "$REDIS_PASSWORD" ping
```

The expected result is:

```text
PONG
```

## Runtime URL for the Application

The application server should use a final Redis URL like:

```text
redis://:PASSWORD@PRIVATE_DATA_SERVER_IP:6379
```

Store that final application-side URL on the application server with:

```bash
pass insert rust-api/app/REDIS_URL
```
