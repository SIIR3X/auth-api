# Data Server Environment Variables

Sensitive values must not be placed in `runtime.env`.

Put secrets in:
- [pass-store.md](./pass-store.md)

## Non-Sensitive Variables

| Variable | Purpose |
| --- | --- |
| `POSTGRES_VERSION` | PostgreSQL container version tag. |
| `POSTGRES_BIND_IP` | Host IP used to expose PostgreSQL. |
| `POSTGRES_PORT` | Host port used to expose PostgreSQL. |
| `POSTGRES_LISTEN_ADDRESSES` | PostgreSQL listen addresses inside the container. |
| `POSTGRES_MAX_CONNECTIONS` | PostgreSQL maximum concurrent connections. |
| `POSTGRES_DATA_DIR` | Host directory used for PostgreSQL persistent data. |
| `REDIS_VERSION` | Redis container version tag. |
| `REDIS_BIND_IP` | Host IP used to expose Redis. |
| `REDIS_PORT` | Host port used to expose Redis. |
| `REDIS_DATA_DIR` | Host directory used for Redis persistent data. |
