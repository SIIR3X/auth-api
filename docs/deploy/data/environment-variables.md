# Data Server Environment Variables

This document lists the non-sensitive environment variables used by the data server.

Sensitive values must not be written into `runtime.env`.
They must be stored in `pass` and exported before starting the services.

See:
- [pass-store.md](pass-store.md)
- [secrets.md](secrets.md)

## Runtime File

The data server uses a local runtime file such as:

```text
/srv/rust-api-data/env/runtime.env
```

## Non-Sensitive Variables

| Variable | Purpose |
| --- | --- |
| `POSTGRES_VERSION` | PostgreSQL image version |
| `POSTGRES_BIND_IP` | PostgreSQL bind address on the host |
| `POSTGRES_PORT` | PostgreSQL host port |
| `POSTGRES_DATA_DIR` | PostgreSQL data directory on the host |
| `REDIS_VERSION` | Redis image version |
| `REDIS_BIND_IP` | Redis bind address on the host |
| `REDIS_PORT` | Redis host port |
| `REDIS_DATA_DIR` | Redis data directory on the host |
