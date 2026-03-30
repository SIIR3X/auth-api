# Database Setup

[Previous: Services](services.md) | [Back to setup](setup.md) | [Next: Monitoring](monitoring.md)

## 1. Create the PostgreSQL roles

Connect to PostgreSQL:

```bash
docker exec -it $(docker ps --filter name=postgres --format '{{.Names}}') psql -U "$(pass show rust-api/data/postgres_user)" -d postgres
```

Run:

```sql
CREATE ROLE rust_api_app LOGIN PASSWORD 'CHANGE_ME';
CREATE ROLE rust_api_grafana LOGIN PASSWORD 'CHANGE_ME';
```

## 2. Create the extensions and grants

Reconnect to the `rust_api` database:

```bash
docker exec -it $(docker ps --filter name=postgres --format '{{.Names}}') psql -U "$(pass show rust-api/data/postgres_user)" -d rust_api
```

Run:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

GRANT CONNECT ON DATABASE rust_api TO rust_api_app;
GRANT USAGE ON SCHEMA public TO rust_api_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rust_api_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO rust_api_app;

ALTER DEFAULT PRIVILEGES FOR ROLE rust_api_migrator IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO rust_api_app;

ALTER DEFAULT PRIVILEGES FOR ROLE rust_api_migrator IN SCHEMA public
GRANT USAGE, SELECT ON SEQUENCES TO rust_api_app;

GRANT CONNECT ON DATABASE rust_api TO rust_api_grafana;
GRANT USAGE ON SCHEMA public TO rust_api_grafana;

GRANT SELECT ON TABLE
    audit_log,
    login_attempts,
    login_locations,
    sessions,
    users
TO rust_api_grafana;
```

Use:
- `rust_api_migrator` for migrations
- `rust_api_app` for the application
- `rust_api_grafana` for Grafana only

## 3. Run migrations

```bash
set -a
. /srv/rust-api-data/env/runtime.env
set +a
```

```bash
export POSTGRES_DB="$(pass show rust-api/data/postgres_db)"
export POSTGRES_USER="$(pass show rust-api/data/postgres_user)"
export POSTGRES_PASSWORD="$(pass show rust-api/data/postgres_password)"
```

```bash
DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}" \
docker run --rm \
  -e DATABASE_URL="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}" \
  ghcr.io/<owner>/rust-api-migrations:<tag>
```

## 4. Create the final URLs for the application server

On the application server:

```bash
pass insert rust-api/app/database_url
pass insert rust-api/app/redis_url
```

Recommended formats:
- `database_url` -> `postgres://rust_api_app:...@__DATA_PRIVATE_IP__:5432/rust_api`
- `redis_url` -> `redis://:...@__DATA_PRIVATE_IP__:6379`
