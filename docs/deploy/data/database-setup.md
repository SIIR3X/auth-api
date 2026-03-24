# PostgreSQL Setup

This guide explains how PostgreSQL is initialized for this project on the data server.

The actual service start is handled by:
- [setup.md](setup.md)

The repository compose file is:
- [docker-compose.yml](../../../deploy/data/docker-compose.yml)

## Recommended Database Name

Use:

```text
rust_api
```

## Recommended Roles

Create three distinct PostgreSQL roles:

| Role | Purpose |
| --- | --- |
| `postgres` | Administrative server-level user |
| `rust_api_migrator` | Owns the schema and runs migrations |
| `rust_api_app` | Used by the application at runtime |

## Why Use Separate Roles

| Role | Reason |
| --- | --- |
| `postgres` | Keeps infrastructure administration separate from application access |
| `rust_api_migrator` | Can create and evolve schema objects |
| `rust_api_app` | Has only the runtime permissions needed by the application |

## Create the Roles

Connect to PostgreSQL as an administrative user and create the roles:

```sql
CREATE ROLE rust_api_migrator LOGIN PASSWORD 'CHANGE_ME';
CREATE ROLE rust_api_app LOGIN PASSWORD 'CHANGE_ME';
```

## Create the Database

Create the application database and assign ownership to the migration role:

```sql
CREATE DATABASE rust_api OWNER rust_api_migrator;
```

## Enable Required Extensions

Connect to the `rust_api` database and install the required extensions:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
```

If your migration role is not allowed to create extensions, do this once as an administrative user before running migrations.

## Grant Runtime Permissions to the Application Role

Connect to the `rust_api` database and grant the required privileges:

```sql
GRANT CONNECT ON DATABASE rust_api TO rust_api_app;
GRANT USAGE ON SCHEMA public TO rust_api_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rust_api_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO rust_api_app;

ALTER DEFAULT PRIVILEGES FOR ROLE rust_api_migrator IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO rust_api_app;

ALTER DEFAULT PRIVILEGES FOR ROLE rust_api_migrator IN SCHEMA public
GRANT USAGE, SELECT ON SEQUENCES TO rust_api_app;
```

## Migration Connection

Run database migrations with the migration role.

The migration connection URL should use:
- database: `rust_api`
- user: `rust_api_migrator`

Example:

```text
postgres://rust_api_migrator:...@127.0.0.1:5432/rust_api
```

## Runtime Connection

The application should connect with the runtime role.

The runtime connection URL should use:
- database: `rust_api`
- user: `rust_api_app`

Example:

```text
postgres://rust_api_app:...@PRIVATE_DATA_SERVER_IP:5432/rust_api
```

Store the final runtime URL on the application server with:

```bash
pass insert rust-api/app/DATABASE_URL
```
