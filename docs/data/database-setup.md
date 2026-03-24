# PostgreSQL Database Setup

This guide explains how to prepare the PostgreSQL database for the project.

Service startup is handled in:
- [setup.md](./setup.md)

This document focuses on:
- how PostgreSQL is installed in this deployment model
- how the database is initialized
- which roles should be created
- which permissions should be granted

The recommended model uses three roles:
- the PostgreSQL administrator
- a migration role
- a runtime application role

## Recommended Names

| Item | Recommended name |
| --- | --- |
| Database | `rust_api` |
| Migration role | `rust_api_migrator` |
| Runtime role | `rust_api_app` |

## Role Model

| Role | Purpose | Used by |
| --- | --- | --- |
| PostgreSQL admin | Server administration | Human operator only |
| `rust_api_migrator` | Owns the database schema and runs migrations | Migration image |
| `rust_api_app` | Reads and writes application data at runtime | Application server |

Rules:
- do not use the PostgreSQL admin account in the application
- do not use the migration account in the application
- keep the runtime account limited to data access

## Step 1: Install PostgreSQL

In this project, PostgreSQL is installed through the data server Compose file:
- [docker-compose.yml](../../deploy/data/docker-compose.yml)

The PostgreSQL service is created from the official `postgres` image and uses:
- `POSTGRES_VERSION`
- `POSTGRES_BIND_IP`
- `POSTGRES_PORT`
- `POSTGRES_DATA_DIR`

The actual start command is run later from:
- [setup.md](./setup.md)

## Step 2: Create the Roles

Connect to PostgreSQL as an administrator and create both roles:

```sql
CREATE ROLE rust_api_migrator WITH
    LOGIN
    PASSWORD 'change-me'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT;

CREATE ROLE rust_api_app WITH
    LOGIN
    PASSWORD 'change-me'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT;
```

## Step 3: Create the Database

Create the database and assign ownership to the migration role:

```sql
CREATE DATABASE rust_api
    OWNER rust_api_migrator
    ENCODING 'UTF8'
    TEMPLATE template0;
```

## Step 4: Install Required Extensions

This project requires:
- `pgcrypto`
- `citext`

The first migration creates them:
- [0001_extensions.sql](../../migrations/0001_extensions.sql)

You have two valid options:

1. allow the migration role to create the extensions in the target database
2. create the extensions once as administrator before running migrations

Administrator-driven option:

```sql
\c rust_api
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
```

If your PostgreSQL setup restricts extension creation, prefer the administrator-driven option.

## Step 5: Run the Migrations

Run the migration image with the migration role.

The actual migration command is run later from:
- [setup.md](./setup.md)

The connection string used for that step should look like:

```dotenv
DATABASE_URL=postgres://rust_api_migrator:password@127.0.0.1:5432/rust_api
```

The migration role should own the schema objects created by the migration process.

## Step 6: Grant Runtime Permissions

After the schema exists, grant runtime access to `rust_api_app`:

```sql
\c rust_api

GRANT CONNECT ON DATABASE rust_api TO rust_api_app;
GRANT USAGE ON SCHEMA public TO rust_api_app;

GRANT SELECT, INSERT, UPDATE, DELETE
ON ALL TABLES IN SCHEMA public
TO rust_api_app;

GRANT USAGE, SELECT
ON ALL SEQUENCES IN SCHEMA public
TO rust_api_app;

ALTER DEFAULT PRIVILEGES FOR ROLE rust_api_migrator IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO rust_api_app;

ALTER DEFAULT PRIVILEGES FOR ROLE rust_api_migrator IN SCHEMA public
GRANT USAGE, SELECT ON SEQUENCES TO rust_api_app;
```

This keeps:
- schema ownership in `rust_api_migrator`
- data access in `rust_api_app`

## Step 7: Build the Final Runtime URL

The application server should use the runtime role only:

```dotenv
DATABASE_URL=postgres://rust_api_app:password@PRIVATE_DB_HOST:5432/rust_api
```

Insert that final URL into `pass` on the application server.

## Summary

| Stage | Role used |
| --- | --- |
| PostgreSQL server administration | PostgreSQL admin |
| Database creation | PostgreSQL admin |
| Extension creation | PostgreSQL admin or `rust_api_migrator` if allowed |
| Schema migrations | `rust_api_migrator` |
| Runtime application traffic | `rust_api_app` |
