# PostgreSQL Datasource for Grafana

This guide explains how to let Grafana query PostgreSQL audit and security tables.

The goal is to keep:
- runtime container logs in Loki
- structured security data in PostgreSQL

Grafana can then display both in one interface.

## 1. Create a Read-Only PostgreSQL Role

Connect to PostgreSQL as an administrator and create a dedicated read-only role.

Example:

```sql
CREATE ROLE rust_api_grafana LOGIN PASSWORD 'CHANGE_ME';
```

If you keep secrets locally with `pass`, a practical path is:

```text
rust-api/observability/POSTGRES_GRAFANA_PASSWORD
```

This secret is also documented in:
- [secrets.md](secrets.md)

## 2. Grant Read Access

Grant only the access Grafana needs.

Recommended baseline:

```sql
GRANT CONNECT ON DATABASE rust_api TO rust_api_grafana;
```

Then inside the application database:

```sql
GRANT USAGE ON SCHEMA public TO rust_api_grafana;

GRANT SELECT ON TABLE
    audit_log,
    login_attempts,
    login_locations,
    sessions,
    users
TO rust_api_grafana;
```

If you want future tables to stay private by default, do not grant broader schema-wide defaults.

## 3. Restrict Network Access

Allow Grafana to connect to PostgreSQL only from the expected private source.

Use:
- firewall rules
- `pg_hba.conf`

Do not expose this role broadly.

## 4. Add the Datasource in Grafana

You can:
- add it manually through the Grafana UI
- or provision it later as a file

Minimum datasource values:

| Field | Value |
| --- | --- |
| Type | PostgreSQL |
| Host | `127.0.0.1:5432` if Grafana runs on the same data server, otherwise the private PostgreSQL host and port |
| Database | application database name |
| User | `rust_api_grafana` |
| Password | password created for the role |
| SSL mode | according to your PostgreSQL setup |

## 5. Recommended First Queries

Useful starting points:

- failed logins by hour from `login_attempts`
- suspicious events from `audit_log`
- recent session revocations from `audit_log`
- recent login locations by user from `login_locations`

## Notes

- This datasource is meant for observation only.
- Do not reuse the application role.
- Do not reuse the migration role.
- Keep the role strictly read-only.
