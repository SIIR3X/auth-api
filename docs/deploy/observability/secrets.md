# Observability Secrets

This document lists the sensitive values used by the observability stack.

These values must not be written into the local runtime file.
They should be stored in `pass` and exported only when needed.

See:
- [pass-store.md](pass-store.md)

## Required Secret

| Secret | Purpose | Recommended `pass` path |
| --- | --- | --- |
| `GRAFANA_ADMIN_PASSWORD` | Grafana administrator password | `rust-api/observability/GRAFANA_ADMIN_PASSWORD` |

## Optional Secret

| Secret | Purpose | Recommended `pass` path |
| --- | --- | --- |
| `POSTGRES_GRAFANA_PASSWORD` | Password for the read-only PostgreSQL role used by Grafana | `rust-api/observability/POSTGRES_GRAFANA_PASSWORD` |

## Notes

- `GRAFANA_ADMIN_PASSWORD` is required as soon as you start Grafana.
- `POSTGRES_GRAFANA_PASSWORD` is only needed if Grafana queries PostgreSQL directly.
- Do not reuse the application PostgreSQL role.
- Do not reuse the migration PostgreSQL role.
