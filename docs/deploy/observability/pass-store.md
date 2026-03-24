# Observability `pass` Store

This document lists the `pass` entries recommended for the observability stack.

The goal is to keep the local secret store explicit and predictable on the data server.

## Required Entry

```text
rust-api/observability/GRAFANA_ADMIN_PASSWORD
```

Create it with:

```bash
pass insert rust-api/observability/GRAFANA_ADMIN_PASSWORD
```

## Optional Entry

If Grafana queries PostgreSQL directly, also create:

```text
rust-api/observability/POSTGRES_GRAFANA_PASSWORD
```

Create it with:

```bash
pass insert rust-api/observability/POSTGRES_GRAFANA_PASSWORD
```

## Notes

- `GRAFANA_ADMIN_PASSWORD` is needed to start Grafana.
- `POSTGRES_GRAFANA_PASSWORD` is only needed for the PostgreSQL datasource.
- Keep these entries on the data server, alongside the rest of the local `pass` store.
