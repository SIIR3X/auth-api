# Observability Setup

This guide explains how to prepare the observability stack.

In the current deployment model, the observability stack runs on the data server.

It is responsible for:
- collecting Docker logs from the data server
- storing logs in Loki
- exposing Grafana
- optionally querying PostgreSQL audit tables through a read-only datasource

The server is not expected to contain the full Git repository.
Repository files are references only.

## Prerequisites

Before starting, prepare the shared local tooling:
- [pass-installation.md](../shared/pass-installation.md)
- [cryptsetup-installation.md](../shared/cryptsetup-installation.md)
- [cryptsetup-volumes.md](../shared/cryptsetup-volumes.md)

## Server Layout

Recommended layout on the data server:

```text
/srv/rust-api-data/
├── observability/
│   ├── alloy/
│   ├── config/
│   │   ├── alloy.config.alloy
│   │   ├── loki-config.yml
│   │   └── grafana/
│   │       └── provisioning/
│   ├── grafana/
│   └── loki/
├── compose/
│   └── observability-docker-compose.yml
└── env/
    └── observability-runtime.env
```

If encrypted storage is enabled, keep this layout under:

```text
/srv/rust-api-data
```

## Step 1. Create `observability-runtime.env`

Create the runtime file directly on the server:

```text
/srv/rust-api-data/env/observability-runtime.env
```

Use this repository file as the reference:
- [runtime.env.example](../../../deploy/observability/runtime.env.example)

Variable descriptions are documented in:
- [environment-variables.md](environment-variables.md)
- [secrets.md](secrets.md)
- [ports.md](ports.md)

Only put non-sensitive values in this file.

## Step 2. Create the Local Secret

Create the Grafana admin password in `pass`:

```bash
pass insert rust-api/observability/GRAFANA_ADMIN_PASSWORD
```

The observability secrets are documented in:
- [pass-store.md](pass-store.md)
- [secrets.md](secrets.md)

## Step 3. Create the Configuration Files

Create the following files directly on the server:

```text
/srv/rust-api-data/observability/config/loki-config.yml
/srv/rust-api-data/observability/config/alloy.config.alloy
/srv/rust-api-data/observability/config/grafana/provisioning/datasources/datasources.yml
/srv/rust-api-data/observability/config/grafana/provisioning/dashboards/providers.yml
/srv/rust-api-data/observability/config/grafana/provisioning/dashboards/json/data-server-overview.json
/srv/rust-api-data/observability/config/grafana/provisioning/dashboards/json/postgresql-and-redis-logs.json
/srv/rust-api-data/observability/config/grafana/provisioning/dashboards/json/observability-services.json
```

Use these repository files as references:
- [loki-config.yml](../../../deploy/observability/loki-config.yml)
- [alloy.config.alloy](../../../deploy/observability/alloy.config.alloy)
- [datasources.yml](../../../deploy/observability/grafana/provisioning/datasources/datasources.yml)
- [providers.yml](../../../deploy/observability/grafana/provisioning/dashboards/providers.yml)
- [data-server-overview.json](../../../deploy/observability/grafana/provisioning/dashboards/json/data-server-overview.json)
- [postgresql-and-redis-logs.json](../../../deploy/observability/grafana/provisioning/dashboards/json/postgresql-and-redis-logs.json)
- [observability-services.json](../../../deploy/observability/grafana/provisioning/dashboards/json/observability-services.json)

## Step 4. Create the Compose File

Create the compose file directly on the server:

```text
/srv/rust-api-data/compose/observability-docker-compose.yml
```

Use this repository file as the reference:
- [docker-compose.yml](../../../deploy/observability/docker-compose.yml)

## Step 5. Create the Data Directories

Create the required directories:

```bash
mkdir -p /srv/rust-api-data/observability/loki
mkdir -p /srv/rust-api-data/observability/grafana
mkdir -p /srv/rust-api-data/observability/alloy
mkdir -p /srv/rust-api-data/observability/config/grafana/provisioning/datasources
mkdir -p /srv/rust-api-data/observability/config/grafana/provisioning/dashboards/json
```

## Step 6. Start Loki, Grafana, and Alloy

Export the Grafana admin password from `pass`:

```bash
export GRAFANA_ADMIN_PASSWORD="$(pass show rust-api/observability/GRAFANA_ADMIN_PASSWORD)"
```

Start the stack:

```bash
docker compose \
  --env-file /srv/rust-api-data/env/observability-runtime.env \
  -f /srv/rust-api-data/compose/observability-docker-compose.yml \
  pull

docker compose \
  --env-file /srv/rust-api-data/env/observability-runtime.env \
  -f /srv/rust-api-data/compose/observability-docker-compose.yml \
  up -d
```

## Step 7. Validate the Stack

Check that the services are running:

```bash
docker compose \
  --env-file /srv/rust-api-data/env/observability-runtime.env \
  -f /srv/rust-api-data/compose/observability-docker-compose.yml \
  ps
```

Expected services:
- `loki`
- `grafana`
- `alloy`

Grafana should expose the UI on the configured bind IP and port.
Loki should remain private unless you intentionally proxy it.

Expected dashboards:
- `Data Server Overview`
- `PostgreSQL and Redis Logs`
- `Observability Services`

## Optional Step. Query `audit_log` and Related Tables

To query PostgreSQL from Grafana, create a dedicated read-only datasource.

Use:
- [postgresql-datasource.md](postgresql-datasource.md)

## Notes

- This stack centralizes logs from the data server first.
- The application server can later run its own Alloy agent and push logs to the same Loki instance.
- `audit_log` remains in PostgreSQL; Loki is intended for container logs, not as a replacement for the audit tables.
- Expose Grafana only through a private network, VPN, or secured reverse proxy.
- Keep Loki private unless another trusted server must push logs to it.
- The provisioned dashboards focus on Docker logs first; SQL dashboards can be added after the PostgreSQL datasource is configured.
