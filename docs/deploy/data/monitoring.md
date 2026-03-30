# Observability

[Previous: Database](database.md) | [Back to setup](setup.md)

## 1. Add Alloy on the data server

```bash
sudo nano /srv/rust-api-data/observability/rust-api/alloy-data/docker-compose.yml
sudo nano /srv/rust-api-data/observability/rust-api/alloy-data/config.alloy
```

Use these files as references:
- [docker-compose.yml](../../../deploy/data/alloy/docker-compose.yml)
- [config.alloy](../../../deploy/data/alloy/config.alloy)

Replace:
- `__HOST_LABEL__` -> `rust-api-data`
- `__LOKI_PUSH_URL__` -> the Loki push URL reachable from the data server
- `__PROMETHEUS_REMOTE_WRITE_URL__` -> the Prometheus remote write URL reachable from the data server

Recommended values when the observability tunnel is already in place:

```text
__LOKI_PUSH_URL__=http://__OBSERVABILITY_SERVER_IP__:3100/loki/api/v1/push
__PROMETHEUS_REMOTE_WRITE_URL__=http://__OBSERVABILITY_SERVER_IP__:9090/api/v1/write
```

Start it:

```bash
cd /srv/rust-api-data/observability/rust-api/alloy-data
docker compose up -d
docker compose ps
docker compose logs alloy --tail 50
```

Before validating cross-service logs and metrics, deploy the application-side Alloy with [../app/monitoring.md](../app/monitoring.md).

## 2. Add the PostgreSQL datasource to the central Grafana stack

```bash
sudo nano /srv/grafana-stack/provisioning/datasources/rust-api-postgresql.yml
```

Use [rust-api-postgresql.yml](../../../deploy/data/grafana/datasources/rust-api-postgresql.yml) as the reference.

Replace:
- `__POSTGRES_HOST__`
- `__POSTGRES_PORT__`
- `__POSTGRES_DB__`
- `__POSTGRES_GRAFANA_USER__`
- `__POSTGRES_GRAFANA_PASSWORD__`

Recommended values:
- `__POSTGRES_HOST__` -> `127.0.0.1`
- `__POSTGRES_PORT__` -> `5432`
- `__POSTGRES_DB__` -> `rust_api`
- `__POSTGRES_GRAFANA_USER__` -> `rust_api_grafana`
- `__POSTGRES_GRAFANA_PASSWORD__` -> password stored in `rust-api/observability/postgres_grafana_password`

## 3. Add the Grafana dashboards

```bash
sudo nano /srv/grafana-stack/dashboards/rust-api-app-server.json
sudo nano /srv/grafana-stack/dashboards/postgresql-and-redis-logs.json
sudo nano /srv/grafana-stack/dashboards/rust-api-audit-overview.json
```

Use these files as references:
- [rust-api-app-server.json](../../../deploy/data/grafana/dashboards/rust-api-app-server.json)
- [postgresql-and-redis-logs.json](../../../deploy/data/grafana/dashboards/postgresql-and-redis-logs.json)
- [rust-api-audit-overview.json](../../../deploy/data/grafana/dashboards/rust-api-audit-overview.json)

Replace:
- `__HOST_LABEL__` in `rust-api-app-server.json`

The datasource UIDs in the dashboard files must match the central Grafana stack.

## 4. Reload Grafana

Export the same Grafana variables used by the central stack, then reload Grafana:

```bash
cd /srv/grafana-stack
export GRAFANA_ADMIN_USER="$(pass show home-server/grafana/admin_user)"
export GRAFANA_ADMIN_PASSWORD="$(pass show home-server/grafana/admin_password)"
export GRAFANA_SECRET_KEY="$(pass show home-server/grafana/secret_key)"
export GRAFANA_DOMAIN="$(pass show home-server/grafana/domain)"
export GRAFANA_ROOT_URL="$(pass show home-server/grafana/root_url)"
export SMTP_HOST="$(pass show home-server/grafana/smtp_host)"
export SMTP_USER="$(pass show home-server/grafana/smtp_user)"
export SMTP_PASSWORD="$(pass show home-server/grafana/smtp_password)"
export SMTP_FROM_ADDRESS="$(pass show home-server/grafana/smtp_from_address)"
export SMTP_FROM_NAME="$(pass show home-server/grafana/smtp_from_name)"
export ALERT_EMAIL_TO="$(pass show home-server/grafana/alert_email_to)"
docker compose up -d grafana
```

## 5. Validate

On the central Grafana stack, validate:
- metrics for `host="rust-api-data"`
- Docker logs for `server_role="data"`
- Docker logs for `server_role="app"`
- PostgreSQL audit queries through the Rust API PostgreSQL datasource

Useful queries:

```text
node_cpu_seconds_total{host="rust-api-data",server_role="data"}
```

```text
{job="docker",server_role="data",host="rust-api-data"}
```

```text
{job="docker",server_role="app",host="rust-api-app"}
```

```sql
SELECT created_at, action FROM audit_log ORDER BY created_at DESC LIMIT 10;
```
