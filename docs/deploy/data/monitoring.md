# Monitoring and Grafana

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
- `__LOKI_PUSH_URL__` -> your existing Loki push URL
- `__PROMETHEUS_REMOTE_WRITE_URL__` -> your existing Prometheus remote write URL

Start it:

```bash
cd /srv/rust-api-data/observability/rust-api/alloy-data
docker compose up -d
docker compose ps
docker compose logs alloy --tail 50
```

Before validating application logs and metrics, deploy the application-side Alloy with [../app/monitoring.md](../app/monitoring.md).

## 2. Add the PostgreSQL datasource to the existing Grafana

On the home server:

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

The dashboards expect these datasource UIDs:
- Loki -> `loki`
- Prometheus -> `prometheus`
- PostgreSQL -> `rust_api_postgres`

## 4. Reload Grafana

On the home server:

```bash
cd /srv/grafana-stack
docker compose restart grafana
```

## 5. Validate in Grafana

Open Grafana from the home server private URL, for example:
- `https://grafana.siir3x.fr`

Check:
- logs from the data server
- logs from the application VPS
- PostgreSQL and Redis logs
- audit panels from PostgreSQL

Useful queries:

```text
{job="docker",server_role="data",host="rust-api-data"}
```

```text
{job="docker",server_role="app",host="rust-api-app"}
```

```sql
SELECT created_at, action FROM audit_log ORDER BY created_at DESC LIMIT 10;
```
