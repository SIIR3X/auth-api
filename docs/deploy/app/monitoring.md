# Observability

[Previous: Service Deployment](services.md) | [Back to setup](setup.md)

## 1. Create the Alloy files on the application server

```bash
sudo mkdir -p /srv/rust-api/observability/alloy-app
sudo nano /srv/rust-api/observability/alloy-app/docker-compose.yml
sudo nano /srv/rust-api/observability/alloy-app/config.alloy
```

Use these files as references:
- [docker-compose.yml](../../../deploy/app/alloy/docker-compose.yml)
- [config.alloy](../../../deploy/app/alloy/config.alloy)

Replace:
- `__HOST_LABEL__` -> `rust-api-app`
- `__LOKI_PUSH_URL__` -> the Loki push URL reachable from the application server
- `__PROMETHEUS_REMOTE_WRITE_URL__` -> the Prometheus remote write URL reachable from the application server

Recommended values when the observability tunnel is already in place:

```text
__LOKI_PUSH_URL__=http://__OBSERVABILITY_SERVER_IP__:3100/loki/api/v1/push
__PROMETHEUS_REMOTE_WRITE_URL__=http://__OBSERVABILITY_SERVER_IP__:9090/api/v1/write
```

## 2. Start Alloy

```bash
cd /srv/rust-api/observability/alloy-app
docker compose up -d
docker compose ps
docker compose logs alloy --tail 50
```

## 3. Add the dashboards and datasource on the central Grafana stack

The application server is expected to send:
- host metrics with `server_role="app"`
- Docker logs with `server_role="app"`
- Nginx logs with `server_role="app"`
- journal logs with `server_role="app"`

Add the Rust API PostgreSQL datasource and dashboards from the deployment assets already used by the data-side guide:
- [../data/monitoring.md](../data/monitoring.md)

That central stack must include at least:
- the PostgreSQL datasource for `rust_api`
- the application host dashboard
- the application audit dashboard
- the PostgreSQL and Redis logs dashboard

## 4. Validate

On the application server:

```bash
cd /srv/rust-api/observability/alloy-app
docker compose logs alloy --tail 100
```

On the central Grafana stack, validate:
- metrics for `host="rust-api-app"`
- Docker logs for `host="rust-api-app"`
- Nginx logs for `host="rust-api-app"`
- audit queries against the PostgreSQL datasource

Useful queries:

```text
node_cpu_seconds_total{host="rust-api-app",server_role="app"}
```

```text
{host="rust-api-app",job="docker",server_role="app"}
```

```text
{host="rust-api-app",job="nginx",server_role="app"}
```
