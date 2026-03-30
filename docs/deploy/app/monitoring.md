# Application Monitoring

[Previous: Nginx](nginx.md) | [Back to setup](setup.md)

## 1. Create the Alloy files

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

## 2. Start Alloy

```bash
cd /srv/rust-api/observability/alloy-app
docker compose up -d
docker compose ps
docker compose logs alloy --tail 50
```

The Grafana datasource and dashboards are added from [../data/monitoring.md](../data/monitoring.md).
