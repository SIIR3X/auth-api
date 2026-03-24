# Observability Environment Variables

This document lists the non-sensitive environment variables used by the observability stack.

Sensitive values must not be written into the runtime file.
They must be stored in `pass` and exported before starting the services.

See:
- [pass-store.md](pass-store.md)
- [secrets.md](secrets.md)

## Runtime File

The observability stack uses a local runtime file such as:

```text
/srv/rust-api-data/env/observability-runtime.env
```

## Non-Sensitive Variables

| Variable | Purpose |
| --- | --- |
| `LOKI_IMAGE` | Loki image reference |
| `LOKI_BIND_IP` | Loki bind address on the host |
| `LOKI_PORT` | Loki host port |
| `LOKI_DATA_DIR` | Loki data directory on the host |
| `LOKI_CONFIG_FILE` | Loki configuration file path on the host |
| `GRAFANA_IMAGE` | Grafana image reference |
| `GRAFANA_BIND_IP` | Grafana bind address on the host |
| `GRAFANA_PORT` | Grafana host port |
| `GRAFANA_ADMIN_USER` | Grafana admin username |
| `GRAFANA_ROOT_URL` | Grafana public root URL |
| `GRAFANA_ALLOW_SIGN_UP` | Controls local self-sign-up in Grafana |
| `GRAFANA_DATA_DIR` | Grafana data directory on the host |
| `GRAFANA_PROVISIONING_DIR` | Grafana provisioning directory on the host |
| `ALLOY_IMAGE` | Alloy image reference |
| `ALLOY_BIND_IP` | Alloy debug UI bind address on the host |
| `ALLOY_PORT` | Alloy debug UI host port |
| `ALLOY_DATA_DIR` | Alloy storage directory on the host |
| `ALLOY_CONFIG_FILE` | Alloy configuration file path on the host |

## Secrets

The following value should be stored in `pass`:

| Secret | Purpose |
| --- | --- |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin password |

Recommended path:

```text
rust-api/observability/GRAFANA_ADMIN_PASSWORD
```
