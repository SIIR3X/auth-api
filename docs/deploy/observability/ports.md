# Observability Ports

This document lists the ports used by the observability stack.

In the current deployment model, the observability stack runs on the data server and typically hosts:
- Grafana
- Loki
- Alloy

## Required Ports

| Port | Protocol | Service | Exposure |
| --- | --- | --- | --- |
| `3001` | TCP | Grafana | Private network, VPN, or reverse proxy only |
| `3100` | TCP | Loki | Private network only |
| `12345` | TCP | Alloy debug UI | Localhost or trusted private network only |

## Recommended Exposure Model

| Service | Recommendation |
| --- | --- |
| Grafana | Keep private unless you intentionally publish it through a secured reverse proxy |
| Loki | Do not expose publicly |
| Alloy | Keep local or private only; it is an operational debug endpoint |

## Notes

- If Grafana runs on the same data server as PostgreSQL, Grafana can query PostgreSQL through `127.0.0.1:5432`.
- If the application server later ships its logs to Loki, only the Loki ingestion endpoint should be reachable from that server over the private network.
- The observability stack should not add any new public Internet-facing service by default.
