# Application Server Setup

## Prerequisites

Already handled outside this repository:
- base OS hardening
- Docker and Docker Compose
- `pass`
- private connectivity to the data services
- an existing central Grafana, Loki, and Prometheus stack
- a working OVH DNS API configuration for Certbot

## Order

1. Nginx and HTTPS: [nginx.md](nginx.md)
2. Service deployment: [services.md](services.md)
3. Observability: [monitoring.md](monitoring.md)
