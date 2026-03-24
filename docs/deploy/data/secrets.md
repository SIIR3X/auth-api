# Data Server Secrets

This document lists the secrets used on the data server.

In this project, data server secrets are not stored in `runtime.env`.
They are stored locally in `pass` and exported before starting the services.

See:
- [pass-store.md](pass-store.md)

## Required Secrets

| Secret | Purpose | Impact if exposed |
| --- | --- | --- |
| `POSTGRES_DB` | PostgreSQL application database name | Helps target the correct database |
| `POSTGRES_USER` | PostgreSQL container initialization user | Administrative misuse risk |
| `POSTGRES_PASSWORD` | PostgreSQL password | Database compromise risk |
| `REDIS_PASSWORD` | Redis password | Cache or session abuse |
