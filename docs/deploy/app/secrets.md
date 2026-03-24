# Application Server Secrets

This document lists the secrets used by the application server.

In this project, application secrets are not stored in `runtime.env`.
They are stored locally in `pass` and exported before starting the service.

See:
- [pass-store.md](pass-store.md)

## Critical Secrets

| Secret | Purpose | Impact if exposed |
| --- | --- | --- |
| `DATABASE_URL` | Connects the application to PostgreSQL | Database compromise risk |
| `REDIS_URL` | Connects the application to Redis | Session, rate-limit, or cache abuse |
| `JWT_SECRET` | Signs and validates tokens | Token forgery |
| `ENCRYPTION_KEY` | Encrypts sensitive application data | Secret disclosure risk |

## High-Sensitivity Secrets

| Secret | Purpose | Impact if exposed |
| --- | --- | --- |
| `SMTP_USERNAME` | Authenticates to the mail provider | Mail provider abuse |
| `SMTP_PASSWORD` | Authenticates to the mail provider | Mail provider abuse |
| `CAPTCHA_SECRET` | Verifies CAPTCHA responses | CAPTCHA validation abuse |

## Rotation Secrets

| Secret | Purpose |
| --- | --- |
| `JWT_PREVIOUS_SECRET` | Supports JWT secret rotation |
| `PREVIOUS_ENCRYPTION_KEY` | Supports encryption key rotation |
