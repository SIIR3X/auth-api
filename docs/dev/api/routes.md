# API Routes

## Legend

| Auth | Meaning |
|------|---------|
| - | No authentication required |
| JWT | Valid access token required |

| Rate limit | Meaning |
|------------|---------|
| General | Shared bucket - `RATE_LIMIT_RPM` requests/min per IP |
| Auth | Strict bucket - `RATE_LIMIT_AUTH_RPM` requests/min per IP |

## Discovery & Health

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/health` | - | General |
| GET | `/.well-known/jwks.json` | - | General |

The JWKS endpoint publishes the ES256 public key(s) (current + previous during
a rotation window) and is served with `cache-control: public, max-age=300` so
downstream verifiers can cache it.

Prometheus metrics (`GET /metrics`) are **not** served on the public port:
they live on a separate internal listener (`METRICS_PORT`, default 9464),
published on loopback only and never routed through the reverse proxy.

## Authentication

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/auth/register` | - | Auth |
| POST | `/auth/login` | - | Auth |
| POST | `/auth/refresh` | - | Auth |
| POST | `/auth/logout` | JWT | General |
| POST | `/auth/verify-email` | - | Auth |
| POST | `/auth/forgot-password` | - | Auth |
| POST | `/auth/reset-password` | - | Auth |
| POST | `/auth/two-factor/complete` | - | Auth |
| POST | `/auth/two-factor/recovery` | - | Auth |
| POST | `/auth/two-factor/email/complete` | - | Auth |
| POST | `/auth/two-factor/email/resend` | - | Auth |

## Device authorization (RFC 8628)

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/auth/device` | - | Auth |
| POST | `/auth/device/token` | - | Auth |
| POST | `/auth/device/verify` | JWT | Auth |

`/auth/device` starts the flow (returns `device_code` + `user_code`),
`/auth/device/token` is polled by the device until approval, and
`/auth/device/verify` is called by the already-authenticated user to approve
or deny the `user_code`. Registered clients and per-user device session
quotas are enforced (`registered_clients`, `user_client_quotas`).

## Profile

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/users/me` | JWT | General |
| PATCH | `/users/me/username` | JWT | General |
| PATCH | `/users/me/password` | JWT | General |
| PATCH | `/users/me/locale` | JWT | General |
| DELETE | `/users/me` | JWT | General |
| POST | `/users/me/reauth` | JWT | Auth |

## Email change

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/users/me/email/start` | JWT | Auth |
| POST | `/users/me/email/verify-current` | JWT | Auth |
| POST | `/users/me/email/submit` | JWT | Auth |
| POST | `/users/me/email/confirm` | JWT | Auth |

## Sessions

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/users/me/sessions` | JWT | General |
| DELETE | `/users/me/sessions` | JWT | General |
| DELETE | `/users/me/sessions/{id}` | JWT | General |

## Two-factor - TOTP

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/users/me/two-factor/totp/setup` | JWT | General |
| POST | `/users/me/two-factor/totp/{id}/verify` | JWT | General |
| DELETE | `/users/me/two-factor/totp/{id}` | JWT | General |
| POST | `/users/me/two-factor/recovery-codes` | JWT | General |
| POST | `/users/me/two-factor/recovery-codes/use` | JWT | General |

## Two-factor - Email OTP

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/users/me/two-factor/email/setup` | JWT | General |
| POST | `/users/me/two-factor/email/send` | JWT | General |
| POST | `/users/me/two-factor/email/{id}/verify` | JWT | General |
| DELETE | `/users/me/two-factor/email/{id}` | JWT | General |
