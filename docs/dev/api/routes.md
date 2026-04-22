# API Routes

## Legend

| Auth | Meaning |
|------|---------|
| — | No authentication required |
| JWT | Valid access token required |

| Rate limit | Meaning |
|------------|---------|
| General | Shared bucket — `RATE_LIMIT_RPM` requests/min per IP |
| Auth | Strict bucket — `RATE_LIMIT_AUTH_RPM` requests/min per IP |

## Authentication

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/auth/register` | — | Auth |
| POST | `/auth/login` | — | Auth |
| POST | `/auth/refresh` | — | Auth |
| POST | `/auth/logout` | JWT | General |
| POST | `/auth/verify-email` | — | Auth |
| POST | `/auth/forgot-password` | — | Auth |
| POST | `/auth/reset-password` | — | Auth |
| POST | `/auth/two-factor/complete` | — | Auth |
| POST | `/auth/two-factor/recovery` | — | Auth |
| POST | `/auth/two-factor/email/complete` | — | Auth |
| POST | `/auth/two-factor/email/resend` | — | Auth |

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

## Two-factor — TOTP

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/users/me/two-factor/totp/setup` | JWT | General |
| POST | `/users/me/two-factor/totp/{id}/verify` | JWT | General |
| DELETE | `/users/me/two-factor/totp/{id}` | JWT | General |
| POST | `/users/me/two-factor/recovery-codes` | JWT | General |
| POST | `/users/me/two-factor/recovery-codes/use` | JWT | General |

## Two-factor — Email OTP

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/users/me/two-factor/email/setup` | JWT | General |
| POST | `/users/me/two-factor/email/send` | JWT | General |
| POST | `/users/me/two-factor/email/{id}/verify` | JWT | General |
| DELETE | `/users/me/two-factor/email/{id}` | JWT | General |
