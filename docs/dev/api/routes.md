# API Routes

The machine-readable contract is [`openapi.yaml`](openapi.yaml). This page is
the overview.

## Legend

| Auth | Meaning |
|------|---------|
| - | No authentication |
| JWT | Access token in `Authorization: Bearer` |
| JWT + reauth | Access token, and a recent re-authentication: `POST /users/me/reauth` within `SENSITIVE_ACTION_REAUTH_SECS`, or `current_password` in the body. A fresh sign-in does not count |

| Rate limit | Meaning |
|------------|---------|
| General | `RATE_LIMIT_RPM` per client per minute |
| Strict | Counts against the general budget **and** `RATE_LIMIT_AUTH_RPM` |

Each request passes one limiter, which checks all of its buckets in a single
Redis call; a refused request consumes nothing. A `429` carries `Retry-After`.

Timestamps are Unix seconds. Errors are `{"code": "...", "message": "..."}`
with a stable `code`.

## Discovery

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/health` | - | General |
| GET | `/.well-known/jwks.json` | - | General |

The JWKS lists the current signing key, and the previous one during a
rotation, with `cache-control: public, max-age=300`.

Prometheus metrics are not on this listener: `METRICS_PORT` (default 9464),
loopback only.

## Sign-in

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/auth/register` | - | Strict |
| POST | `/auth/verify-email` | - | Strict |
| POST | `/auth/login` | - | Strict |
| POST | `/auth/two-factor/complete` | pre-auth token | Strict |
| POST | `/auth/two-factor/email/complete` | pre-auth token | Strict |
| POST | `/auth/two-factor/email/resend` | pre-auth token | Strict |
| POST | `/auth/two-factor/recovery` | pre-auth token | Strict |
| POST | `/auth/refresh` | refresh token | Strict |
| POST | `/auth/logout` | JWT | General |
| POST | `/auth/forgot-password` | - | Strict |
| POST | `/auth/reset-password` | - | Strict |

- `register` answers `202` the same way whether or not the address is taken;
  the owner of a taken address gets an email instead.
- `login` answers tokens, or `{ "two_factor_required": ..., "pre_auth_token", "method" }`.
  Each pre-auth token is bound to the method it was issued for.
- `refresh` rotates the refresh token. Presenting a rotated token again revokes
  the whole session family, except within 2 seconds of the rotation (two tabs,
  a retried request).
- Logout stays outside the strict bucket so an exhausted budget never prevents
  ending a session.

## Client applications

### Device authorization (RFC 8628)

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/auth/device` | - | Strict |
| POST | `/auth/device/token` | - | Strict |
| GET | `/auth/device/{user_code}` | JWT | Strict |
| POST | `/auth/device/verify` | JWT | Strict |

The device starts a flow (`client_id` optional: the primary client) and polls
`token`; polling faster than the interval returns `slow_down`. The signed-in
user previews the request, then approves or denies it. An approval is collected
once; account status and the client's session limit are checked when tokens are
issued.

### Authorization code with PKCE (RFC 7636, RFC 8252)

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/auth/authorize/describe` | JWT | Strict |
| POST | `/auth/authorize` | JWT (+ reauth for non-primary clients) | Strict |
| POST | `/auth/authorize/token` | code + verifier | Strict |

- `S256` only; the verifier follows RFC 7636 (43-128 characters).
- The redirect URI must be registered exactly, or be a loopback
  `http://127.0.0.1:{port}/path` / `http://[::1]:{port}/path` for a registered
  path when the client allows it. `localhost` is refused.
- A code is single use: a failed redemption burns it, and a replayed code
  revokes the session it produced.
- Tokens carry only the permissions consented for the client, on issue and
  on every refresh.

## Account

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/users/me` | JWT | General |
| GET | `/users/me/audit` | JWT | General |
| POST | `/users/me/reauth` | JWT | Strict |
| PATCH | `/users/me/username` | JWT + reauth | General |
| PATCH | `/users/me/password` | JWT + reauth | General |
| PATCH | `/users/me/locale` | JWT | General |
| DELETE | `/users/me` | JWT + reauth | General |

`/users/me/audit?limit=&cursor=` returns the caller's own security history,
newest first: `{ "entries": [...], "next_cursor" }`. Pass `next_cursor` back as
`cursor`; it is absent on the last page. `limit` is clamped to 1-200.

## Email change

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| POST | `/users/me/email/start` | JWT + reauth | Strict |
| POST | `/users/me/email/verify-current` | JWT | Strict |
| POST | `/users/me/email/submit` | JWT | Strict |
| POST | `/users/me/email/confirm` | JWT | Strict |

A code is sent to the current address, then to the new one. Confirming revokes
every other session and notifies the previous address.

## Sessions

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/users/me/sessions` | JWT | General |
| DELETE | `/users/me/sessions` | JWT + reauth | General |
| DELETE | `/users/me/sessions/{id}` | JWT + reauth | General |

## Two-factor

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/users/me/two-factor` | JWT | General |
| POST | `/users/me/two-factor/totp/setup` | JWT + reauth | General |
| POST | `/users/me/two-factor/totp/{id}/verify` | JWT | General |
| DELETE | `/users/me/two-factor/totp/{id}` | JWT + reauth | General |
| POST | `/users/me/two-factor/email/setup` | JWT + reauth | General |
| POST | `/users/me/two-factor/email/send` | JWT | General |
| POST | `/users/me/two-factor/email/{id}/verify` | JWT | General |
| DELETE | `/users/me/two-factor/email/{id}` | JWT + reauth | General |
| POST | `/users/me/two-factor/recovery-codes` | JWT + reauth | General |
| POST | `/users/me/two-factor/recovery-codes/use` | JWT | General |

`GET /users/me/two-factor` lists the configured methods (with the ids the other
routes need) and `recovery_codes_remaining`, the unused and unexpired codes.
Recovery codes are shown once, when a method is first verified or when they
are regenerated.
