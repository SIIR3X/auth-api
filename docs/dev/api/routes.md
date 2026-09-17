# API Routes

The machine-readable contract is [`openapi.yaml`](openapi.yaml). This page is
the overview.

## Legend

| Auth | Meaning |
|------|---------|
| - | No authentication |
| JWT | Access token in `Authorization: Bearer` |
| Admin | Access token carrying the named permission, still granted in the database, from an account with a second factor |
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
| GET | `/health`, `/live` | - | None (liveness) |
| GET | `/ready` | - | None (readiness: database, Redis, NATS) |
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
| POST | `/auth/verify-email/resend` | - | Strict |
| POST | `/auth/login` | - | Strict |
| POST | `/auth/two-factor/complete` | pre-auth token | Strict |
| POST | `/auth/two-factor/email/complete` | pre-auth token | Strict |
| POST | `/auth/two-factor/email/resend` | pre-auth token | Strict |
| POST | `/auth/two-factor/recovery` | pre-auth token | Strict |
| POST | `/auth/refresh` | refresh token | Strict |
| POST | `/auth/logout` | JWT | General |
| POST | `/auth/magic-link` | - | Strict |
| POST | `/auth/magic-link/complete` | sign-in link | Strict |
| POST | `/auth/personal-access-tokens/exchange` | personal access token | Strict |
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
- `magic-link` (when `MAGIC_LINK_ENABLED`) mails a sign-in link valid 15 minutes
  and once, answering alike for every address; `magic-link/complete` answers
  like `login`, including the two-factor challenge. A new link replaces the
  previous one.

## Client applications (OAuth 2.1)

Standard endpoints: RFC 6749, 7636 (PKCE), 8252 (native apps), 8414 (metadata)
and 8628 (device authorization). Token and device authorization requests are
`application/x-www-form-urlencoded`; their errors are
`{ "error", "error_description" }` with `Cache-Control: no-store`.

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/.well-known/oauth-authorization-server` | - | General |
| GET | `/oauth/authorize` | - | Strict |
| GET | `/oauth/authorization-requests/{id}` | JWT | Strict |
| POST | `/oauth/authorization-requests/{id}/approve` | JWT (+ reauth for non-primary clients) | Strict |
| POST | `/oauth/authorization-requests/{id}/deny` | JWT | Strict |
| POST | `/oauth/token` | client | Strict |
| POST | `/oauth/device_authorization` | client | Strict |
| POST | `/oauth/introspect` | confidential client | Strict |
| POST | `/oauth/revoke` | client | Strict |
| GET | `/oauth/device/{user_code}` | JWT | Strict |
| POST | `/oauth/device/verify` | JWT | Strict |

**Client authentication.** A public client sends `client_id`. A confidential
client (one given a secret with `POST /admin/clients/{client_id}/secret`)
authenticates with `Authorization: Basic` (`client_secret_basic`) or
`client_id` and `client_secret` in the body (`client_secret_post`), never both;
a failure answers `401 invalid_client`.

**Authorization code.** `GET /oauth/authorize` takes `response_type=code`,
`client_id`, `redirect_uri` (optional when the client has exactly one),
`code_challenge` with `code_challenge_method=S256`, `scope` and `state`.

- An unknown client or an unregistered redirect URI answers directly with an
  error, never through the redirect.
- Other errors (`unsupported_response_type`, `invalid_request`,
  `invalid_scope`) go back to the redirect URI with `error` and `state`.
- A valid request is stored for 10 minutes and the browser is sent (`303`) to
  `OAUTH_CONSENT_URI?request_id=...`. The consent page reads it with
  `GET /oauth/authorization-requests/{id}` (client, scopes, session limits,
  whether a re-authentication is needed) and approves or denies it; the answer
  holds `redirect_to`, the client redirect carrying `code` and `state`, or
  `error=access_denied`. A request is decided once.
- The redirect URI must be registered exactly, or be a loopback
  `http://127.0.0.1:{port}/path` / `http://[::1]:{port}/path` for a registered
  path when the client allows it. `localhost` is refused.
- The client redeems the code at `POST /oauth/token` with
  `grant_type=authorization_code`, `code`, `code_verifier` and `redirect_uri`.
  A code is single use: a failed redemption burns it, and a replayed code
  revokes the session it produced.

**Scopes.** `scope` lists permissions. A client registered with scopes may ask
for a subset of them; without `scope`, its registered scopes apply. Tokens carry
the consented scopes the user holds, on issue and on every refresh, and no
roles. The token response echoes `scope` when the session is restricted.

**Refresh.** A client refreshes its sessions at `POST /oauth/token` with
`grant_type=refresh_token`; `/auth/refresh` refuses them. The session must
belong to the authenticated client.

**Introspection (RFC 7662).** A confidential client (a resource server)
posts `token` and learns `active`, and for an active token its `token_type`
(`access_token`, `refresh_token`, `personal_access_token`), `scope`,
`client_id`, `sub`, `exp`, `iat` and, for access tokens, `iss`, `aud` and `jti`.
Anything unknown, expired or revoked is `{ "active": false }`.

**Revocation (RFC 7009).** A client posts one of its tokens. A refresh token
ends its session and every access token of it; an access token stops working
until it expires. Unknown tokens and tokens of other clients get the same `200`
and are left alone.

**Device authorization.** `POST /oauth/device_authorization` (`client_id`,
`scope`) answers `device_code`, `user_code`, `verification_uri`,
`verification_uri_complete`, `expires_in` and `interval`. The device polls
`POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`:
`authorization_pending`, `slow_down` when polling faster than the interval,
`access_denied`, `expired_token`, or tokens. The signed-in user previews the
request (`GET /oauth/device/{user_code}`) and approves or denies it
(`POST /oauth/device/verify`). An approval is collected once, by the client that
started the flow; account status and the client's session limit are checked
when tokens are issued (`invalid_grant` otherwise).

## Account

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/users/me` | JWT | General |
| GET | `/users/me/audit` | JWT | General |
| POST | `/users/me/reauth` | JWT | Strict |
| GET | `/users/me/export` | JWT + reauth (recent only) | Strict |
| GET | `/users/me/tokens` | JWT | General |
| POST | `/users/me/tokens` | JWT + reauth (recent only) | General |
| DELETE | `/users/me/tokens/{id}` | JWT | General |
| PATCH | `/users/me/username` | JWT + reauth | General |
| PATCH | `/users/me/password` | JWT + reauth | General |
| PATCH | `/users/me/locale` | JWT | General |
| DELETE | `/users/me` | JWT + reauth | General |

`/users/me/audit?limit=&cursor=` returns the caller's own security history,
newest first: `{ "entries": [...], "next_cursor" }`. Pass `next_cursor` back as
`cursor`; it is absent on the last page. `limit` is clamped to 1-200.

Personal access tokens (`aapat_...`) are shown once, at creation. Their
exchange returns `{ "access_token", "token_type": "Bearer", "expires_in" }`: an
access token carrying the token's scopes (intersected with the account's
current permissions) and no roles. A token lives in a session of type
`personal_access_token`: revoking either ends both.

`/users/me/export` downloads everything stored about the account as one JSON
document (`account-data.json`): profile, roles, sessions, second factors,
recovery code counts, known devices, client quotas, sign-in attempts and the
security history. No password hash, secret or token digest is included. As a
`GET` it takes no body: re-authenticate with `POST /users/me/reauth` first.

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

## Administration

| Method | Route | Auth | Rate limit |
|--------|-------|------|------------|
| GET | `/admin/users` | Admin `users:read` | General |
| GET | `/admin/users/{id}` | Admin `users:read` | General |
| POST | `/admin/users/{id}/suspend` | Admin `users:manage` | General |
| POST | `/admin/users/{id}/reactivate` | Admin `users:manage` | General |
| POST | `/admin/users/{id}/unlock` | Admin `users:manage` | General |
| DELETE | `/admin/users/{id}/sessions` | Admin `users:manage` | General |
| POST | `/admin/users/{id}/password-reset` | Admin `users:manage` | General |
| DELETE | `/admin/users/{id}` | Admin `users:manage` + reauth | General |
| POST | `/admin/users/{id}/roles` | Admin `roles:manage` + reauth | General |
| DELETE | `/admin/users/{id}/roles/{name}` | Admin `roles:manage` | General |
| GET | `/admin/permissions` | Admin `roles:manage` | General |
| GET | `/admin/roles` | Admin `roles:manage` | General |
| POST | `/admin/roles` | Admin `roles:manage` + reauth | General |
| PUT | `/admin/roles/{name}/permissions` | Admin `roles:manage` + reauth | General |
| DELETE | `/admin/roles/{name}` | Admin `roles:manage` | General |
| GET | `/admin/clients` | Admin `clients:manage` | General |
| PUT | `/admin/clients/{client_id}` | Admin `clients:manage` + reauth | General |
| DELETE | `/admin/clients/{client_id}` | Admin `clients:manage` | General |
| POST | `/admin/clients/{client_id}/secret` | Admin `clients:manage` + reauth | General |
| DELETE | `/admin/clients/{client_id}/secret` | Admin `clients:manage` | General |
| GET | `/admin/audit` | Admin `audit:read` | General |

`GET /admin/users` takes `query` (start of the address or username), `status`,
`limit` and `cursor`, and pages newest first. Administrators cannot suspend,
sign out, reset or delete their own account here; they use `/users/me`.

A change to roles that would leave no account with `roles:manage` answers
`409 last_administrator`; the default role cannot be deleted
(`409 default_role`). Access tokens carry the permissions of their issuance
until refreshed; `/admin` routes read them from the database on every request.
Webhooks (`webhooks:manage`): `GET`/`POST /admin/webhooks`,
`PUT`/`DELETE /admin/webhooks/{id}`, `POST /admin/webhooks/{id}/secret`,
`GET /admin/webhooks/{id}/deliveries` and
`POST /admin/webhooks/{id}/deliveries/{delivery_id}/retry`. See the
[webhook guide](../guides/webhooks.md).

`GET /admin/audit` takes `user_id`, `action`, `limit` and `cursor`.
