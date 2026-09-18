# Integration Guide

[Index](../README.md)

How applications and services use auth-api: which flow to pick, how to verify
its tokens, and how to follow account changes. The routes are listed in
[routes](../api/routes.md); the contract is [openapi.yaml](../api/openapi.yaml).

## 1. Pick a flow

| You build | Use | Client registration |
|-----------|-----|---------------------|
| The frontend that ships with auth-api (sign-up, sign-in, account pages) | The first-party routes: `/auth/login`, `/auth/passkeys/*`, `/auth/magic-link`, `/auth/external/*`, `/auth/refresh` | None |
| Another web application, or a single-page application | Authorization code with PKCE (`/oauth/authorize`, `/oauth/token`) | Public (SPA) or confidential (server-side) |
| A desktop or command-line application with a browser | Authorization code with PKCE and a loopback redirect | Public, `allows_loopback_redirect` |
| A TV, a device without a browser, a CLI over SSH | Device authorization (`/oauth/device_authorization`) | Public |
| A service calling another service, with no user | Client credentials | Confidential, `allows_client_credentials`, with scopes |
| A user's own scripts | Personal access tokens (`/users/me/tokens`) | None |
| "Sign in with" for a third-party site | OpenID Connect: the code flow with `scope=openid` | Public or confidential |
| An API receiving these tokens | Token verification (section 3) | Confidential only to introspect |

Register clients with `PUT /admin/clients/{client_id}` (or
`auth-api --register-client`): display name, redirect URIs, scopes (the
permissions its tokens may carry, empty for all of the user's), session limit.
`POST /admin/clients/{client_id}/secret` makes it confidential and returns its
secret once.

## 2. Flows

### Authorization code with PKCE

1. Generate a `code_verifier` (43 to 128 characters of `A-Z a-z 0-9 - . _ ~`),
   its `code_challenge` (base64url of its SHA-256), a random `state`, and for
   OpenID Connect a `nonce`.
2. Send the browser to:

   ```text
   https://auth.example.com/oauth/authorize?response_type=code&client_id=invoices-web
     &redirect_uri=https://invoices.example.com/callback&scope=invoices:read%20openid
     &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
     &state=af0ifjsldkj&nonce=n-0S6_WzA2Mj
   ```

   auth-api's frontend signs the user in if needed, shows the consent screen,
   and the browser comes back to the redirect URI with `code` and `state`, or
   with `error`. Check that `state` is the one you sent.
3. Exchange the code, from your server for a confidential client:

   ```bash
   curl -u invoices-web:$CLIENT_SECRET https://auth.example.com/oauth/token \
     -d grant_type=authorization_code -d code=$CODE -d code_verifier=$VERIFIER \
     -d redirect_uri=https://invoices.example.com/callback
   ```

   A public client sends `client_id` in the body instead of the credentials.
   The answer holds `access_token` (15 minutes by default), `refresh_token`,
   `expires_in`, `scope`, and `id_token` when `openid` was granted.
4. Refresh before the access token expires:

   ```bash
   curl -u invoices-web:$CLIENT_SECRET https://auth.example.com/oauth/token \
     -d grant_type=refresh_token -d refresh_token=$REFRESH_TOKEN
   ```

   Each refresh returns a new refresh token; keep only the latest. Presenting a
   replaced one revokes the whole session (two requests within two seconds are
   treated as the same client retrying).

Native applications register a loopback redirect such as
`http://127.0.0.1/callback` and listen on any free port: the redirect
`http://127.0.0.1:53817/callback` is accepted.

### Device authorization

```bash
curl https://auth.example.com/oauth/device_authorization -d client_id=tv-app -d scope=media:read
# {"device_code":"...","user_code":"WDJB-4726","verification_uri":"https://auth.example.com/device",
#  "verification_uri_complete":"https://auth.example.com/device?user_code=WDJB-4726","expires_in":300,"interval":5}
```

Show `user_code` and `verification_uri` (or a QR code of
`verification_uri_complete`), then poll every `interval` seconds:

```bash
curl https://auth.example.com/oauth/token -d client_id=tv-app \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code -d device_code=$DEVICE_CODE
```

`authorization_pending`: keep polling. `slow_down`: add five seconds to the
interval. `access_denied` or `expired_token`: stop. Tokens: done.

### Client credentials

```bash
curl -u billing-worker:$CLIENT_SECRET https://auth.example.com/oauth/token \
  -d grant_type=client_credentials -d scope=invoices:read
```

The token has no refresh token and no user: `client_id` names the client, `sub`
is a UUID derived from it, `sid` is nil. Request a new one when it expires.

### Personal access tokens

A signed-in user creates one with `POST /users/me/tokens` (name, scopes, 1 to
365 days) and copies the `aapat_...` secret, shown once. The script exchanges it
for an access token when it needs one:

```bash
curl https://auth.example.com/auth/personal-access-tokens/exchange \
  -H 'content-type: application/json' -d "{\"token\": \"$AAPAT\"}"
```

### OpenID Connect

Add `openid` (and `profile`, `email` for the matching claims) to the code flow
and a `nonce`. Verify the `id_token` like an access token (section 3) with the
client id as audience, then check its `nonce` and, if you use the access token,
its `at_hash`. `GET /oauth/userinfo` with the access token returns the same
claims. Libraries configure themselves from
`https://auth.example.com/.well-known/openid-configuration`.

## 3. Verifying access tokens

Every resource server:

1. Reads `Authorization: Bearer <token>`.
2. Verifies the ES256 signature with the key of the token's `kid` from
   `https://auth.example.com/.well-known/jwks.json`. Cache the key set; fetch it
   again when a `kid` is unknown, at most once a minute. Accept `ES256` only.
3. Checks `iss` equals auth-api's `APP_PUBLIC_URL`, `aud` contains the
   service's own identifier (listed in auth-api's `JWT_AUDIENCE`), and `exp` and
   `nbf` with a small leeway.
4. Authorizes on `permissions` (`resource:action` names). `roles` are absent
   from tokens restricted to scopes (a client registered with scopes, or a
   request naming them): authorize on permissions.

Ready-made: the Rust crate [`crates/verifier`](../../../crates/verifier/README.md)
(with an axum extractor) and the npm package
[`clients/js/verifier`](../../../clients/js/verifier/README.md) (with an Express
middleware). Any JOSE library does the same with the rules above.

Offline verification cannot see a token revoked before it expires (a logout, a
password change, an administrator ending the sessions). Where that matters,
register the service as a confidential client and call
`POST /oauth/introspect` (both packages do it with a short cache), or keep
`JWT_ACCESS_EXPIRY_SECS` short.

A token's claims:

| Claim | Meaning |
|-------|---------|
| `sub` | User id (UUID), or the client's derived id for client credentials |
| `sid` | Session id; nil for client credentials |
| `jti` | Token id, for revocation and introspection caches |
| `iss`, `aud`, `iat`, `nbf`, `exp` | Standard |
| `roles` | Role names; absent from scoped and client credentials tokens |
| `permissions` | Permission names, intersected with the consented scopes |
| `client_id` | For client credentials tokens |

## 4. Following account changes

Services keeping data about users must follow `user.deleted` at least, to erase
it. Two channels carry the same events, recorded with the change that caused
them and delivered at least once:

- **NATS JetStream**: stream `AUTH_EVENTS`, subjects `events.auth.user.*`,
  kept 30 days. Create a durable consumer and acknowledge after processing.
- **Webhooks**: signed HTTPS calls, see the [webhook guide](webhooks.md).

Each event is `{ "user_id", "event_id", "occurred_at" }` (plus `"event"` in
webhooks): `user.created`, `user.email_verified`, `user.email_changed`,
`user.password_changed`, `user.sessions_revoked`, `user.suspended`,
`user.reactivated`, `user.deleted`. Events carry no personal data: read the
account from the API when needed. Deduplicate on `event_id`; order with
`occurred_at`.

## 5. Errors

- First-party and account routes answer `{ "code", "message" }` with a stable
  `code` to branch on (`invalid_credentials`, `reauthentication_required`,
  `two_factor_required`, ...).
- `/oauth/token`, `/oauth/device_authorization`, `/oauth/introspect` and
  `/oauth/revoke` answer RFC 6749 errors: `{ "error", "error_description" }`.
- `429` carries `Retry-After`: wait that long. `503` means a dependency is
  unavailable: retry with backoff.
- Sensitive account actions need a recent re-authentication: on
  `403 reauthentication_required`, ask for the password, call
  `POST /users/me/reauth`, then repeat the request.

## 6. Checklist

- [ ] The service's audience is listed in auth-api's `JWT_AUDIENCE`.
- [ ] Tokens are verified with `ES256` only, and `iss` and `aud` are checked.
- [ ] Refresh tokens and client secrets are stored server-side, never in the
      browser's local storage.
- [ ] `state` (and `nonce` for OpenID Connect) is checked on every redirect.
- [ ] The service erases a user's data on `user.deleted`.
- [ ] Retries honour `Retry-After`, and `503` is retried with backoff.
