# Security Model

What the service protects, against whom, and how. Each control below is pinned
by tests (`tests/http/`) so that a regression fails the build.

## Assets and adversaries

| Asset | Worst outcome |
|-------|---------------|
| Passwords | Offline cracking after a database leak |
| Sessions and tokens | Account takeover without the password |
| Second factors | Bypass by someone who holds the password |
| Account existence | Enumeration for phishing or credential stuffing |
| Security history, addresses | Personal data exposure |

Adversaries considered: an anonymous attacker on the network, an attacker
holding a leaked password, an attacker holding a stolen access or refresh
token, a malicious client application, and a read-only database leak.
An attacker with code execution on the host, or with the `ENCRYPTION_KEY` and
the database together, is out of scope.

## Credentials

- **Argon2id**, 64 MiB and 3 iterations by default; hashes run on a bounded
  pool (`ARGON2_MAX_CONCURRENCY`) so a login storm queues instead of exhausting
  memory.
- **No account oracle.** An unknown identifier still pays a full hash against a
  decoy. A locked account answers the same whatever the password. Registration
  answers `202` identically whether or not the address is taken (the owner is
  emailed instead). Forgot-password takes a constant minimum time and answers
  identically.
- **Lockout** after `LOCKOUT_THRESHOLD` consecutive wrong passwords. Failed
  second factors never count: whoever fails a second factor already holds the
  password, and letting them lock the account would let them shut the owner out.
- **Brute force** is bounded per identifier and per address (database counters),
  across identifiers from one address (HyperLogLog), and per submitted token.
  Budgets are consumed atomically in Redis before the guarded check runs, so
  parallel requests cannot all pass; they fail closed when Redis is down.

## Sessions and tokens

- **Access tokens** are ES256 JWTs (15 minutes) carrying `iss`, `aud`, `sid` and
  `jti`. Every authenticated request checks, in one Redis round trip, that the
  `jti` was not revoked by a logout and that the session is still active. A
  Redis failure refuses the request: revocation cannot be proven.
- **Refresh tokens** are opaque, stored as SHA-256 digests, and rotated on every
  use. Presenting a rotated token again revokes the whole session family;
  within 2 seconds of the rotation it is treated as a concurrent refresh from
  the same client (two tabs) and refused without revocation.
- **Absolute lifetime.** A sign-in ends after `JWT_MAX_SESSION_LIFETIME_SECS`
  however often it is refreshed. `JWT_STRICT_SESSION_BINDING` refuses a refresh
  from another address.
- **Sensitive actions require a recent re-authentication**: changing the
  password, username or email, deleting the account, revoking sessions, and
  adding or removing a second factor. A fresh sign-in does not count - a stolen
  refresh token or an approved device must not change the credentials.

## Second factors

- A pre-auth token (5 minutes) is bound to the method it was issued for: a TOTP
  challenge cannot be completed with an email code or vice versa.
- TOTP codes are accepted once (durable replay table), with per-challenge and
  per-account failure budgets. Email codes and recovery codes have their own
  budgets.
- Adding or removing a method notifies the account's address. Removing the last
  method deletes the recovery codes; removing a primary method promotes another.
- TOTP secrets are encrypted with AES-256-GCM. Ciphertexts name their key, so
  the key can be rotated without downtime and the rotation can be resumed.

## Client applications

- Only registered clients can obtain sessions through the device or
  authorization code flows.
- **Device flow (RFC 8628):** user codes are reserved atomically, polling is
  paced, an approval is collected exactly once, and account status and session
  limits are rechecked when tokens are issued.
- **Authorization code with PKCE:** S256 only, exact redirect URIs (loopback on
  any port only for a registered path, never `localhost`), single-use codes
  consumed atomically, a replayed code revokes its session. Consenting to a
  third-party client requires a re-authentication.
- **Scopes:** a client's tokens carry only the consented permissions, re-derived
  from the user's current permissions on every refresh, and no roles.

## Data

- Every token, code and refresh token is stored as a digest.
- The audit log is append-only (enforced by a trigger) and holds no personal
  data such as addresses in its metadata. Users read their own history through
  `GET /users/me/audit`.
- An email change is confirmed on both addresses, revokes the other sessions,
  and notifies the previous address.
- Account deletion publishes `user.deleted` with a JetStream acknowledgement
  before the row is deleted, so downstream erasure cannot be lost.

## Network edge

- Client addresses come from forwarding headers only when the direct peer is a
  trusted proxy (`TRUSTED_PROXY_CIDRS`); IPv6 clients are limited per `/64`.
- Rate limits: a sliding-window estimate per client, one script per request,
  fail closed in production.
- Request bodies are capped at 64 KB and handlers at 30 seconds. Responses carry
  HSTS, CSP `default-src 'none'`, `nosniff`, `DENY` framing and `no-store`.
- Logs record route templates, never raw paths carrying codes. Metrics are served
  on a loopback-only listener.

## Configuration

Production refuses to start with a configuration that disables a control: HTTP
public or frontend URLs, no trusted proxy, committed development keys, a
wildcard CORS origin, fail-open rate limiting or CAPTCHA, and more. The full
list is in [Configuration](guides/configuration.md#production-checks).

## Known limits

- An administrative revocation outside the API (a direct database update) takes
  effect within the 5-second session cache.
- Email codes are 6 digits; their strength is the attempt budgets and short
  lifetime, not their entropy.
- Outside production, rate limiting and CAPTCHA fail open by default.
- Anyone holding both `ENCRYPTION_KEY` and a database dump can read TOTP secrets.
