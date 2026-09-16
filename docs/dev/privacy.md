# Personal Data

[Index](README.md)

What auth-api stores about people, why, for how long, and what happens when an
account is deleted. Durations are the defaults; the variables are in the
[configuration guide](guides/configuration.md). The operator of a deployment is
the controller: this document is the technical basis of its record of
processing, not a legal notice.

## Register

| Data | Where | Purpose | Kept | When the account is deleted |
|------|-------|---------|------|-----------------------------|
| Email address, username, password hash (Argon2id), locale, status, timestamps | `users` | Account and sign-in | Until the account is deleted | Deleted |
| Accounts whose address was never verified | `users` | Letting the owner finish signing up | 7 days (`CLEANUP_UNVERIFIED_ACCOUNT_DAYS`), then deleted and announced like a deletion | - |
| Sessions: client address, user agent, device name | `sessions` | Signed-in devices, revocation, replay detection | Until expiry or revocation, plus 7 days (`CLEANUP_SESSIONS_GRACE_DAYS`) | Deleted |
| Sign-in attempts: identifier typed, client address, user agent of failures | `login_attempts` | Brute-force protection, lockout, security history | 90 days (`CLEANUP_LOGIN_ATTEMPTS_RETENTION_DAYS`) | Deleted, including failed attempts typed with the account's address or username before it existed |
| Security history: action, request id, client address | `audit_log` | Investigating incidents, showing users their own history | 12 months (`AUDIT_LOG_RETENTION_MONTHS`); the client address keeps only its network (/24, /48) after 90 days (`AUDIT_IP_RETENTION_DAYS`) | Kept without identity: the account link and the client addresses are removed |
| Second factors: TOTP secret (encrypted), recovery code hashes, email code hashes | `two_factor_methods`, `recovery_codes`, `email_2fa_codes`, `used_totp_codes` | Second factor | Codes until expiry plus a grace period; methods until removed | Deleted |
| One-time tokens (hashes) and the address being verified | `email_verification_tokens`, `password_reset_tokens` | Verification, reset, email change | 1 day after expiry (`CLEANUP_TOKENS_GRACE_DAYS`) | Deleted |
| Consents to client applications, authorization codes | `user_client_quotas`, `authorization_codes` | Device and authorization code flows | Codes one hour after expiry | Deleted |
| Domain events: the user id only | `event_outbox`, then NATS JetStream | Letting other services follow account changes, erasure included | Outbox: 7 days after delivery; JetStream: 30 days | `user.deleted` tells every consumer to erase its own data |
| Counters and short-lived state: budgets per client address (/64 in IPv6) or per account, pre-authentication and email-change flows | Redis | Rate limiting, abuse budgets, multi-step flows | Minutes to hours (key expiry) | Expire on their own |
| Emails sent (address, content) | The SMTP relay | Verification, reset, security notices | The relay's own retention | Outside auth-api |

The application logs record the route, status, latency and request id of each
request, not the client address. nginx records client addresses in its access
log, rotated by the system's logrotate. Database backups are encrypted and kept
7 days on the server and 30 days offsite (`RETAIN_DAYS`, `OFFSITE_RETAIN_DAYS`);
pgBackRest keeps the last two full backups and the WAL they need
(`repo1-retention-full=2`). A deleted account disappears from backups when the
last backup holding it expires.

## Account deletion

`DELETE /users/me`, after re-authentication, runs one transaction:

1. an `account_deleted` audit entry, without identity in its metadata;
2. a `user.deleted` event in the outbox;
3. the client addresses of the account's audit entries are removed, and its
   sign-in attempts deleted;
4. the account row is deleted, and with it (foreign keys) its sessions, second
   factors, tokens, codes and consents; the audit entries keep their action and
   date, no longer linked to anyone.

The event is published even if NATS is down at the time. Services consuming it
erase their own data about that user id.

## Exercising rights

| Right | How |
|-------|-----|
| Access | `GET /users/me`, `GET /users/me/sessions`, `GET /users/me/audit`, `GET /users/me/two-factor` |
| Rectification | `PATCH /users/me/username`, `PATCH /users/me/locale`, the email change flow (`/users/me/email/*`) |
| Erasure | `DELETE /users/me`; for an account the user cannot reach, an operator deletes it (see the [operations runbook](../deploy/guides/operations.md#5-manual-interventions)) |
| Restriction | An operator suspends the account (`status = 'suspended'`) |

## Minimization choices

- Events carry the user id only: an address or a username stored 30 days in a
  broker every consumer reads would outlive changes and deletions.
- The audit log never holds an address, a username or a token in its metadata.
- Client addresses of the audit log lose their host part after 90 days.
- Failed sign-ins keep the user agent, successful ones do not.
