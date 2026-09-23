# Threat Model

[Index](README.md)

What can go wrong, where, and what stops it. The controls are described in the
[security model](security-model.md) and pinned by the tests of its control
catalog (`SEC-nn` below); this document maps threats to them and records what
is left. Review it when a trust boundary, a flow or a dependency changes, and
at least once a year.

## 1. System and trust boundaries

```text
 [Browser / app / device]      [Resource servers]      [Webhook endpoints]
          |  TB1 (internet, TLS)      | TB1                     ^ TB5 (internet)
          v                           v                         |
      [nginx: TLS, proxy] ------> [auth-api instances] ---------+
                                   |   |   |   |   \
                         TB2 (private network, WireGuard)       TB6 (internet)
                                   |   |   |   |      [Identity providers, Pwned
                          [PostgreSQL] [Redis] [NATS]  Passwords, SMTP relay]
                                               |
                                       TB3 [event consumers]
 [Operators] -- TB4 (SSH, pass, CLI, /admin with a second factor) --> hosts, API
```

| Boundary | Crossed by | Trust |
|----------|------------|-------|
| TB1 | Every client request | None: every input is hostile |
| TB2 | Queries, cache reads, event publishing | Authenticated services on a private network |
| TB3 | Domain events | Consumers are trusted to process them, not to publish |
| TB4 | Administration | Operators with host access; administrators through the API |
| TB5 | Webhook deliveries | Endpoints are registered by administrators, but may be hostile or compromised |
| TB6 | Identity providers, breach checks, mail | Trusted for their one purpose, answers verified where possible |

## 2. Assets

| Asset | Where | Worst outcome |
|-------|-------|---------------|
| Credentials: password hashes, TOTP secrets, passkey keys, recovery codes | PostgreSQL | Offline cracking, second factor bypass |
| Sessions: refresh tokens, access tokens, personal access tokens, client secrets | Clients, digests in PostgreSQL | Account or client takeover |
| Signing keys (`JWT_PRIVATE_KEY`), `ENCRYPTION_KEY`, webhook and client secrets | `pass` on the API host, encrypted columns | Forged tokens for every account |
| Personal data: addresses, usernames, client addresses, histories | PostgreSQL, backups, logs, events | Exposure, profiling |
| Availability of sign-in | The whole stack | Users locked out of every dependent service |

## 3. Threats by STRIDE

### Spoofing

| Threat | Mitigation | Residual |
|--------|------------|----------|
| Credential stuffing and password guessing | Per-address and per-identifier budgets, lockout, backoff, CAPTCHA, breached password refusal (SEC-03, SEC-04, SEC-23, SEC-29) | A slow, distributed attack below every budget; watch `auth_logins_total{outcome="invalid_credentials"}` |
| Account enumeration | Identical answers and timing for unknown and known identifiers (SEC-02) | Timing measured on one machine; network jitter helps, co-located attackers are out of scope. Usernames are public by design: registration and profile changes say when one is taken (accepted risk, section 5) |
| Stolen access token | 15-minute lifetime, revocation checked per request, session binding option (SEC-05, SEC-08) | Resource servers verifying offline accept it until expiry unless they introspect |
| Stolen refresh token | Rotation with replay detection revoking the family; the grace window forgives only the client that rotated (SEC-07, SEC-61) | The thief wins if they refresh first and the owner never does again |
| Forged tokens | ES256 only, `kid` pinned to its key, issuer and audience checked (SEC-05) | Theft of `JWT_PRIVATE_KEY`: rotate the key (runbook section 1) |
| Second factor bypass | Pre-auth token bound to its method, single-use codes, budgets (SEC-10, SEC-11) | Email codes are as strong as the mailbox |
| Phishing of sign-in links | Off by default, short-lived, single-use, never skip the second factor (SEC-33) | Enabled, the mailbox is a first factor |
| Passkey cloning or forged assertions | Signature, origin, relying party, user verification, counters (SEC-40) | Attestation not verified: an authenticator's make is not trusted nor checked |
| Login CSRF with an external identity | Browser binding secret on the outcome, `state`, `nonce` (SEC-41) | A compromised identity provider signs in whoever it vouches for, for linked accounts |
| Account pre-hijacking (registering the victim's address first or second) | A verification link activates the account only with the password of the registration that sent it; a reset takes a pending account back without its factors (SEC-43, SEC-44) | - |
| Account takeover through a provider's email | Identities never matched by email; linking needs the signed-in owner (SEC-41) | - |
| Malicious OAuth client | Registered clients only, exact redirects checked again at approval and redemption, PKCE S256, consent and device approval re-authentication with the scope shown, scopes following the client's registration (SEC-14 to SEC-17, SEC-36, SEC-62) | A user consenting to a malicious registered client |
| Client impersonation at the token endpoint | Confidential client secrets, client-bound refresh and device codes (SEC-36) | Public clients rely on PKCE and redirect registration |

### Tampering

| Threat | Mitigation | Residual |
|--------|------------|----------|
| Audit log alteration | Append-only trigger; only anonymization allowed (SEC-19) | A database superuser |
| SQL injection | Bound parameters only, static guard (SEC-27) | - |
| Tampered webhook delivery | HMAC signature over id, timestamp and body (SEC-35) | Endpoints that do not verify |
| Tampered events on NATS | Publishing restricted by broker credentials | A consumer holding publishing credentials |
| Migration drift | Released migrations checksummed (SEC-27) | - |

### Repudiation

| Threat | Mitigation | Residual |
|--------|------------|----------|
| "I did not do that" | Audit entries for every security-relevant action, with request id and coarsened address; administrative changes name the administrator (SEC-19, SEC-31) | Addresses keep only their network after 90 days by design |

### Information disclosure

| Threat | Mitigation | Residual |
|--------|------------|----------|
| Database leak | Argon2id hashes, digests of every token and code, encrypted TOTP and webhook secrets (SEC-01, SEC-13, SEC-18) | `ENCRYPTION_KEY` and a dump together reveal TOTP and webhook secrets |
| Secrets in logs | Route templates only, redacted configuration (SEC-25) | Third-party log shipping configuration |
| Personal data in events | User id only in events and webhooks | Consumers' own storage |
| SSRF through webhooks | Address checks after resolution, pinned connection, no redirects (SEC-35) | DNS rebinding between check and connect is closed by pinning; an internal service on a public address |
| Data export abuse | Recent re-authentication, own account only (SEC-32) | A session with a known password |
| Introspection as an oracle | Confidential clients only; inactive tokens reveal nothing (SEC-37) | A compromised resource server secret |

### Denial of service

| Threat | Mitigation | Residual |
|--------|------------|----------|
| Login storms exhausting CPU or memory | Bounded Argon2 queue, per-route rate limits, body limit, request timeout (SEC-23, SEC-24) | Volumetric attacks belong to the network edge |
| Redis outage | Fail closed on budgets and revocation checks, `503` (SEC-04, SEC-23) | Sign-in unavailable while Redis is |
| Broker outage | Events wait in the outbox; nothing is refused (SEC-21) | Consumers learn late |
| Mailbox flooding | Per-account and per-address budgets on every email (SEC-02, SEC-33) | - |
| Lockout of a victim by guessing | The lock covers the password only, ends on its own, is restarted by any sign-in or a reset, and is mailed to the owner; recovery links and second-factor budgets count per address (SEC-03, SEC-58) | Anyone knowing the identifier can delay a password sign-in for a lock period; passkeys, sign-in links and external identities still work |
| Webhook endpoint slowing deliveries | Timeouts, leases, bounded attempts | A slow endpoint delays its own deliveries |

### Elevation of privilege

| Threat | Mitigation | Residual |
|--------|------------|----------|
| Session escalation to sensitive actions | Recent re-authentication required; sign-in does not grant it (SEC-09) | - |
| Scope widening by a client | Scopes frozen at consent, re-derived at refresh (SEC-17) | - |
| Administrator account compromise | Second factor required and kept, permission rechecked in the database, re-authentication for every action that grants, withdraws, reopens or destroys, no self-granted permission, owners mailed of changes, last administrator kept (SEC-31, SEC-59) | A compromised administrator who can re-authenticate acts as one |
| Client credentials used as a user | No session: account routes refuse them (SEC-38) | - |
| Personal access token overreach | Scopes limited to the holder's permissions; account, approval and administration routes refuse delegated tokens (SEC-34, SEC-42) | - |

## 4. Supply chain and operations

| Threat | Mitigation |
|--------|------------|
| Vulnerable or malicious dependency | `cargo deny` (advisories, licenses, sources, bans) in CI; lockfile committed |
| Tampered CI | Actions pinned by commit, read-only permissions, secret scanning |
| Tampered release | Checksummed release bundle verified on the host (runbook section 7) |
| Image vulnerabilities | Trivy scan of the image in CI |
| Lost backups | Encrypted backups on and off site, restore drills (runbook section 3) |

## 5. Accepted risks

- An attacker with code execution on an API host reads the signing key and every
  secret; host hardening and access control are the defence, not auth-api.
- Access tokens remain valid for resource servers verifying offline until they
  expire (15 minutes by default) after a revocation.
- The first factor of an account is only as strong as its email address when
  magic links are enabled, and as its identity provider when one is linked.
- Passkey attestation is not verified.
- Email one-time codes have 6 digits; their budgets and lifetime make them hold.
- A username is an identifier others can learn exists: choosing one that is
  taken answers `username_taken`, whatever the case. Email addresses, the
  identifier that reaches a person, are never confirmed this way. Budgets on
  registration (`REGISTRATIONS_PER_IP_PER_HOUR`) bound how fast usernames can
  be tried or squatted, and a pending account frees its username after
  `CLEANUP_UNVERIFIED_ACCOUNT_DAYS` (2 by default); a deployment that treats
  usernames as secret should let users sign in by email only.

## 6. Verification

The control catalog test (`tests/security/catalog.rs`) fails when a cited test
disappears. Fuzz targets cover every parser at the boundaries: redirect URIs,
client addresses, cursors, breach-check answers, webhook URLs and WebAuthn data.
An external penetration test is recommended before exposing a deployment to
high-value accounts; it is outside what this repository can provide.
