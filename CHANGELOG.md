# Changelog

All notable changes. Versions follow [Semantic Versioning](https://semver.org/)
as described in the [versioning policy](docs/dev/guides/versioning.md).

## [Unreleased]

## [2.1.0] - 2026-09-26

Security release: fixes every finding of the security audit of 2026-09-26
and of the four independent re-audits that followed it.
Some fixes refuse what was unsafe to accept, as the versioning policy allows
for security fixes: each such change is listed under **Security**. No
deployment exists yet, so the migrations were consolidated: each table is
defined whole in the migration that creates it, and a database is created
from scratch (read **Upgrading**).

### Security

- Production refuses `LOCKOUT_THRESHOLD` above 50, request limits above
  10 000 a minute, refresh or session lifetimes above a year,
  `REGISTRATIONS_PER_IP_PER_HOUR=0`, `PWNED_PASSWORDS_ENABLED=false`, and a
  `TRUSTED_PROXY_CIDRS` network wider than `/24` (IPv4) or `/64` (IPv6). New
  `deploy/api/nftables-auth-api.conf` lets only nginx and root reach the
  published ports; nginx masks the codes carried by URLs in its access log;
  the internal listener refuses bodies and slow requests; the image is built
  with `--locked`; the Redis ACL template allows the Lua scripts by name.

- Introspection of the access tokens of others is reserved to resource servers
  (new `allows_introspection` client setting; register yours with it), and a
  resource server registered with scopes sees only those. Access tokens carry
  `sub_type` and `session_type`, also reported by introspection. The ID
  token's `auth_time` is when the password was proved for the consent.
  `prompt=none`, `request`, `request_uri` and response modes other than
  `query` are refused; `max_age` and `prompt=login` ask for the password
  again. An authorization request belongs to the first user who looks at it.
  A code replayed under another client's id revokes nothing (it is logged). A
  device's consent is intersected with the user's permissions at the
  approval.

- Audit partitions created after `deploy/db/auth-api-grants.sql` ran lose
  `UPDATE` and `DELETE` for the runtime role (the owner's default privileges
  granted them), and partitions are created two years ahead at most.
  `forget_account_traces` deletes the account with its traces, so it can no
  longer anonymize the audit trail of an account that stays. Key identifiers
  in ciphertexts are derived by HKDF. A stored password hash asking for far
  more than the configured Argon2 cost is refused before any work.

- Nobody grants a role a permission they do not hold (`403`), whether they
  hold the role or not: `roles:manage` alone no longer lets two accounts give
  each other every permission. A client's audit entry lists the settings that
  changed. A rename, a session revoked by its owner and a re-authentication
  are written with their audit entry. A failed webhook delivery records a fixed
  message instead of the client error, which carried the URL. A forced reset
  records no administrator address. Status and permissions checked before a
  suspension, an erasure or a role grant are read under the account's lock.
  The export shows only the network of failed sign-ins and of mailed-link
  requests.

- A password reset removes the second factors, passkeys and external
  identities added in the 72 hours before it was asked for
  (`RESET_REVOKES_FACTORS_ADDED_HOURS`) and lists them in its mail. New `DELETE
  /admin/users/{id}/access-factors` (re-authentication, audited as
  `access_factors_removed`) and `revoke_access_factors` on `POST
  /admin/users/{id}/password-reset` remove every way in but the password; an
  administrator's last second factor stays. The owner is mailed of an unlock.

- Second factors: 10 wrong TOTP codes an hour per address and 30 per account
  (100 before); spending the account budget mails the owner (new
  `second_factor_attempts` template). Recovery-code budgets cover an hour
  instead of a day. `POST /auth/two-factor/email/resend` is limited to 2 per
  challenge and 10 an hour per account, keeps the previous code usable, and
  checks the account status. A password change ends the open second-factor
  challenges. Regenerating recovery codes is refused while Redis is down.

- A password attempt is reserved atomically in Redis (per account and per
  address) before the hash is computed: a burst of simultaneous guesses no
  longer outruns the budgets, which were read before the hash and written
  after. With a CAPTCHA required, the identifier's budget no longer answers
  `429` (every attempt already costs a challenge); the lockout still applies.
  An unknown identifier costs the same database work as a wrong password, and
  at most five second-factor challenges stay open per account.

- Every OAuth consent needs a recent re-authentication, the instance's own
  application included: an access token alone could approve an authorization
  request for it and obtain a new, long-lived session. Signing an account out
  from the administration needs one too, and mails the owner only when
  sessions were actually ended.

- nginx: `PUT` is allowed (the administration's role, client and webhook
  updates answered `405`), `/.well-known/` serves the OAuth and OpenID Connect
  metadata (they answered `403`), and the strict zone follows the API's strict
  bucket by method and path through a map that a test checks against the
  routers (it named routes that do not exist and missed most credential
  routes).
- The internal listener (`/metrics`, detailed `/ready`) requires
  `Authorization: Bearer <METRICS_TOKEN>`, required in production; Prometheus
  reads it from a file. The public `/ready` reuses its answer for a second.
- `docker-compose.api.yml` mounts the secrets as files written by
  `scripts/write-secrets.sh` to `/etc/auth-api/secrets` (root-only directory,
  files readable by the image's user only): they no longer appear in `docker
  inspect` or the process environment.
- `restore-db.sh` takes the database URL from `RESTORE_DATABASE_URL` or a file
  (`-D`) instead of `-d <url>`, out of `ps` and the shell history.
  `pgbackrest.conf` is installed mode 600 and carries a commented offsite
  repository.

- Refused at start-up: `LOCKOUT_DURATION_SECS` under 60, `DEVICE_AUTH_TTL_SECS`
  above 1800, a blank required variable (it counted as set), and in
  production `DEVICE_AUTH_VERIFICATION_URI` without HTTPS and a
  `TRUSTED_PROXY_CIDRS` network wider than `/8` (IPv4) or `/32` (IPv6).
  `PWNED_PASSWORDS_FAIL_OPEN` stays allowed in production, documented as the
  one fail-open switch kept, with its alert.

- The maintenance functions keep minimums only the schema owner can lower
  (`maintenance_floors`: six months of audit partitions, 30 days before an
  audit address is coarsened, a day before a pending account is purged): the
  runtime role can no longer use them to erase the audit trail. Only `v2`
  ciphertexts (bound to their row) are read, and a secret in another format
  stops the start. In production `DATABASE_URL`, `DATABASE_READ_URL` and
  `REDIS_URL` must carry a password; `deploy/db/pg_hba.auth-api.conf` and
  `deploy/db/users.acl.template` hold the rules to install. A blank variable
  leaves its place to `X_FILE`.

- Device flow: every approval needs a recent re-authentication, the instance's
  own application included, and `GET /oauth/device/{user_code}` adds `scopes`,
  `unavailable_scopes`, `unrestricted` and the session allowance. Unknown user
  codes are budgeted per signed-in user as well as per address.
- A public client's request budget is split by client address (a confidential
  client keeps one budget, spent once it has authenticated), and every client
  authentication failure reads `client authentication failed`.
- Codes and approvals follow the client as registered now: a redirect URI
  removed since the request receives no code and its codes no longer redeem,
  and access tokens are narrowed to the client's current scopes at every
  refresh. Authorization responses carry `iss` (RFC 9207). Access tokens carry
  the header `typ: at+jwt` and a `client_id` claim for client sessions.
- Introspection describes a refresh token only to its own client and never a
  personal access token. The metadata's `scopes_supported` lists only the
  scopes some registered client may ask for. Outgoing calls (CAPTCHA, breached
  passwords, identity providers) no longer follow redirects, and a provider's
  key set is fetched again once when an ID token names an unknown key.

- A rotated refresh token presented again within the 1-second grace window is
  forgiven only from the network and user agent that rotated it; from anywhere
  else the family is revoked as for any replay. Registrations are budgeted per
  client address (`REGISTRATIONS_PER_IP_PER_HOUR`, 20 by default, `429` past
  it), accounts never verified are purged after 2 days instead of 7
  (`CLEANUP_UNVERIFIED_ACCOUNT_DAYS`), and failed sign-ins are budgeted under
  the identifier they are recorded with.

- `GET /users/me/audit` no longer shows the id and address of an administrator
  who changed the account, as the export already did. A refresh replay records
  `same_network` instead of the two addresses in its audit metadata, which is
  never coarsened nor erased. The purge of accounts never verified delivers
  `user.deleted` to webhooks too. The export adds passkeys, personal access
  tokens, linked identities and where each mailed link was asked from. Two
  accounts confirming the same new address at once: the second gets `409
  email_taken` instead of `500`.

- Administration: nobody adds to a role they hold a permission they lack
  (`403`), the default role never grants an administrative permission (`409
  default_role_administration`), and an account holding administrative
  permissions cannot remove its last second factor (`409
  administrator_needs_second_factor`; the grant itself is now checked under the
  account's lock). Withdrawing or deleting a role, unlocking (never one's own
  account), reactivating, deleting a client, deleting a webhook and retrying a
  delivery need a recent re-authentication. `DELETE /admin/users/{id}` no longer
  takes `current_password` in its body: re-authenticate with `POST
  /users/me/reauth` first. The owner is mailed when an administrator suspends
  or reactivates the account, changes its roles or signs it out (new
  `changed_by_administrator` template); deleting a role writes `role_revoked`
  in each holder's history. Sessions revoked by a suspension or a forced reset
  are read in the revoking transaction. `--grant-role` and `--register-client`
  commit with their audit entry, and `--register-client` validates like the
  administration.

- Wrong passwords lock the password for `LOCKOUT_DURATION_SECS` only: the count
  covers a day, restarts after any completed sign-in (second factor, sign-in
  link, passkey, external identity), an administrator's unlock, a password
  reset or the end of a lock, and one guess per lock period no longer keeps an
  account locked for good. Passkeys, sign-in links, external identities and
  personal access tokens keep working during a lock. A locked password answers
  `401 invalid_credentials` like a wrong one (it answered `403
  account_locked`), and the owner is mailed (new `account_locked` template,
  English and French).
- Reset and sign-in links coexist until one is used (a new request revoked the
  previous link), and their budget counts per client address (3 an hour) before
  the account's (10 an hour). Second-factor failure budgets count per address,
  with a ceiling five times higher for the account, and a password reset
  restarts them. Signing in again within the minute an e-mail code stays fresh
  continues the challenge instead of failing, and a second-factor sign-in
  without Redis answers `503`.

- `POST /auth/verify-email` takes the `password` of the registration that sent
  the link, along with the `token`. A later registration on a pending address
  could otherwise mail the owner a link carrying the attacker's password; a
  resent link asks for the password the account was created with. A wrong
  password answers `401 invalid_credentials` and leaves the link unused.

- Tokens delegated to a client application (another client than the
  instance's own, or any session restricted to consented scopes) and tokens
  obtained from a personal access token no longer act as the account: the
  account routes (`/users/me/*`), the approval routes
  (`/oauth/authorization-requests/*`, `/oauth/device/*`) and `/admin/*` answer
  `403 first_party_session_required`. Such a token could previously approve a
  device flow of the instance's application and obtain an unrestricted
  session. Logout, `/oauth/userinfo` and resource servers are unchanged.
- Approving a device of a client other than the instance's own application
  requires a recent re-authentication, or `current_password` in the body of
  `POST /oauth/device/verify`; `GET /oauth/device/{user_code}` tells it in
  `reauthentication_required`.
- A registration on an address whose account is still pending verification
  carries its own password, username and locale in its verification link, and
  the link applies them. Registering someone's address first no longer lets an
  attacker choose the password the owner activates. The links of a pending
  account now coexist until one of them verifies it.
- Adding a passkey, a personal access token or an external identity e-mails
  the owner (new `access_added` template, English and French). The e-mail sent
  after a password change now lists what still opens the account, and a reset
  sends it too. A reset that verifies a pending account deletes its second
  factors, recovery codes, passkeys, identities and tokens.
- The callback of an external identity link no longer links: the link is made
  by `POST /users/me/external-identities/complete`, once the binding proves the
  browser that started the flow. A victim opening the provider URL of a link an
  attacker started no longer gets their identity linked to the attacker's
  account.
- `/admin/*` requires a session whose sign-in proved a second factor (TOTP,
  email code, recovery code, or a passkey), recorded on the session; an
  enrolled factor is no longer enough. An administrator
  who signed in with a password alone, or a sign-in link, gets
  `403 two_factor_required`.
- A role granting an administrative permission goes only to an active account
  with a verified second factor or a passkey (`409
  administrator_without_second_factor`, also refused by `--grant-role`), and
  no administrator grants a role to their own account (`403`).
- Creating, updating or re-keying a webhook, suspending an account, forcing a
  password reset and removing a client secret need a recent re-authentication
  (`403 reauthentication_required`). Webhook changes and redeliveries are
  audited with the host of the endpoint, and client secret and unlock changes
  commit with their audit entry.
- The last active account able to manage roles can no longer be suspended or
  deleted, by an administrator or by its owner (`409 last_administrator`), and
  two concurrent role withdrawals can no longer both pass the check. Suspended
  accounts no longer count as able to manage roles.
- The database schema can belong to a separate owner role: the API then
  connects with a role limited to reading and writing data
  (`deploy/db/auth-api-grants.sql`), which cannot alter the schema, rewrite or
  truncate the audit log, or change the permission catalog. The maintenance
  functions that need more run with their owner's privileges.
- `deploy/db/postgresql.auth-api.conf` logs slow statements without their bound
  values (`log_parameter_max_length = 0`): password hashes and token digests no
  longer reach the PostgreSQL log.
- Requests to paths no route matches spend the general rate-limit budget, and
  the HTTP metrics label them all `<unmatched>`: a scan no longer creates one
  series per URL.
- The public `GET /ready` answers only `{"status": ...}`; which dependency is
  down is served at `/ready` on the internal metrics listener.
- A passkey sign-in without the credential's user handle is refused
  (`401 invalid_credentials`).
- Webhook deliveries no longer connect to local-use NAT64 (`64:ff9b:1::/48`)
  or the former 6to4 relay range (`192.88.99.0/24`).
- An account's export no longer names the administrator who changed it, nor
  the address they acted from.
- A lockout that cannot be applied is logged as an error and counted in
  `auth_lockout_failures_total` (alert `AuthApiLockoutFailing`).
- Every variable can be given as `X_FILE`, the path of a file holding its
  value (a Docker, Kubernetes or systemd secret), which keeps it out of
  `docker inspect` and the process environment.

- Granting, withdrawing, emptying or deleting a role needs every permission
  it grants (`403`), checked under the role's lock: `roles:manage` alone can
  no longer hand `admin` to an account it controls, nor strip it from a
  greater administrator.
- Removing an account's access factors revokes every session, browser and
  device ones included; a forced reset with `revoke_access_factors` is one
  transaction (a refusal revokes nothing). The primary client is designated
  and changed from the command line only
  (`409 primary_client_managed_by_command_line`). Command-line changes record
  the operator and host in the audit log.
- A session that exhausted its re-authentication budget stops filling the
  account's: a stolen session can no longer lock its owner out of revoking it.
  An administrator's unlock and a password reset forgive earlier sign-in
  failures. E-mail change codes are budgeted per account across flows, and a
  flow starts at most once a minute. The budgets guarding a link, a device
  code or an e-mail change target now fail closed (`503`) when Redis cannot
  count them; the mailbox budgets last as long as the links they bound.
- A registration on an address that already has an account reserves its
  username until the link would expire: whether a username is taken no longer
  tells whether an address is registered. Renames honour reservations.
- Every consent and device approval is audited (`client_authorized`,
  `device_approved`, with the client, scopes and the requesting device), and
  handing a session to a client is recorded as a sign-in, with the new-device
  alert; a device session's `auth_time` is when the password was proven.
- Third-party clients never carry the account's roles; a client without
  scopes needs `"unrestricted": true` (`422` otherwise). Redirect URIs must be
  `https`, loopback `http` or a private-use scheme with a dot. Wrong client
  secrets are budgeted per address and client id; a code replayed under a
  public client's id without its verifier revokes nothing;
  `error_description` no longer tells an account's state; an identity
  provider's discovery document must name its configured issuer; OpenID
  Connect scopes are refused with `client_credentials`; the primary client's
  device flow is counted against its default quota and, for an account with a
  second factor, approved only from a session that proved one
  (`403 second_factor_session_required`).
- A consumed TOTP code stays refused 120 seconds, judged on the application's
  clock. `POST /users/me/two-factor/recovery-codes/use` is removed: it granted
  nothing and let a stolen session burn recovery codes.
- Production refuses an `ENCRYPTION_KEY` that is printable text, and every
  configuration refuses a CORS entry that is not an origin and two JWT keys
  sharing a key id (now 16 hex digits). A stored password hash may cost at most
  twice the configured Argon2 parameters; profiles M, L and XL get 640, 768
  and 768 MiB so that worst case fits.
- The nftables rule also closes the compose bridge (`172.30.0.0/24`); nginx
  limits count an IPv6 client's /64; `deploy/api/logrotate-auth-api` keeps the
  access log 14 days; the infrastructure check verifies that PostgreSQL and
  Redis listen on the VPN address only.

- Every administrative invariant holds on every route: a role gains an
  administrative permission only when each holder is active with a second
  factor (`409 holders_without_second_factor`), and each holder is audited and
  told; the primary client can neither be deleted nor have its secret changed
  over HTTP; a password reset keeps the last second factor of an account
  holding administration; the primary client needs a second-factor session in
  the authorization code flow too; changing the password ends a lockout.
- An account whose address is not verified answers a password sign-in like a
  wrong password (`401 invalid_credentials`, no longer `403
  email_not_verified`) and gets a new verification link: registering an
  address and signing in with one's own password no longer tells whether it
  had an account. Verification links are budgeted per client address first; a
  registered address holds one username reservation at a time; a reset that
  activates a pending account adopts the username of its latest registration;
  a refresh refused for its address answers `token_invalid`.
- Sign-in challenges and e-mail change flows are kept in Redis under their
  digest; a sign-in e-mail code completes its own challenge only (codes are
  budgeted per challenge and per account); `POST /users/me/two-factor/email/send`
  answers `404` unless a method is being set up; a lockout is applied, audited
  and mailed once; no route hashes a password longer than 256 bytes.
- Administrative reads (account search, account detail, `/admin/audit`) are
  audited in the administrator's history (`admin_data_read`, without the
  search). The owner's history and export no longer show a command-line
  operator or host; strangers' user agents in the export are reduced to their
  family. The runtime role cannot delete events from the outbox or webhook
  deliveries (owner functions with floors do). Pointing a webhook at another
  host regenerates its secret, returned once by `PUT /admin/webhooks/{id}`.
- OAuth: an identity provider's endpoints must use its issuer's transport;
  redirect URIs with a fragment or credentials are refused; a client
  credentials token is introspected against the client's current scopes; a
  refresh may narrow `scope` and is refused (`invalid_scope`) when it widens
  it; device refusals are audited (`device_denied`).
- Production names trusted proxies one address at a time (`/32`, `/128`) and
  bounds `RECOVERY_CODE_EXPIRY_DAYS` to 1-730; weakened settings are logged at
  startup. An IPv4-mapped peer is compared as IPv4. The NATS broker runs
  read-only with a PID limit, its monitoring endpoint on loopback and the
  exporter in its network namespace. nginx redirects to a fixed host and
  limits connections per client network. `write-secrets.sh` reads pass
  directly. The runtime role executes the owner-privileged functions by name.
  New `METRICS_HOST`. Errors of the Pwned Passwords API are logged without
  their URL.

### Upgrading

- Administrators signed in before the upgrade sign in again with their second
  factor: sessions opened earlier carry no proof of it.
- The migrations were rewritten (18 files instead of 28): a database migrated
  by an earlier version is not upgraded but recreated. Development databases:
  drop and recreate them (`make dev` migrates the new one).
- Create the database with two roles (database deployment guide, section
  2.5): `auth_api_owner` runs the migrations, the API connects as `auth_api`
  after `deploy/db/auth-api-grants.sql`.
- Check the settings refused at start-up (listed under Security) against your
  environment before upgrading.
- Monitoring that reads the dependencies from the public `/ready` must query
  the internal listener instead (`http://10.0.0.1:9465/ready`), with the new
  `METRICS_TOKEN` (`pass insert prod/auth-api/metrics-token`, `openssl rand -hex
  32`); install it for Prometheus as the monitoring guide shows.
- Install `deploy/api/nftables-auth-api.conf` on the API VPS and run the
  rolling update with `sudo -E` (update guide); copy the new ACL template line
  to `/etc/redis/users.acl`.
- Resource servers that introspect access tokens need `allows_introspection`
  (`PUT /admin/clients/{client_id}`).
- Deployments export the secrets as before, then run `./write-secrets.sh`
  before `./rolling-update.sh` (update guide, section 4).
- Copy the new `log_parameter_max_length` lines of
  `deploy/db/postgresql.auth-api.conf` and reload PostgreSQL.
- Reinstall `deploy/api/nftables-auth-api.conf` (new bridge rule) and install
  `deploy/api/logrotate-auth-api` (nginx guide, Logs). Check that Redis is 7
  or later.
- Scripts saving clients without scopes through `PUT /admin/clients/{id}` add
  `"unrestricted": true`; the primary client is changed with
  `auth-api --register-client ... --primary`. Clients registered with other
  redirect schemes than `https`, loopback `http` or `reverse.domain:` are
  refused at their next save.
- Callers of `POST /users/me/two-factor/recovery-codes/use` stop calling it:
  recovery codes are used at sign-in (`/auth/two-factor/recovery`).
- Resource servers that authorized third-party tokens by role authorize them
  by permission: those tokens no longer carry roles.
- Front ends that told an unverified user so at sign-in: `/auth/login` now
  answers `401 invalid_credentials` and mails a new link; point users at their
  mailbox after a registration instead.
- `TRUSTED_PROXY_CIDRS` lists addresses in production (`172.30.0.1/32` as
  shipped). `write-secrets.sh` reads pass itself: stop exporting the secrets
  before running it. Reapply `deploy/db/auth-api-grants.sql` (functions granted
  by name, no delete on the outbox and deliveries). Update
  `docker-compose.api.yml` and `nats.conf` together (monitoring on loopback).
- Scripts calling `PUT /admin/webhooks/{id}` with a new host store the
  `secret` of the response.

## [2.0.1] - 2026-09-18

Dependency and image updates; no change to the API, the events or the
configuration.

### Changed

- Dependencies: `argon2` 0.6, `jsonwebtoken` 11, `totp-rs` 6, `async-nats` 0.50,
  `base64` 0.23 and `sha1` 0.11, plus minor and patch updates. Password hashes
  and TOTP secrets stored by earlier releases remain valid, pinned by tests.
- Images: Rust 1.98 for the build, Prometheus 3.14, Alertmanager 0.34, blackbox
  exporter 0.28, NATS exporter 0.20, Mailpit 1.31. The test and development
  stacks stay on PostgreSQL 17 and Redis 7, the versions production runs.
- PostgreSQL 17 and Redis 7 images of the test and development stacks
  refreshed to their latest builds.

## [2.0.0] - 2026-09-16

The release after 1.1.3, and the first under the
[versioning policy](docs/dev/guides/versioning.md): from here on the contract
only breaks in a major release. Compared with 1.1.3 it hardens every flow, adds
administration, standard OAuth 2.1 and OpenID Connect, passkeys, external
identity providers, webhooks, telemetry and high availability, and changes the
HTTP contract and the configuration: read **Breaking changes** and
**Upgrading** before deploying over 1.1.3.

### Breaking changes

**API**

- Client flows moved to standard OAuth 2.1 endpoints. `POST /auth/authorize`,
  `/auth/authorize/describe` and `/auth/authorize/token` are replaced by
  `GET /oauth/authorize` (redirecting to `OAUTH_CONSENT_URI`),
  `/oauth/authorization-requests/{id}` (describe, approve, deny) and
  `POST /oauth/token`. `POST /auth/device` and `/auth/device/token` are replaced
  by `POST /oauth/device_authorization` and `POST /oauth/token`;
  `/auth/device/{user_code}` and `/auth/device/verify` move to `/oauth/device/`.
  Token and device requests are form-encoded and answer RFC 6749 errors
  (`{ "error", "error_description" }`); a device flow names its `client_id`.
- Client sessions are refreshed at `POST /oauth/token` by their client;
  `/auth/refresh` refuses them.
- `POST /auth/register` answers `202` with `{ "status", "message" }` for every
  request, whether or not the address is taken; the owner of a taken address is
  emailed. The response no longer carries the account.
- Signing in no longer grants a re-authentication. Changing the password,
  username or email, deleting the account, revoking sessions, and adding or
  removing a second factor need `POST /users/me/reauth` within
  `SENSITIVE_ACTION_REAUTH_SECS`, or `current_password` in the body. The
  `DELETE` routes accept an optional JSON body for it.
- A pre-auth token completes only the method it was issued for
  (`/auth/two-factor/complete` for TOTP, `/auth/two-factor/email/complete` for
  email codes).
- Validation errors return their message; conflicts return a specific `code`
  (`email_taken`, `username_taken`, ...).
- Tokens issued to a registered client carry only the permissions consented for
  it, and no roles.
- The device flow requires a registered client (`--register-client`); a flow
  without `client_id` uses the primary client.
- `429` responses carry a computed `Retry-After` instead of a fixed 60.
- Email links point at `FRONTEND_URL` (defaults to `APP_PUBLIC_URL`).

**Configuration**

- `APP_ENV` is required; a present but unparsable value is an error instead of
  falling back to the default.
- Production refuses to start without `TRUSTED_PROXY_CIDRS`, with an HTTP
  `FRONTEND_URL`, or with a committed or arithmetic `ENCRYPTION_KEY`.
- Removed with risk scoring: `GEOIP_DB_PATH`, `GEOIP_REQUIRED`, `RISK_*`, the
  `login_locations` table, and the new-device and suspicious-login emails.
- `docker-compose.api.yml` runs `auth-api:${AUTH_API_VERSION}` built by
  `make release`; no image is published to a registry.
- Behind the compose file, `TRUSTED_PROXY_CIDRS` must be `172.30.0.1/32`.
- Startup refuses `LOCKOUT_THRESHOLD=0`, `DEVICE_AUTH_TTL_SECS=0`, a
  `DEVICE_AUTH_POLL_INTERVAL_SECS` of 0 or not shorter than the device code
  lifetime, and `JWT_MAX_SESSION_LIFETIME_SECS=0`.

**Data**

- New TOTP secrets are written in a versioned format (`v1:{key id}:...`) that
  earlier versions cannot read: once this version has written secrets, rolling
  back breaks TOTP for those accounts.
- Retention runs only in the application: the migrations install no pg_cron
  job, which ran with the SQL defaults instead of the configured retention.
- The migrations are consolidated into one file per domain, each creating its
  tables in their final form. A database created by an earlier development
  version is created again rather than upgraded.

### Added

- Administration API under `/admin`, open to accounts holding the new `admin`
  role (or any role granted `users:read`, `users:manage`, `roles:manage`,
  `clients:manage`, `audit:read`, `webhooks:manage`) with a second factor
  enrolled. Permissions are checked in the token and again in the database, so
  a revoked role stops working at once. `auth-api --grant-role admin --user
  <email>` appoints the first administrator.
- `/admin/users`: search by address or username prefix and status, account
  detail (roles, second factors, sessions), suspend, reactivate, unlock (the
  failed sign-ins that caused the lockout are forgiven), sign out everywhere,
  forced password reset, and deletion after a re-authentication. Each change is
  audited on the account with the administrator's id; suspensions and
  reactivations publish `user.suspended` and `user.reactivated`.
- `/admin/roles`, `/admin/permissions` and `/admin/users/{id}/roles`: create
  roles, set the permissions they grant, grant and take them back (granting
  needs a re-authentication). A change that would leave nobody with
  `roles:manage` is refused with `409 last_administrator`.
- `/admin/clients`: register, update (`PUT`) and remove client applications;
  removing one revokes its sessions. `/admin/audit`: the audit log of every
  account, filtered by account and action, paged newest first.
- CORS allows `PUT`.
- Sign-in links by email (`MAGIC_LINK_ENABLED`, off by default):
  `POST /auth/magic-link` and `POST /auth/magic-link/complete`. A link stands
  for the password only: accounts with a second factor still answer their
  challenge. English and French emails.
- Personal access tokens: `GET`/`POST /users/me/tokens` and
  `DELETE /users/me/tokens/{id}` (creation needs a re-authentication; at most
  20 active, 1 to 365 days, scopes limited to the account's permissions), and
  `POST /auth/personal-access-tokens/exchange` for a short-lived access token
  carrying those scopes and no roles. Each token owns a session of the new type
  `personal_access_token`, so revoking the session, changing the password or
  suspending the account ends it too.
- Webhooks: `/admin/webhooks` registers HTTPS endpoints for domain events
  (`user.created` ... `user.deleted`, or `*`). Deliveries are recorded in the
  transaction of the change, signed per Standard Webhooks (`webhook-id`,
  `webhook-timestamp`, `webhook-signature` with HMAC-SHA256), retried with
  backoff for about fourteen hours, and inspectable and retriable by an
  administrator. Endpoints resolving to internal addresses are never called,
  redirects are not followed, and the connection goes to the checked address.
  `WEBHOOK_*`, `CLEANUP_WEBHOOK_DELIVERY_DAYS`, alert `AuthApiWebhooksFailing`;
  `--rotate-totp-keys` also re-encrypts webhook secrets.
- Passkeys (WebAuthn): `/users/me/passkeys` registers, lists and removes them;
  `POST /auth/passkeys/options` and `/auth/passkeys/sign-in` sign in with one,
  without password or second-factor challenge. Discoverable credentials with
  user verification, ES256/EdDSA/RS256, challenge single use, signature
  counters checked against clones; the first passkey comes with recovery codes,
  and a passkey counts as an administrator's second factor (`WEBAUTHN_*`).
- Sign-in with Google, GitHub or any OpenID Connect provider
  (`IDENTITY_PROVIDERS`, `IDP_*`): identities are linked by the signed-in owner
  (`/users/me/external-identities`) and never matched by email; the sign-in is
  bound to the browser that started it, the ID token verified against the
  provider's keys, and an enrolled second factor still applies.
- `docs/dev/guides/integration.md`: which flow each kind of application uses,
  token verification rules for resource servers, and following account events.
- `clients/js/verifier` (`@auth-api/verifier`, internal): the same verification
  for Node.js resource servers, without dependency, with an Express middleware;
  `make js-test` and a CI job run its tests.
- `crates/verifier` (`auth-api-verifier`, internal): verifies access tokens in
  Rust resource servers, with JWKS caching, issuer and audience checks, an
  optional introspection-backed revocation check and an axum extractor.
- `DATABASE_READ_URL`: an optional read replica for security histories, the
  admin audit log, account search and webhook delivery lists; sizing profile
  XL (three API hosts, 450 sign-ins per second, extrapolated).
- High availability, self-hosted: `docs/deploy/guides/high-availability.md`
  (keepalived and nginx, Patroni behind HAProxy, Redis Sentinel, a NATS cluster,
  failover drills). `NATS_URL` accepts the servers of a cluster and
  `NATS_STREAM_REPLICAS` sets the copies of the event stream.
- OpenTelemetry traces over OTLP/HTTP (`OTEL_EXPORTER_OTLP_ENDPOINT`,
  `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER_ARG`): one server span per request,
  named after its route template, continuing a W3C `traceparent`.
- `GET /users/me/export`: everything stored about the account as a JSON
  download, after a recent re-authentication, audited as `data_exported`.
- Simulations of random account lifecycles checked against a model, a timing
  test comparing existing and unknown accounts, and `make soak`: an hour of
  mixed traffic that fails on any error or on growing memory.
- OAuth 2.1 authorization server: authorization code with PKCE, device
  authorization and refresh at `POST /oauth/token`, `scope` requests narrowed to
  the client's registration, metadata at `/.well-known/oauth-authorization-server`
  (RFC 8414), confidential clients authenticating with `client_secret_basic` or
  `client_secret_post` (`POST`/`DELETE /admin/clients/{client_id}/secret`),
  the client credentials grant for confidential clients that enable it
  (tokens with a `client_id` claim and no user), an OpenID Connect provider
  (discovery, `openid`/`profile`/`email` scopes, ID tokens with `nonce` and
  `at_hash`, `GET /oauth/userinfo`), token introspection for
  resource servers (`POST /oauth/introspect`, RFC 7662)
  and revocation (`POST /oauth/revoke`, RFC 7009).
- Client registry: scopes, redirect URIs, loopback redirects, default session
  limit; `auth-api --register-client`.
- A sign-in from a browser and system family the account never used e-mails
  its owner (English and French) and is audited as `new_device_login`
  (`NEW_DEVICE_ALERTS_ENABLED`); devices unused for `CLEANUP_KNOWN_DEVICE_DAYS`
  (90) are forgotten.
- `PATCH /users/me/password` and `DELETE /users/me/sessions` accept
  `keep_current_session`: every other session is revoked and the one making the
  request stays signed in.
- Passwords found in known data breaches are refused at registration, change
  and reset (`422 password_compromised`), through the Pwned Passwords range API
  with k-anonymity: only five characters of the SHA-1 leave the service
  (`PWNED_PASSWORDS_*`, fail-open by default).
- Personal data: deleting an account (or purging a never-verified one) also
  deletes its sign-in attempts, including failures typed with its address before
  it existed, and removes the client addresses of its audit entries; audit
  addresses keep only their network after `AUDIT_IP_RETENTION_DAYS` (90); domain
  events carry the user id only. `docs/dev/privacy.md` records what is stored,
  why, for how long and what deletion removes.
- `POST /auth/verify-email/resend`: a new verification link for a pending
  account, answering alike for every address and capped per account and per
  address; registering again on a pending address sends the verification again.
- Accounts whose address was never verified are deleted after
  `CLEANUP_UNVERIFIED_ACCOUNT_DAYS` (7), audited and announced with
  `user.deleted`. A password reset verifies a pending account, so the owner of
  an address takes back an account someone else registered with it.
- `GET /oauth/device/{user_code}`: what the signed-in user is about to approve.
- `GET /users/me/audit`: the caller's security history, cursor-paginated.
- `GET /users/me/two-factor`: configured methods and remaining recovery codes.
- Events `user.password_changed` and `user.sessions_revoked`.
- Emails: account already exists, email address changed (to the previous
  address), two-factor enabled; subjects translated in English and French.
- Encryption keyring: `PREVIOUS_ENCRYPTION_KEY` stays readable during a
  rotation; `--rotate-totp-keys` is resumable and audited as
  `encryption_key_rotated`.
- Access log (route template, status, latency, request id), nextest
  configuration, `make ci`, `make release`, OpenAPI document generated from the
  code, security model, this changelog.
- The OpenAPI document lists the responses every operation can return (`400`,
  `401`, `413`, `415`, `422`, `429`, `503`) with their error body.
- Test suites by layer (`make test-unit`, `test-integration`, `test-security`,
  `test-sim`), a shared harness (`crates/testkit`), every test response checked
  against the OpenAPI document, an authorization matrix over every operation,
  a control catalog in the security model, fuzz targets (`make fuzz`) replayed
  on stable in `make ci`, and `migrations/SHA256SUMS` freezing released
  migrations. Property tests pit the validators against the database
  constraints; `make mutants` runs mutation testing over the security-relevant
  pure code. `make coverage` fails under 90 % of lines, 85 % of regions and 79 %
  of functions. See `docs/dev/guides/testing.md`.

### Security

- Second factors: pre-auth tokens bound to their method; failure budgets per
  challenge and per account for TOTP, email and recovery codes; second-factor
  failures no longer lock the account out.
- No account oracle: the lockout answers the same whatever the password,
  unknown identifiers pay a full hash, registration and forgot-password answer
  identically; forgot-password is capped per account.
- Sessions: an absolute lifetime measured from the sign-in; concurrent refreshes
  within 2 seconds no longer revoke a legitimate family; email change keeps the
  account status and records no addresses in the audit log.
- Attempt budgets are consumed atomically before the check they guard.
- IPv6 clients are rate limited per `/64`.
- Device flow: user codes reserved atomically, approvals collected once, polling
  paced, account status and session limits checked at issue.
- `user.deleted` is recorded in the same transaction as the account deletion:
  the account is never gone without its event, and the event never announces a
  deletion that failed.
- Nginx served `403` for `/.well-known/jwks.json` (hidden-file rule), appended
  client-supplied `X-Forwarded-For` hops, and duplicated security headers.
- Behind Docker's port proxy the trusted proxy never matched, so every client
  shared one rate-limit bucket.
- `AUDIT_LOG_RETENTION_MONTHS=0` deleted every past audit partition instead of
  keeping them, and the pg_cron job deleted audit months beyond six whatever the
  configuration.
- Base images pinned by digest; OpenSSL removed from the images; development
  ports bound to loopback.
- Passwords need at least 10 characters, not 10 bytes: an accented password of
  ten bytes could hold seven characters (found by fuzzing). The upper bound
  stays 128 bytes so every accepted password remains usable at sign-in.
- A loopback redirect on port 0 is refused.
- TOTP verification refuses a time within the skew of the epoch instead of
  panicking.
- Every error response carries the documented `{ "code", "message" }` body:
  rate limiter and timeout refusals, unknown routes and malformed or oversized
  JSON no longer answer in plain text, and no longer quote the JSON parser.
- `LOCKOUT_THRESHOLD=0` is refused at startup: it locked an account on every
  wrong password instead of disabling the lockout.
- The re-authentication budget is consumed atomically before the password is
  hashed, and fails closed: parallel guesses could all pass a count read
  before any of them was recorded.
- Failed sign-ins are capped per IPv6 /64, like every other per-address
  budget: rotating addresses inside one /64 reset the cap.
- Device flow approvals check the client's session limit under the same lock
  as code redemptions: concurrent polls could each count the same sessions and
  exceed the limit.
- A refresh no longer dates the new session past the absolute lifetime of its
  sign-in, so session listings and revocation lifetimes match the real end.
- Confirming a TOTP method records its code in the durable replay table shared
  with sign-in (it could complete a sign-in in the same window, and the Redis
  guard was skipped without Redis), under a budget of 5 wrong codes per 15
  minutes.
- Recovery codes have one per-account budget (10 per 24 hours) shared by the
  sign-in challenge and `POST /users/me/two-factor/recovery-codes/use`, which
  had its own; purging a user's challenges also clears their email-code
  budgets.
- Second factors and client flows answer `account_inactive` and
  `email_not_verified` like the password sign-in, instead of
  `account_suspended` for every status other than active.
- An authorization code redirect keeps the query of its registered URI.
- The API never authenticated to NATS: async-nats ignores the credentials of
  a URL, so the documented `NATS_URL=nats://<token>@nats:4222` against the
  token-protected broker of `docker-compose.api.yml` was refused and the service
  could not start. The credentials are now read from `NATS_URL` and presented
  to the broker, production refuses a `NATS_URL` without them, and the test
  broker requires a token so every suite exercises it.
- The deployment docs said `CAPTCHA_SECRET` could be left unset and redeployed
  a TOTP key rotation before storing the new key; production requires the
  secret, and the rotation now stores both keys first.
- The production image runs on distroless (no shell, no package manager): the
  Debian runtime carried two HIGH vulnerabilities in `libpcre2`. The binary and
  templates belong to root, the service runs as a numeric non-root user, and the
  image carries its version and commit as OCI labels.
- `make release` builds the image from the commit rather than the working tree,
  refuses a dirty tree, a version that differs from `Cargo.toml` or an untagged
  commit, stops on a HIGH or CRITICAL vulnerability, records the image
  identifier and signs the checksums with an SSH key. `make docker-refresh-pins`
  moves every pinned base image to its current digest; the development and test
  compose files are pinned too.
- `GET /live` (liveness, dependencies unchecked) and `GET /ready` (database,
  Redis and NATS, one second each, 503 when one is down) sit outside the rate
  limiter; `/health` stays as an alias of `/live`. The image health check calls
  `/live`: a rate-limited `/health` turned every instance unhealthy during a
  Redis outage.
- A database failure while checking a token answers 503 instead of 401, which
  signed users out during an outage and hid it from the server-error alerts.
- Domain events go through a transactional outbox: each event is recorded in
  the transaction of the change it announces and a background relay publishes
  it to JetStream in order, with its id as message id (deduplication) and
  `event_id` and `occurred_at` in the payload. An event is no longer lost when
  NATS is down, requests never wait for the broker, and a rolled-back change
  announces nothing. Registration, email verification, password changes and
  resets, session revocation and email changes now commit their writes in one
  transaction. `AuthApiEventsStalled` replaces `AuthApiEventsDropped`. Account
  deletion no longer answers 503 while NATS is down. An unreachable broker no longer stops
  the start (a refused token still does): the client reconnects in the
  background, the stream is declared before the first acknowledged event, and
  `/ready` reports NATS.
- Stopping the service drains in bounded phases that fit a 40-second stop:
  in-flight requests (32 s), then notifications and cache invalidations started
  by requests (5 s, counted in `auth_background_tasks`), then events the NATS
  client still buffers (2 s). Before, the drain had no deadline and background
  tasks and buffered events were lost at every restart.
- Notifications are capped at 1 000 pending (`auth_notifications_pending`;
  `auth_notifications_failed_total` and `auth_notifications_dropped_total` by
  task). The SMTP relay is reached through a connection pool with a 10-second
  timeout instead of a new connection per message and lettre's one-minute
  default, and a temporary refusal is retried twice (after 2 and 8 seconds).
- New metrics for the alerts: pool saturation (`auth_db_pool_connections`,
  `auth_redis_pool_connections`, `auth_redis_pool_waiting`), Redis failures by
  operation (`auth_redis_errors_total`) and cleanup results
  (`auth_cleanup_deleted_rows_total`, `auth_cleanup_failures_total`).
- Every log line of a request carries its `request_id` through a span. A
  client-supplied `X-Request-Id` is kept only when it has at most 64 letters,
  digits or `-_.:`; otherwise a new identifier replaces it.
- The `Debug` output of the configuration masks connection URLs, the JWT
  private key, the encryption keys and the SMTP and CAPTCHA secrets.
- `DB_ACQUIRE_TIMEOUT_SECS` defaults to 5 seconds instead of 30: an exhausted
  pool answers fast instead of waiting out the request timeout.
- A signing key rotation no longer makes resource servers refuse new tokens
  for up to 5 minutes. `JWT_NEXT_PUBLIC_KEY` publishes the next key in the JWKS
  and has it accepted before the signing key switches to it, and the API
  verifies a token with the key its `kid` names (a token without a known `kid`
  is tried against every key). The runbook rotation now runs in three phases.
- The API VPS runs two API instances (`api-a` and `api-b`, on loopback ports
  3001 and 3002) sized by a profile: `deploy/profiles/s.env`, `m.env` or
  `l.env`, passed with `--env-file` (`docker-compose.api.l.yml` adds two
  instances for profile L). Each instance has CPU, memory and process limits, a
  40-second stop grace period and rotated logs, and its health check calls
  `/live` every 10 seconds. `scripts/rolling-update.sh` replaces the instances
  one at a time and waits for `/ready`, so an update no longer stops the
  service. The NATS token moves to `nats-auth.conf`, mounted as a secret instead
  of a command-line argument, and JetStream storage is capped in `nats.conf`.
  Pool sizes and Argon2 concurrency leave `config.prod.env` for the profiles.
- nginx balances the API instances: an instance that refuses or fails is
  skipped for 10 seconds and the request goes to the other one, while a
  request an instance already received is never resent. Proxy timeouts are 35
  seconds (credential routes cut at 10 while a sign-in queued behind Argon2 may
  take up to 30), HEAD is allowed for uptime probes, every request is logged as
  one JSON line with the `request_id` passed on to the API, and the nginx rate
  limits sit at twice the API's so clients see the API's 429 and `Retry-After`.
- The DB VPS ships its settings in `deploy/db/`: PostgreSQL sized per profile
  (memory, connections, WAL, `pg_stat_statements`, slow statement logs) with
  session limits for the `auth_api` role (25-second statements, 10-second lock
  waits, 60 seconds idle in a transaction); Redis with `maxmemory` and
  `noeviction`, append-only persistence, the default user disabled and an
  `auth_api` ACL user without administrative or dangerous commands
  (`REDIS_URL` becomes `redis://auth_api:<password>@10.0.0.2:6379`); kernel
  settings (overcommit, swappiness, no transparent huge pages). The migrations
  vacuum `sessions` and `login_attempts` once 2 % of their rows changed
  instead of 20 %. The API VPS no longer opens a WireGuard port it never
  listened on.
- Backups fail loudly and restore safely. `backup-db.sh` reads
  `/etc/auth-api/backup.env` instead of being edited, refuses the placeholder
  key, writes through a temporary file so a failed run leaves nothing that looks
  like a backup, fails when the offsite copy fails, and writes
  `auth_backup_last_success_timestamp`, the size and the duration for
  node_exporter after a complete run only: `AuthBackupMissing` could never fire
  before, since nothing wrote its metric, and it now also fires when the metric
  is absent. `AuthBackupShrunk` warns of a backup half the size of the previous
  ones. `restore-db.sh` restores in a single transaction and `--force` empties
  the target first. The drill restores as the non-superuser owner, checks that a
  failed backup leaves nothing, that an overwrite without `--force` is refused,
  and compares every table. Profiles M and L get point-in-time recovery with
  pgBackRest (`deploy/db/pgbackrest.conf`, `postgresql.pitr.conf`).
- Monitoring moves to its own host (`deploy/monitoring/`): Prometheus,
  Alertmanager with a dead man's switch, and a blackbox probe of the public
  `/ready` and its certificate. Exporters listen on WireGuard addresses only;
  the API compose adds a NATS exporter and publishes the metrics listeners on
  `METRICS_BIND_ADDRESS`. `rules/infrastructure.yml` alerts on hosts, disks,
  PostgreSQL, Redis (including refused writes under `noeviction`), NATS, pool
  saturation, dropped events and e-mails and failing retention jobs, each with
  a promtool test. Each API instance publishes its container's memory against
  its limit, CPU throttling and start time from its cgroup
  (`auth_container_*`, `auth_process_start_time_seconds`), so the container
  alerts need no host exporter.
- The operations runbook covers a full Redis, NATS and SMTP outages and adding
  an instance; its addresses match the two-instance deployment. The
  `config.prod.env` comment no longer calls `JWT_AUDIENCE` required:
  `APP_PUBLIC_URL` is always part of the audience.
- GitHub Actions: `ci.yml` checks pull requests to `main` with one required
  check, `ci-ok`, and runs only the jobs a change concerns (formatting, clippy,
  dependency policy and every suite; deployment files; the image and Trivy);
  `scheduled.yml` runs advisories, the image scan, coverage and the long
  simulations weekly, the backup drill and fuzzing monthly, and tracks failures
  in an issue; `backmerge.yml` fast-forwards `staging` after a merge; Dependabot
  opens grouped pull requests monthly. Actions are pinned by commit, the token is
  read-only by default, and the toolchain is pinned in `rust-toolchain.toml`.
  `scripts/infra-check.sh` gains check families (`CHECKS=hygiene|static|image`),
  actionlint, a repository secret scan and an image size limit.
- `make stack-test` (`scripts/stack-smoke.sh`) runs the production compose
  with profile M behind the repository's nginx configuration and checks the
  container limits, balancing, a sign-in flow, failover, a rolling update under
  load with no failed request, the deletion event through the authenticated
  broker and a clean stop. `make sizing` (`perf/sizing.sh`) checks the profiles
  under real container quotas: sign-ins per CPU, peak memory and overload,
  Redis, NATS and PostgreSQL footprint at 100 000 and 1 million accounts, the
  restore time, and a soak at a chosen profile.
- The OpenAPI document said a password change and `DELETE /users/me/sessions`
  revoke the other sessions; both revoke every session, the current one
  included.
- `X-Forwarded-For` is read across every header line, and a hop that is not an
  address stops the walk at the trusted proxy instead of letting the value to
  its left through. `X-Real-IP` only counts without `X-Forwarded-For`. The
  bundled nginx configuration was not affected: it overwrites both headers.
- A recovery code no longer completes a pre-auth state that names no method
  (the format written before challenges were bound to their method).

### Reliability

- An unreachable PostgreSQL or Redis answers `503 service_unavailable` instead
  of `500`, including connections dropped while being set up.
- The Redis pool replaces a connection whose transport failed. Before, a Redis
  restart under traffic was never recovered from: each request failed on a dead
  connection and counted as a use, so the connection never went idle long
  enough to be checked.
- A refresh no longer fails when the Redis pool is unavailable: its per-address
  budget fails open and the database decides, as documented.

### Performance

- Indexes matched to the queries: unused ones dropped, expiry and referencing
  columns indexed.
- A sign-in writes its session, account stamp, ledger entry and audit record in
  one transaction; roles and permissions load in one query.
- Cleanups run in bounded batches under an advisory lock.
- Redis: recycled connections are pinged only after 5 seconds idle; the rate
  limiter is O(1) and checks every bucket in one script; token checks read the
  blocklist and session cache in one pipeline. Profile reads went from 1.05 ms to
  0.71 ms at p50 in the HTTP benchmark.
- Retention batches select their rows through a TID scan:
  a session purge batch at 1 million accounts went from 950 ms (the old query
  gathered the whole backlog) to about 20 ms.
- Indexes no query uses are dropped: `idx_sessions_family_active` and the
  audit log's request id index (755 MB at 1 million accounts); the internal
  `audit::find_by_request_id`, which no route called, is removed.
- The audit history page skips the empty partitions created for future months.
- The API logs its Argon2 capacity at startup and warns when the container
  memory limit cannot hold it; Argon2 saturation alerts at 5 and 15 minutes.
- Measurement campaign and report: `make perf`, `docs/perf/performance-report.md`.

### Upgrading

1. Back up the database.
2. Create the database from the migrations (see the note under **Data**).
3. Set `APP_ENV`, `FRONTEND_URL`, `DEVICE_AUTH_VERIFICATION_URI` and
   `TRUSTED_PROXY_CIDRS=172.30.0.1/32`; remove `GEOIP_*` and `RISK_*`.
4. Register the primary client, and any device or authorization code client,
   with `auth-api --register-client`.
5. Update client applications: re-authenticate before sensitive actions, and
   stop reading the account from the registration response.
6. Move client applications to the `/oauth` endpoints (**Breaking changes**),
   give confidential clients their secret
   (`POST /admin/clients/{client_id}/secret`), and set `OAUTH_CONSENT_URI` if
   the consent page is not `{FRONTEND_URL}/authorize`.
7. Appoint the first administrator with
   `auth-api --grant-role admin --user <email>`, and have them enroll a second
   factor or a passkey.
8. Review the new variables and their defaults: `MAGIC_LINK_ENABLED`,
   `PWNED_PASSWORDS_*`, `NEW_DEVICE_ALERTS_ENABLED`, `WEBAUTHN_*`,
   `IDENTITY_PROVIDERS` and `IDP_*`, `EXTERNAL_LOGIN_URI`, `WEBHOOK_*`,
   `OTEL_*`, `NATS_STREAM_REPLICAS`, `DATABASE_READ_URL`, and the retention
   variables `CLEANUP_UNVERIFIED_ACCOUNT_DAYS`, `CLEANUP_KNOWN_DEVICE_DAYS`,
   `CLEANUP_WEBHOOK_DELIVERY_DAYS`, `AUDIT_IP_RETENTION_DAYS`.
