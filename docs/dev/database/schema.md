# Database Schema

Migrations live in `migrations/` and are never edited once released: every
change is a new file. Tokens, codes and refresh tokens are stored as SHA-256
digests (32 bytes), never in clear.

## Accounts

### users

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `created_at` | TIMESTAMPTZ | No | |
| `updated_at` | TIMESTAMPTZ | No | Set by trigger |
| `email_verified_at` | TIMESTAMPTZ | Yes | |
| `last_login_at` | TIMESTAMPTZ | Yes | Last completed sign-in |
| `locked_until` | TIMESTAMPTZ | Yes | Lockout expiry after repeated wrong passwords |
| `status` | user_status | No | `pending_verification`, `active`, `inactive`, `suspended` |
| `preferred_locale` | VARCHAR(10) | No | `en`, `fr`, ... |
| `username` | VARCHAR(50) | No | Unique, case-insensitive |
| `email` | CITEXT | No | Unique, case-insensitive |
| `password_hash` | TEXT | No | Argon2id |

### roles, permissions, role_permissions, user_roles

Role-based access control. A token carries the names of the user's roles and of
the permissions those roles grant (`permissions.name` is generated as
`resource:action`). Exactly one role is `is_default` and is assigned at
registration. `user_roles.granted_by` records who granted a role.

## Sessions and tokens

### sessions

One row per refresh token. Rotation creates a new row in the same family and
marks the old one rotated.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key; `sid` claim of access tokens |
| `user_id` | UUID | No | FK -> users |
| `session_family_id` | UUID | No | Rotations of one sign-in |
| `family_created_at` | TIMESTAMPTZ | No | Start of the sign-in; the absolute lifetime counts from it |
| `token_hash` | BYTEA | No | Refresh token digest, unique |
| `created_at`, `last_used_at`, `expires_at` | TIMESTAMPTZ | No | |
| `revoked_at` | TIMESTAMPTZ | Yes | |
| `rotated_at` | TIMESTAMPTZ | Yes | |
| `replaced_by_session_id` | UUID | Yes | FK -> sessions, the successor |
| `compromised_at`, `compromise_reason` | | Yes | Set when a replay is detected |
| `session_type` | session_type | No | `web` or `device` |
| `client_id` | VARCHAR(100) | Yes | Registered client the session was issued to |
| `scopes` | TEXT[] | Yes | Permissions consented for that client; `NULL` is unrestricted |
| `ip_address`, `user_agent`, `device_name` | | Yes | |
| `remember_me` | BOOLEAN | No | |

### email_verification_tokens, password_reset_tokens

Single-use tokens (`token_hash`, `expires_at`, `used_at`). At most one active
token per user.

### authorization_codes

Authorization code flow with PKCE.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `code_hash` | BYTEA | No | Unique |
| `user_id` | UUID | No | FK -> users |
| `client_id` | VARCHAR(100) | No | FK -> registered_clients |
| `redirect_uri` | TEXT | No | Compared exactly at redemption |
| `code_challenge` | TEXT | No | S256 challenge, 43 characters |
| `code_challenge_method` | VARCHAR(10) | No | Always `S256` |
| `scopes` | TEXT[] | Yes | Consent frozen at approval |
| `expires_at` | TIMESTAMPTZ | No | One minute after issue |
| `consumed_at` | TIMESTAMPTZ | Yes | Set atomically at redemption |
| `session_id` | UUID | Yes | FK -> sessions, revoked if the code is replayed |

## Client applications

### registered_clients

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `client_id` | VARCHAR(100) | No | Primary key |
| `display_name` | VARCHAR(200) | No | Shown on consent screens |
| `is_primary` | BOOLEAN | No | The application this instance owns; at most one |
| `scopes` | TEXT[] | No | Permissions its tokens may carry; empty is unrestricted |
| `redirect_uris` | TEXT[] | No | Exact redirect URIs |
| `allows_loopback_redirect` | BOOLEAN | No | Accept loopback redirects on any port for a registered path |
| `default_max_sessions` | SMALLINT | No | Concurrent sessions per user without a quota row (the primary client is unlimited) |
| `created_at` | TIMESTAMPTZ | No | |

Managed with `auth-api --register-client`.

### user_client_quotas

Per-user override of a client's session limit: `user_id`, `client_id`,
`max_sessions` (> 0), unique per user and client.

## Second factors

### two_factor_methods

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | No | FK -> users |
| `method_type` | two_factor_type | No | `totp` or `email`, at most one of each per user |
| `is_verified` | BOOLEAN | No | |
| `is_primary` | BOOLEAN | No | At most one per user |
| `totp_secret` | TEXT | Yes | Encrypted: `v1:{key id}:{base64(nonce, ciphertext)}`, or bare base64 for values written before versioning |
| `created_at`, `updated_at`, `last_used_at` | TIMESTAMPTZ | | |

### used_totp_codes

Replay guard: `(user_id, code_hash)` primary key, `used_at`. A TOTP code is
accepted once within its validity window.

### email_2fa_codes

Codes sent during an email challenge: `code_hash`, `expires_at`, `used_at`.

### recovery_codes

`code_hash`, `code_position`, optional `expires_at`, `used_at`. Deleted with the
last second factor.

## Security records

### login_attempts

Ledger feeding brute-force limits and lockout.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | Yes | FK -> users, null for an unknown identifier |
| `attempted_at` | TIMESTAMPTZ | No | |
| `attempted_identifier` | CITEXT | No | |
| `was_successful` | BOOLEAN | No | |
| `failure_reason` | login_failure_reason | Yes | Only `invalid_password` counts toward a lockout |
| `request_ip` | INET | Yes | |
| `request_user_agent` | TEXT | Yes | Kept for failures only |

### audit_log

Append-only, partitioned by month: a trigger refuses deletes and every update
except detaching a deleted user (`user_id` to NULL) and forgetting or coarsening
a client address.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key with `created_at` |
| `created_at` | TIMESTAMPTZ | No | Partition key |
| `user_id` | UUID | Yes | FK -> users |
| `request_id` | UUID | Yes | `x-request-id` of the request |
| `action` | audit_action | No | `login`, `password_changed`, `session_replay_detected`, `encryption_key_rotated`, ... |
| `ip_address` | INET | Yes | Only the network (/24, /48) after `AUDIT_IP_RETENTION_DAYS`; removed when the account is deleted |
| `metadata` | JSONB | No | Action details, without personal data such as addresses |

## Events

### event_outbox

Domain events waiting for, or already delivered to, NATS JetStream. A service
inserts the event in the transaction of the change it announces; the relay
publishes pending rows in `seq` order and marks them published.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `seq` | BIGINT | No | Primary key, publication order |
| `id` | UUID | No | Unique; the JetStream message id and the payload's `event_id` |
| `subject` | TEXT | No | `events.auth.user.*` |
| `payload` | JSONB | No | Event fields; `occurred_at` is added from `created_at` when published |
| `created_at` | TIMESTAMPTZ | No | |
| `published_at` | TIMESTAMPTZ | Yes | Set once JetStream stored the event |
| `attempts`, `next_attempt_at`, `last_error` | | | Failed attempts and the next retry |

Published rows are kept seven days (`cleanup_published_events`).

## Retention

`cleanup_*` SQL functions take a grace interval and a batch size; the
application's cleanup task calls them in batches under an advisory lock, and
calls `rotate_audit_log_partitions(retention_months)` on every run
(`0` keeps every partition). See [Configuration](../guides/configuration.md#retention).
