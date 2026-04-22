# Database Schema

## users

Core account table.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `created_at` | TIMESTAMPTZ | No | Account creation date |
| `updated_at` | TIMESTAMPTZ | No | Last update (auto-set by trigger) |
| `email_verified_at` | TIMESTAMPTZ | Yes | When the email was verified |
| `last_login_at` | TIMESTAMPTZ | Yes | Last successful login |
| `locked_until` | TIMESTAMPTZ | Yes | Lockout expiry after failed attempts |
| `status` | user_status | No | `active`, `inactive`, `suspended`, `pending_verification` |
| `preferred_locale` | VARCHAR(10) | No | Locale code (e.g. `en`, `fr_FR`) |
| `username` | VARCHAR(50) | No | Unique, alphanumeric + underscore, 3–50 chars |
| `email` | CITEXT | No | Unique, case-insensitive |
| `password_hash` | TEXT | No | Argon2id hash |

### roles

Application roles for RBAC.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `created_at` | TIMESTAMPTZ | No | |
| `is_default` | BOOLEAN | No | Automatically assigned on registration (only one allowed) |
| `name` | VARCHAR(50) | No | Unique role name |
| `description` | TEXT | Yes | |

## permissions

Permission catalog for RBAC.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `created_at` | TIMESTAMPTZ | No | |
| `resource` | VARCHAR(50) | No | Resource name (e.g. `users`) |
| `action` | VARCHAR(50) | No | Action name (e.g. `read`) |
| `name` | TEXT | No | Generated: `resource:action` |
| `description` | TEXT | Yes | |

## role_permissions

Pivot table — roles to permissions.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `role_id` | UUID | No | FK → roles |
| `permission_id` | UUID | No | FK → permissions |

## user_roles

Pivot table — users to roles.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `user_id` | UUID | No | FK → users |
| `role_id` | UUID | No | FK → roles |
| `granted_by` | UUID | Yes | FK → users (actor who granted the role) |
| `granted_at` | TIMESTAMPTZ | No | |

## sessions

Persistent refresh token sessions with rotation and compromise detection.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | No | FK → users |
| `session_family_id` | UUID | No | Groups related sessions for family revocation |
| `token_hash` | BYTEA | No | SHA-256 of the refresh token (32 bytes) |
| `created_at` | TIMESTAMPTZ | No | |
| `last_used_at` | TIMESTAMPTZ | No | |
| `expires_at` | TIMESTAMPTZ | No | |
| `revoked_at` | TIMESTAMPTZ | Yes | Set when session is terminated |
| `rotated_at` | TIMESTAMPTZ | Yes | Set when token was rotated |
| `compromised_at` | TIMESTAMPTZ | Yes | Set on replay detection |
| `compromise_reason` | session_compromise_reason | Yes | `refresh_token_reuse`, `manual_security_action`, `credentials_rotated` |
| `replaced_by_session_id` | UUID | Yes | FK → sessions (successor after rotation) |
| `ip_address` | INET | Yes | |
| `user_agent` | TEXT | Yes | |
| `device_name` | VARCHAR(100) | Yes | |
| `remember_me` | BOOLEAN | No | |

## two_factor_methods

Second-factor registry per user.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | No | FK → users |
| `method_type` | two_factor_type | No | `totp` or `email` |
| `is_primary` | BOOLEAN | No | Only one primary method allowed per user |
| `is_verified` | BOOLEAN | No | Must be true before a method can be primary |
| `totp_secret` | TEXT | Yes | AES-256-GCM encrypted TOTP secret (only for `totp`) |
| `created_at` | TIMESTAMPTZ | No | |
| `updated_at` | TIMESTAMPTZ | No | |
| `last_used_at` | TIMESTAMPTZ | Yes | |

## email_2fa_codes

Short-lived OTP codes sent by email during a 2FA challenge.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | No | FK → users |
| `code_hash` | BYTEA | No | Hashed OTP code |
| `created_at` | TIMESTAMPTZ | No | |
| `expires_at` | TIMESTAMPTZ | No | |
| `used_at` | TIMESTAMPTZ | Yes | Set when code is consumed |

## email_verification_tokens

One-time tokens for email verification and email change flows.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | No | FK → users |
| `token_hash` | BYTEA | No | SHA-256 of the token (32 bytes) |
| `target_email` | CITEXT | No | The email address being verified |
| `created_at` | TIMESTAMPTZ | No | |
| `expires_at` | TIMESTAMPTZ | No | |
| `used_at` | TIMESTAMPTZ | Yes | Set when token is consumed |
| `request_ip` | INET | Yes | |
| `request_user_agent` | VARCHAR(255) | Yes | |

## password_reset_tokens

One-time tokens for the forgot-password flow.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | No | FK → users |
| `token_hash` | BYTEA | No | SHA-256 of the token (32 bytes) |
| `created_at` | TIMESTAMPTZ | No | |
| `expires_at` | TIMESTAMPTZ | No | |
| `used_at` | TIMESTAMPTZ | Yes | Set when token is consumed |
| `request_ip` | INET | Yes | |
| `request_user_agent` | VARCHAR(255) | Yes | |

## recovery_codes

Hashed backup codes used when the primary 2FA method is unavailable.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | No | FK → users |
| `code_hash` | BYTEA | No | SHA-256 of the code (32 bytes) |
| `code_position` | SMALLINT | No | Position in the set (1–20) |
| `created_at` | TIMESTAMPTZ | No | |
| `expires_at` | TIMESTAMPTZ | Yes | Optional expiry |
| `used_at` | TIMESTAMPTZ | Yes | Set when code is consumed |

## login_attempts

Operational ledger of authentication attempts for lockout and risk scoring.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | Yes | FK → users (null if identifier not found) |
| `attempted_at` | TIMESTAMPTZ | No | |
| `attempted_identifier` | CITEXT | No | Username or email submitted |
| `was_successful` | BOOLEAN | No | |
| `failure_reason` | login_failure_reason | Yes | `invalid_password`, `two_factor_failed`, `rate_limited`, etc. |
| `request_ip` | INET | Yes | |
| `request_user_agent` | VARCHAR(255) | Yes | |

## audit_log

Append-only security event log, partitioned by month.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Part of composite PK |
| `created_at` | TIMESTAMPTZ | No | Part of composite PK (partition key) |
| `user_id` | UUID | Yes | FK → users |
| `request_id` | UUID | Yes | Correlates with the HTTP request |
| `action` | audit_action | No | `login`, `logout`, `password_changed`, `session_revoked`, etc. |
| `ip_address` | INET | Yes | |
| `metadata` | JSONB | No | Action-specific details |

## login_locations

Behavioral history used for login risk scoring.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | No | Primary key |
| `user_id` | UUID | No | FK → users |
| `country` | TEXT | No | |
| `city` | TEXT | No | |
| `user_agent` | TEXT | No | |
| `ip_address` | INET | No | Most recent IP for this location |
| `latitude` | DOUBLE PRECISION | Yes | |
| `longitude` | DOUBLE PRECISION | Yes | |
| `first_seen` | TIMESTAMPTZ | No | |
| `last_seen` | TIMESTAMPTZ | No | Updated on each login from the same location |
