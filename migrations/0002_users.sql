-- User accounts: identity, lifecycle status, locale, verification state and
-- password hash.
CREATE TYPE user_status AS ENUM (
    'active',
    'inactive',
    'suspended',
    'pending_verification'
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    email_verified_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    locked_until TIMESTAMPTZ,
    -- An administrator unlocking an account also forgives the failed sign-ins
    -- that locked it: consecutive failures count from the later of the last
    -- success and this date.
    lockout_cleared_at TIMESTAMPTZ,
    status user_status NOT NULL DEFAULT 'pending_verification',
    preferred_locale VARCHAR(10) NOT NULL DEFAULT 'en',
    username VARCHAR(50) NOT NULL,
    email CITEXT NOT NULL,
    password_hash TEXT NOT NULL,

    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_username_format CHECK (username ~ '^[a-zA-Z0-9_]{3,50}$'),
    CONSTRAINT users_locale_format CHECK (preferred_locale ~ '^[a-z]{2}(_[A-Z]{2})?$'),
    CONSTRAINT users_email_format CHECK (email ~* '^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$'),
    CONSTRAINT users_password_hash_min_length CHECK (char_length(password_hash) >= 40),
    CONSTRAINT users_status_email_verification_consistency CHECK (
        (status = 'pending_verification' AND email_verified_at IS NULL)
        OR (status <> 'pending_verification' AND email_verified_at IS NOT NULL)
    )
);

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Usernames are unique whatever their case: `Alice` and `alice` never coexist,
-- one impersonating the other. The same index serves the sign-in lookup and,
-- through text_pattern_ops, administrators searching by the start of a name.
CREATE UNIQUE INDEX users_username_lower_key ON users ((lower(username::text)) text_pattern_ops);

-- Administrators search accounts by the start of an address.
CREATE INDEX idx_users_email_prefix ON users ((lower(email::text)) text_pattern_ops);
-- Listing pages newest first.
CREATE INDEX idx_users_created ON users (created_at DESC, id DESC);
-- The purge of never-verified accounts reads them by age.
CREATE INDEX idx_users_pending_created
    ON users (created_at) WHERE status = 'pending_verification';

-- Only locked accounts are looked up by lockout expiry.
CREATE INDEX idx_users_locked_until ON users (locked_until) WHERE locked_until IS NOT NULL;
