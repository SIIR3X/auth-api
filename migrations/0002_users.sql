-- 0002_users.sql
-- Creates the core users table used by the API for authentication and profile data.
-- Stores account identity, lifecycle status, locale preference, verification state,
-- and password hash metadata. Also defines the generic updated_at trigger reused later.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

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
    status user_status NOT NULL DEFAULT 'pending_verification',
    preferred_locale VARCHAR(10) NOT NULL DEFAULT 'en',
    username VARCHAR(50) NOT NULL,
    email CITEXT NOT NULL,
    password_hash TEXT NOT NULL,

    CONSTRAINT users_username_key UNIQUE (username),
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

CREATE INDEX idx_users_status ON users (status);
CREATE INDEX idx_users_last_login ON users (last_login_at);
CREATE INDEX idx_users_locked_until ON users (locked_until) WHERE locked_until IS NOT NULL;
