-- Single-use tokens sent by e-mail: address verification (at registration and
-- for an e-mail change, bound to the exact address verified) and password
-- reset. Stored as SHA-256 hashes. Retention functions are bounded like
-- cleanup_expired_sessions.
--
-- A registration on an address whose account is still pending verification
-- carries its own credentials in its verification link: whoever clicks a link
-- activates the account with the password chosen by the registration that sent
-- it, so registering someone's address first never lets an attacker decide the
-- password the owner activates. The links of a pending account therefore
-- coexist until one of them is used, which revokes the others; so do the links
-- of a password reset.
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    request_ip INET,
    request_user_agent TEXT,
    target_email CITEXT NOT NULL,
    -- Credentials of the registration that sent the link, all or none.
    password_hash TEXT,
    username VARCHAR(50),
    preferred_locale VARCHAR(10),

    CONSTRAINT email_verification_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT email_verification_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT email_verification_tokens_expires_after_creation CHECK (expires_at > created_at),
    CONSTRAINT email_verification_tokens_used_after_creation CHECK (used_at IS NULL OR used_at >= created_at),
    CONSTRAINT email_verification_tokens_target_email_format CHECK (
        target_email ~* '^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$'
    ),
    CONSTRAINT email_verification_tokens_credentials_together CHECK (
        (password_hash IS NULL) = (username IS NULL)
        AND (password_hash IS NULL) = (preferred_locale IS NULL)
    ),
    CONSTRAINT email_verification_tokens_username_format CHECK (
        username IS NULL OR username ~ '^[a-zA-Z0-9_]{3,50}$'
    ),
    CONSTRAINT email_verification_tokens_locale_format CHECK (
        preferred_locale IS NULL OR preferred_locale ~ '^[a-z]{2}(_[A-Z]{2})?$'
    )
)
WITH (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

CREATE INDEX idx_email_verification_tokens_user ON email_verification_tokens (user_id);
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens (expires_at);

-- A username asked for by a registration on an address that already has an
-- account stays reserved as long as the registration's link would live: the
-- next registration asking for it is refused as if an account held it, so
-- whether a username is taken never tells whether an address is registered.
-- One reservation per registered address at a time: each registration on it
-- replaces the previous one, so nobody squats usernames in bulk through an
-- address they own.
CREATE TABLE username_reservations (
    username VARCHAR(50) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    reserved_for UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    CONSTRAINT username_reservations_username_format CHECK (
        username ~ '^[a-zA-Z0-9_]{3,50}$'
    )
);

CREATE UNIQUE INDEX username_reservations_username_lower_key
    ON username_reservations (lower(username));
CREATE UNIQUE INDEX username_reservations_reserved_for_key ON username_reservations (reserved_for);
CREATE INDEX idx_username_reservations_expires_at ON username_reservations (expires_at);

-- Expired reservations go with the expired links they shadowed.
CREATE OR REPLACE FUNCTION cleanup_expired_email_verification_tokens(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM email_verification_tokens WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM email_verification_tokens
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    DELETE FROM username_reservations WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM username_reservations
        WHERE expires_at < NOW()
        LIMIT batch_size
    ));
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    request_ip INET,
    request_user_agent TEXT,

    CONSTRAINT password_reset_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT password_reset_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT password_reset_tokens_expires_after_creation CHECK (expires_at > created_at),
    CONSTRAINT password_reset_tokens_used_after_creation CHECK (used_at IS NULL OR used_at >= created_at)
)
WITH (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

CREATE INDEX idx_password_reset_tokens_user ON password_reset_tokens (user_id);
-- Pending links of an account, revoked together when one is used.
CREATE INDEX idx_password_reset_tokens_user_active
    ON password_reset_tokens (user_id) WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);

CREATE OR REPLACE FUNCTION cleanup_expired_password_reset_tokens(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM password_reset_tokens WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM password_reset_tokens
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
