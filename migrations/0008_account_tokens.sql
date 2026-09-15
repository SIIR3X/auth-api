-- Single-use tokens sent by e-mail: address verification (at registration and
-- for an e-mail change, bound to the exact address verified) and password
-- reset. Stored as SHA-256 hashes; at most one unused token per user.
-- Retention functions are bounded like cleanup_expired_sessions.
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

    CONSTRAINT email_verification_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT email_verification_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT email_verification_tokens_expires_after_creation CHECK (expires_at > created_at),
    CONSTRAINT email_verification_tokens_used_after_creation CHECK (used_at IS NULL OR used_at >= created_at),
    CONSTRAINT email_verification_tokens_target_email_format CHECK (
        target_email ~* '^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$'
    )
)
WITH (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

CREATE INDEX idx_email_verification_tokens_user ON email_verification_tokens (user_id);
CREATE UNIQUE INDEX idx_email_verification_tokens_user_active
    ON email_verification_tokens (user_id) WHERE used_at IS NULL;
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens (expires_at);

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
CREATE UNIQUE INDEX idx_password_reset_tokens_user_active
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
