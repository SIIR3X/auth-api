-- 0010_email_verification_tokens.sql
-- Creates one-time email verification tokens.
-- Used both for initial registration verification and for email change flows,
-- with single-use semantics, expiration, and the exact target email being verified.
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
);

CREATE UNIQUE INDEX idx_email_verification_tokens_user_active
    ON email_verification_tokens (user_id) WHERE used_at IS NULL;
CREATE INDEX idx_email_verification_tokens_expires_active
    ON email_verification_tokens (expires_at) WHERE used_at IS NULL;

ALTER TABLE email_verification_tokens SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

CREATE OR REPLACE FUNCTION cleanup_expired_email_verification_tokens(
    grace_interval INTERVAL DEFAULT '1 day'
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    WITH deleted_rows AS (
        DELETE FROM email_verification_tokens
        WHERE expires_at < NOW() - grace_interval
        RETURNING id
    )
    SELECT count(*) INTO deleted FROM deleted_rows;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
