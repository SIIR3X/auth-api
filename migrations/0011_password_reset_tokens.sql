-- 0011_password_reset_tokens.sql
-- Creates one-time password reset tokens for "forgot password" workflows.
-- Tokens are stored as hashes only, expire automatically, and are consumed once
-- to avoid replay or reuse after a successful password change.
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    request_ip INET,
    request_user_agent VARCHAR(255),

    CONSTRAINT password_reset_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT password_reset_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT password_reset_tokens_expires_after_creation CHECK (expires_at > created_at),
    CONSTRAINT password_reset_tokens_used_after_creation CHECK (used_at IS NULL OR used_at >= created_at)
);

CREATE UNIQUE INDEX idx_password_reset_tokens_user_active
    ON password_reset_tokens (user_id) WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_tokens_expires_active
    ON password_reset_tokens (expires_at) WHERE used_at IS NULL;

ALTER TABLE password_reset_tokens SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);
