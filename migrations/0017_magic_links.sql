-- Sign-in links sent by email, for deployments that enable them
-- (MAGIC_LINK_ENABLED). The link replaces the password, never the second factor.
CREATE TABLE magic_link_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    request_ip INET,
    request_user_agent TEXT,

    CONSTRAINT magic_link_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT magic_link_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT magic_link_tokens_expires_after_creation CHECK (expires_at > created_at),
    CONSTRAINT magic_link_tokens_used_after_creation CHECK (used_at IS NULL OR used_at >= created_at)
);

-- A new link replaces the pending ones of the account.
CREATE INDEX idx_magic_link_tokens_user_pending ON magic_link_tokens (user_id) WHERE used_at IS NULL;
CREATE INDEX idx_magic_link_tokens_expires ON magic_link_tokens (expires_at);

CREATE OR REPLACE FUNCTION cleanup_expired_magic_link_tokens(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM magic_link_tokens WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM magic_link_tokens
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'magic_link_sent';
