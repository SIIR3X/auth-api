-- Authorization code flow with PKCE (RFC 6749 section 4.1, RFC 7636, RFC 8252).
--
-- A code is a single-use bearer of a user's consent, stored as a SHA-256 hash
-- like every other token: a database read must not yield something redeemable.
CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash BYTEA NOT NULL,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id VARCHAR(100) NOT NULL REFERENCES registered_clients (client_id) ON DELETE CASCADE,
    -- Compared exactly at redemption (RFC 6749 section 4.1.3).
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256',
    -- Consented scopes, frozen at approval; NULL for an unrestricted client.
    scopes TEXT[],
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    -- Session issued from the code, revoked if the code is ever replayed.
    session_id UUID REFERENCES sessions (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT authorization_codes_code_hash_key UNIQUE (code_hash),
    CONSTRAINT authorization_codes_code_hash_length CHECK (octet_length(code_hash) = 32),
    CONSTRAINT authorization_codes_method_supported CHECK (code_challenge_method = 'S256'),
    CONSTRAINT authorization_codes_challenge_format CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$')
);

CREATE INDEX idx_authorization_codes_expires ON authorization_codes (expires_at);
CREATE INDEX idx_authorization_codes_user ON authorization_codes (user_id);
-- Deleting a session clears the reference through this index.
CREATE INDEX idx_authorization_codes_session
    ON authorization_codes (session_id) WHERE session_id IS NOT NULL;

-- Consumed codes are kept past expiry for a grace period, so a replay still
-- finds the row it replays and revokes the session it produced. Bounded like
-- cleanup_expired_sessions.
CREATE OR REPLACE FUNCTION cleanup_expired_authorization_codes(
    grace_interval INTERVAL DEFAULT '1 hour',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM authorization_codes WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM authorization_codes
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
