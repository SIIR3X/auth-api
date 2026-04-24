-- 0007_sessions.sql
-- Creates persistent user sessions used for login state, refresh-token rotation,
-- per-device visibility, revocation, and compromise detection.
-- token_hash stores the SHA-256 of the actual token; plaintext tokens are never persisted.
CREATE TYPE session_compromise_reason AS ENUM (
    'refresh_token_reuse',
    'manual_security_action',
    'credentials_rotated'
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_family_id UUID NOT NULL DEFAULT gen_random_uuid(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    compromised_at TIMESTAMPTZ,
    replaced_by_session_id UUID REFERENCES sessions (id) ON DELETE SET NULL,
    ip_address INET,
    device_name VARCHAR(100),
    remember_me BOOLEAN NOT NULL DEFAULT false,
    token_hash BYTEA NOT NULL,
    user_agent TEXT,
    compromise_reason session_compromise_reason,

    CONSTRAINT sessions_token_hash_key UNIQUE (token_hash),
    CONSTRAINT sessions_expires_after_creation CHECK (expires_at > created_at),
    CONSTRAINT sessions_revoked_after_creation CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CONSTRAINT sessions_rotated_after_creation CHECK (rotated_at IS NULL OR rotated_at >= created_at),
    CONSTRAINT sessions_compromised_after_creation CHECK (
        compromised_at IS NULL OR compromised_at >= created_at
    ),
    CONSTRAINT sessions_replacement_metadata_consistency CHECK (
        (replaced_by_session_id IS NULL AND rotated_at IS NULL)
        OR (replaced_by_session_id IS NOT NULL AND rotated_at IS NOT NULL AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT sessions_compromise_metadata_consistency CHECK (
        (compromised_at IS NULL AND compromise_reason IS NULL)
        OR (compromised_at IS NOT NULL AND compromise_reason IS NOT NULL AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT sessions_not_self_replaced CHECK (
        replaced_by_session_id IS NULL OR replaced_by_session_id <> id
    ),
    CONSTRAINT sessions_token_hash_length CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX idx_sessions_user_active ON sessions (user_id, last_used_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_expires_active ON sessions (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_family_created ON sessions (session_family_id, created_at DESC);
CREATE INDEX idx_sessions_family_active
    ON sessions (session_family_id, last_used_at DESC) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX idx_sessions_replaced_by
    ON sessions (replaced_by_session_id) WHERE replaced_by_session_id IS NOT NULL;

CREATE OR REPLACE FUNCTION revoke_session_family(
    p_session_id UUID,
    p_reason session_compromise_reason DEFAULT 'refresh_token_reuse'
)
RETURNS INTEGER AS $$
DECLARE
    target_family_id UUID;
    affected_rows INTEGER;
BEGIN
    SELECT session_family_id
    INTO target_family_id
    FROM sessions
    WHERE id = p_session_id;

    IF target_family_id IS NULL THEN
        RAISE EXCEPTION 'session % does not exist', p_session_id;
    END IF;

    UPDATE sessions
    SET revoked_at = COALESCE(revoked_at, NOW()),
        compromised_at = COALESCE(compromised_at, NOW()),
        compromise_reason = COALESCE(compromise_reason, p_reason)
    WHERE session_family_id = target_family_id
      AND (
          revoked_at IS NULL
          OR compromised_at IS NULL
          OR compromise_reason IS NULL
      );

    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    RETURN affected_rows;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE sessions SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

CREATE OR REPLACE FUNCTION cleanup_expired_sessions(
    grace_interval INTERVAL DEFAULT '7 days'
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    WITH deleted_rows AS (
        DELETE FROM sessions
        WHERE expires_at < NOW() - grace_interval
           OR (revoked_at IS NOT NULL AND revoked_at < NOW() - grace_interval)
        RETURNING id
    )
    SELECT count(*) INTO deleted FROM deleted_rows;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
