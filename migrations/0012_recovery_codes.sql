-- 0012_recovery_codes.sql
-- Creates hashed recovery codes used as backup access factors.
-- These codes allow account recovery when the primary second factor is unavailable
-- and are tracked individually so each code can be consumed exactly once.
CREATE TABLE recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ,
    code_position SMALLINT NOT NULL,
    code_hash BYTEA NOT NULL,

    CONSTRAINT recovery_codes_code_hash_key UNIQUE (code_hash),
    CONSTRAINT recovery_codes_user_position_key UNIQUE (user_id, code_position),
    CONSTRAINT recovery_codes_code_hash_length CHECK (octet_length(code_hash) = 32),
    CONSTRAINT recovery_codes_position_range CHECK (code_position BETWEEN 1 AND 20),
    CONSTRAINT recovery_codes_expiration_consistency CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT recovery_codes_used_after_creation CHECK (used_at IS NULL OR used_at >= created_at)
);

CREATE INDEX idx_recovery_codes_user_active
    ON recovery_codes (user_id, code_position) WHERE used_at IS NULL;
CREATE INDEX idx_recovery_codes_expires_active
    ON recovery_codes (expires_at) WHERE used_at IS NULL AND expires_at IS NOT NULL;

ALTER TABLE recovery_codes SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

CREATE OR REPLACE FUNCTION cleanup_expired_recovery_codes(
    grace_interval INTERVAL DEFAULT '7 days'
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    WITH deleted_rows AS (
        DELETE FROM recovery_codes
        WHERE expires_at IS NOT NULL AND expires_at < NOW() - grace_interval
        RETURNING id
    )
    SELECT count(*) INTO deleted FROM deleted_rows;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
