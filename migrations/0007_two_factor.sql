-- Second factors: the methods a user enrolled (TOTP, e-mail codes), the e-mail
-- codes sent during a challenge, recovery codes, and the durable TOTP replay
-- guard. Retention functions are bounded like cleanup_expired_sessions.
CREATE TYPE two_factor_type AS ENUM ('totp', 'email');

CREATE TABLE two_factor_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    method_type two_factor_type NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    -- Encrypted by the application before insert.
    totp_secret TEXT,

    CONSTRAINT two_factor_primary_requires_verification CHECK (NOT is_primary OR is_verified),
    CONSTRAINT two_factor_method_payload CHECK (
        (method_type = 'totp' AND totp_secret IS NOT NULL)
        OR (method_type = 'email' AND totp_secret IS NULL)
    )
);

CREATE TRIGGER two_factor_methods_set_updated_at
    BEFORE UPDATE ON two_factor_methods
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- (user_id) alone is served by the prefix of idx_2fa_user_created.
CREATE INDEX idx_2fa_user_created ON two_factor_methods (user_id, created_at DESC);
CREATE INDEX idx_2fa_user_verified ON two_factor_methods (user_id) WHERE is_verified = TRUE;
CREATE UNIQUE INDEX idx_2fa_user_totp ON two_factor_methods (user_id) WHERE method_type = 'totp';
CREATE UNIQUE INDEX idx_2fa_user_email ON two_factor_methods (user_id) WHERE method_type = 'email';
CREATE UNIQUE INDEX idx_2fa_user_primary ON two_factor_methods (user_id) WHERE is_primary = TRUE;

-- Short-lived codes sent by e-mail during a challenge.
CREATE TABLE email_2fa_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX idx_email_2fa_codes_user ON email_2fa_codes (user_id, expires_at DESC);
CREATE INDEX idx_email_2fa_codes_expires_at ON email_2fa_codes (expires_at);

CREATE OR REPLACE FUNCTION cleanup_expired_email_2fa_codes(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM email_2fa_codes WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM email_2fa_codes
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

-- Hashed recovery codes, each consumed at most once.
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
)
WITH (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

CREATE INDEX idx_recovery_codes_user ON recovery_codes (user_id);
CREATE INDEX idx_recovery_codes_user_active
    ON recovery_codes (user_id, code_position) WHERE used_at IS NULL;
CREATE INDEX idx_recovery_codes_expires_at
    ON recovery_codes (expires_at) WHERE expires_at IS NOT NULL;

CREATE OR REPLACE FUNCTION cleanup_expired_recovery_codes(
    grace_interval INTERVAL DEFAULT '7 days',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM recovery_codes WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM recovery_codes
        WHERE expires_at IS NOT NULL AND expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

-- Durable TOTP replay guard: the SHA-256 of every accepted TOTP code, so a code
-- cannot be used twice within its validity window even when Redis (the fast
-- path) is unavailable. Codes repeat over time (6 digits, 30-second steps), so
-- rows live only for the window (current step +/- TOTP_SKEW): the repository
-- purges the user's expired rows on every attempt, and cleanup_used_totp_codes
-- sweeps the rest.
CREATE TABLE used_totp_codes (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, code_hash),
    CONSTRAINT used_totp_codes_hash_length CHECK (octet_length(code_hash) = 32)
)
-- Constant insert and delete churn: vacuum early.
WITH (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 200
);

CREATE INDEX idx_used_totp_codes_used_at ON used_totp_codes (used_at);

CREATE OR REPLACE FUNCTION cleanup_used_totp_codes(
    retention INTERVAL DEFAULT '90 seconds',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM used_totp_codes WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM used_totp_codes
        WHERE used_at < NOW() - retention
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
