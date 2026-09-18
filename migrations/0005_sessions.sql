-- Sessions: one row per refresh token. A refresh rotates the session into a new
-- row of the same family; replaying a rotated token revokes the whole family.
-- token_hash is the SHA-256 of the refresh token, never the token itself.
CREATE TYPE session_type AS ENUM ('web', 'device');

CREATE TYPE session_compromise_reason AS ENUM (
    'refresh_token_reuse',
    'manual_security_action',
    'credentials_rotated'
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_family_id UUID NOT NULL DEFAULT gen_random_uuid(),
    -- Start of the sign-in the family comes from: the absolute session lifetime
    -- (JWT_MAX_SESSION_LIFETIME_SECS) counts from it, not from the latest rotation.
    family_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    compromised_at TIMESTAMPTZ,
    compromise_reason session_compromise_reason,
    replaced_by_session_id UUID REFERENCES sessions (id) ON DELETE SET NULL,
    token_hash BYTEA NOT NULL,
    session_type session_type NOT NULL DEFAULT 'web',
    client_id VARCHAR(100),
    -- Permissions consented for the client the session was issued to; NULL for
    -- an unrestricted session.
    scopes TEXT[],
    ip_address INET,
    user_agent TEXT,
    device_name VARCHAR(100),
    remember_me BOOLEAN NOT NULL DEFAULT FALSE,

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
)
-- The table changes fast (a row per sign-in and per refresh): vacuum and
-- analyze at 2 % and 1 % of changed rows instead of the default 20 % and 10 %,
-- so it does not bloat and the planner's statistics stay current.
WITH (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

-- Deleting a user reads its sessions through this index.
CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_user_active ON sessions (user_id, last_used_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_family_created ON sessions (session_family_id, created_at DESC);
CREATE UNIQUE INDEX idx_sessions_replaced_by
    ON sessions (replaced_by_session_id) WHERE replaced_by_session_id IS NOT NULL;
-- Retention deletes by expiry and by revocation, whatever the row's state.
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX idx_sessions_revoked_at ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;

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

-- Retention, called by the application's cleanup task. Each call deletes at
-- most batch_size rows (NULL: all), so a backlog is swept in short
-- transactions. Rows are selected with `ctid = ANY (ARRAY(SELECT ... LIMIT n))`,
-- a TID scan over exactly the rows found: `ctid IN (...)` hashed the whole
-- candidate set first (950 ms against 20 ms for a 5 000-row batch at 1 million
-- accounts). Expired sessions go first, then revoked ones, each through its
-- own index and within what is left of the batch.
CREATE OR REPLACE FUNCTION cleanup_expired_sessions(
    grace_interval INTERVAL DEFAULT '7 days',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    expired INTEGER;
    revoked INTEGER;
BEGIN
    DELETE FROM sessions WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM sessions
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS expired = ROW_COUNT;
    IF batch_size IS NOT NULL AND expired >= batch_size THEN
        RETURN expired;
    END IF;

    -- NULL batch_size stays NULL: no limit.
    DELETE FROM sessions WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM sessions
        WHERE revoked_at IS NOT NULL AND revoked_at < NOW() - grace_interval
        LIMIT batch_size - expired
    ));
    GET DIAGNOSTICS revoked = ROW_COUNT;
    RETURN expired + revoked;
END;
$$ LANGUAGE plpgsql;
