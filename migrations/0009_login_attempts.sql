-- Sign-in attempts, successful and failed: brute-force counters, lockout, and
-- the security history of an account. Kept 90 days by default.
CREATE TYPE login_failure_reason AS ENUM (
    'unknown_identifier',
    'invalid_password',
    'email_not_verified',
    'account_inactive',
    'account_suspended',
    'account_disabled',
    'two_factor_required',
    'two_factor_failed',
    'rate_limited'
);

CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users (id) ON DELETE SET NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempted_identifier CITEXT NOT NULL,
    was_successful BOOLEAN NOT NULL,
    failure_reason login_failure_reason,
    request_ip INET,
    request_user_agent TEXT,

    CONSTRAINT login_attempts_identifier_not_blank CHECK (
        char_length(btrim(attempted_identifier::TEXT)) > 0
    ),
    CONSTRAINT login_attempts_failure_reason_consistency CHECK (
        (was_successful AND failure_reason IS NULL)
        OR (NOT was_successful AND failure_reason IS NOT NULL)
    )
)
-- An insert per sign-in attempt and a purge by age: vacuum, freeze and analyze
-- at 2 %, 2 % and 1 % of changed rows instead of the defaults.
WITH (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_vacuum_insert_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);

CREATE INDEX idx_login_attempts_user_time
    ON login_attempts (user_id, attempted_at DESC) WHERE user_id IS NOT NULL;
-- Brute-force counters only count failures.
CREATE INDEX idx_login_attempts_failed_identifier_time
    ON login_attempts (attempted_identifier, attempted_at DESC) WHERE was_successful = FALSE;
CREATE INDEX idx_login_attempts_failed_ip_time
    ON login_attempts (request_ip, attempted_at DESC)
    WHERE was_successful = FALSE AND request_ip IS NOT NULL;
-- Retention deletes by age: a BRIN index serves it at a fraction of a B-tree.
CREATE INDEX idx_login_attempts_time_brin ON login_attempts USING BRIN (attempted_at);

-- Bounded like cleanup_expired_sessions. The BRIN index is selective only while
-- rows sit on disk in time order, as the API writes them: see "Bulk Imports" in
-- the operations runbook for data loaded in another order.
CREATE OR REPLACE FUNCTION cleanup_old_login_attempts(
    retention_interval INTERVAL DEFAULT '90 days',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM login_attempts WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM login_attempts
        WHERE attempted_at < NOW() - retention_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;
