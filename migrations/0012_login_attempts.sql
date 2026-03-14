-- 0012_login_attempts.sql
-- Creates the operational login-attempt ledger.
-- Stores recent successful and failed authentication attempts for brute-force
-- detection, risk scoring, lockout logic, and support/security investigations.
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
    request_user_agent VARCHAR(255),

    CONSTRAINT login_attempts_identifier_not_blank CHECK (
        char_length(btrim(attempted_identifier::TEXT)) > 0
    ),
    CONSTRAINT login_attempts_failure_reason_consistency CHECK (
        (was_successful AND failure_reason IS NULL)
        OR (NOT was_successful AND failure_reason IS NOT NULL)
    )
);

CREATE INDEX idx_login_attempts_identifier_time
    ON login_attempts (attempted_identifier, attempted_at DESC);
CREATE INDEX idx_login_attempts_user_time
    ON login_attempts (user_id, attempted_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX idx_login_attempts_failed_identifier_time
    ON login_attempts (attempted_identifier, attempted_at DESC) WHERE was_successful = FALSE;
CREATE INDEX idx_login_attempts_failed_ip_time
    ON login_attempts (request_ip, attempted_at DESC)
    WHERE was_successful = FALSE AND request_ip IS NOT NULL;
CREATE INDEX idx_login_attempts_attempted_at ON login_attempts (attempted_at);

ALTER TABLE login_attempts SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_threshold = 500
);
