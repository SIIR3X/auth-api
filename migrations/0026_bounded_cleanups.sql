-- 0026_bounded_cleanups.sql
-- Findings of the performance campaign (docs/perf/performance-report.md).
--
-- 1. Cleanups select their rows with `ctid = ANY (ARRAY(SELECT ... LIMIT n))`:
--    a TID scan over exactly the n rows found. `ctid IN (SELECT ... LIMIT n)`
--    hashed the candidates first, and the session purge's UNION collected and
--    deduplicated the whole backlog before keeping n rows: at 1 million
--    accounts, 4.9 million candidates and 113 MB spilled to disk for a
--    5 000-row batch (950 ms, against 20 ms with the plan below).
-- 2. The session purge deletes expired sessions, then revoked ones, each
--    bounded by what is left of the batch and read through its own index.
-- 3. Two indexes no query uses are dropped; both were updated on every insert:
--    - idx_sessions_family_active: revoke_session_family filters on
--      `revoked_at IS NULL OR compromised_at IS NULL OR ...`, which this partial
--      index cannot serve (idx_sessions_family_created does);
--    - idx_audit_log_request: no route searches the audit log by request id
--      (755 MB at 1 million accounts).

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

CREATE OR REPLACE FUNCTION cleanup_expired_email_verification_tokens(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM email_verification_tokens WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM email_verification_tokens
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_expired_password_reset_tokens(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM password_reset_tokens WHERE ctid = ANY (ARRAY(
        SELECT ctid FROM password_reset_tokens
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    ));
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

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

-- The BRIN index on attempted_at makes this selective only while rows sit on
-- disk in time order, as the API writes them. See "Bulk Imports" in the
-- operations runbook for data loaded in another order.
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

DROP INDEX IF EXISTS idx_sessions_family_active;
DROP INDEX IF EXISTS idx_audit_log_request;
