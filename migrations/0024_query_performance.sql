-- 0024_query_performance.sql
-- Index set matched to the queries the application runs, bounded cleanups, and
-- a single scheduler for retention.
--
-- Plain (transactional) index builds: PostgreSQL refuses CREATE INDEX
-- CONCURRENTLY in a multi-statement migration. On a large existing deployment,
-- create the new indexes CONCURRENTLY by hand before upgrading; the IF NOT
-- EXISTS clauses below then make this migration a no-op for them.

-- Indexes no query uses: each one only costs writes.
DROP INDEX IF EXISTS idx_users_status;
DROP INDEX IF EXISTS idx_users_last_login;
-- (user_id) is the prefix of idx_2fa_user_created.
DROP INDEX IF EXISTS idx_2fa_user;
-- Brute-force counters only look at failures: idx_login_attempts_failed_identifier_time.
DROP INDEX IF EXISTS idx_login_attempts_identifier_time;
-- Retention deletes by range: the BRIN index serves it at a fraction of the size.
DROP INDEX IF EXISTS idx_login_attempts_attempted_at;
-- Written on every audited event, read by no route.
DROP INDEX IF EXISTS idx_audit_log_action;

-- Cleanups delete by expiry whatever the row's state; partial indexes limited
-- to unused or unrevoked rows could not serve them.
DROP INDEX IF EXISTS idx_sessions_expires_active;
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked_at ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;

DROP INDEX IF EXISTS idx_password_reset_tokens_expires_active;
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);

DROP INDEX IF EXISTS idx_email_verification_tokens_expires_active;
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_expires_at ON email_verification_tokens (expires_at);

DROP INDEX IF EXISTS idx_recovery_codes_expires_active;
CREATE INDEX IF NOT EXISTS idx_recovery_codes_expires_at ON recovery_codes (expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_email_2fa_codes_expires_at ON email_2fa_codes (expires_at);
CREATE INDEX IF NOT EXISTS idx_used_totp_codes_used_at ON used_totp_codes (used_at);

-- Referencing columns: without an index, deleting a user (or a session) scans
-- every referencing table. The existing user_id indexes are partial.
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user ON email_verification_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes (user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_granted_by ON user_roles (granted_by) WHERE granted_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_authorization_codes_session ON authorization_codes (session_id) WHERE session_id IS NOT NULL;

-- Bounded cleanups. Each call deletes at most batch_size rows (NULL: all) so
-- the application can sweep a large backlog in short transactions instead of
-- one long one holding locks and bloating WAL.
DROP FUNCTION IF EXISTS cleanup_expired_sessions(INTERVAL);
CREATE FUNCTION cleanup_expired_sessions(
    grace_interval INTERVAL DEFAULT '7 days',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM sessions WHERE ctid IN (
        SELECT ctid FROM sessions
        WHERE expires_at < NOW() - grace_interval
        UNION
        SELECT ctid FROM sessions
        WHERE revoked_at IS NOT NULL AND revoked_at < NOW() - grace_interval
        LIMIT batch_size
    );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS cleanup_expired_email_2fa_codes(INTERVAL);
CREATE FUNCTION cleanup_expired_email_2fa_codes(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM email_2fa_codes WHERE ctid IN (
        SELECT ctid FROM email_2fa_codes
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS cleanup_expired_email_verification_tokens(INTERVAL);
CREATE FUNCTION cleanup_expired_email_verification_tokens(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM email_verification_tokens WHERE ctid IN (
        SELECT ctid FROM email_verification_tokens
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS cleanup_expired_password_reset_tokens(INTERVAL);
CREATE FUNCTION cleanup_expired_password_reset_tokens(
    grace_interval INTERVAL DEFAULT '1 day',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM password_reset_tokens WHERE ctid IN (
        SELECT ctid FROM password_reset_tokens
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS cleanup_expired_recovery_codes(INTERVAL);
CREATE FUNCTION cleanup_expired_recovery_codes(
    grace_interval INTERVAL DEFAULT '7 days',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM recovery_codes WHERE ctid IN (
        SELECT ctid FROM recovery_codes
        WHERE expires_at IS NOT NULL AND expires_at < NOW() - grace_interval
        LIMIT batch_size
    );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS cleanup_old_login_attempts(INTERVAL);
CREATE FUNCTION cleanup_old_login_attempts(
    retention_interval INTERVAL DEFAULT '90 days',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM login_attempts WHERE ctid IN (
        SELECT ctid FROM login_attempts
        WHERE attempted_at < NOW() - retention_interval
        LIMIT batch_size
    );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS cleanup_used_totp_codes(INTERVAL);
CREATE FUNCTION cleanup_used_totp_codes(
    retention INTERVAL DEFAULT '90 seconds',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM used_totp_codes WHERE ctid IN (
        SELECT ctid FROM used_totp_codes
        WHERE used_at < NOW() - retention
        LIMIT batch_size
    );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS cleanup_expired_authorization_codes(INTERVAL);
CREATE FUNCTION cleanup_expired_authorization_codes(
    grace_interval INTERVAL DEFAULT '1 hour',
    batch_size INTEGER DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM authorization_codes WHERE ctid IN (
        SELECT ctid FROM authorization_codes
        WHERE expires_at < NOW() - grace_interval
        LIMIT batch_size
    );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

-- Audit partition rotation.
--   * retention_months <= 0 keeps every partition ("keep forever", as the
--     configuration documents); it used to drop everything before this month;
--   * at least one month of lookahead is always created;
--   * concurrent callers (several instances starting together) are serialized.
CREATE OR REPLACE FUNCTION rotate_audit_log_partitions(
    retention_months INTEGER DEFAULT 6,
    lookahead_months INTEGER DEFAULT 12
)
RETURNS VOID AS $$
DECLARE
    create_start DATE := (date_trunc('month', NOW()) - INTERVAL '1 month')::DATE;
    create_end DATE := (date_trunc('month', NOW()) + make_interval(months => GREATEST(lookahead_months, 1)))::DATE;
    keep_from DATE := (date_trunc('month', NOW()) - make_interval(months => GREATEST(retention_months, 0)))::DATE;
    month_start DATE;
    part_name TEXT;
    rel_name TEXT;
    rel_month DATE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('rotate_audit_log_partitions', 0));

    FOR month_start IN
        SELECT generate_series(create_start, create_end, INTERVAL '1 month')::DATE
    LOOP
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS audit_log_%s PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L) WITH (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.01, autovacuum_vacuum_threshold = 2000, autovacuum_analyze_threshold = 1000);',
            to_char(month_start, 'YYYY_MM'),
            month_start,
            (month_start + INTERVAL '1 month')::DATE
        );
    END LOOP;

    IF retention_months <= 0 THEN
        RETURN;
    END IF;

    FOR rel_name IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'audit_log'
          AND c.relname ~ '^audit_log_[0-9]{4}_[0-9]{2}$'
    LOOP
        part_name := substring(rel_name from '^audit_log_([0-9]{4}_[0-9]{2})$');
        rel_month := to_date(part_name, 'YYYY_MM');
        IF rel_month < keep_from THEN
            EXECUTE format('DROP TABLE IF EXISTS %I;', rel_name);
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- One scheduler. The pg_cron jobs from 0014, 0017 and 0019 ran with the SQL
-- defaults, not the configured retention: with AUDIT_LOG_RETENTION_MONTHS=12
-- the nightly job still dropped audit months 7 to 12. The application's
-- cleanup task, driven by the configuration, is now the only one.
DO $$
DECLARE
    job TEXT;
BEGIN
    IF to_regclass('cron.job') IS NULL THEN
        RETURN;
    END IF;
    FOR job IN
        SELECT jobname FROM cron.job WHERE jobname IN (
            'audit_log_partition_rotation',
            'cleanup_expired_sessions',
            'cleanup_expired_email_2fa_codes',
            'cleanup_expired_email_verification_tokens',
            'cleanup_expired_password_reset_tokens',
            'cleanup_expired_recovery_codes',
            'cleanup_old_login_attempts',
            'cleanup_used_totp_codes'
        )
    LOOP
        PERFORM cron.unschedule(job);
    END LOOP;
END;
$$;
