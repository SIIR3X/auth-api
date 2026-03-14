-- 0013_audit_log.sql
-- Creates the append-only audit log for security-relevant events.
-- This table is partitioned by month, optimized for long-term retention and
-- forensic analysis, and records actions like logins, role changes, 2FA events,
-- and session compromise handling.
CREATE TYPE audit_action AS ENUM (
    'login',
    'login_failed',
    'logout',
    'register',
    'email_verification_sent',
    'email_verified',
    'password_changed',
    'password_reset_requested',
    'password_reset_completed',
    'two_factor_enabled',
    'two_factor_disabled',
    'two_factor_verified',
    'two_factor_failed',
    'role_assigned',
    'role_revoked',
    'session_revoked',
    'session_replay_detected',
    'session_family_revoked',
    'account_suspended',
    'account_reactivated',
    'rate_limit_exceeded'
);

CREATE TABLE audit_log (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users (id) ON DELETE SET NULL,
    request_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action audit_action NOT NULL,
    ip_address INET,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    PRIMARY KEY (created_at, id)
) PARTITION BY RANGE (created_at);

CREATE TABLE audit_log_default
PARTITION OF audit_log DEFAULT
WITH (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01,
    autovacuum_vacuum_threshold = 2000,
    autovacuum_analyze_threshold = 1000
);

CREATE OR REPLACE FUNCTION rotate_audit_log_partitions(
    retention_months INTEGER DEFAULT 6,
    lookahead_months INTEGER DEFAULT 12
)
RETURNS VOID AS $$
DECLARE
    create_start DATE := (date_trunc('month', NOW()) - INTERVAL '1 month')::DATE;
    create_end DATE := (date_trunc('month', NOW()) + make_interval(months => lookahead_months))::DATE;
    keep_from DATE := (date_trunc('month', NOW()) - make_interval(months => retention_months))::DATE;
    month_start DATE;
    part_name TEXT;
    rel_name TEXT;
    rel_month DATE;
BEGIN
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

SELECT rotate_audit_log_partitions();

DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'pg_cron extension not installed (insufficient privilege); schedule rotate_audit_log_partitions() externally.';
            RETURN;
        WHEN undefined_file THEN
            RAISE NOTICE 'pg_cron extension is not available on this PostgreSQL instance; schedule rotate_audit_log_partitions() externally.';
            RETURN;
    END;

    IF NOT EXISTS (
        SELECT 1
        FROM cron.job
        WHERE jobname = 'audit_log_partition_rotation'
    ) THEN
        PERFORM cron.schedule(
            'audit_log_partition_rotation',
            '15 2 * * *',
            'SELECT rotate_audit_log_partitions();'
        );
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.user_id IS NOT NULL
       AND NEW.user_id IS NULL
       AND NEW.id = OLD.id
       AND NEW.request_id IS NOT DISTINCT FROM OLD.request_id
       AND NEW.created_at = OLD.created_at
       AND NEW.action = OLD.action
       AND NEW.ip_address IS NOT DISTINCT FROM OLD.ip_address
       AND NEW.metadata = OLD.metadata THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

CREATE INDEX idx_audit_log_user ON audit_log (user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_log_request ON audit_log (request_id, created_at DESC) WHERE request_id IS NOT NULL;
CREATE INDEX idx_audit_log_action ON audit_log (action, created_at DESC);
CREATE INDEX idx_audit_log_created_brin ON audit_log USING BRIN (created_at);
