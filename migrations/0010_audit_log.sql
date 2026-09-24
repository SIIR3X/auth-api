-- Append-only audit log of security events, partitioned by month.
--
-- Partitions are created and dropped by rotate_audit_log_partitions(), which the
-- application calls at startup and from its cleanup task with the configured
-- retention; the application is the only scheduler.
--
-- Functions doing what the runtime role may not do by itself, once the schema
-- belongs to a separate owner role (deploy/db/auth-api-grants.sql), run with
-- their owner's privileges and a fixed search path, and only the roles the
-- grants name may call them. A deployment where one role owns and uses the
-- schema is unchanged: the owner runs its own functions.
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
    'rate_limit_exceeded',
    'suspicious_login',
    'new_device_login',
    'account_deleted',
    'reauthenticated',
    'username_changed',
    'recovery_code_used',
    'email_changed',
    'encryption_key_rotated',
    'data_exported',
    'magic_link_sent',
    'personal_access_token_created',
    'personal_access_token_revoked',
    'passkey_registered',
    'passkey_removed',
    'external_identity_linked',
    'external_identity_unlinked',
    -- Administrative changes.
    'account_unlocked',
    'password_reset_forced',
    'access_factors_removed',
    'role_created',
    'role_deleted',
    'role_permissions_changed',
    'client_registered',
    'client_updated',
    'client_deleted',
    'client_secret_rotated',
    'webhook_created',
    'webhook_updated',
    'webhook_deleted',
    'webhook_secret_rotated'
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

-- Minimums the maintenance functions apply whatever their caller asks: the
-- runtime role calls them with the configured retention, but cannot lower
-- these (deploy/db/auth-api-grants.sql leaves it read access only), so an SQL
-- injection or a compromised service cannot use them to erase the audit trail
-- or delete accounts. The owner changes them with an UPDATE.
CREATE TABLE maintenance_floors (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    -- Audit partitions younger than this are never dropped.
    audit_retention_months INTEGER NOT NULL DEFAULT 6,
    -- Audit addresses younger than this are never coarsened.
    audit_address_min_age INTERVAL NOT NULL DEFAULT '30 days',
    -- Accounts pending verification for less than this are never purged.
    unverified_account_min_age INTERVAL NOT NULL DEFAULT '1 day',

    CONSTRAINT maintenance_floors_single_row CHECK (id),
    CONSTRAINT maintenance_floors_audit_retention_positive CHECK (audit_retention_months >= 1)
);

INSERT INTO maintenance_floors DEFAULT VALUES;

-- Creates the monthly partitions from last month to lookahead_months ahead (at
-- least one), and drops those older than retention_months, never fewer than the
-- floor; retention_months <= 0 keeps every partition. Concurrent callers
-- (instances starting together) are serialized.
CREATE OR REPLACE FUNCTION rotate_audit_log_partitions(
    retention_months INTEGER DEFAULT 6,
    lookahead_months INTEGER DEFAULT 12
)
RETURNS VOID AS $$
DECLARE
    create_start DATE := (date_trunc('month', NOW()) - INTERVAL '1 month')::DATE;
    -- Two years ahead at most: a caller cannot fill the catalog with tables.
    create_end DATE := (date_trunc('month', NOW())
        + make_interval(months => LEAST(GREATEST(lookahead_months, 1), 24)))::DATE;
    floor_months INTEGER := (SELECT audit_retention_months FROM maintenance_floors);
    keep_from DATE := (date_trunc('month', NOW())
        - make_interval(months => GREATEST(retention_months, floor_months, 0)))::DATE;
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
        -- The owner's default privileges hand every new table to the runtime
        -- role with UPDATE and DELETE: a partition must not have them.
        IF current_user <> 'auth_api'
           AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_api') THEN
            EXECUTE format('REVOKE UPDATE, DELETE ON %I FROM auth_api',
                'audit_log_' || to_char(month_start, 'YYYY_MM'));
        END IF;
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
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

REVOKE EXECUTE ON FUNCTION rotate_audit_log_partitions(INTEGER, INTEGER) FROM PUBLIC;

SELECT rotate_audit_log_partitions();

-- Rows are never updated or deleted. Two narrowing updates are allowed and
-- nothing else: detaching a deleted user (user_id to NULL), and forgetting or
-- coarsening a client address (ip_address to NULL, or to a network containing
-- it).
CREATE OR REPLACE FUNCTION prevent_audit_log_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.id = OLD.id
       AND NEW.request_id IS NOT DISTINCT FROM OLD.request_id
       AND NEW.created_at = OLD.created_at
       AND NEW.action = OLD.action
       AND NEW.metadata = OLD.metadata
       AND (NEW.user_id IS NOT DISTINCT FROM OLD.user_id OR NEW.user_id IS NULL)
       AND (
           NEW.ip_address IS NOT DISTINCT FROM OLD.ip_address
           OR NEW.ip_address IS NULL
           OR (masklen(NEW.ip_address) < masklen(OLD.ip_address)
               AND OLD.ip_address <<= NEW.ip_address)
       )
       AND (NEW.user_id IS DISTINCT FROM OLD.user_id
            OR NEW.ip_address IS DISTINCT FROM OLD.ip_address) THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_modification();

CREATE INDEX idx_audit_log_user ON audit_log (user_id, created_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX idx_audit_log_created_brin ON audit_log USING BRIN (created_at);
-- The global audit log, newest first.
CREATE INDEX idx_audit_log_created ON audit_log (created_at DESC, id DESC);
