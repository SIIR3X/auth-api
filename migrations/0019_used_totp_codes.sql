-- 0019_used_totp_codes.sql
-- Durable TOTP replay guard: records the SHA-256 of every successfully
-- verified TOTP code so that a code cannot be consumed twice within its
-- validity window, even if Redis (the fast-path cache) is unavailable.
--
-- TOTP codes naturally repeat over time (6 digits, 30-second steps), so rows
-- MUST be short-lived: the repository purges the user's expired rows on every
-- attempt, cleanup_used_totp_codes() sweeps leftovers, and the primary key
-- only needs to hold uniqueness for the ~90-second validity window
-- (current step +/- TOTP_SKEW).
CREATE TABLE used_totp_codes (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, code_hash),
    CONSTRAINT used_totp_codes_hash_length CHECK (octet_length(code_hash) = 32)
);

-- Rows are extremely short-lived; keep autovacuum aggressive so the table
-- never accumulates dead tuples from the constant insert/delete churn.
ALTER TABLE used_totp_codes SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_vacuum_threshold = 200
);

CREATE OR REPLACE FUNCTION cleanup_used_totp_codes(
    retention INTERVAL DEFAULT '90 seconds'
)
RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    WITH deleted_rows AS (
        DELETE FROM used_totp_codes
        WHERE used_at < NOW() - retention
        RETURNING user_id
    )
    SELECT count(*) INTO deleted FROM deleted_rows;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

-- Schedule via pg_cron when available (same pattern as 0017_cleanup_schedule.sql);
-- the application background task is the fallback.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        RAISE NOTICE 'pg_cron not available; cleanup_used_totp_codes will run via the application background task.';
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup_used_totp_codes') THEN
        PERFORM cron.schedule('cleanup_used_totp_codes', '*/10 * * * *', 'SELECT cleanup_used_totp_codes()');
    END IF;
END;
$$;
