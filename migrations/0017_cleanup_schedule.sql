-- 0017_cleanup_schedule.sql
-- Schedules nightly cleanup jobs for expired operational data via pg_cron.
-- If pg_cron is unavailable, the application background task handles cleanup instead.
-- Cleanup functions are defined in their respective table migrations (0007, 0009–0013).
DO $$
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_cron;
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'pg_cron not available (insufficient privilege); cleanup will run via the application background task.';
            RETURN;
        WHEN undefined_file THEN
            RAISE NOTICE 'pg_cron not available on this instance; cleanup will run via the application background task.';
            RETURN;
        WHEN feature_not_supported THEN
            RAISE NOTICE 'pg_cron not supported on this instance; cleanup will run via the application background task.';
            RETURN;
        WHEN others THEN
            RAISE NOTICE 'pg_cron could not be loaded (%); cleanup will run via the application background task.', SQLERRM;
            RETURN;
    END;

    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup_expired_sessions') THEN
        PERFORM cron.schedule('cleanup_expired_sessions',        '0 3 * * *', 'SELECT cleanup_expired_sessions()');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup_expired_email_2fa_codes') THEN
        PERFORM cron.schedule('cleanup_expired_email_2fa_codes', '5 3 * * *', 'SELECT cleanup_expired_email_2fa_codes()');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup_expired_email_verification_tokens') THEN
        PERFORM cron.schedule('cleanup_expired_email_verification_tokens', '10 3 * * *', 'SELECT cleanup_expired_email_verification_tokens()');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup_expired_password_reset_tokens') THEN
        PERFORM cron.schedule('cleanup_expired_password_reset_tokens', '15 3 * * *', 'SELECT cleanup_expired_password_reset_tokens()');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup_expired_recovery_codes') THEN
        PERFORM cron.schedule('cleanup_expired_recovery_codes', '20 3 * * *', 'SELECT cleanup_expired_recovery_codes()');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup_old_login_attempts') THEN
        PERFORM cron.schedule('cleanup_old_login_attempts',     '30 3 * * *', 'SELECT cleanup_old_login_attempts()');
    END IF;
END;
$$;
