-- Privileges of the runtime role `auth_api` on a schema owned by
-- `auth_api_owner` (docs/deploy/database/deployment.md, section 2.1). Run as
-- postgres in the auth-api database, after the first migration run:
--   sudo -u postgres psql -d auth_api -f auth-api-grants.sql
-- Running it again is harmless. Later migrations run as `auth_api_owner` and
-- the default privileges below extend to the tables they create.
--
-- The runtime role reads and writes data and nothing else: it cannot alter,
-- drop or truncate a table, disable a trigger, rewrite the audit log, change
-- the permission catalog or the migration history. A compromised application
-- or an SQL injection is bounded by that.

GRANT USAGE ON SCHEMA public TO auth_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auth_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO auth_api;
-- The functions running with the owner's privileges are granted by name: a
-- function added later runs for the application only once listed here. Every
-- other function keeps PostgreSQL's default EXECUTE for everyone.
GRANT EXECUTE ON FUNCTION
    rotate_audit_log_partitions(INTEGER, INTEGER),
    forget_account_traces(UUID),
    purge_unverified_accounts(INTERVAL, INTEGER),
    coarsen_audit_addresses(INTERVAL, INTEGER),
    cleanup_published_events(INTERVAL, INTEGER),
    cleanup_finished_webhook_deliveries(INTERVAL, INTEGER)
TO auth_api;

ALTER DEFAULT PRIVILEGES FOR ROLE auth_api_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_api;
ALTER DEFAULT PRIVILEGES FOR ROLE auth_api_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO auth_api;

-- The audit log is append-only for the application: rows are rewritten only
-- by the maintenance functions of the migrations, which run as the owner, and removed only
-- with their partition.
REVOKE UPDATE, DELETE ON audit_log FROM auth_api;
DO $$
DECLARE
    partition RECORD;
BEGIN
    FOR partition IN
        SELECT c.relname FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'audit_log'
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE ON %I FROM auth_api', partition.relname);
    END LOOP;
END
$$;

-- Outgoing events and webhook deliveries leave only through the owner's
-- retention functions: the runtime role marks them sent or failed, never
-- deletes them, so an unpublished `user.deleted` cannot be made to vanish.
REVOKE DELETE ON event_outbox, webhook_deliveries FROM auth_api;

-- The permission catalog and the migration history change with migrations only.
REVOKE INSERT, UPDATE, DELETE ON permissions FROM auth_api;
REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations FROM auth_api;
-- The minimums of the maintenance functions are the owner's to change: the
-- runtime role calls the functions but cannot lower what they keep.
REVOKE INSERT, UPDATE, DELETE ON maintenance_floors FROM auth_api;
