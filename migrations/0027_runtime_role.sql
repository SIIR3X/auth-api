-- Functions the application calls for work it may not do by itself once the
-- schema belongs to a separate owner role (see deploy/db/auth-api-grants.sql):
-- creating and dropping audit partitions, rewriting audit rows when an address
-- is coarsened or an account forgotten, and purging accounts never verified.
-- They run with the privileges of their owner, with a fixed search path.
--
-- A deployment where one role owns and uses the schema is unchanged: the
-- owner runs its own functions.
ALTER FUNCTION rotate_audit_log_partitions(INTEGER, INTEGER)
    SECURITY DEFINER SET search_path = public, pg_temp;
ALTER FUNCTION coarsen_audit_addresses(INTERVAL, INTEGER)
    SECURITY DEFINER SET search_path = public, pg_temp;
ALTER FUNCTION forget_account_traces(UUID)
    SECURITY DEFINER SET search_path = public, pg_temp;
ALTER FUNCTION purge_unverified_accounts(INTERVAL, INTEGER)
    SECURITY DEFINER SET search_path = public, pg_temp;

-- A function running with its owner's privileges is callable only by roles
-- the grants name, not by every role of the cluster.
REVOKE EXECUTE ON FUNCTION rotate_audit_log_partitions(INTEGER, INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION coarsen_audit_addresses(INTERVAL, INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION forget_account_traces(UUID) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION purge_unverified_accounts(INTERVAL, INTEGER) FROM PUBLIC;
