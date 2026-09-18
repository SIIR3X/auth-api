-- Session limits of the auth-api role. Run once, as postgres:
--   sudo -u postgres psql -d auth_api -f auth-api-role.sql
--
-- A statement or a lock wait gives up before the API's own 30-second request
-- timeout, and a connection left idle inside a transaction is closed instead of
-- holding its locks. Migrations lift the statement timeout for their own
-- session (see docs/deploy/database/deployment.md, section 2.5).
ALTER ROLE auth_api SET statement_timeout = '25s';
ALTER ROLE auth_api SET lock_timeout = '10s';
ALTER ROLE auth_api SET idle_in_transaction_session_timeout = '60s';
