-- Creates the Appsmith read-only user for the admin panel.
-- Runs automatically at first PostgreSQL container startup.

CREATE USER appsmith WITH PASSWORD 'appsmith';

\connect auth_api

GRANT CONNECT ON DATABASE auth_api TO appsmith;
GRANT USAGE ON SCHEMA public TO appsmith;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO appsmith;

-- Applies to tables created later by migrations
ALTER DEFAULT PRIVILEGES FOR ROLE auth_api IN SCHEMA public
    GRANT SELECT ON TABLES TO appsmith;
