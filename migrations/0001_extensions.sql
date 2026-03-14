-- 0001_extensions.sql
-- Enables PostgreSQL extensions required by the schema:
-- - pgcrypto: generates UUIDs with gen_random_uuid()
-- - citext: provides case-insensitive text for identifiers like email
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";
