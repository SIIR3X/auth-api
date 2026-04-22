-- 0016_seed.sql
-- Inserts the base authorization data required by the application to boot with
-- sensible defaults: standard roles and the initial permission catalog.
-- This migration provides the minimum RBAC dataset expected by the API.
INSERT INTO roles (name, description, is_default) VALUES
    ('user', 'Default role assigned on registration', TRUE);
