-- 0004_permissions.sql
-- Creates the permissions catalog for the RBAC system.
-- Each permission is normalized as resource + action and exposes a generated
-- resource:action name that is convenient for authorization checks and tokens.
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    -- Always consistent with resource + action, never manually set
    name TEXT GENERATED ALWAYS AS (resource || ':' || action) STORED,
    description TEXT,

    CONSTRAINT permissions_resource_action_key UNIQUE (resource, action)
);

CREATE UNIQUE INDEX idx_permissions_name ON permissions (name);
CREATE INDEX idx_permissions_resource ON permissions (resource);
