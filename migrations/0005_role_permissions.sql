-- 0005_role_permissions.sql
-- Joins roles to permissions.
-- This pivot table expresses which permissions are granted by each role and is
-- the main link used to resolve effective authorization for a user.
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_permission ON role_permissions (permission_id);
