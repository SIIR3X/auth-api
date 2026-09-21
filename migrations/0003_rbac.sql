-- Role-based access control: roles, the permission catalog, the permissions
-- each role grants, the roles each user holds, the default role granted at
-- registration, and the `admin` role granting every administrative permission
-- the /admin routes require.
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    name VARCHAR(50) NOT NULL,
    description TEXT,

    CONSTRAINT roles_name_key UNIQUE (name)
);

-- At most one default role.
CREATE UNIQUE INDEX idx_roles_default ON roles (is_default) WHERE is_default = TRUE;

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    -- Always consistent with resource + action, never set by hand.
    name TEXT GENERATED ALWAYS AS (resource || ':' || action) STORED,
    description TEXT,

    CONSTRAINT permissions_resource_action_key UNIQUE (resource, action)
);

CREATE UNIQUE INDEX idx_permissions_name ON permissions (name);
CREATE INDEX idx_permissions_resource ON permissions (resource);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_permission ON role_permissions (permission_id);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users (id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_role ON user_roles (role_id);
-- Deleting a user clears the grants it made.
CREATE INDEX idx_user_roles_granted_by ON user_roles (granted_by) WHERE granted_by IS NOT NULL;

INSERT INTO roles (name, description, is_default) VALUES
    ('user', 'Default role assigned on registration', TRUE);

INSERT INTO permissions (resource, action, description) VALUES
    ('users', 'read', 'Search accounts and read their details'),
    ('users', 'manage', 'Suspend, reactivate, unlock, sign out, reset and delete accounts'),
    ('roles', 'manage', 'Create and delete roles, set their permissions, assign them to accounts'),
    ('clients', 'manage', 'Register, update and remove client applications'),
    ('audit', 'read', 'Read the audit log of every account'),
    ('webhooks', 'manage', 'Manage webhook subscriptions and their deliveries');

INSERT INTO roles (name, description, is_default) VALUES
    ('admin', 'Administrators: every administrative permission', FALSE);

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles CROSS JOIN permissions
WHERE roles.name = 'admin';
