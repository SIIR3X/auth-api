-- Administration: the permissions the /admin routes require, the `admin` role
-- granting all of them, and the audit actions of administrative changes.
INSERT INTO permissions (resource, action, description) VALUES
    ('users', 'read', 'Search accounts and read their details'),
    ('users', 'manage', 'Suspend, reactivate, unlock, sign out, reset and delete accounts'),
    ('roles', 'manage', 'Create and delete roles, set their permissions, assign them to accounts'),
    ('clients', 'manage', 'Register, update and remove client applications'),
    ('audit', 'read', 'Read the audit log of every account'),
    ('webhooks', 'manage', 'Manage webhook subscriptions and their deliveries')
ON CONFLICT (resource, action) DO NOTHING;

INSERT INTO roles (name, description, is_default)
VALUES ('admin', 'Administrators: every administrative permission', FALSE)
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles CROSS JOIN permissions
WHERE roles.name = 'admin'
  AND permissions.name IN (
      'users:read', 'users:manage', 'roles:manage', 'clients:manage', 'audit:read', 'webhooks:manage'
  )
ON CONFLICT DO NOTHING;

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'account_unlocked';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'password_reset_forced';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'role_created';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'role_deleted';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'role_permissions_changed';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'client_registered';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'client_updated';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'client_deleted';

-- An administrator unlocking an account also forgives the failed sign-ins that
-- locked it: the consecutive failures count from the later of the last success
-- and this date.
ALTER TABLE users ADD COLUMN lockout_cleared_at TIMESTAMPTZ;

-- Administrators search accounts by the start of an address or a username.
CREATE INDEX idx_users_email_prefix ON users ((lower(email::text)) text_pattern_ops);
CREATE INDEX idx_users_username_prefix ON users ((lower(username::text)) text_pattern_ops);
-- Listing pages newest first.
CREATE INDEX idx_users_created ON users (created_at DESC, id DESC);
