-- 0003_roles.sql
-- Creates application roles used by the RBAC layer.
-- A role groups permissions under a stable name and can optionally be marked
-- as the default role automatically granted to newly registered users.
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    name VARCHAR(50) NOT NULL,
    description TEXT,

    CONSTRAINT roles_name_key UNIQUE (name)
);

CREATE UNIQUE INDEX idx_roles_default ON roles (is_default) WHERE is_default = TRUE;
