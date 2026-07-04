-- 0018_registered_clients.sql
-- Client registry for the device authorization flow (RFC 8628).
--
-- registered_clients:  known client applications allowed to use the device
--   flow. The primary client is the native application owned by this auth-api
--   instance; external clients are third-party applications granted access
--   through federation. Device auth requests with an unknown client_id are
--   rejected.
-- user_client_quotas:  per-client concurrent device-session limits. When no
--   quota row exists for a (user_id, client_id) pair, device auth is denied.
CREATE TABLE registered_clients (
    client_id VARCHAR(100) PRIMARY KEY,
    display_name VARCHAR(200) NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- At most one client can be primary.
CREATE UNIQUE INDEX idx_registered_clients_primary
    ON registered_clients (is_primary) WHERE is_primary = true;

CREATE TABLE user_client_quotas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id VARCHAR(100) NOT NULL,
    max_sessions SMALLINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT user_client_quotas_unique UNIQUE (user_id, client_id),
    CONSTRAINT user_client_quotas_max_sessions_positive CHECK (max_sessions > 0)
);

CREATE INDEX idx_user_client_quotas_user ON user_client_quotas (user_id);

CREATE TRIGGER user_client_quotas_set_updated_at
    BEFORE UPDATE ON user_client_quotas
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
