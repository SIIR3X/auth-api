-- Client applications allowed to use the native sign-in flows (device
-- authorization, RFC 8628, and the authorization code flow with PKCE).
--
-- registered_clients: the primary client is the application this instance
--   owns; the others are third-party applications. A request naming an unknown
--   client is refused.
--   - scopes: permissions a token issued for the client may carry, intersected
--     with the user's own (empty = unrestricted);
--   - redirect_uris: exact redirect URIs accepted by the authorization code flow;
--   - allows_loopback_redirect: a loopback redirect on any port is accepted for
--     a registered path (RFC 8252 section 7.3);
--   - default_max_sessions: concurrent device sessions per user for a
--     non-primary client without a user_client_quotas row.
-- user_client_quotas: per-user override of a client's session limit.
CREATE TABLE registered_clients (
    client_id VARCHAR(100) PRIMARY KEY,
    display_name VARCHAR(200) NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    allows_loopback_redirect BOOLEAN NOT NULL DEFAULT FALSE,
    default_max_sessions SMALLINT NOT NULL DEFAULT 5,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT registered_clients_client_id_format CHECK (client_id ~ '^[A-Za-z0-9._-]{1,100}$'),
    CONSTRAINT registered_clients_default_max_sessions_positive CHECK (default_max_sessions > 0)
);

-- At most one primary client.
CREATE UNIQUE INDEX idx_registered_clients_primary
    ON registered_clients (is_primary) WHERE is_primary = TRUE;

CREATE TABLE user_client_quotas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id VARCHAR(100) NOT NULL REFERENCES registered_clients (client_id) ON DELETE CASCADE,
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
