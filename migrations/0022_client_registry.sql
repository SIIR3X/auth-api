-- 0022_client_registry.sql
-- Turns registered_clients into the registry both native sign-in flows rely on
-- (device authorization, and the authorization code flow in 0023):
-- - scopes: permissions a token issued for the client may carry, intersected
--   with the user's own when the access token is built (empty = unrestricted);
-- - redirect_uris: exact redirect URIs accepted for the authorization code flow;
-- - allows_loopback_redirect: whether a loopback redirect on any port is
--   accepted for a registered path (RFC 8252 section 7.3, native apps);
-- - default_max_sessions: concurrent device sessions per user for a non-primary
--   client when no user_client_quotas row overrides it.
ALTER TABLE registered_clients
    ADD COLUMN scopes TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN allows_loopback_redirect BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN default_max_sessions SMALLINT NOT NULL DEFAULT 5,
    ADD CONSTRAINT registered_clients_default_max_sessions_positive
        CHECK (default_max_sessions > 0),
    ADD CONSTRAINT registered_clients_client_id_format
        CHECK (client_id ~ '^[A-Za-z0-9._-]{1,100}$') NOT VALID;

-- A quota row for a client that no longer exists is meaningless: tie it to the
-- registry. NOT VALID so existing orphan rows do not block the migration.
ALTER TABLE user_client_quotas
    ADD CONSTRAINT user_client_quotas_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES registered_clients (client_id) ON DELETE CASCADE
        NOT VALID;
