-- The client credentials grant: a confidential client obtains tokens for
-- itself, carrying its registered scopes and no user. Enabled per client.
ALTER TABLE registered_clients
    ADD COLUMN allows_client_credentials BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT registered_clients_client_credentials_confidential
        CHECK (NOT allows_client_credentials OR client_secret_hash IS NOT NULL),
    ADD CONSTRAINT registered_clients_client_credentials_scoped
        CHECK (NOT allows_client_credentials OR cardinality(scopes) > 0);
