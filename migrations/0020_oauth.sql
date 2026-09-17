-- Confidential clients: a client holding a secret authenticates at the token
-- endpoint (client_secret_basic or client_secret_post). The secret is 256 random
-- bits, so its SHA-256 digest is stored, not a slow hash.
ALTER TABLE registered_clients
    ADD COLUMN client_secret_hash BYTEA,
    ADD CONSTRAINT registered_clients_secret_hash_length
        CHECK (client_secret_hash IS NULL OR octet_length(client_secret_hash) = 32);

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'client_secret_rotated';
