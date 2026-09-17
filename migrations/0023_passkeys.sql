-- Passkeys (WebAuthn discoverable credentials): an account signs in with one
-- instead of its password, and holding one counts as a second factor.
CREATE TABLE passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    -- COSE key as the authenticator encoded it.
    public_key BYTEA NOT NULL,
    algorithm INTEGER NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    aaguid UUID NOT NULL,
    name VARCHAR(100) NOT NULL,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    CONSTRAINT passkeys_credential_id_key UNIQUE (credential_id),
    CONSTRAINT passkeys_credential_id_length CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    CONSTRAINT passkeys_algorithm_supported CHECK (algorithm IN (-7, -8, -257)),
    CONSTRAINT passkeys_sign_count_range CHECK (sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT passkeys_name_not_blank CHECK (char_length(btrim(name)) > 0)
);

CREATE INDEX idx_passkeys_user ON passkeys (user_id, created_at);

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'passkey_registered';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'passkey_removed';
