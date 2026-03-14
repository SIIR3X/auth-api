-- 0008_two_factor_methods.sql
-- Creates the second-factor registry for each user account.
-- Supports TOTP, email-based verification, and multiple WebAuthn credentials,
-- with constraints ensuring only the fields relevant to each method are populated.
CREATE TYPE two_factor_type AS ENUM ('totp', 'email', 'webauthn');

CREATE TABLE two_factor_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Detects cloned authenticators: reject auth if counter <= stored value
    webauthn_sign_count BIGINT NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    method_type two_factor_type NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    -- Encrypted at the application layer before insert
    totp_secret TEXT,
    webauthn_credential_id TEXT,
    webauthn_public_key TEXT,

    CONSTRAINT two_factor_webauthn_sign_count_non_negative CHECK (webauthn_sign_count >= 0),
    CONSTRAINT two_factor_webauthn_sign_count_usage CHECK (
        method_type = 'webauthn' OR webauthn_sign_count = 0
    ),
    CONSTRAINT two_factor_primary_requires_verification CHECK (NOT is_primary OR is_verified),
    CONSTRAINT two_factor_method_payload CHECK (
        (method_type = 'totp' AND totp_secret IS NOT NULL AND webauthn_credential_id IS NULL AND webauthn_public_key IS NULL)
        OR (method_type = 'email' AND totp_secret IS NULL AND webauthn_credential_id IS NULL AND webauthn_public_key IS NULL)
        OR (method_type = 'webauthn' AND totp_secret IS NULL AND webauthn_credential_id IS NOT NULL AND webauthn_public_key IS NOT NULL)
    )
);

CREATE TRIGGER two_factor_methods_set_updated_at
    BEFORE UPDATE ON two_factor_methods
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_2fa_user ON two_factor_methods (user_id);
CREATE INDEX idx_2fa_user_verified ON two_factor_methods (user_id) WHERE is_verified = TRUE;
CREATE UNIQUE INDEX idx_2fa_user_totp ON two_factor_methods (user_id) WHERE method_type = 'totp';
CREATE UNIQUE INDEX idx_2fa_user_email ON two_factor_methods (user_id) WHERE method_type = 'email';
CREATE UNIQUE INDEX idx_2fa_user_primary ON two_factor_methods (user_id) WHERE is_primary = TRUE;
CREATE UNIQUE INDEX idx_2fa_webauthn_credential ON two_factor_methods (webauthn_credential_id) WHERE webauthn_credential_id IS NOT NULL;
