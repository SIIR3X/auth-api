-- Personal access tokens: long-lived credentials an account creates for its own
-- scripts, exchanged for short-lived access tokens. Each one owns a session of
-- type `personal_access_token`, so every revocation path (the token list, the
-- session list, a password change, an administrator) ends it the same way.
ALTER TYPE session_type ADD VALUE IF NOT EXISTS 'personal_access_token';

CREATE TABLE personal_access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    token_hash BYTEA NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,

    CONSTRAINT personal_access_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT personal_access_tokens_session_key UNIQUE (session_id),
    CONSTRAINT personal_access_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT personal_access_tokens_name_not_blank CHECK (char_length(btrim(name)) > 0),
    CONSTRAINT personal_access_tokens_expires_after_creation CHECK (expires_at > created_at)
);

CREATE INDEX idx_personal_access_tokens_user ON personal_access_tokens (user_id, created_at DESC);

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'personal_access_token_created';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'personal_access_token_revoked';
