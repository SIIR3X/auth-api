-- Accounts linked to identities at external providers (Google, GitHub, OpenID
-- Connect). A link is made by the signed-in owner of the account, never
-- inferred from a matching email address.
CREATE TABLE external_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    -- The provider's stable identifier of the person (`sub`, GitHub user id).
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    CONSTRAINT external_identities_subject_key UNIQUE (provider, subject),
    CONSTRAINT external_identities_one_per_provider UNIQUE (user_id, provider),
    CONSTRAINT external_identities_subject_length CHECK (char_length(subject) BETWEEN 1 AND 255)
);

ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'external_identity_linked';
ALTER TYPE audit_action ADD VALUE IF NOT EXISTS 'external_identity_unlinked';
