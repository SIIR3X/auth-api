-- 0009_email_2fa_codes.sql
-- Short-lived OTP codes sent by email during the Email 2FA challenge.
-- One active code per user at a time; expired or used codes are kept briefly for auditing.
CREATE TABLE email_2fa_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX idx_email_2fa_codes_user ON email_2fa_codes (user_id, expires_at DESC);
