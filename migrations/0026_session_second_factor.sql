-- Whether the sign-in that started a session proved a second factor (TOTP,
-- email code, recovery code, or a passkey with user verification). The
-- administration requires it of the session itself: an administrator's
-- password alone, or a sign-in link alone, must not open it, whatever factors
-- the account has enrolled. Rotations inherit it.
ALTER TABLE sessions ADD COLUMN mfa BOOLEAN NOT NULL DEFAULT FALSE;
