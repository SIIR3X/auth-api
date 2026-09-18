-- A registration on an address whose account is still pending verification
-- carries its own credentials in its verification link. Whoever clicks a link
-- activates the account with the password chosen by the registration that
-- sent it, so registering someone's address first no longer lets an attacker
-- decide the password the owner will activate.
--
-- The links of a pending account therefore coexist until one of them is used:
-- a later registration or resend must not revoke the owner's own link. The
-- verification revokes the others.
ALTER TABLE email_verification_tokens
    ADD COLUMN password_hash TEXT,
    ADD COLUMN username VARCHAR(50),
    ADD COLUMN preferred_locale VARCHAR(10),
    ADD CONSTRAINT email_verification_tokens_credentials_together CHECK (
        (password_hash IS NULL) = (username IS NULL)
        AND (password_hash IS NULL) = (preferred_locale IS NULL)
    ),
    ADD CONSTRAINT email_verification_tokens_username_format CHECK (
        username IS NULL OR username ~ '^[a-zA-Z0-9_]{3,50}$'
    ),
    ADD CONSTRAINT email_verification_tokens_locale_format CHECK (
        preferred_locale IS NULL OR preferred_locale ~ '^[a-z]{2}(_[A-Z]{2})?$'
    );

DROP INDEX idx_email_verification_tokens_user_active;
