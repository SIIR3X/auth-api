-- OpenID Connect: the nonce of an authentication request travels with its
-- authorization code into the ID token.
ALTER TABLE authorization_codes
    ADD COLUMN nonce TEXT,
    ADD CONSTRAINT authorization_codes_nonce_length CHECK (nonce IS NULL OR char_length(nonce) <= 512);
