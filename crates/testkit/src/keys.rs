//! Key material of the test configuration. Never valid outside the suites:
//! production refuses these keys (see `config::validate`).

pub const PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgL+1qOaZ7C+H1mGbV\njUP83/W450N4GfOnZSrQ7P//4Y2hRANCAAR4BApTJy8Anvp+O7YNVlTeCbBZ+1YJ\nk+r5ELHGFIXciAEGSrCTOkCm3yChSYroYWLE3ZN4reh6JDbIMX/QnBGx\n-----END PRIVATE KEY-----";

pub const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeAQKUycvAJ76fju2DVZU3gmwWftW\nCZPq+RCxxhSF3IgBBkqwkzpApt8goUmK6GFixN2TeK3oeiQ2yDF/0JwRsQ==\n-----END PUBLIC KEY-----";

/// Base64 of the bytes 0..32.
pub const ENCRYPTION_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
