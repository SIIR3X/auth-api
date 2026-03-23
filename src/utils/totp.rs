//! TOTP secret generation and code verification.
//!
//! Secrets are generated as raw bytes, base32-encoded for the authenticator app,
//! then AES-256-GCM encrypted before being stored in the database.
//! Verification decrypts the stored secret, rebuilds the TOTP context, and checks
//! the submitted code with a 1-step (30s) tolerance window.

use totp_rs::{Algorithm, Secret, TOTP};

use crate::utils::crypto::{self, CryptoError};

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid TOTP secret")]
    InvalidSecret,
    #[error("system time error")]
    TimeError,
}

/// Generates a new TOTP secret and returns its base32 representation.
/// The caller is responsible for encrypting it before storage.
pub fn generate_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

/// Returns the otpauth URI to encode into a QR code for authenticator apps.
pub fn qr_uri(base32_secret: &str, email: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        percent_encode(issuer),
        percent_encode(email),
        base32_secret,
        percent_encode(issuer),
    )
}

/// Verifies a 6-digit TOTP code against the encrypted secret stored in the database.
/// `skew` controls how many 30-second steps before/after the current one are accepted.
pub fn verify_code(
    encrypted_secret: &str,
    code: &str,
    key: &[u8; 32],
    skew: u8,
) -> Result<bool, TotpError> {
    let plaintext = crypto::decrypt(encrypted_secret, key)?;

    let secret_bytes = Secret::Encoded(plaintext)
        .to_bytes()
        .map_err(|_| TotpError::InvalidSecret)?;

    let totp = TOTP::new(Algorithm::SHA1, 6, skew, 30, secret_bytes)
        .map_err(|_| TotpError::InvalidSecret)?;

    totp.check_current(code).map_err(|_| TotpError::TimeError)
}

// Percent-encodes a string for use in a URI (RFC 3986 unreserved chars pass through).
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b => {
                use std::fmt::Write;
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::crypto;
    use totp_rs::{Algorithm, Secret, TOTP};

    const KEY: &[u8; 32] = &[7u8; 32];

    #[test]
    fn generate_secret_is_valid_base32() {
        let secret = generate_secret();
        assert!(!secret.is_empty());
        // totp-rs must be able to decode it back to bytes
        assert!(Secret::Encoded(secret).to_bytes().is_ok());
    }

    #[test]
    fn qr_uri_has_correct_structure() {
        let uri = qr_uri("JBSWY3DPEHPK3PXP", "user@example.com", "MyApp");
        assert!(uri.starts_with("otpauth://totp/MyApp:user%40example.com?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=MyApp"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn qr_uri_percent_encodes_special_chars() {
        let uri = qr_uri("SECRET", "user@example.com", "My App");
        // space -> %20, @ -> %40
        assert!(uri.contains("My%20App"));
        assert!(uri.contains("user%40example.com"));
    }

    #[test]
    fn verify_correct_code_returns_true() {
        let secret_b32 = generate_secret();
        let encrypted = crypto::encrypt(&secret_b32, KEY).unwrap();

        // Generate the current valid code using the same secret
        let secret_bytes = Secret::Encoded(secret_b32).to_bytes().unwrap();
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes).unwrap();
        let code = totp.generate_current().unwrap();

        assert!(verify_code(&encrypted, &code, KEY, 1).unwrap());
    }

    #[test]
    fn verify_wrong_code_returns_false() {
        let secret_b32 = generate_secret();
        let encrypted = crypto::encrypt(&secret_b32, KEY).unwrap();
        assert!(!verify_code(&encrypted, "000000", KEY, 1).unwrap());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let secret_b32 = generate_secret();
        let encrypted = crypto::encrypt(&secret_b32, KEY).unwrap();
        let wrong_key = &[99u8; 32];
        assert!(verify_code(&encrypted, "123456", wrong_key, 1).is_err());
    }
}
