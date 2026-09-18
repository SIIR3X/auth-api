//! TOTP secret generation and code verification.
//!
//! Secrets are generated as raw bytes, base32-encoded for the authenticator app,
//! then AES-256-GCM encrypted before being stored in the database.
//! Verification decrypts the stored secret, rebuilds the TOTP context, and checks
//! the submitted code with a 1-step (30s) tolerance window.

use totp_rs::{Algorithm, Builder, Secret, Totp};

use crate::utils::crypto::{CryptoError, Keyring};

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
    Secret::generate().to_base32()
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
/// `skew` controls how many 30-second steps before/after the one containing
/// `now` (Unix timestamp, from the application clock) are accepted.
pub fn verify_code(
    encrypted_secret: &str,
    code: &str,
    keyring: &Keyring,
    skew: u8,
    now: i64,
) -> Result<bool, TotpError> {
    let now = u64::try_from(now).map_err(|_| TotpError::TimeError)?;
    // totp-rs subtracts the skew from the current step, which underflows within
    // `skew` steps of the epoch: refuse such a time rather than panic.
    if now < u64::from(skew) * 30 {
        return Err(TotpError::TimeError);
    }
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(false);
    }
    let plaintext = keyring.decrypt(encrypted_secret)?;

    Ok(totp(&plaintext, skew)?.check(code, now).is_some())
}

/// The code an authenticator app shows at `unix_time` for a base32 secret: for
/// tests, benchmarks and diagnostics.
pub fn code_at(base32_secret: &str, unix_time: u64) -> Result<String, TotpError> {
    Ok(totp(base32_secret, 0)?.generate(unix_time).to_string())
}

/// The code an authenticator app shows now, by the system clock.
pub fn current_code(base32_secret: &str) -> Result<String, TotpError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TotpError::TimeError)?;
    code_at(base32_secret, now.as_secs())
}

/// SHA-1, 6 digits, 30-second steps: what every authenticator app supports.
/// `build` refuses secrets under 128 bits.
fn totp(base32_secret: &str, skew: u8) -> Result<Totp, TotpError> {
    let secret = Secret::try_from_base32(base32_secret).map_err(|_| TotpError::InvalidSecret)?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(u16::from(skew))
        .with_step_duration(30)
        .with_secret(secret)
        .build()
        .map_err(|_| TotpError::InvalidSecret)
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

    fn keyring() -> Keyring {
        Keyring::new(*KEY, None)
    }
    use totp_rs::Secret;

    const KEY: &[u8; 32] = &[7u8; 32];
    const NOW: i64 = 1_700_000_000;

    #[test]
    fn generate_secret_is_valid_base32() {
        let secret = generate_secret();
        assert!(!secret.is_empty());
        // totp-rs must be able to decode it back to bytes
        assert_eq!(
            Secret::try_from_base32(secret).unwrap().as_bytes().len(),
            20
        );
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

    /// The RFC 6238 test secret ("12345678901234567890"), base32-encoded.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    /// Code of the step containing `at`.
    fn code_at(at: i64) -> String {
        super::code_at(RFC_SECRET, at as u64).unwrap()
    }

    fn encrypted_rfc_secret() -> String {
        crypto::encrypt(RFC_SECRET, KEY).unwrap()
    }

    #[test]
    fn codes_match_the_rfc_6238_vectors() {
        // RFC 6238 appendix B, SHA-1, truncated to 6 digits.
        assert_eq!(code_at(59), "287082");
        assert_eq!(code_at(1_111_111_109), "081804");
        assert_eq!(code_at(2_000_000_000), "279037");
    }

    #[test]
    fn verify_correct_code_returns_true() {
        let code = code_at(NOW);
        assert!(verify_code(&encrypted_rfc_secret(), &code, &keyring(), 1, NOW).unwrap());
    }

    #[test]
    fn skew_bounds_the_accepted_steps() {
        let encrypted = encrypted_rfc_secret();
        let (previous, next, two_back) = (code_at(NOW - 30), code_at(NOW + 30), code_at(NOW - 60));
        assert_ne!(previous, code_at(NOW));
        assert_ne!(two_back, previous);

        assert!(verify_code(&encrypted, &previous, &keyring(), 1, NOW).unwrap());
        assert!(verify_code(&encrypted, &next, &keyring(), 1, NOW).unwrap());
        assert!(!verify_code(&encrypted, &previous, &keyring(), 0, NOW).unwrap());
        assert!(!verify_code(&encrypted, &two_back, &keyring(), 1, NOW).unwrap());
    }

    #[test]
    fn a_time_before_the_epoch_is_an_error() {
        assert!(matches!(
            verify_code(&encrypted_rfc_secret(), "123456", &keyring(), 1, -1),
            Err(TotpError::TimeError)
        ));
    }

    #[test]
    fn verify_wrong_code_returns_false() {
        let encrypted = encrypted_rfc_secret();
        let wrong = if code_at(NOW) == "000000" {
            "000001"
        } else {
            "000000"
        };
        assert!(!verify_code(&encrypted, wrong, &keyring(), 0, NOW).unwrap());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let wrong_key = Keyring::new([99u8; 32], None);
        assert!(verify_code(&encrypted_rfc_secret(), &code_at(NOW), &wrong_key, 1, NOW).is_err());
    }

    #[test]
    fn times_within_the_skew_of_the_epoch_are_refused_without_panicking() {
        for now in [0, 29, 59] {
            assert!(matches!(
                verify_code(&encrypted_rfc_secret(), "287082", &keyring(), 2, now),
                Err(TotpError::TimeError)
            ));
        }
        assert!(verify_code(&encrypted_rfc_secret(), &code_at(60), &keyring(), 2, 60).unwrap());
    }

    #[test]
    fn only_six_ascii_digits_can_match() {
        let code = code_at(NOW);
        let fullwidth: String = code
            .chars()
            .map(|c| char::from_u32(c as u32 - '0' as u32 + '\u{FF10}' as u32).unwrap())
            .collect();
        for candidate in [
            format!("{code} "),
            format!("0{code}"),
            code[..5].to_owned(),
            fullwidth,
        ] {
            assert!(!verify_code(&encrypted_rfc_secret(), &candidate, &keyring(), 1, NOW).unwrap());
        }
    }

    #[test]
    fn a_malformed_code_is_refused_before_the_secret_is_decrypted() {
        // With a key that cannot decrypt the secret, only a code that reached
        // the decryption fails with an error: malformed codes stop before it.
        let wrong_key = Keyring::new([99u8; 32], None);
        for code in ["12345", "abcdef", "1234567", ""] {
            assert!(
                matches!(
                    verify_code(&encrypted_rfc_secret(), code, &wrong_key, 1, NOW),
                    Ok(false)
                ),
                "{code:?}"
            );
        }
        assert!(verify_code(&encrypted_rfc_secret(), "123456", &wrong_key, 1, NOW).is_err());
    }
}
