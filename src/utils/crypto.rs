//! Cryptographic primitives: hashing, random token generation, AES-256-GCM encryption.
//!
//! AES-256-GCM is used exclusively to encrypt TOTP secrets at rest before storing
//! them in the database. The nonce (12 bytes) is prepended to the ciphertext
//! and the whole thing is base64-encoded for storage.

use std::fmt::Write;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed")]
    Decryption,
    #[error("invalid key: must be base64-encoded 32 bytes")]
    InvalidKey,
    #[error("invalid input")]
    InvalidInput,
}

// Hashing

/// Returns the SHA-256 digest of the input. Used to hash tokens before DB storage.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// Random generation

/// Generates a 32-byte cryptographically secure random token, base64url-encoded.
/// Used for email verification and password reset tokens.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Generates `n` secure random recovery codes formatted as "XXXX-XXXX-XXXX-XXXX-XXXX".
/// 5 groups x 4 hex chars = 10 bytes = 80 bits of entropy (meets NIST SP 800-63B guidance).
pub fn generate_recovery_codes(n: usize) -> Vec<String> {
    (0..n)
        .map(|_| {
            let mut bytes = [0u8; 10];
            OsRng.fill_bytes(&mut bytes);

            // Format 10 bytes as 5 groups of 4 uppercase hex chars
            let mut code = String::with_capacity(24);
            for (i, chunk) in bytes.chunks(2).enumerate() {
                if i > 0 {
                    code.push('-');
                }
                let _ = write!(code, "{:02X}{:02X}", chunk[0], chunk[1]);
            }
            code
        })
        .collect()
}

// Key management

/// Decodes a base64-encoded 32-byte encryption key from the config.
/// Call once at startup to validate the key before the server accepts traffic.
pub fn decode_encryption_key(b64: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = B64.decode(b64).map_err(|_| CryptoError::InvalidKey)?;
    bytes.try_into().map_err(|_| CryptoError::InvalidKey)
}

// AES-256-GCM

/// Encrypts plaintext using AES-256-GCM. Returns base64(nonce || ciphertext).
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    // aead 0.6 dropped `AeadCore::generate_nonce`; fill the 96-bit nonce
    // directly from the OS CSPRNG instead.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::Encryption)?;

    // Prepend the 12-byte nonce so we can recover it during decryption
    let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    Ok(B64.encode(combined))
}

/// Re-encrypts a ciphertext from `old_key` to `new_key` in a single step.
/// Used during encryption key rotation to migrate all stored TOTP secrets.
pub fn re_encrypt(
    encoded: &str,
    old_key: &[u8; 32],
    new_key: &[u8; 32],
) -> Result<String, CryptoError> {
    let plaintext = decrypt(encoded, old_key)?;
    encrypt(&plaintext, new_key)
}

/// Decrypts a value produced by `encrypt`.
pub fn decrypt(encoded: &str, key: &[u8; 32]) -> Result<String, CryptoError> {
    let combined = B64.decode(encoded).map_err(|_| CryptoError::InvalidInput)?;

    // 12-byte nonce + at least 16-byte GCM tag
    if combined.len() < 28 {
        return Err(CryptoError::InvalidInput);
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| CryptoError::InvalidInput)?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::Decryption)?;

    String::from_utf8(plaintext).map_err(|_| CryptoError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8; 32] = &[42u8; 32];
    const OTHER_KEY: &[u8; 32] = &[13u8; 32];

    #[test]
    fn sha256_is_deterministic() {
        let a = sha256(b"hello");
        let b = sha256(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_differs_for_different_inputs() {
        assert_ne!(sha256(b"hello"), sha256(b"world"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = "my secret totp seed";
        let ciphertext = encrypt(plaintext, KEY).unwrap();
        let recovered = decrypt(&ciphertext, KEY).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_produces_different_output_each_call() {
        let a = encrypt("same input", KEY).unwrap();
        let b = encrypt("same input", KEY).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let ciphertext = encrypt("secret", KEY).unwrap();
        assert!(matches!(
            decrypt(&ciphertext, OTHER_KEY),
            Err(CryptoError::Decryption)
        ));
    }

    #[test]
    fn decrypt_truncated_input_fails() {
        assert!(matches!(
            decrypt("dG9vc2hvcnQ=", KEY),
            Err(CryptoError::InvalidInput)
        ));
    }

    #[test]
    fn decrypt_invalid_base64_fails() {
        assert!(matches!(
            decrypt("!!!not-base64!!!", KEY),
            Err(CryptoError::InvalidInput)
        ));
    }

    #[test]
    fn generate_token_is_url_safe() {
        let token = generate_token();
        assert!(!token.is_empty());
        assert!(
            token
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn generate_recovery_codes_count_and_format() {
        let codes = generate_recovery_codes(10);
        assert_eq!(codes.len(), 10);
        for code in &codes {
            // Expected format: "XXXX-XXXX-XXXX-XXXX-XXXX" (5 groups of 4 hex chars = 80 bits)
            let parts: Vec<&str> = code.split('-').collect();
            assert_eq!(parts.len(), 5);
            for part in parts {
                assert_eq!(part.len(), 4);
                assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
            }
        }
    }

    #[test]
    fn decode_encryption_key_valid() {
        let b64 = B64.encode(KEY);
        let decoded = decode_encryption_key(&b64).unwrap();
        assert_eq!(&decoded, KEY);
    }

    #[test]
    fn decode_encryption_key_wrong_length_fails() {
        let b64 = B64.encode(b"too-short");
        assert!(matches!(
            decode_encryption_key(&b64),
            Err(CryptoError::InvalidKey)
        ));
    }
}
