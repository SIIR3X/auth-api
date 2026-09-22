//! Cryptographic primitives: hashing, constant-time comparison, random
//! generation, keyed digests of one-time codes and AES-256-GCM encryption.
//!
//! AES-256-GCM encrypts secrets at rest (TOTP secrets, webhook signing
//! secrets). The nonce (12 bytes) is prepended to the ciphertext and the whole
//! thing is base64-encoded for storage; since `v2`, the ciphertext is bound to
//! the row it belongs to through associated data.

use std::fmt::Write;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
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
    #[error("ciphertext names a key that is not configured")]
    UnknownKey,
}

// Hashing

/// Returns the SHA-256 digest of the input. Used to hash tokens before DB storage.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Whether two byte strings are equal, in time independent of their contents:
/// comparing a secret or its digest byte by byte and stopping at the first
/// difference tells an attacker how much of a guess was right.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// Random generation

/// A uniformly drawn index below `bound` (1..=u32::MAX), from the OS CSPRNG,
/// by rejection sampling: no value is favoured by a modulo.
pub fn random_below(bound: u32) -> u32 {
    assert!(bound > 0, "an empty range has no index");
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let draw = OsRng.next_u32();
        if draw < zone {
            return draw % bound;
        }
    }
}

/// A 6-digit numeric one-time code (000000..999999, ~20 bits), from the OS
/// CSPRNG.
///
/// Its strength is not the entropy alone: every flow using it pairs the code
/// with an attempt budget, backoff and a short TTL, and stores it as a keyed
/// digest ([`Keyring::otp_digest`]).
pub fn generate_otp() -> String {
    format!("{:06}", random_below(1_000_000))
}

/// `N` bytes from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generates a 32-byte cryptographically secure random token, base64url-encoded.
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

// Keyring

/// Prefix of ciphertexts bound to their row: `v2:{kid}:{base64(...)}`, sealed
/// with `V2_AAD_LABEL || context` as associated data.
const V2_PREFIX: &str = "v2:";
const V2_AAD_LABEL: &[u8] = b"auth-api v2:";
/// HKDF parameters of the key that digests one-time codes.
const OTP_KEY_SALT: &[u8] = b"auth-api keyring";
const OTP_KEY_INFO: &[u8] = b"auth-api otp v1";

/// Keys for data encrypted at rest: the current key, which encrypts, and the
/// previous one, still accepted for reading while a rotation runs.
///
/// Ciphertexts name their key (`v2:{kid}:...`), so a read goes straight to the
/// right key and a rotation can tell which rows are done: it can stop and pick
/// up where it left off. Each `v2` ciphertext is bound to the row it belongs to
/// (a context such as the account id): swapping two rows' ciphertexts makes
/// both unreadable instead of trading secrets. `v1` values (no context) and
/// values written before versioning (bare base64) are still read.
///
/// Each key also derives, by HKDF, the key of the one-time code digests.
#[derive(Clone)]
pub struct Keyring {
    current: KeyEntry,
    previous: Option<KeyEntry>,
}

#[derive(Clone)]
struct KeyEntry {
    kid: String,
    key: [u8; 32],
    otp_key: [u8; 32],
}

impl KeyEntry {
    fn new(key: [u8; 32]) -> Self {
        // First 8 bytes of the key's SHA-256: identifies it without revealing it.
        let kid = sha256(&key)[..8]
            .iter()
            .fold(String::with_capacity(16), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            });
        Self {
            kid,
            key,
            otp_key: hkdf_sha256(&key, OTP_KEY_SALT, OTP_KEY_INFO),
        }
    }

    fn otp_digest(&self, purpose: &str, subject: &[u8], code: &str) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.otp_key).expect("HMAC accepts keys of any length");
        // Length-prefixed fields: no two (purpose, subject, code) triples
        // produce the same input.
        for field in [purpose.as_bytes(), subject, code.as_bytes()] {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }
}

/// HKDF-SHA256 (RFC 5869) for one 32-byte output block.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract =
        Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts keys of any length");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();
    let mut expand = Hmac::<Sha256>::new_from_slice(&prk).expect("HMAC accepts keys of any length");
    expand.update(info);
    expand.update(&[1]);
    expand.finalize().into_bytes().into()
}

impl Keyring {
    pub fn new(current: [u8; 32], previous: Option<[u8; 32]>) -> Self {
        Self {
            current: KeyEntry::new(current),
            previous: previous.map(KeyEntry::new),
        }
    }

    /// Build from the base64 keys of the configuration.
    pub fn from_base64(current: &str, previous: Option<&str>) -> Result<Self, CryptoError> {
        Ok(Self::new(
            decode_encryption_key(current)?,
            previous.map(decode_encryption_key).transpose()?,
        ))
    }

    /// Identifier of the key new ciphertexts are written with.
    pub fn current_kid(&self) -> &str {
        &self.current.kid
    }

    /// Encrypt `plaintext` under the current key, bound to `context` (the id of
    /// the row it belongs to): it decrypts only with the same context.
    pub fn encrypt(&self, plaintext: &str, context: &[u8]) -> Result<String, CryptoError> {
        Ok(format!(
            "{V2_PREFIX}{}:{}",
            self.current.kid,
            encrypt_with_aad(plaintext, &self.current.key, &v2_aad(context))?
        ))
    }

    /// Decrypt a value written by [`Keyring::encrypt`] for `context`. Only the
    /// `v2` format is read: a value without its row bound in could be moved to
    /// another account's row, and no deployment holds one.
    pub fn decrypt(&self, stored: &str, context: &[u8]) -> Result<String, CryptoError> {
        let rest = stored
            .strip_prefix(V2_PREFIX)
            .ok_or(CryptoError::InvalidInput)?;
        let (kid, body) = rest.split_once(':').ok_or(CryptoError::InvalidInput)?;
        let key = self.key_for(kid).ok_or(CryptoError::UnknownKey)?;
        decrypt_with_aad(body, key, &v2_aad(context))
    }

    /// Whether `stored` still has to be rewritten: under another key, or in a
    /// format older than `v2`.
    pub fn needs_rotation(&self, stored: &str) -> bool {
        stored
            .strip_prefix(V2_PREFIX)
            .and_then(|rest| rest.split_once(':'))
            .is_none_or(|(kid, _)| kid != self.current.kid)
    }

    /// Whether `stored` is a `v2` value under a key this keyring holds: what
    /// [`Keyring::decrypt`] can read. Anything else stops the start-up.
    pub fn knows_key_of(&self, stored: &str) -> bool {
        stored
            .strip_prefix(V2_PREFIX)
            .and_then(|rest| rest.split_once(':'))
            .is_some_and(|(kid, _)| self.key_for(kid).is_some())
    }

    /// Identifiers of the keys this keyring holds, current first.
    pub fn kids(&self) -> Vec<&str> {
        std::iter::once(&self.current)
            .chain(self.previous.as_ref())
            .map(|entry| entry.kid.as_str())
            .collect()
    }

    /// Keyed digest of a one-time code, under the current key: what is stored.
    /// `purpose` separates the flows, `subject` binds the code to its account:
    /// a digest read from the database or Redis cannot be brute-forced offline
    /// without the key, nor matched against another flow or account.
    pub fn otp_digest(&self, purpose: &str, subject: &[u8], code: &str) -> [u8; 32] {
        self.current.otp_digest(purpose, subject, code)
    }

    /// Digests of a submitted code under every key held, current first: a code
    /// issued just before a key rotation still verifies.
    pub fn otp_digests(&self, purpose: &str, subject: &[u8], code: &str) -> Vec<[u8; 32]> {
        std::iter::once(&self.current)
            .chain(self.previous.as_ref())
            .map(|entry| entry.otp_digest(purpose, subject, code))
            .collect()
    }

    fn key_for(&self, kid: &str) -> Option<&[u8; 32]> {
        std::iter::once(&self.current)
            .chain(self.previous.as_ref())
            .find(|entry| entry.kid == kid)
            .map(|entry| &entry.key)
    }
}

// AES-256-GCM

fn v2_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(V2_AAD_LABEL.len() + context.len());
    aad.extend_from_slice(V2_AAD_LABEL);
    aad.extend_from_slice(context);
    aad
}

/// Encrypts plaintext using AES-256-GCM. Returns base64(nonce || ciphertext).
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<String, CryptoError> {
    encrypt_with_aad(plaintext, key, &[])
}

/// [`encrypt`] with associated data: authenticated, not encrypted, and required
/// again to decrypt.
pub fn encrypt_with_aad(
    plaintext: &str,
    key: &[u8; 32],
    aad: &[u8],
) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    // aead 0.6 dropped `AeadCore::generate_nonce`; fill the 96-bit nonce
    // directly from the OS CSPRNG instead.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    // Prepend the 12-byte nonce so we can recover it during decryption
    let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    Ok(B64.encode(combined))
}

/// Decrypts a value produced by `encrypt`.
pub fn decrypt(encoded: &str, key: &[u8; 32]) -> Result<String, CryptoError> {
    decrypt_with_aad(encoded, key, &[])
}

/// Decrypts a value produced by [`encrypt_with_aad`] with the same data.
pub fn decrypt_with_aad(encoded: &str, key: &[u8; 32], aad: &[u8]) -> Result<String, CryptoError> {
    let combined = B64.decode(encoded).map_err(|_| CryptoError::InvalidInput)?;

    // 12-byte nonce + at least 16-byte GCM tag
    if combined.len() < 28 {
        return Err(CryptoError::InvalidInput);
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| CryptoError::InvalidInput)?;

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
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

    #[test]
    fn keyring_writes_versioned_ciphertexts_it_can_read() {
        let keyring = Keyring::new([1u8; 32], None);
        let stored = keyring.encrypt("JBSWY3DPEHPK3PXP", b"row-1").unwrap();
        assert!(stored.starts_with(&format!("v2:{}:", keyring.current_kid())));
        assert_eq!(
            keyring.decrypt(&stored, b"row-1").unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
        assert!(!keyring.needs_rotation(&stored));
        assert!(keyring.knows_key_of(&stored));
    }

    #[test]
    fn a_ciphertext_moved_to_another_row_no_longer_decrypts() {
        let keyring = Keyring::new([1u8; 32], None);
        let stored = keyring.encrypt("victim's secret", b"victim").unwrap();
        assert!(matches!(
            keyring.decrypt(&stored, b"attacker"),
            Err(CryptoError::Decryption)
        ));
    }

    #[test]
    fn keyring_reads_the_previous_key_and_refuses_unbound_formats() {
        let old = Keyring::new([1u8; 32], None);
        let v2_old = old.encrypt("secret", b"row").unwrap();
        let rotating = Keyring::new([2u8; 32], Some([1u8; 32]));
        assert_eq!(rotating.decrypt(&v2_old, b"row").unwrap(), "secret");
        assert!(rotating.needs_rotation(&v2_old));

        // Values without their row bound in are not read, and stop the start.
        let v1 = format!(
            "v1:{}:{}",
            old.current_kid(),
            encrypt("secret", &[1u8; 32]).unwrap()
        );
        let unversioned = encrypt("secret", &[1u8; 32]).unwrap();
        for stored in [&v1, &unversioned] {
            assert!(matches!(
                old.decrypt(stored, b"row"),
                Err(CryptoError::InvalidInput)
            ));
            assert!(!old.knows_key_of(stored));
        }
    }

    #[test]
    fn keyring_refuses_a_key_it_does_not_hold() {
        let stored = Keyring::new([1u8; 32], None)
            .encrypt("secret", b"row")
            .unwrap();
        let other = Keyring::new([2u8; 32], None);
        assert!(matches!(
            other.decrypt(&stored, b"row"),
            Err(CryptoError::UnknownKey)
        ));
        assert!(!other.knows_key_of(&stored));
    }

    #[test]
    fn otp_digests_are_keyed_bound_and_survive_a_rotation() {
        let keyring = Keyring::new([1u8; 32], None);
        let digest = keyring.otp_digest("email_2fa", b"user-1", "123456");
        assert_ne!(digest, sha256(b"123456"), "not a bare hash");
        assert_ne!(digest, keyring.otp_digest("email_2fa", b"user-2", "123456"));
        assert_ne!(
            digest,
            keyring.otp_digest("email_change", b"user-1", "123456")
        );
        assert_ne!(
            digest,
            Keyring::new([2u8; 32], None).otp_digest("email_2fa", b"user-1", "123456")
        );

        let rotating = Keyring::new([2u8; 32], Some([1u8; 32]));
        assert!(
            rotating
                .otp_digests("email_2fa", b"user-1", "123456")
                .contains(&digest)
        );
    }

    #[test]
    fn constant_time_equality_compares_contents_and_lengths() {
        assert!(constant_time_eq(b"digest", b"digest"));
        assert!(!constant_time_eq(b"digest", b"digesT"));
        assert!(!constant_time_eq(b"digest", b"digest+"));
    }

    #[test]
    fn random_indexes_stay_in_range_and_cover_it() {
        let mut seen = [false; 8];
        for _ in 0..1_000 {
            let index = random_below(8) as usize;
            seen[index] = true;
        }
        assert!(seen.iter().all(|&s| s));
        assert_eq!(random_below(1), 0);
    }

    mod properties {
        use proptest::prelude::*;

        use super::super::Keyring;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            #[test]
            fn any_secret_survives_encryption_and_a_key_rotation(
                secret in "\\PC{0,200}",
                old in any::<[u8; 32]>(),
                new in any::<[u8; 32]>(),
            ) {
                prop_assume!(old != new);
                let before = Keyring::new(old, None);
                let stored = before.encrypt(&secret, b"row").unwrap();
                prop_assert_eq!(before.decrypt(&stored, b"row").unwrap(), secret.clone());
                prop_assert!(!before.needs_rotation(&stored));

                // During a rotation the old ciphertext stays readable...
                let during = Keyring::new(new, Some(old));
                prop_assert!(during.needs_rotation(&stored));
                prop_assert_eq!(during.decrypt(&stored, b"row").unwrap(), secret.clone());

                // ...and once rewritten, no longer needs the old key.
                let rewritten = during.encrypt(&secret, b"row").unwrap();
                prop_assert!(!during.needs_rotation(&rewritten));
                prop_assert_eq!(Keyring::new(new, None).decrypt(&rewritten, b"row").unwrap(), secret);
                prop_assert!(before.decrypt(&rewritten, b"row").is_err());
            }
        }
    }

    #[test]
    fn one_time_codes_are_six_ascii_digits() {
        for _ in 0..64 {
            let otp = generate_otp();
            assert_eq!(otp.len(), 6, "{otp:?}");
            assert!(otp.bytes().all(|b| b.is_ascii_digit()), "{otp:?}");
        }
    }

    #[test]
    fn tokens_carry_32_fresh_random_bytes() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (a, b) = (generate_token(), generate_token());
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn an_empty_secret_round_trips() {
        // Nonce and tag only: the shortest ciphertext there is.
        let stored = encrypt("", KEY).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&stored)
                .unwrap()
                .len(),
            28
        );
        assert_eq!(decrypt(&stored, KEY).unwrap(), "");
    }
}
