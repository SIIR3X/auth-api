//! Argon2id password hashing and verification.
//!
//! Parameters are loaded from CryptoConfig so they can be tuned per environment
//! without recompiling. Use the defaults in .env.example as a starting point
//! and benchmark on your target hardware before going to production.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::config::CryptoConfig;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("invalid argon2 params: {0}")]
    Params(argon2::Error),
    #[error("hashing failed: {0}")]
    Hash(argon2::password_hash::Error),
    #[error("hash string is malformed: {0}")]
    Parse(argon2::password_hash::Error),
    #[error("verification failed: {0}")]
    Verify(argon2::password_hash::Error),
    #[error("password worker task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

/// Hashes a plaintext password using Argon2id with a random salt.
/// The returned string is a self-contained PHC hash (includes params + salt).
pub fn hash(password: &str, cfg: &CryptoConfig) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);

    let params = Params::new(
        cfg.argon2_memory_kib,
        cfg.argon2_iterations,
        cfg.argon2_parallelism,
        None,
    )
    .map_err(PasswordError::Params)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(PasswordError::Hash)
}

/// Returns true if the password matches the stored hash, false otherwise.
/// Invalid password is not an error; only a malformed hash string is.
pub fn verify(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(hash).map_err(PasswordError::Parse)?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::Verify(e)),
    }
}

/// Runs Argon2id hashing on the blocking threadpool so authentication work
/// does not stall the async runtime under load.
pub async fn hash_async(password: &str, cfg: &CryptoConfig) -> Result<String, PasswordError> {
    let password = password.to_owned();
    let cfg = cfg.clone();

    tokio::task::spawn_blocking(move || hash(&password, &cfg)).await?
}

/// Runs Argon2id verification on the blocking threadpool.
pub async fn verify_async(password: &str, hash_value: &str) -> Result<bool, PasswordError> {
    let password = password.to_owned();
    let hash_value = hash_value.to_owned();

    tokio::task::spawn_blocking(move || verify(&password, &hash_value)).await?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CryptoConfig {
        CryptoConfig {
            argon2_memory_kib: 1024,
            argon2_iterations: 1,
            argon2_parallelism: 1,
            totp_issuer: "test".into(),
            encryption_key: String::new(),
            previous_encryption_key: None,
            totp_skew: 1,
            recovery_code_expiry_days: 365,
        }
    }

    #[test]
    fn hash_and_verify_correct_password() {
        let cfg = test_config();
        let h = hash("hunter2", &cfg).unwrap();
        assert!(verify("hunter2", &h).unwrap());
    }

    #[test]
    fn verify_wrong_password_returns_false() {
        let cfg = test_config();
        let h = hash("hunter2", &cfg).unwrap();
        assert!(!verify("wrong", &h).unwrap());
    }

    #[test]
    fn verify_malformed_hash_returns_error() {
        assert!(matches!(
            verify("password", "not-a-hash"),
            Err(PasswordError::Parse(_))
        ));
    }

    #[test]
    fn same_password_produces_different_hashes() {
        let cfg = test_config();
        let h1 = hash("password", &cfg).unwrap();
        let h2 = hash("password", &cfg).unwrap();
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn async_hash_and_verify_match_sync_behavior() {
        let cfg = test_config();
        let h = hash_async("hunter2", &cfg).await.unwrap();

        assert!(verify_async("hunter2", &h).await.unwrap());
        assert!(!verify_async("wrong", &h).await.unwrap());
    }
}
