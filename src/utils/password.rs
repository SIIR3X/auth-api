//! Argon2id password hashing and verification.
//!
//! Parameters are loaded from CryptoConfig so they can be tuned per environment
//! without recompiling. Use the defaults in .env.dev / config.prod.env as a starting point
//! and benchmark on your target hardware before going to production.

use std::sync::OnceLock;

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use tokio::sync::Semaphore;

use crate::config::CryptoConfig;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("invalid argon2 params: {0}")]
    Params(argon2::Error),
    #[error("hashing failed: {0}")]
    Hash(argon2::password_hash::Error),
    #[error("hash string is malformed: {0}")]
    Parse(argon2::password_hash::phc::Error),
    #[error("verification failed: {0}")]
    Verify(argon2::password_hash::Error),
    #[error("password worker task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error("password worker queue closed")]
    Queue,
}

/// Global semaphore bounding concurrent Argon2 operations.
///
/// Each Argon2id run pins `argon2_memory_kib` of RAM and one blocking-pool
/// thread for ~50-100 ms. Without a bound, a distributed login storm could
/// spawn hundreds of concurrent hashes (Tokio's blocking pool allows 512
/// threads by default) and exhaust memory. Excess requests wait here instead.
///
/// Initialized from the config on first use; the limit is process-wide.
fn argon2_semaphore(cfg: &CryptoConfig) -> &'static Semaphore {
    static SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();
    SEMAPHORE.get_or_init(|| Semaphore::new(cfg.argon2_max_concurrency.max(1) as usize))
}

/// Hashes a plaintext password using Argon2id with a random 16-byte salt from
/// the operating system. The returned string is a self-contained PHC hash
/// (includes params + salt).
pub fn hash(password: &str, cfg: &CryptoConfig) -> Result<String, PasswordError> {
    let params = Params::new(
        cfg.argon2_memory_kib,
        cfg.argon2_iterations,
        cfg.argon2_parallelism,
        None,
    )
    .map_err(PasswordError::Params)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(PasswordError::Hash)
}

/// Returns true if the password matches the stored hash, false otherwise.
/// Invalid password is not an error; only a malformed hash string is.
pub fn verify(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(hash).map_err(PasswordError::Parse)?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(e) => Err(PasswordError::Verify(e)),
    }
}

/// Whether `hash` was computed with weaker parameters than `cfg` asks for, or
/// another algorithm: the password is then hashed again once proven, so raising
/// `ARGON2_*` protects existing accounts as they sign in, not only new ones.
/// A hash that does not parse is left alone (verification refuses it anyway).
pub fn needs_rehash(hash: &str, cfg: &CryptoConfig) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    if parsed.algorithm.as_str() != "argon2id" {
        return true;
    }
    match Params::try_from(&parsed) {
        Ok(params) => {
            params.m_cost() < cfg.argon2_memory_kib
                || params.t_cost() < cfg.argon2_iterations
                || params.p_cost() < cfg.argon2_parallelism
        }
        Err(_) => false,
    }
}

/// How many times the configured cost a stored hash may take: room for a
/// configuration halved since the hash was written (it is rehashed at the
/// next sign-in), not for a hash planted to exhaust memory.
pub const STORED_COST_FACTOR: u32 = 2;

/// Whether the parameters written in `hash` would cost far more than the
/// configured ones: a hash planted in the database with, say, 256 MiB of
/// memory would take an instance down at each sign-in attempt, since every
/// concurrent hash could cost that much. Bounded by `STORED_COST_FACTOR` times
/// the configuration (at least 4 iterations and 4 lanes), so the memory the
/// container needs is known: see `log_capacity`.
pub fn exceeds_configured_cost(hash: &str, cfg: &CryptoConfig) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    let Ok(params) = Params::try_from(&parsed) else {
        return false;
    };
    params.m_cost() > cfg.argon2_memory_kib.saturating_mul(STORED_COST_FACTOR)
        || params.t_cost() > (cfg.argon2_iterations.saturating_mul(STORED_COST_FACTOR)).max(4)
        || params.p_cost() > (cfg.argon2_parallelism.saturating_mul(STORED_COST_FACTOR)).max(4)
}

/// Runs Argon2id hashing on the blocking threadpool so authentication work
/// does not stall the async runtime under load. Concurrency is bounded by
/// the global Argon2 semaphore (see `argon2_semaphore`).
pub async fn hash_async(password: &str, cfg: &CryptoConfig) -> Result<String, PasswordError> {
    let semaphore = argon2_semaphore(cfg);
    let permit = semaphore
        .acquire()
        .await
        .map_err(|_| PasswordError::Queue)?;
    record_argon2_permits(semaphore);

    let password = password.to_owned();
    let cfg = cfg.clone();

    // The permit travels with the work: if the request is cancelled (client
    // gone, HTTP timeout) the hash keeps running on the blocking pool, and so
    // must its slot, or the bound on concurrent Argon2 memory stops holding.
    let result = tokio::task::spawn_blocking(move || {
        let outcome = hash(&password, &cfg);
        drop(permit);
        outcome
    })
    .await;
    record_argon2_permits(semaphore);
    result?
}

/// Runs Argon2id verification on the blocking threadpool. Concurrency is
/// bounded by the global Argon2 semaphore (see `argon2_semaphore`).
/// Longest password any route verifies, in bytes: no password the policy
/// accepts is longer, so a longer one is simply wrong, answered without
/// hashing a 64 KiB body.
pub const MAX_VERIFIED_PASSWORD_BYTES: usize = 256;

pub async fn verify_async(
    password: &str,
    hash_value: &str,
    cfg: &CryptoConfig,
) -> Result<bool, PasswordError> {
    if password.len() > MAX_VERIFIED_PASSWORD_BYTES {
        return Ok(false);
    }
    if exceeds_configured_cost(hash_value, cfg) {
        tracing::error!("stored password hash asks for far more than the configured cost: refused");
        return Ok(false);
    }
    let semaphore = argon2_semaphore(cfg);
    let permit = semaphore
        .acquire()
        .await
        .map_err(|_| PasswordError::Queue)?;
    record_argon2_permits(semaphore);

    let password = password.to_owned();
    let hash_value = hash_value.to_owned();

    // See `hash_async`: the permit is released when the work ends, not when the
    // awaiting future is dropped.
    let result = tokio::task::spawn_blocking(move || {
        let outcome = verify(&password, &hash_value);
        drop(permit);
        outcome
    })
    .await;
    record_argon2_permits(semaphore);
    result?
}

/// Expose the Argon2 queue depth to Prometheus. Zero available permits while
/// requests keep arriving is the leading indicator of a login storm: latency
/// climbs as logins queue on the semaphore. No-op when no recorder is
/// installed (tests, `METRICS_ENABLED=false`).
fn record_argon2_permits(semaphore: &Semaphore) {
    metrics::gauge!("argon2_queue_available_permits").set(semaphore.available_permits() as f64);
}

/// Log the Argon2 capacity at startup, and warn when the container's memory
/// limit cannot hold every concurrent hash beside the rest of the process.
///
/// Sign-ins are the first thing to saturate (about 11-13 per second per core
/// with the production parameters, see docs/perf/performance-report.md), so
/// the operator should see the bound the process actually runs with.
pub fn log_capacity(cfg: &CryptoConfig) {
    let (concurrency, per_hash_mib, budget_mib) = argon2_budget(cfg);
    tracing::info!(
        concurrency,
        per_hash_mib,
        budget_mib,
        "argon2: at most {concurrency} concurrent hashes"
    );
    if let Some(limit_mib) = cgroup_memory_limit_mib()
        && limit_too_tight(limit_mib, budget_mib)
    {
        tracing::warn!(
            limit_mib,
            budget_mib,
            "memory limit leaves less than {BASELINE_MIB} MiB beside the Argon2 budget: \
             lower ARGON2_MAX_CONCURRENCY or raise the limit"
        );
    }
}

/// Concurrent hashes, memory per hash and their total, in MiB. The total is
/// the worst case: every concurrent hash checking a stored hash at the highest
/// cost `exceeds_configured_cost` accepts.
fn argon2_budget(cfg: &CryptoConfig) -> (u64, u64, u64) {
    let concurrency = u64::from(cfg.argon2_max_concurrency.max(1));
    let per_hash_mib = u64::from(cfg.argon2_memory_kib) / 1024;
    (
        concurrency,
        per_hash_mib,
        concurrency * per_hash_mib * u64::from(STORED_COST_FACTOR),
    )
}

/// Whether a memory limit leaves less than [`BASELINE_MIB`] beside the budget.
fn limit_too_tight(limit_mib: u64, budget_mib: u64) -> bool {
    limit_mib < budget_mib + BASELINE_MIB
}

/// Memory the process needs besides Argon2 (pools, caches, runtime).
const BASELINE_MIB: u64 = 256;

/// The cgroup v2 memory limit, when the process runs under one.
fn cgroup_memory_limit_mib() -> Option<u64> {
    parse_memory_max(&std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?)
}

/// `memory.max` in MiB; `max` (no limit) and anything unreadable give `None`.
fn parse_memory_max(contents: &str) -> Option<u64> {
    contents
        .trim()
        .parse::<u64>()
        .ok()
        .map(|bytes| bytes / 1024 / 1024)
}

#[cfg(test)]
mod rehash_tests {
    use super::*;

    fn config(memory: u32, iterations: u32, parallelism: u32) -> CryptoConfig {
        CryptoConfig {
            argon2_memory_kib: memory,
            argon2_iterations: iterations,
            argon2_parallelism: parallelism,
            argon2_max_concurrency: 1,
            totp_issuer: String::new(),
            encryption_key: String::new(),
            previous_encryption_key: None,
            totp_skew: 1,
            recovery_code_expiry_days: 0,
        }
    }

    #[test]
    fn a_hash_weaker_than_the_configuration_is_rehashed() {
        let weak = hash("Password-1!", &config(8, 1, 1)).unwrap();
        assert!(needs_rehash(&weak, &config(16, 1, 1)), "memory");
        assert!(needs_rehash(&weak, &config(8, 2, 1)), "iterations");
        assert!(needs_rehash(&weak, &config(8, 1, 2)), "parallelism");
        assert!(!needs_rehash(&weak, &config(8, 1, 1)), "as configured");
        assert!(
            !needs_rehash(&weak, &config(4, 1, 1)),
            "stronger than asked"
        );
        assert!(!needs_rehash("not a phc string", &config(8, 1, 1)));
    }

    /// A password longer than any the policy accepts is wrong, without work.
    #[tokio::test]
    async fn a_password_longer_than_any_accepted_is_wrong() {
        let cfg = config(1024, 1, 1);
        let long = "x".repeat(MAX_VERIFIED_PASSWORD_BYTES + 1);
        let stored = hash(&long, &cfg).unwrap();
        assert!(!verify_async(&long, &stored, &cfg).await.unwrap());
    }

    /// A hash asking for far more than the configured cost is refused before
    /// any work (SEC-71).
    #[tokio::test]
    async fn a_hash_costing_far_more_than_configured_is_refused() {
        let cfg = config(19_456, 2, 1);
        let planted = "$argon2id$v=19$m=4194304,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA";
        assert!(exceeds_configured_cost(planted, &cfg));
        assert!(!verify_async("Password-1!", planted, &cfg).await.unwrap());

        let lowered = hash("Password-1!", &config(38_912, 3, 2)).unwrap();
        assert!(
            !exceeds_configured_cost(&lowered, &cfg),
            "a cost halved since stays readable"
        );
        // 256 MiB per hash: three concurrent sign-ins would exhaust a 512 MiB
        // container (C-04).
        let heavy = "$argon2id$v=19$m=262144,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA";
        assert!(exceeds_configured_cost(heavy, &cfg));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CryptoConfig {
        CryptoConfig {
            argon2_memory_kib: 1024,
            argon2_iterations: 1,
            argon2_parallelism: 1,
            argon2_max_concurrency: 4,
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

    /// Hashes written by argon2 0.5.3, the version every stored password so far
    /// was hashed with: an upgrade must never lock anyone out.
    #[test]
    fn hashes_written_by_the_previous_argon2_release_still_verify() {
        for stored in [
            "$argon2id$v=19$m=1024,t=1,p=1$LQRmYeOMiT51hO+QHoiZjA$sgcCK0PEj5O2MB5lT2uHBZBeABzytakC4LLNDPyWiGw",
            "$argon2id$v=19$m=65536,t=3,p=4$LQRmYeOMiT51hO+QHoiZjA$PrWpnvu6FOD76HTZWdrRJT9Ubkho34paSp7Sa04Hwhc",
        ] {
            assert!(verify("correct horse battery staple", stored).unwrap());
            assert!(!verify("correct horse battery stapler", stored).unwrap());
        }
    }

    #[test]
    fn a_new_hash_is_argon2id_with_the_configured_parameters() {
        let h = hash("hunter2", &test_config()).unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=1024,t=1,p=1$"), "{h}");
        // A 16-byte salt, base64 without padding.
        assert_eq!(h.split('$').nth(4).unwrap().len(), 22);
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

        assert!(verify_async("hunter2", &h, &cfg).await.unwrap());
        assert!(!verify_async("wrong", &h, &cfg).await.unwrap());
    }

    #[test]
    fn the_argon2_budget_is_concurrency_times_the_highest_accepted_cost() {
        let mut cfg = test_config();
        cfg.argon2_memory_kib = 65_536;
        cfg.argon2_max_concurrency = 4;
        assert_eq!(argon2_budget(&cfg), (4, 64, 512));
        cfg.argon2_max_concurrency = 0;
        assert_eq!(argon2_budget(&cfg), (1, 64, 128));
    }

    #[test]
    fn a_limit_is_too_tight_below_the_budget_plus_the_baseline() {
        assert!(limit_too_tight(511, 256));
        assert!(!limit_too_tight(512, 256));
        assert!(!limit_too_tight(4096, 256));
    }

    #[test]
    fn memory_max_is_read_in_mib_and_max_means_unlimited() {
        assert_eq!(parse_memory_max("536870912\n"), Some(512));
        assert_eq!(parse_memory_max("1048575"), Some(0));
        assert_eq!(parse_memory_max("max\n"), None);
        assert_eq!(parse_memory_max(""), None);
    }
}
