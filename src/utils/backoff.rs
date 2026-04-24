//! Exponential backoff helper shared across auth services.
//!
//! Delay formula: 2^(failures-1) seconds, capped at `MAX_SECS`.
//! Called *before* returning a failure response so attackers cannot pipeline
//! requests and bypass per-attempt cost.

/// Initial delay after the first failure: 1 second.
pub const BASE_SECS: u64 = 1;
/// Maximum delay cap: 16 seconds. Sequence: 1, 2, 4, 8, 16, 16, ...
pub const MAX_SECS: u64 = 16;

/// Sleeps for `2^(failures-1)` seconds (capped at [`MAX_SECS`]).
/// Does nothing when `failures <= 0`.
pub async fn apply(failures: i64) {
    if failures <= 0 {
        return;
    }
    let exp = (failures - 1).min(4) as u32; // 2^4 = 16 = cap
    let secs = BASE_SECS.saturating_mul(2u64.pow(exp)).min(MAX_SECS);
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
}
