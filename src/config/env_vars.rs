//! Reading environment variables: strict parsing, blank values treated as unset.

use std::{env, str::FromStr};

use ipnetwork::IpNetwork;

use super::ConfigError;

pub(super) fn env_require(key: &str) -> Result<String, ConfigError> {
    env::var(key).map_err(|_| ConfigError::Missing(key.into()))
}

/// Optional string variable. A blank value counts as unset: a secret that
/// survives as `Some("")` satisfies every "must be set" check while the code
/// using it treats blank as "not configured" and skips the protection.
pub(super) fn env_string(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

pub(super) fn env_csv(key: &str) -> Option<Vec<String>> {
    let value = env::var(key).ok()?;
    let values = value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    Some(values)
}

pub(super) fn env_ip_network_list(key: &str) -> Result<Vec<IpNetwork>, ConfigError> {
    env_csv(key)
        .unwrap_or_default()
        .into_iter()
        .map(|raw| {
            raw.parse::<IpNetwork>().map_err(|e| ConfigError::Invalid {
                key: key.into(),
                reason: format!("invalid CIDR '{raw}': {e}"),
            })
        })
        .collect()
}

/// Parse an optional variable. Absent or blank yields `None`; a value that is
/// present but does not parse is an error, never a silent fallback to the
/// default (`LOCKOUT_THRESHOLD=1O` must not quietly become 10).
pub(super) fn env_parse<T>(key: &str) -> Result<Option<T>, ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    env_string(key)
        .map(|raw| {
            raw.trim().parse::<T>().map_err(|e| ConfigError::Invalid {
                key: key.into(),
                reason: format!("cannot parse '{raw}': {e}"),
            })
        })
        .transpose()
}

pub(super) fn default_argon2_max_concurrency() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}
