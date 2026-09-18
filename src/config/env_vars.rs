//! Reading environment variables: strict parsing, blank values treated as unset.
//!
//! Variables come from a lookup function: the process environment in
//! production, a map in tests, so loading is tested without mutating the
//! environment of a running process.

use std::str::FromStr;

use ipnetwork::IpNetwork;

use super::ConfigError;

pub(super) struct Env<L> {
    lookup: L,
}

impl<L: Fn(&str) -> Option<String>> Env<L> {
    pub(super) fn new(lookup: L) -> Self {
        Self { lookup }
    }

    pub(super) fn require(&self, key: &str) -> Result<String, ConfigError> {
        (self.lookup)(key).ok_or_else(|| ConfigError::Missing(key.into()))
    }

    /// Optional string variable. A blank value counts as unset: a secret that
    /// survives as `Some("")` satisfies every "must be set" check while the code
    /// using it treats blank as "not configured" and skips the protection.
    pub(super) fn string(&self, key: &str) -> Option<String> {
        (self.lookup)(key).filter(|value| !value.trim().is_empty())
    }

    pub(super) fn csv(&self, key: &str) -> Option<Vec<String>> {
        let value = (self.lookup)(key)?;
        let values = value
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();

        Some(values)
    }

    pub(super) fn ip_network_list(&self, key: &str) -> Result<Vec<IpNetwork>, ConfigError> {
        self.csv(key)
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

    /// Parse an optional variable. Absent or blank yields `None`; a value that
    /// is present but does not parse is an error, never a silent fallback to
    /// the default (`LOCKOUT_THRESHOLD=1O` must not quietly become 10).
    pub(super) fn parse<T>(&self, key: &str) -> Result<Option<T>, ConfigError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        self.string(key)
            .map(|raw| {
                raw.trim().parse::<T>().map_err(|e| ConfigError::Invalid {
                    key: key.into(),
                    reason: format!("cannot parse '{raw}': {e}"),
                })
            })
            .transpose()
    }
}

pub(super) fn default_argon2_max_concurrency() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}
