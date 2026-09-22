//! Reading environment variables: strict parsing, blank values treated as unset.
//!
//! Variables come from a lookup function: the process environment in
//! production, a map in tests, so loading is tested without mutating the
//! environment of a running process.

use std::{collections::HashMap, str::FromStr};

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

/// The values of the variables given as `X_FILE`, keyed by `X`: the content
/// of the file, without the trailing newline editors and `echo` add. Setting
/// both `X` and `X_FILE` is refused: which one wins would be a guess. A file
/// that does not exist counts as an unset variable, like an empty one: Docker
/// mounts no file for a secret whose value is empty, such as the previous key
/// outside a rotation. A required variable then stops the start as missing.
pub(super) fn values_from_files(
    vars: impl IntoIterator<Item = (String, String)>,
    read: impl Fn(&str) -> std::io::Result<String>,
) -> Result<HashMap<String, String>, ConfigError> {
    let vars: HashMap<String, String> = vars.into_iter().collect();
    let mut values = HashMap::new();
    for (file_key, path) in &vars {
        let Some(key) = file_key.strip_suffix("_FILE") else {
            continue;
        };
        if key.is_empty() || path.trim().is_empty() {
            continue;
        }
        if vars.get(key).is_some_and(|value| !value.trim().is_empty()) {
            return Err(ConfigError::Invalid {
                key: file_key.clone(),
                reason: format!("{key} is also set: give one of them"),
            });
        }
        let content = match read(path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(ConfigError::Invalid {
                    key: file_key.clone(),
                    reason: format!("cannot read '{path}': {e}"),
                });
            }
        };
        let value = content.strip_suffix('\n').unwrap_or(&content);
        let value = value.strip_suffix('\r').unwrap_or(value);
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

/// The value of a variable: set in the environment, or read from its
/// `X_FILE`. A blank variable counts as unset and leaves the file its place,
/// as `values_from_files` already judged it.
pub(super) fn env_or_file(value: Option<String>, from_file: Option<&String>) -> Option<String> {
    value
        .filter(|value| !value.trim().is_empty())
        .or_else(|| from_file.cloned())
}

pub(super) fn default_argon2_max_concurrency() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}
