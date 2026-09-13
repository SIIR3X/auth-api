//! Startup validation: refuse a configuration that is unsafe for its environment.

use base64::{Engine, engine::general_purpose::STANDARD};

use super::*;

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_jwt_keys(&self.jwt)?;
        validate_encryption_key("ENCRYPTION_KEY", &self.crypto.encryption_key)?;
        validate_optional_encryption_key(
            "PREVIOUS_ENCRYPTION_KEY",
            self.crypto.previous_encryption_key.as_deref(),
        )?;
        validate_cors(&self.cors, self.is_production())?;
        validate_security(&self.security)?;
        validate_device_auth(&self.device_auth)?;
        validate_session_lifetime(&self.jwt)?;
        validate_crypto(&self.crypto)?;

        validate_jwt_audience(&self.jwt.audience, self.is_production())?;

        let (_, nats_credentials) =
            crate::utils::nats::split_credentials(&self.nats.url).map_err(|reason| {
                ConfigError::Invalid {
                    key: "NATS_URL".into(),
                    reason,
                }
            })?;

        if self.is_production() {
            // The development key pair is committed in `.env.dev` and therefore
            // public: anyone can mint valid tokens for a deployment that uses
            // it. Refuse to boot rather than run with a known-compromised key.
            if self
                .jwt
                .public_key
                .replace(['\n', ' ', '\t'], "")
                .contains(DEV_JWT_PUBLIC_KEY_MARKER)
            {
                return Err(ConfigError::Invalid {
                    key: "JWT_PUBLIC_KEY".into(),
                    reason: "this is the committed development key from .env.dev -- it is public and must never be used in production".into(),
                });
            }

            validate_https_url("APP_PUBLIC_URL", &self.server.public_url)?;
            validate_https_url("FRONTEND_URL", &self.server.frontend_url)?;

            // TLS terminates at a reverse proxy in production. With no trusted
            // CIDR every request resolves to the proxy's address: one rate-limit
            // bucket for the whole internet and one IP in every audit row.
            if self.server.trusted_proxy_cidrs.is_empty() {
                return Err(ConfigError::Invalid {
                    key: "TRUSTED_PROXY_CIDRS".into(),
                    reason: "must not be empty in production -- without it every client is rate-limited and audited as the reverse proxy".into(),
                });
            }

            validate_production_encryption_key("ENCRYPTION_KEY", &self.crypto.encryption_key)?;
            if let Some(previous) = self.crypto.previous_encryption_key.as_deref() {
                validate_production_encryption_key("PREVIOUS_ENCRYPTION_KEY", previous)?;
            }

            if self.captcha.secret.is_some() {
                validate_https_url("CAPTCHA_VERIFY_URL", &self.captcha.verify_url)?;
            } else {
                return Err(ConfigError::Invalid {
                    key: "CAPTCHA_SECRET".into(),
                    reason: "must be set in production -- CAPTCHA protection cannot be disabled in production".into(),
                });
            }

            if self.mail.smtp.username.is_empty() {
                return Err(ConfigError::Invalid {
                    key: "SMTP_USERNAME".into(),
                    reason: "must not be empty in production (unauthenticated/unencrypted SMTP is not allowed)".into(),
                });
            }

            // The broker carries the erasure events: anything that reaches it
            // must not be able to publish or read them.
            if nats_credentials == crate::utils::nats::NatsCredentials::None {
                return Err(ConfigError::Invalid {
                    key: "NATS_URL".into(),
                    reason:
                        "must carry the broker credentials in production (nats://<token>@host:port)"
                            .into(),
                });
            }

            // Hardened-default switches: in production these MUST be set to the
            // secure value, even if an env override re-enables the permissive
            // behaviour. Refuse to boot rather than start in a degraded state.
            if self.rate_limit.fail_open_on_redis_error {
                return Err(ConfigError::Invalid {
                    key: "RATE_LIMIT_FAIL_OPEN".into(),
                    reason: "must be false in production -- a Redis outage would otherwise disable rate limiting entirely".into(),
                });
            }

            if self.rate_limit.allow_requests_without_ip {
                return Err(ConfigError::Invalid {
                    key: "RATE_LIMIT_ALLOW_MISSING_IP".into(),
                    reason: "must be false in production -- requests without a resolved client IP must be rejected, not let through".into(),
                });
            }

            if self.captcha.fail_open_on_error {
                return Err(ConfigError::Invalid {
                    key: "CAPTCHA_FAIL_OPEN".into(),
                    reason: "must be false in production -- CAPTCHA upstream errors must not let traffic through".into(),
                });
            }

            if !self.jwt.strict_session_binding {
                return Err(ConfigError::Invalid {
                    key: "JWT_STRICT_SESSION_BINDING".into(),
                    reason: "must be true in production -- refresh tokens must be bound to the originating IP".into(),
                });
            }
        }

        Ok(())
    }
}

/// Symmetric keys committed in `.env.dev` or used as examples: public by
/// definition, refused in production.
pub(super) const DEV_ENCRYPTION_KEYS: [&str; 2] = [
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
];

pub(super) fn validate_jwt_keys(jwt: &JwtConfig) -> Result<(), ConfigError> {
    use crate::utils::jwt as jwt_util;

    let signing_key =
        jwt_util::parse_signing_key(&jwt.private_key).map_err(|e| ConfigError::Invalid {
            key: "JWT_PRIVATE_KEY".into(),
            reason: e.to_string(),
        })?;

    let verifying_key =
        jwt_util::parse_p256_verifying_key(&jwt.public_key).map_err(|e| ConfigError::Invalid {
            key: "JWT_PUBLIC_KEY".into(),
            reason: e.to_string(),
        })?;

    // Verify that the public key matches the private key.
    let derived = p256::ecdsa::VerifyingKey::from(&signing_key);
    if derived != verifying_key {
        return Err(ConfigError::Invalid {
            key: "JWT_PUBLIC_KEY".into(),
            reason: "public key does not match the private key".into(),
        });
    }

    if let Some(ref prev_pub) = jwt.previous_public_key {
        jwt_util::parse_p256_verifying_key(prev_pub).map_err(|e| ConfigError::Invalid {
            key: "JWT_PREVIOUS_PUBLIC_KEY".into(),
            reason: e.to_string(),
        })?;
    }

    if let Some(ref next_pub) = jwt.next_public_key {
        jwt_util::parse_p256_verifying_key(next_pub).map_err(|e| ConfigError::Invalid {
            key: "JWT_NEXT_PUBLIC_KEY".into(),
            reason: e.to_string(),
        })?;
    }

    Ok(())
}

pub(super) fn validate_encryption_key(key_name: &str, value: &str) -> Result<(), ConfigError> {
    let decoded = STANDARD.decode(value).map_err(|e| ConfigError::Invalid {
        key: key_name.into(),
        reason: format!("must be valid base64: {e}"),
    })?;

    if decoded.len() != 32 {
        return Err(ConfigError::Invalid {
            key: key_name.into(),
            reason: "must decode to exactly 32 bytes".into(),
        });
    }

    // Reject low-entropy keys using Shannon entropy over byte distribution.
    // A truly random 32-byte key typically has >= 3.5 bits of entropy per byte.
    let mut counts = [0u32; 256];
    for &b in &decoded {
        counts[b as usize] += 1;
    }
    let len = decoded.len() as f64;
    let shannon: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum();
    if shannon < 3.0 {
        return Err(ConfigError::Invalid {
            key: key_name.into(),
            reason: format!(
                "key has insufficient entropy ({shannon:.2} bits/byte, minimum 3.0): \
                 use a cryptographically random key (e.g. openssl rand -base64 32)"
            ),
        });
    }

    Ok(())
}

/// Production-only checks on a symmetric key, on top of the entropy floor.
///
/// Shannon entropy counts byte frequencies, so any 32 distinct bytes score a
/// perfect 5 bits/byte -- including the counted sequence `00 01 .. 1f` from
/// `.env.dev`. A constant stride between bytes gives such keys away.
pub(super) fn validate_production_encryption_key(
    key_name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if DEV_ENCRYPTION_KEYS.contains(&value) {
        return Err(ConfigError::Invalid {
            key: key_name.into(),
            reason: "this is a committed development key -- it is public and must never be used in production".into(),
        });
    }

    let decoded = STANDARD.decode(value).map_err(|e| ConfigError::Invalid {
        key: key_name.into(),
        reason: format!("must be valid base64: {e}"),
    })?;

    let stride = decoded
        .windows(2)
        .next()
        .map(|w| w[1].wrapping_sub(w[0]))
        .unwrap_or_default();
    if decoded
        .windows(2)
        .all(|w| w[1].wrapping_sub(w[0]) == stride)
    {
        return Err(ConfigError::Invalid {
            key: key_name.into(),
            reason: "key bytes form an arithmetic sequence: use a cryptographically random key (e.g. openssl rand -base64 32)".into(),
        });
    }

    Ok(())
}

pub(super) fn validate_optional_encryption_key(
    key_name: &str,
    value: Option<&str>,
) -> Result<(), ConfigError> {
    if let Some(value) = value {
        validate_encryption_key(key_name, value)?;
    }

    Ok(())
}

pub(super) fn validate_https_url(key: &str, value: &str) -> Result<(), ConfigError> {
    if !value.starts_with("https://") {
        return Err(ConfigError::Invalid {
            key: key.into(),
            reason: "must use https in production".into(),
        });
    }

    Ok(())
}

/// `JWT_AUDIENCE` validation. In production we refuse to start without at
/// least one audience: emitting tokens with an empty `aud` would silently
/// break every downstream service that pins the audience claim. In dev we
/// only warn so local stacks (no resource server, scratch tests) keep
/// working.
pub(super) fn validate_jwt_audience(
    audience: &[String],
    is_production: bool,
) -> Result<(), ConfigError> {
    if audience.is_empty() {
        if is_production {
            return Err(ConfigError::Invalid {
                key: "JWT_AUDIENCE".into(),
                reason: "must not be empty in production -- downstream services that pin `aud` would reject all tokens".into(),
            });
        }

        tracing::warn!(
            "JWT_AUDIENCE is empty: issued access tokens will not carry an `aud` claim, downstream services pinning audience will reject them"
        );
        return Ok(());
    }

    for value in audience {
        if value.trim().is_empty() {
            return Err(ConfigError::Invalid {
                key: "JWT_AUDIENCE".into(),
                reason: "entries must not be empty or whitespace-only".into(),
            });
        }
    }

    Ok(())
}

pub(super) fn validate_crypto(crypto: &CryptoConfig) -> Result<(), ConfigError> {
    if crypto.argon2_max_concurrency == 0 {
        return Err(ConfigError::Invalid {
            key: "ARGON2_MAX_CONCURRENCY".into(),
            reason: "must be greater than 0".into(),
        });
    }

    Ok(())
}

pub(super) fn validate_security(security: &SecurityConfig) -> Result<(), ConfigError> {
    // 0 would not disable the lockout: every wrong password would lock the account.
    if security.lockout_threshold == 0 {
        return Err(ConfigError::Invalid {
            key: "LOCKOUT_THRESHOLD".into(),
            reason: "must be at least 1".into(),
        });
    }

    if security.sensitive_action_reauth_secs == 0 {
        return Err(ConfigError::Invalid {
            key: "SENSITIVE_ACTION_REAUTH_SECS".into(),
            reason: "must be greater than 0".into(),
        });
    }

    Ok(())
}

/// A device flow needs a code that lives long enough to be polled at least once.
pub(super) fn validate_device_auth(device: &DeviceAuthConfig) -> Result<(), ConfigError> {
    if device.ttl_secs == 0 {
        return Err(ConfigError::Invalid {
            key: "DEVICE_AUTH_TTL_SECS".into(),
            reason: "must be greater than 0".into(),
        });
    }
    // 0 was advertised to clients as is, while polling was paced at one second:
    // a client following the advertised interval was always told to slow down.
    if device.poll_interval_secs == 0 {
        return Err(ConfigError::Invalid {
            key: "DEVICE_AUTH_POLL_INTERVAL_SECS".into(),
            reason: "must be at least 1".into(),
        });
    }
    if device.poll_interval_secs >= device.ttl_secs {
        return Err(ConfigError::Invalid {
            key: "DEVICE_AUTH_POLL_INTERVAL_SECS".into(),
            reason: "must be shorter than DEVICE_AUTH_TTL_SECS, or no poll can succeed".into(),
        });
    }
    Ok(())
}

/// A zero absolute lifetime would refuse every refresh.
pub(super) fn validate_session_lifetime(jwt: &JwtConfig) -> Result<(), ConfigError> {
    if jwt.max_session_lifetime_secs == 0 {
        return Err(ConfigError::Invalid {
            key: "JWT_MAX_SESSION_LIFETIME_SECS".into(),
            reason: "must be greater than 0".into(),
        });
    }
    Ok(())
}
pub(super) fn validate_cors(cors: &CorsConfig, is_production: bool) -> Result<(), ConfigError> {
    if cors.allowed_origins.is_empty() {
        return Err(ConfigError::Invalid {
            key: "CORS_ALLOWED_ORIGINS".into(),
            reason: "must not be empty".into(),
        });
    }

    let has_wildcard = cors.allowed_origins.iter().any(|origin| origin == "*");
    if has_wildcard && cors.allow_credentials {
        return Err(ConfigError::Invalid {
            key: "CORS_ALLOWED_ORIGINS".into(),
            reason: "cannot use '*' when CORS_ALLOW_CREDENTIALS=true".into(),
        });
    }

    if is_production && has_wildcard {
        return Err(ConfigError::Invalid {
            key: "CORS_ALLOWED_ORIGINS".into(),
            reason: "cannot use '*' in production".into(),
        });
    }

    for origin in cors
        .allowed_origins
        .iter()
        .filter(|origin| origin.as_str() != "*")
    {
        let parsed = reqwest::Url::parse(origin).map_err(|e| ConfigError::Invalid {
            key: "CORS_ALLOWED_ORIGINS".into(),
            reason: format!("invalid origin '{origin}': {e}"),
        })?;

        if is_production && parsed.scheme() != "https" {
            return Err(ConfigError::Invalid {
                key: "CORS_ALLOWED_ORIGINS".into(),
                reason: format!("origin '{origin}' must use https in production"),
            });
        }
    }

    Ok(())
}
