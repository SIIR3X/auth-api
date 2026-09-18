//! Verify auth-api access tokens in a Rust resource server.
//!
//! ```no_run
//! # async fn example() -> Result<(), auth_api_verifier::VerifyError> {
//! use auth_api_verifier::{Verifier, VerifierConfig};
//!
//! let verifier = Verifier::new(VerifierConfig::new(
//!     "https://auth.example.com",
//!     "https://api.example.com",
//! ));
//! let token = verifier.verify("eyJ...").await?;
//! if token.has_permission("invoices:read") {
//!     // serve the request for token.subject
//! }
//! # Ok(())
//! # }
//! ```
//!
//! What is checked offline, on every call: the ES256 signature against the
//! issuer's published keys (fetched once, refreshed when an unknown key id
//! appears), the issuer, the audience, and the validity period. What is not:
//! whether the token was revoked (a logout, a password change, a revoked
//! session) before it expires. Access tokens live 15 minutes by default; when
//! that is too long for an operation, configure [`Introspection`] and the
//! verifier asks auth-api, caching the answer briefly.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

#[cfg(feature = "axum")]
mod extractor;
#[cfg(feature = "axum")]
pub use extractor::Authenticated;

/// Why a token was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("the token is not a well-formed JWT")]
    Malformed,
    #[error("the token is signed with a key the issuer does not publish")]
    UnknownKey,
    #[error("the token's signature or claims do not verify: {0}")]
    Invalid(String),
    #[error("the token has expired")]
    Expired,
    #[error("the token was revoked")]
    Revoked,
    #[error("auth-api could not be reached: {0}")]
    Unavailable(String),
}

/// Checking revocation with auth-api's introspection endpoint, as a
/// confidential client.
#[derive(Debug, Clone)]
pub struct Introspection {
    pub client_id: String,
    pub client_secret: String,
    /// How long an answer is reused for the same token. Default: 30 seconds.
    pub cache_ttl: Duration,
    /// Default: `{issuer}/oauth/introspect`.
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// `APP_PUBLIC_URL` of auth-api, the `iss` of its tokens.
    pub issuer: String,
    /// This resource server's identifier, one of auth-api's `JWT_AUDIENCE`.
    pub audience: String,
    /// Default: `{issuer}/.well-known/jwks.json`.
    pub jwks_uri: Option<String>,
    /// Clock difference tolerated on `exp` and `nbf`. Default: 30 seconds.
    pub leeway: Duration,
    /// Shortest wait between two key fetches caused by unknown key ids, so a
    /// flood of forged tokens cannot turn into a flood of requests. Default: 60 s.
    pub min_refresh_interval: Duration,
    pub introspection: Option<Introspection>,
}

impl VerifierConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into().trim_end_matches('/').to_owned(),
            audience: audience.into(),
            jwks_uri: None,
            leeway: Duration::from_secs(30),
            min_refresh_interval: Duration::from_secs(60),
            introspection: None,
        }
    }
}

/// A verified access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The user, or for a client credentials token a UUID standing for the client.
    pub subject: Uuid,
    /// The session the token belongs to; nil for a client credentials token.
    pub session_id: Uuid,
    pub token_id: Uuid,
    /// The client application the token was issued through, when there was one.
    pub client_id: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    /// Unix seconds.
    pub expires_at: i64,
}

impl VerifiedToken {
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// A token a client obtained for itself: no user behind it.
    pub fn is_client_token(&self) -> bool {
        self.session_id.is_nil() && self.client_id.is_some()
    }
}

#[derive(Deserialize)]
struct Claims {
    sub: Uuid,
    sid: Uuid,
    jti: Uuid,
    exp: i64,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    client_id: Option<String>,
}

#[derive(Default)]
struct Keys {
    by_id: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
}

pub struct Verifier {
    config: VerifierConfig,
    jwks_uri: String,
    http: reqwest::Client,
    keys: RwLock<Keys>,
    /// Serializes key fetches.
    refreshing: Mutex<()>,
    introspected: Mutex<HashMap<Uuid, (Instant, bool)>>,
}

impl Verifier {
    pub fn new(config: VerifierConfig) -> Self {
        let jwks_uri = config
            .jwks_uri
            .clone()
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", config.issuer));
        Self {
            config,
            jwks_uri,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            keys: RwLock::default(),
            refreshing: Mutex::default(),
            introspected: Mutex::default(),
        }
    }

    /// Verify `token` (without the `Bearer ` prefix).
    pub async fn verify(&self, token: &str) -> Result<VerifiedToken, VerifyError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| VerifyError::Malformed)?;
        if header.alg != Algorithm::ES256 {
            return Err(VerifyError::Invalid(
                "only ES256 tokens are accepted".into(),
            ));
        }
        let kid = header.kid.ok_or(VerifyError::UnknownKey)?;
        let key = self.key(&kid).await?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.leeway = self.config.leeway.as_secs();
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => VerifyError::Expired,
                _ => VerifyError::Invalid(e.to_string()),
            })?
            .claims;

        let verified = VerifiedToken {
            subject: claims.sub,
            session_id: claims.sid,
            token_id: claims.jti,
            client_id: claims.client_id,
            roles: claims.roles,
            permissions: claims.permissions,
            expires_at: claims.exp,
        };
        if let Some(introspection) = &self.config.introspection
            && !self.active(introspection, token, verified.token_id).await?
        {
            return Err(VerifyError::Revoked);
        }
        Ok(verified)
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, VerifyError> {
        if let Some(key) = self.keys.read().await.by_id.get(kid) {
            return Ok(key.clone());
        }
        let _one_fetch = self.refreshing.lock().await;
        // Another call may have fetched while this one waited.
        {
            let keys = self.keys.read().await;
            if let Some(key) = keys.by_id.get(kid) {
                return Ok(key.clone());
            }
            if keys
                .fetched_at
                .is_some_and(|at| at.elapsed() < self.config.min_refresh_interval)
            {
                return Err(VerifyError::UnknownKey);
            }
        }
        let set: JwkSet = self
            .http
            .get(&self.jwks_uri)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| VerifyError::Unavailable(e.to_string()))?
            .json()
            .await
            .map_err(|e| VerifyError::Unavailable(e.to_string()))?;
        let by_id: HashMap<String, DecodingKey> = set
            .keys
            .iter()
            .filter_map(|jwk| Some((jwk.common.key_id.clone()?, DecodingKey::from_jwk(jwk).ok()?)))
            .collect();
        let found = by_id.get(kid).cloned();
        *self.keys.write().await = Keys {
            by_id,
            fetched_at: Some(Instant::now()),
        };
        found.ok_or(VerifyError::UnknownKey)
    }

    async fn active(
        &self,
        introspection: &Introspection,
        token: &str,
        token_id: Uuid,
    ) -> Result<bool, VerifyError> {
        if let Some((at, active)) = self.introspected.lock().await.get(&token_id)
            && at.elapsed() < introspection.cache_ttl
        {
            return Ok(*active);
        }
        #[derive(Deserialize)]
        struct Answer {
            active: bool,
        }
        let answer: Answer = self
            .http
            .post(
                introspection
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| format!("{}/oauth/introspect", self.config.issuer)),
            )
            .basic_auth(&introspection.client_id, Some(&introspection.client_secret))
            .form(&[("token", token)])
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| VerifyError::Unavailable(e.to_string()))?
            .json()
            .await
            .map_err(|e| VerifyError::Unavailable(e.to_string()))?;
        let mut cache = self.introspected.lock().await;
        cache.retain(|_, (at, _)| at.elapsed() < introspection.cache_ttl);
        cache.insert(token_id, (Instant::now(), answer.active));
        Ok(answer.active)
    }
}

impl Introspection {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            cache_ttl: Duration::from_secs(30),
            endpoint: None,
        }
    }
}
