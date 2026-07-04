//! JWT encoding/decoding for ES256 access tokens, backed by the audited
//! `jsonwebtoken` crate.
//!
//! Access tokens carry sid (session ID) so handlers can revoke the right session
//! on logout without an extra DB lookup, and jti for individual token revocation.
//!
//! Uses ECDSA with the P-256 curve (ES256) for asymmetric signing: the auth API
//! signs tokens with a private key, while other services verify with the public key.
//! The `p256` crate is still used for key material that `jsonwebtoken` does not
//! expose: startup private/public key consistency checks, `kid` derivation, and
//! the JWKS document served at /.well-known/jwks.json.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("failed to encode token: {0}")]
    Encode(String),
    #[error("failed to decode token: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: user UUID.
    pub sub: Uuid,
    /// Session ID: the refresh session this access token was issued for.
    pub sid: Uuid,
    /// JWT ID: unique per token, used for blocklist-based revocation.
    pub jti: Uuid,
    /// Expiry (Unix timestamp).
    pub exp: i64,
    /// Issued at (Unix timestamp).
    pub iat: i64,
    /// Not Before (Unix timestamp). Optional for backward compatibility with
    /// tokens issued before this field was added; validated when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issuer (the `iss` standard claim, RFC 7519 section 4.1.1).
    /// Optional in the type for backward compatibility with tests and tokens
    /// issued before this field was added; populated by `build_access_token`
    /// at runtime so downstream services can pin the issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience (the `aud` standard claim, RFC 7519 section 4.1.3).
    /// Emitted as a JSON array of strings so multiple downstream services
    /// (core-api, billing-api, ...) can each accept the same token.
    /// Defaults to empty for tests / backward compat; production tokens
    /// always carry at least one entry (enforced by config validation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aud: Vec<String>,
    /// Role names assigned to the user (e.g. ["user", "admin"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Permission names granted through roles (e.g. ["billing:read", "billing:create"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
}

impl Claims {
    pub fn new(user_id: Uuid, session_id: Uuid, exp: i64) -> Self {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Self {
            sub: user_id,
            sid: session_id,
            jti: Uuid::new_v4(),
            exp,
            iat: now,
            nbf: Some(now),
            iss: None,
            aud: Vec::new(),
            roles: Vec::new(),
            permissions: Vec::new(),
        }
    }

    pub fn with_rbac(mut self, roles: Vec<String>, permissions: Vec<String>) -> Self {
        self.roles = roles;
        self.permissions = permissions;
        self
    }
}

pub fn encode_token(
    claims: &Claims,
    key: &EncodingKey,
    kid: Option<&str>,
) -> Result<String, JwtError> {
    let mut header = Header::new(Algorithm::ES256);
    // Optional key identifier. When present, JWKS-based verifiers (core-api,
    // billing-api, ...) can pin verification to a specific key, allowing
    // safe key rotation.
    header.kid = kid.map(str::to_owned);

    jsonwebtoken::encode(&header, claims, key).map_err(|e| JwtError::Encode(e.to_string()))
}

pub fn decode_token(token: &str, key: &DecodingKey) -> Result<Claims, JwtError> {
    decode_token_with_fallback(token, key, None)
}

/// Defense-in-depth post-decode validation of the `iss` and `aud` claims.
///
/// `decode_token` and `decode_token_with_fallback` only verify the signature
/// and the time-based claims (exp/nbf): they do NOT pin the issuer or the
/// audience, mostly so legacy tests that produce tokens without those fields
/// keep passing. Callers that mint and consume tokens within the same trust
/// boundary (the `AuthenticatedUser` extractor here in auth-api, downstream
/// resource servers like core-api / billing-api) MUST run this check after
/// decoding to make sure a token issued by another deployment, or addressed
/// to another service, is rejected.
///
/// `expected_iss` is matched for exact equality against `claims.iss`.
/// `expected_aud` must appear in the `claims.aud` array (which is `Vec<String>`
/// so a single token can be addressed to multiple resource servers).
/// A token missing `iss` or with an empty/unmatching `aud` is rejected.
pub fn validate_iss_aud(
    claims: &Claims,
    expected_iss: &str,
    expected_aud: &str,
) -> Result<(), JwtError> {
    match claims.iss.as_deref() {
        Some(iss) if iss == expected_iss => {}
        Some(_) => return Err(JwtError::Decode("issuer mismatch".into())),
        None => return Err(JwtError::Decode("missing issuer claim".into())),
    }

    if !claims.aud.iter().any(|a| a == expected_aud) {
        return Err(JwtError::Decode("audience mismatch".into()));
    }

    Ok(())
}

/// Decodes a JWT, trying `key` first and then `previous_key` if provided.
/// Used to accept tokens signed with the previous key during a rotation window.
pub fn decode_token_with_fallback(
    token: &str,
    key: &DecodingKey,
    previous_key: Option<&DecodingKey>,
) -> Result<Claims, JwtError> {
    match decode_token_inner(token, key) {
        Ok(claims) => Ok(claims),
        Err(primary_error) => {
            if let Some(previous_key) = previous_key {
                decode_token_inner(token, previous_key).map_err(|_| primary_error)
            } else {
                Err(primary_error)
            }
        }
    }
}

fn decode_token_inner(token: &str, key: &DecodingKey) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::ES256);
    // Match the historical in-house behaviour: strict time-based validation
    // with no leeway, `nbf` checked when present, and `iss`/`aud` left to the
    // explicit `validate_iss_aud` call so trust-boundary pinning stays visible
    // at the call sites (extractor, downstream resource servers).
    validation.leeway = 0;
    validation.validate_nbf = true;
    validation.validate_aud = false;

    jsonwebtoken::decode::<Claims>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|e| JwtError::Decode(e.to_string()))
}

// Key parsing helpers

/// Parse a PEM-encoded PKCS#8 EC private key into a p256 signing key.
/// Only used for startup validation (private/public key consistency check);
/// token signing goes through `parse_encoding_key`.
pub fn parse_signing_key(pem: &str) -> Result<SigningKey, JwtError> {
    SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| JwtError::Decode(format!("invalid private key PEM: {e}")))
}

/// Parse a PEM-encoded SubjectPublicKeyInfo EC public key into a p256 verifying
/// key. Used for startup validation, `kid` derivation and JWKS construction;
/// token verification goes through `parse_verifying_key`.
pub fn parse_p256_verifying_key(pem: &str) -> Result<VerifyingKey, JwtError> {
    pem.parse::<VerifyingKey>()
        .map_err(|e| JwtError::Decode(format!("invalid public key PEM: {e}")))
}

/// Parse a PEM-encoded PKCS#8 EC private key into a `jsonwebtoken` encoding key.
pub fn parse_encoding_key(pem: &str) -> Result<EncodingKey, JwtError> {
    EncodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| JwtError::Decode(format!("invalid private key PEM: {e}")))
}

/// Parse a PEM-encoded SubjectPublicKeyInfo EC public key into a `jsonwebtoken`
/// decoding key used for token verification.
pub fn parse_verifying_key(pem: &str) -> Result<DecodingKey, JwtError> {
    DecodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| JwtError::Decode(format!("invalid public key PEM: {e}")))
}

/// Compute a short key ID (first 8 hex chars of the SHA-256 of the uncompressed public point).
pub fn compute_kid(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(false);
    let hash = Sha256::digest(point.as_bytes());
    hash[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a JWK representation of a P-256 public key for the JWKS endpoint.
pub fn public_key_to_jwk(key: &VerifyingKey, kid: &str) -> serde_json::Value {
    let point = key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": x,
        "y": y,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::PublicKey;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use proptest::prelude::*;
    use rand_core::OsRng;

    fn test_keys() -> (EncodingKey, DecodingKey) {
        let (sk, vk) = test_key_pems();
        (
            parse_encoding_key(&sk).unwrap(),
            parse_verifying_key(&vk).unwrap(),
        )
    }

    fn test_key_pems() -> (String, String) {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let private_pem = sk.to_pkcs8_pem(Default::default()).unwrap().to_string();
        let public_pem = PublicKey::from(vk).to_string();
        (private_pem, public_pem)
    }

    fn valid_claims() -> Claims {
        Claims::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        )
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (sk, vk) = test_keys();
        let claims = valid_claims();
        let token = encode_token(&claims, &sk, None).unwrap();
        let decoded = decode_token(&token, &vk).unwrap();

        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.sid, claims.sid);
        assert_eq!(decoded.jti, claims.jti);
        assert_eq!(decoded.exp, claims.exp);
    }

    #[test]
    fn each_token_has_unique_jti() {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let exp = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let c1 = Claims::new(user_id, session_id, exp);
        let c2 = Claims::new(user_id, session_id, exp);
        assert_ne!(c1.jti, c2.jti);
    }

    #[test]
    fn decode_with_wrong_key_fails() {
        let (sk, _vk) = test_keys();
        let (_sk2, vk2) = test_keys();
        let token = encode_token(&valid_claims(), &sk, None).unwrap();
        assert!(matches!(
            decode_token(&token, &vk2),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn decode_expired_token_fails() {
        let (sk, vk) = test_keys();
        let claims = Claims {
            sub: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            jti: Uuid::new_v4(),
            exp: 1,
            iat: 1,
            nbf: None,
            iss: None,
            aud: Vec::new(),
            roles: Vec::new(),
            permissions: Vec::new(),
        };
        let token = encode_token(&claims, &sk, None).unwrap();
        assert!(matches!(
            decode_token(&token, &vk),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn decode_not_yet_valid_token_fails() {
        let (sk, vk) = test_keys();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            sub: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            jti: Uuid::new_v4(),
            exp: now + 7200,
            iat: now,
            nbf: Some(now + 3600),
            iss: None,
            aud: Vec::new(),
            roles: Vec::new(),
            permissions: Vec::new(),
        };
        let token = encode_token(&claims, &sk, None).unwrap();
        assert!(matches!(
            decode_token(&token, &vk),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn decode_malformed_token_fails() {
        let (_sk, vk) = test_keys();
        assert!(matches!(
            decode_token("not.a.token", &vk),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn decode_rejects_non_es256_alg() {
        // A structurally valid token whose header declares HS256 must be
        // rejected before any signature logic runs (algorithm confusion guard).
        let (_sk, vk) = test_keys();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&valid_claims()).expect("claims must serialize"));
        let token = format!("{header}.{payload}.AAAA");
        assert!(matches!(
            decode_token(&token, &vk),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn decode_with_previous_key_accepts_rotated_tokens() {
        let (old_sk, old_vk) = test_keys();
        let (_new_sk, new_vk) = test_keys();
        let claims = valid_claims();
        let token = encode_token(&claims, &old_sk, None).unwrap();

        let decoded = decode_token_with_fallback(&token, &new_vk, Some(&old_vk)).unwrap();

        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.sid, claims.sid);
    }

    #[test]
    fn validate_iss_aud_accepts_matching_claims() {
        let mut claims = valid_claims();
        claims.iss = Some("https://auth.example.com".into());
        claims.aud = vec![
            "https://auth.example.com".into(),
            "https://core.example.com".into(),
        ];

        assert!(
            validate_iss_aud(
                &claims,
                "https://auth.example.com",
                "https://auth.example.com"
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_iss_aud_rejects_missing_issuer() {
        let mut claims = valid_claims();
        claims.iss = None;
        claims.aud = vec!["https://auth.example.com".into()];

        assert!(matches!(
            validate_iss_aud(
                &claims,
                "https://auth.example.com",
                "https://auth.example.com"
            ),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn validate_iss_aud_rejects_wrong_issuer() {
        let mut claims = valid_claims();
        claims.iss = Some("https://attacker.example.com".into());
        claims.aud = vec!["https://auth.example.com".into()];

        assert!(matches!(
            validate_iss_aud(
                &claims,
                "https://auth.example.com",
                "https://auth.example.com"
            ),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn validate_iss_aud_rejects_missing_audience() {
        let mut claims = valid_claims();
        claims.iss = Some("https://auth.example.com".into());
        claims.aud = vec!["https://core.example.com".into()];

        assert!(matches!(
            validate_iss_aud(
                &claims,
                "https://auth.example.com",
                "https://auth.example.com"
            ),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn validate_iss_aud_rejects_empty_audience() {
        let mut claims = valid_claims();
        claims.iss = Some("https://auth.example.com".into());
        claims.aud = vec![];

        assert!(matches!(
            validate_iss_aud(
                &claims,
                "https://auth.example.com",
                "https://auth.example.com"
            ),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn jwks_output_contains_required_fields() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let kid = compute_kid(&vk);
        let jwk = public_key_to_jwk(&vk, &kid);

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");
        assert_eq!(jwk["kid"], kid);
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
    }

    #[test]
    fn parse_key_roundtrip() {
        let (private_pem, public_pem) = test_key_pems();

        // p256 parsers (startup validation / JWKS path)
        parse_signing_key(&private_pem).unwrap();
        parse_p256_verifying_key(&public_pem).unwrap();

        // jsonwebtoken parsers (token signing / verification path)
        let encoding_key = parse_encoding_key(&private_pem).unwrap();
        let decoding_key = parse_verifying_key(&public_pem).unwrap();

        let claims = valid_claims();
        let token = encode_token(&claims, &encoding_key, None).unwrap();
        let decoded = decode_token(&token, &decoding_key).unwrap();
        assert_eq!(decoded.sub, claims.sub);
    }

    #[test]
    fn kid_is_stamped_into_header() {
        let (sk, _vk) = test_keys();
        let token = encode_token(&valid_claims(), &sk, Some("abcd1234")).unwrap();
        let header = jsonwebtoken::decode_header(&token).expect("header must parse");
        assert_eq!(header.kid.as_deref(), Some("abcd1234"));
        assert_eq!(header.alg, Algorithm::ES256);
    }

    proptest! {
        #[test]
        fn property_roundtrip_preserves_claims(
            sub in any::<[u8; 16]>(),
            sid in any::<[u8; 16]>(),
            jti in any::<[u8; 16]>(),
            exp_delta in 1i64..86_400i64,
            iat_back in 0i64..3_600i64,
        ) {
            let (sk, vk) = test_keys();
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let claims = Claims {
                sub: Uuid::from_bytes(sub),
                sid: Uuid::from_bytes(sid),
                jti: Uuid::from_bytes(jti),
                exp: now + exp_delta,
                iat: now.saturating_sub(iat_back),
                nbf: None,
                iss: None,
                aud: Vec::new(),
                roles: Vec::new(),
                permissions: Vec::new(),
            };

            let token = encode_token(&claims, &sk, None).unwrap();
            let decoded = decode_token(&token, &vk).unwrap();

            prop_assert_eq!(decoded.sub, claims.sub);
            prop_assert_eq!(decoded.sid, claims.sid);
            prop_assert_eq!(decoded.jti, claims.jti);
            prop_assert_eq!(decoded.exp, claims.exp);
        }

        #[test]
        fn property_tampered_signature_is_rejected(
            sub in any::<[u8; 16]>(),
            sid in any::<[u8; 16]>(),
            jti in any::<[u8; 16]>(),
            exp_delta in 1i64..86_400i64,
            suffix in "[A-Za-z0-9_-]{1,6}",
        ) {
            let (sk, vk) = test_keys();
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let claims = Claims {
                sub: Uuid::from_bytes(sub),
                sid: Uuid::from_bytes(sid),
                jti: Uuid::from_bytes(jti),
                exp: now + exp_delta,
                iat: now,
                nbf: None,
                iss: None,
                aud: Vec::new(),
                roles: Vec::new(),
                permissions: Vec::new(),
            };

            let token = encode_token(&claims, &sk, None).unwrap();
            let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
            parts[2].push_str(&suffix);
            let tampered = parts.join(".");

            prop_assert!(matches!(
                decode_token(&tampered, &vk),
                Err(JwtError::Decode(_))
            ));
        }
    }
}
