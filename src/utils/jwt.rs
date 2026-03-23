//! Minimal JWT encoding/decoding for HS256 access tokens.
//!
//! Access tokens carry sid (session ID) so handlers can revoke the right session
//! on logout without an extra DB lookup, and jti for individual token revocation.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

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
}

impl Claims {
    pub fn new(user_id: Uuid, session_id: Uuid, exp: i64) -> Self {
        Self {
            sub: user_id,
            sid: session_id,
            jti: Uuid::new_v4(),
            exp,
            iat: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
}

pub fn encode_token(claims: &Claims, secret: &str) -> Result<String, JwtError> {
    let header = Header {
        alg: "HS256",
        typ: "JWT",
    };

    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| JwtError::Encode(e.to_string()))?);
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).map_err(|e| JwtError::Encode(e.to_string()))?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign(&signing_input, secret)?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}

pub fn decode_token(token: &str, secret: &str) -> Result<Claims, JwtError> {
    decode_token_with_fallback(token, secret, None)
}

/// Decodes a JWT, trying `secret` first and then `previous_secret` if provided.
/// Used to accept tokens signed with the previous key during a rotation window.
pub fn decode_token_with_fallback(
    token: &str,
    secret: &str,
    previous_secret: Option<&str>,
) -> Result<Claims, JwtError> {
    match decode_token_inner(token, secret) {
        Ok(claims) => Ok(claims),
        Err(primary_error) => {
            if let Some(previous_secret) = previous_secret {
                decode_token_inner(token, previous_secret).map_err(|_| primary_error)
            } else {
                Err(primary_error)
            }
        }
    }
}

fn decode_token_inner(token: &str, secret: &str) -> Result<Claims, JwtError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(JwtError::Decode(
            "token must contain exactly 3 non-empty segments".into(),
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| JwtError::Decode(format!("invalid header encoding: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwtError::Decode(format!("invalid header json: {e}")))?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JwtError::Decode("missing alg header".into()))?;
    if alg != "HS256" {
        return Err(JwtError::Decode(format!("unsupported alg: {alg}")));
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| JwtError::Decode(format!("invalid signature encoding: {e}")))?;
    verify_signature(&signing_input, secret, &signature)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| JwtError::Decode(format!("invalid payload encoding: {e}")))?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwtError::Decode(format!("invalid payload json: {e}")))?;

    if claims.exp <= time::OffsetDateTime::now_utc().unix_timestamp() {
        return Err(JwtError::Decode("token expired".into()));
    }

    Ok(claims)
}

fn sign(signing_input: &str, secret: &str) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| JwtError::Encode(format!("invalid HMAC key: {e}")))?;
    mac.update(signing_input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_signature(signing_input: &str, secret: &str, signature: &[u8]) -> Result<(), JwtError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| JwtError::Decode(format!("invalid HMAC key: {e}")))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(signature)
        .map_err(|_| JwtError::Decode("invalid token signature".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SECRET: &str = "super-secret-key-for-tests";

    fn valid_claims() -> Claims {
        Claims::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        )
    }

    #[test]
    fn encode_decode_roundtrip() {
        let claims = valid_claims();
        let token = encode_token(&claims, SECRET).unwrap();
        let decoded = decode_token(&token, SECRET).unwrap();

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
    fn decode_with_wrong_secret_fails() {
        let token = encode_token(&valid_claims(), SECRET).unwrap();
        assert!(matches!(
            decode_token(&token, "wrong-secret"),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn decode_expired_token_fails() {
        let claims = Claims {
            sub: Uuid::new_v4(),
            sid: Uuid::new_v4(),
            jti: Uuid::new_v4(),
            exp: 1,
            iat: 1,
        };
        let token = encode_token(&claims, SECRET).unwrap();
        assert!(matches!(
            decode_token(&token, SECRET),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn decode_malformed_token_fails() {
        assert!(matches!(
            decode_token("not.a.token", SECRET),
            Err(JwtError::Decode(_))
        ));
    }

    #[test]
    fn decode_with_previous_secret_accepts_rotated_tokens() {
        let claims = valid_claims();
        let token = encode_token(&claims, "old-secret").unwrap();

        let decoded = decode_token_with_fallback(&token, "new-secret", Some("old-secret")).unwrap();

        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.sid, claims.sid);
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
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let claims = Claims {
                sub: Uuid::from_bytes(sub),
                sid: Uuid::from_bytes(sid),
                jti: Uuid::from_bytes(jti),
                exp: now + exp_delta,
                iat: now.saturating_sub(iat_back),
            };

            let token = encode_token(&claims, SECRET).unwrap();
            let decoded = decode_token(&token, SECRET).unwrap();

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
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let claims = Claims {
                sub: Uuid::from_bytes(sub),
                sid: Uuid::from_bytes(sid),
                jti: Uuid::from_bytes(jti),
                exp: now + exp_delta,
                iat: now,
            };

            let token = encode_token(&claims, SECRET).unwrap();
            let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
            parts[2].push_str(&suffix);
            let tampered = parts.join(".");

            prop_assert!(matches!(
                decode_token(&tampered, SECRET),
                Err(JwtError::Decode(_))
            ));
        }
    }
}
