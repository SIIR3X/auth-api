//! JWT encoding and decoding using HS256.
//!
//! Access tokens carry a jti (unique ID) so they can be individually revoked
//! via a Redis blocklist without invalidating other tokens for the same user.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("failed to encode token: {0}")]
    Encode(jsonwebtoken::errors::Error),
    #[error("failed to decode token: {0}")]
    Decode(jsonwebtoken::errors::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: user UUID.
    pub sub: Uuid,
    /// JWT ID: unique per token, used for blocklist-based revocation.
    pub jti: Uuid,
    /// Expiry (Unix timestamp).
    pub exp: i64,
    /// Issued at (Unix timestamp).
    pub iat: i64,
}

impl Claims {
    pub fn new(user_id: Uuid, exp: i64) -> Self {
        Self {
            sub: user_id,
            jti: Uuid::new_v4(),
            exp,
            iat: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }
}

pub fn encode_token(claims: &Claims, secret: &str) -> Result<String, JwtError> {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(JwtError::Encode)
}

pub fn decode_token(token: &str, secret: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|d| d.claims)
    .map_err(JwtError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "super-secret-key-for-tests";

    fn valid_claims() -> Claims {
        Claims::new(
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
        assert_eq!(decoded.jti, claims.jti);
        assert_eq!(decoded.exp, claims.exp);
    }

    #[test]
    fn each_token_has_unique_jti() {
        let user_id = Uuid::new_v4();
        let exp = time::OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let c1 = Claims::new(user_id, exp);
        let c2 = Claims::new(user_id, exp);
        assert_ne!(c1.jti, c2.jti);
    }

    #[test]
    fn decode_with_wrong_secret_fails() {
        let token = encode_token(&valid_claims(), SECRET).unwrap();
        assert!(matches!(decode_token(&token, "wrong-secret"), Err(JwtError::Decode(_))));
    }

    #[test]
    fn decode_expired_token_fails() {
        let claims = Claims {
            sub: Uuid::new_v4(),
            jti: Uuid::new_v4(),
            exp: 1,
            iat: 1,
        };
        let token = encode_token(&claims, SECRET).unwrap();
        assert!(matches!(decode_token(&token, SECRET), Err(JwtError::Decode(_))));
    }

    #[test]
    fn decode_malformed_token_fails() {
        assert!(matches!(decode_token("not.a.token", SECRET), Err(JwtError::Decode(_))));
    }
}
