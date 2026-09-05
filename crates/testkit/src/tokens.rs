//! Access tokens forged for attacking the authentication of the API.

use auth_api::utils::jwt::{self, Claims};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::{ecdsa::SigningKey, pkcs8::EncodePrivateKey};
use uuid::Uuid;

use crate::{app::TestApp, keys};

impl TestApp {
    /// The claims the API puts in an access token for this session, issued now.
    pub fn access_claims(&self, user_id: Uuid, session_id: Uuid) -> Claims {
        let now = self.state.clock.now().unix_timestamp();
        let mut claims = Claims::new(user_id, session_id, now, now + 900);
        claims.iss = Some(self.state.config.server.public_url.clone());
        claims.aud = self.state.config.jwt.audience.clone();
        claims
    }

    /// `claims` signed with the app's own key, as the API signs them.
    pub fn sign(&self, claims: &Claims) -> String {
        jwt::encode_token(
            claims,
            &self.state.jwt_signing_key,
            Some(&self.state.jwt_kid),
        )
        .expect("sign test claims")
    }
}

/// `claims` signed with a P-256 key generated on the spot, which no deployment holds.
pub fn sign_with_foreign_key(claims: &Claims) -> String {
    let key = SigningKey::random(&mut rand_core::OsRng);
    let pem = key
        .to_pkcs8_pem(Default::default())
        .expect("encode the foreign key");
    let encoding = jwt::parse_encoding_key(&pem).expect("parse the foreign key");
    jwt::encode_token(claims, &encoding, None).expect("sign with the foreign key")
}

/// `claims` in an unsigned token (`alg: none`).
pub fn unsigned(claims: &Claims) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims to JSON"));
    format!("{header}.{payload}.")
}

/// `claims` signed with HS256 using the public key as the HMAC secret: the
/// algorithm confusion attack against verifiers that trust the header.
pub fn hs256_with_public_key(claims: &Claims) -> String {
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(keys::PUBLIC_KEY_PEM.as_bytes()),
    )
    .expect("sign with HS256")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Claims {
        Claims::new(Uuid::new_v4(), Uuid::new_v4(), 1_000, 2_000)
    }

    fn header(token: &str) -> serde_json::Value {
        let encoded = token.split('.').next().unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
    }

    #[test]
    fn forged_tokens_declare_what_they_claim_to_be() {
        assert_eq!(header(&unsigned(&claims()))["alg"], "none");
        assert!(unsigned(&claims()).ends_with('.'));
        assert_eq!(header(&hs256_with_public_key(&claims()))["alg"], "HS256");
        assert_eq!(header(&sign_with_foreign_key(&claims()))["alg"], "ES256");
    }

    #[test]
    fn a_foreign_signature_does_not_verify_with_the_test_key() {
        let key = jwt::parse_verifying_key(keys::PUBLIC_KEY_PEM).unwrap();
        let token = sign_with_foreign_key(&claims());
        assert!(jwt::decode_token(&token, &key, 1_500).is_err());
    }
}
