//! Signing key rotation in three phases: publish the next key, sign with it,
//! retire the previous one. In each phase every token signed with a published
//! key verifies, and the JWKS already lists the key before anything is signed
//! with it.

use auth_api::utils::jwt;
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use serde_json::Value;

use crate::common::{app::TestApp, fixtures};

struct KeyPair {
    private: String,
    public: String,
    kid: String,
}

fn key_pair() -> KeyPair {
    let signing = SigningKey::random(&mut rand_core::OsRng);
    let public = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    KeyPair {
        private: signing.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
        kid: jwt::compute_kid(&jwt::parse_p256_verifying_key(&public).unwrap()),
        public,
    }
}

fn test_key_pair() -> KeyPair {
    KeyPair {
        private: testkit::keys::PRIVATE_KEY_PEM.to_owned(),
        public: testkit::keys::PUBLIC_KEY_PEM.to_owned(),
        kid: jwt::compute_kid(
            &jwt::parse_p256_verifying_key(testkit::keys::PUBLIC_KEY_PEM).unwrap(),
        ),
    }
}

async fn published_kids(app: &TestApp) -> Vec<String> {
    let jwks: Value = app
        .get("/.well-known/jwks.json")
        .await
        .json()
        .await
        .unwrap();
    jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["kid"].as_str().unwrap().to_owned())
        .collect()
}

/// Status of `GET /users/me` with a token signed by `signer`, for a live session
/// of a new user (`index` tells the users of one app apart).
async fn profile_status(app: &TestApp, index: usize, signer: &KeyPair) -> u16 {
    let user = fixtures::authenticated_user(app, index).await;
    let session = app.decode_access_token(&user.access_token).sid;
    let claims = app.access_claims(user.id, session);
    let token = jwt::encode_token(
        &claims,
        &jwt::parse_encoding_key(&signer.private).unwrap(),
        Some(&signer.kid),
    )
    .unwrap();
    app.get_auth("/users/me", &token).await.status().as_u16()
}

#[tokio::test]
async fn a_rotation_keeps_every_published_key_valid() {
    let old = test_key_pair();
    let new = key_pair();

    // Phase 1: the new key is published and accepted; the old one still signs.
    let next_public = new.public.clone();
    let app = TestApp::spawn_with_config(move |config| {
        config.jwt.next_public_key = Some(next_public);
    })
    .await;
    assert_eq!(
        published_kids(&app).await,
        [old.kid.clone(), new.kid.clone()]
    );
    assert_eq!(
        profile_status(&app, 1, &new).await,
        200,
        "the next key is accepted"
    );
    drop(app);

    // Phase 2: the new key signs; tokens signed with the old one still verify.
    let (private, public, previous) = (new.private.clone(), new.public.clone(), old.public.clone());
    let app = TestApp::spawn_with_config(move |config| {
        config.jwt.private_key = private;
        config.jwt.public_key = public;
        config.jwt.previous_public_key = Some(previous);
    })
    .await;
    assert_eq!(
        published_kids(&app).await,
        [new.kid.clone(), old.kid.clone()]
    );
    assert_eq!(
        profile_status(&app, 1, &old).await,
        200,
        "the previous key still verifies"
    );
    assert_eq!(profile_status(&app, 2, &new).await, 200);
    drop(app);

    // Phase 3: the old key is retired and refused.
    let (private, public) = (new.private.clone(), new.public.clone());
    let app = TestApp::spawn_with_config(move |config| {
        config.jwt.private_key = private;
        config.jwt.public_key = public;
    })
    .await;
    assert_eq!(published_kids(&app).await, std::slice::from_ref(&new.kid));
    assert_eq!(
        profile_status(&app, 1, &old).await,
        401,
        "a retired key is refused"
    );
}
