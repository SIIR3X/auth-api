//! JWT / auth-middleware edge-case tests.
//!
//! Tests index range 350-369.

use crate::common::{app::TestApp, fixtures};

// Missing / malformed Authorization header

#[tokio::test]
async fn no_authorization_header_returns_401() {
    let app = TestApp::spawn().await;
    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn basic_auth_scheme_returns_401() {
    let app = TestApp::spawn().await;
    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .header("Authorization", "Basic dXNlcjpwYXNz")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn bearer_with_empty_token_returns_401() {
    let app = TestApp::spawn().await;
    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .header("Authorization", "Bearer ")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn random_string_token_returns_401() {
    let app = TestApp::spawn().await;
    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .bearer_auth("this-is-not-a-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn tampered_jwt_signature_returns_401() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 350).await;

    // Replace the signature segment with garbage.
    let parts: Vec<&str> = user.access_token.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3, "token must have 3 JWT segments");
    let tampered = format!("{}.{}.invalidsignatureXXXXXXXX", parts[0], parts[1]);

    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .bearer_auth(&tampered)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn jwt_signed_with_wrong_secret_returns_401() {
    use auth_api::utils::jwt;

    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 351).await;

    // Decode claims from the real token, re-sign with a different key.
    let claims = jwt::decode_token(&user.access_token, &app.state.jwt_verifying_key)
        .expect("real token must decode");
    let wrong_key = {
        use p256::pkcs8::EncodePrivateKey;
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let pem = sk.to_pkcs8_pem(Default::default()).expect("pkcs8 pem");
        jwt::parse_encoding_key(&pem).expect("encoding key")
    };
    let forged = jwt::encode_token(&claims, &wrong_key, None).expect("encode must succeed");

    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .bearer_auth(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

// Expired token

#[tokio::test]
async fn expired_access_token_returns_401() {
    use auth_api::utils::jwt::{self, Claims};

    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 352).await;

    let real_claims = jwt::decode_token(&user.access_token, &app.state.jwt_verifying_key)
        .expect("real token must decode");

    // Build a claims with exp in the past.
    let expired_claims = Claims {
        exp: 1_000_000, // Unix timestamp well in the past (year 1970)
        ..real_claims
    };

    let expired_token = jwt::encode_token(&expired_claims, &app.state.jwt_signing_key, None)
        .expect("encode must succeed");

    let res = app
        .client
        .get(format!("{}/users/me", app.base_url))
        .bearer_auth(&expired_token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

// Valid token still works

#[tokio::test]
async fn valid_token_is_accepted() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 353).await;
    let res = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(res.status().as_u16(), 200);
}
