//! The verifier against a running auth-api.

use std::{sync::Arc, time::Duration};

use auth_api_verifier::{Authenticated, Introspection, Verifier, VerifierConfig, VerifyError};
use axum::{Router, body::Body, http::Request, routing::get};
use testkit::{TestApp, fixtures, tokens};
use tower::ServiceExt;

fn config(app: &TestApp) -> VerifierConfig {
    let issuer = app.state.config.server.public_url.clone();
    let mut config = VerifierConfig::new(issuer.clone(), issuer);
    config.jwks_uri = Some(app.url("/.well-known/jwks.json"));
    config
}

#[tokio::test]
async fn a_token_of_auth_api_verifies_with_its_permissions() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let verifier = Verifier::new(config(&app));

    let token = verifier.verify(&user.access_token).await.unwrap();
    assert_eq!(token.subject, user.id);
    assert!(token.has_role("user"));
    assert!(!token.has_permission("users:manage"));
    assert!(!token.is_client_token());
}

#[tokio::test]
async fn forged_expired_and_foreign_tokens_are_refused() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let claims = app.decode_access_token(&user.access_token);
    let verifier = Verifier::new(config(&app));

    let mut expired = claims.clone();
    expired.exp = expired.iat - 3600;
    expired.iat -= 7200;
    expired.nbf = Some(expired.iat);
    assert_eq!(
        verifier.verify(&app.sign(&expired)).await,
        Err(VerifyError::Expired)
    );

    let mut foreign_issuer = claims.clone();
    foreign_issuer.iss = Some("https://evil.example.com".into());
    assert!(matches!(
        verifier.verify(&app.sign(&foreign_issuer)).await,
        Err(VerifyError::Invalid(_))
    ));

    let mut other_audience = config(&app);
    other_audience.audience = "https://other.example.com".into();
    assert!(matches!(
        Verifier::new(other_audience)
            .verify(&user.access_token)
            .await,
        Err(VerifyError::Invalid(_))
    ));

    assert!(matches!(
        verifier
            .verify(&tokens::sign_with_foreign_key(&claims))
            .await,
        Err(VerifyError::UnknownKey | VerifyError::Invalid(_))
    ));
    assert!(verifier.verify(&tokens::unsigned(&claims)).await.is_err());
    assert_eq!(
        verifier.verify("not-a-token").await,
        Err(VerifyError::Malformed)
    );
}

#[tokio::test]
async fn introspection_catches_a_token_revoked_before_it_expires() {
    let app = TestApp::spawn().await;
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, client_secret_hash)
         VALUES ('resource-server', 'Resource server', $1)",
    )
    .bind(auth_api::utils::crypto::sha256(b"aacs_rs-secret").to_vec())
    .execute(&app.db)
    .await
    .unwrap();
    let user = fixtures::authenticated_user(&app, 1).await;

    let offline = Verifier::new(config(&app));
    let mut checked = config(&app);
    let mut introspection = Introspection::new("resource-server", "aacs_rs-secret");
    introspection.cache_ttl = Duration::ZERO;
    introspection.endpoint = Some(app.url("/oauth/introspect"));
    checked.introspection = Some(introspection);
    let online = Verifier::new(checked);
    assert!(online.verify(&user.access_token).await.is_ok());

    let logout = app
        .post_auth("/auth/logout", &user.access_token, &serde_json::json!({}))
        .await;
    assert_eq!(logout.status(), 204);

    assert!(
        offline.verify(&user.access_token).await.is_ok(),
        "offline checks cannot see a revocation"
    );
    assert_eq!(
        online.verify(&user.access_token).await,
        Err(VerifyError::Revoked)
    );
}

#[tokio::test]
async fn the_axum_extractor_refuses_missing_and_invalid_tokens() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let verifier = Arc::new(Verifier::new(config(&app)));
    let router = Router::new()
        .route(
            "/invoices",
            get(|Authenticated(token): Authenticated| async move { token.subject.to_string() }),
        )
        .with_state(verifier);

    let call = |authorization: Option<String>| {
        let router = router.clone();
        async move {
            let mut request = Request::get("/invoices");
            if let Some(value) = authorization {
                request = request.header("authorization", value);
            }
            router
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
        }
    };
    assert_eq!(
        call(Some(format!("Bearer {}", user.access_token)))
            .await
            .status(),
        200
    );
    let missing = call(None).await;
    assert_eq!(missing.status(), 401);
    assert_eq!(missing.headers()["www-authenticate"], "Bearer");
    let invalid = call(Some("Bearer nope".into())).await;
    assert_eq!(
        invalid.headers()["www-authenticate"],
        "Bearer error=\"invalid_token\""
    );
}
