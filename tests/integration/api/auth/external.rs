//! Signing in with external identity providers, against mock OpenID Connect and
//! GitHub providers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use auth_api::config::{IdentityProviderConfig, IdentityProviderKind};
use axum::{
    Form, Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{self, get},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use p256::{ecdsa::SigningKey, pkcs8::EncodePrivateKey};
use reqwest::header::HeaderValue;
use serde_json::{Value, json};

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

/// What the provider answers for a code: the person, and the nonce it signs.
#[derive(Clone)]
struct Grant {
    subject: String,
    nonce: String,
    email: String,
}

#[derive(Clone)]
struct Provider {
    base: String,
    key: Arc<SigningKey>,
    grants: Arc<Mutex<HashMap<String, Grant>>>,
    /// Signs ID tokens with another key when set.
    forge: Arc<Mutex<bool>>,
}

impl Provider {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = Self {
            base: format!("http://{}", listener.local_addr().unwrap()),
            key: Arc::new(SigningKey::random(&mut rand_core::OsRng)),
            grants: Arc::default(),
            forge: Arc::default(),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", routing::post(token))
            .route("/login/oauth/access_token", routing::post(github_token))
            .route("/user", get(github_user))
            .with_state(provider.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        provider
    }

    fn grant(&self, code: &str, subject: &str, nonce: &str) {
        self.grants.lock().unwrap().insert(
            code.to_owned(),
            Grant {
                subject: subject.to_owned(),
                nonce: nonce.to_owned(),
                email: "someone@example.com".into(),
            },
        );
    }

    fn config(&self, kind: IdentityProviderKind) -> IdentityProviderConfig {
        IdentityProviderConfig {
            name: match kind {
                IdentityProviderKind::Oidc => "corp".into(),
                IdentityProviderKind::Github => "github".into(),
            },
            kind,
            display_name: "Corporate SSO".into(),
            client_id: "auth-api".into(),
            client_secret: "provider-secret".into(),
            issuer: self.base.clone(),
            scopes: vec!["openid".into()],
            authorization_url: format!("{}/login/oauth/authorize", self.base),
            token_url: format!("{}/login/oauth/access_token", self.base),
            user_url: format!("{}/user", self.base),
        }
    }
}

async fn discovery(State(provider): State<Provider>) -> Json<Value> {
    Json(json!({
        "issuer": provider.base,
        "authorization_endpoint": format!("{}/authorize", provider.base),
        "token_endpoint": format!("{}/token", provider.base),
        "jwks_uri": format!("{}/jwks", provider.base),
    }))
}

async fn jwks(State(provider): State<Provider>) -> Json<Value> {
    let point = provider.key.verifying_key().to_encoded_point(false);
    Json(json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
        "x": B64URL.encode(point.x().unwrap()), "y": B64URL.encode(point.y().unwrap()),
    }]}))
}

async fn token(
    State(provider): State<Provider>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    assert_eq!(form["client_secret"], "provider-secret");
    assert!(form.contains_key("code_verifier"));
    let grant = provider
        .grants
        .lock()
        .unwrap()
        .remove(&form["code"])
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    let key = if *provider.forge.lock().unwrap() {
        SigningKey::random(&mut rand_core::OsRng)
    } else {
        (*provider.key).clone()
    };
    let pem = key.to_pkcs8_pem(Default::default()).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("k1".into());
    let id_token = jsonwebtoken::encode(
        &header,
        &json!({
            "iss": provider.base, "aud": "auth-api", "sub": grant.subject,
            "nonce": grant.nonce, "iat": now, "exp": now + 300,
            "email": grant.email, "email_verified": true,
        }),
        &jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();
    Ok(Json(
        json!({ "access_token": "provider-access", "id_token": id_token }),
    ))
}

async fn github_token(
    State(provider): State<Provider>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    let grant = provider
        .grants
        .lock()
        .unwrap()
        .remove(&form["code"])
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    Ok(Json(
        json!({ "access_token": format!("gho_{}", grant.subject) }),
    ))
}

async fn github_user(headers: HeaderMap) -> Json<Value> {
    let token = headers["authorization"].to_str().unwrap();
    let id: u64 = token.trim_start_matches("Bearer gho_").parse().unwrap();
    Json(json!({ "id": id, "login": "octocat" }))
}

fn param(url: &str, name: &str) -> String {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// The browser comes back from the provider: follow the callback once.
async fn callback(app: &TestApp, provider: &str, code: &str, state: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = client
        .get(app.url(&format!(
            "/auth/external/{provider}/callback?code={code}&state={state}"
        )))
        .header(
            "x-forwarded-for",
            HeaderValue::from_str(&app.client_ip).unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    response.headers()["location"].to_str().unwrap().to_owned()
}

async fn post(app: &TestApp, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
    let response = match token {
        Some(token) => app.post_auth(path, token, &body).await,
        None => app.post(path, &body).await,
    };
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// Run a flow for `subject` through `provider`: the outcome code and binding.
async fn through_provider(
    app: &TestApp,
    mock: &Provider,
    provider: &str,
    start: (&str, Option<&str>),
    subject: &str,
) -> (String, String) {
    let (status, started) = post(app, start.0, start.1, json!({})).await;
    assert_eq!(status, 200, "{started}");
    let url = started["authorization_url"].as_str().unwrap();
    assert_eq!(param(url, "code_challenge_method"), "S256");
    assert!(param(url, "redirect_uri").ends_with(&format!("/auth/external/{provider}/callback")));
    let code = format!("code-{}", uuid::Uuid::new_v4().simple());
    mock.grant(&code, subject, &param(url, "nonce"));
    let location = callback(app, provider, &code, &param(url, "state")).await;
    assert!(
        location.starts_with("http://localhost:5173/external-login"),
        "{location}"
    );
    (
        param(&location, "code"),
        started["binding"].as_str().unwrap().to_owned(),
    )
}

async fn link(
    app: &TestApp,
    mock: &Provider,
    user: &AuthenticatedUser,
    subject: &str,
) -> (u16, Value) {
    let (code, binding) = through_provider(
        app,
        mock,
        "corp",
        (
            "/users/me/external-identities/corp/start",
            Some(&user.access_token),
        ),
        subject,
    )
    .await;
    post(
        app,
        "/users/me/external-identities/complete",
        Some(&user.access_token),
        json!({ "code": code, "binding": binding }),
    )
    .await
}

async fn sign_in(app: &TestApp, mock: &Provider, subject: &str) -> (u16, Value) {
    let (code, binding) = through_provider(
        app,
        mock,
        "corp",
        ("/auth/external/corp/start", None),
        subject,
    )
    .await;
    post(
        app,
        "/auth/external/complete",
        None,
        json!({ "code": code, "binding": binding }),
    )
    .await
}

async fn app_with(mock: &Provider, kind: IdentityProviderKind) -> TestApp {
    let provider = mock.config(kind);
    TestApp::spawn_with_config(move |c| c.identity_providers = vec![provider]).await
}

#[tokio::test]
async fn a_linked_identity_signs_in_and_an_unlinked_one_never_does() {
    let mock = Provider::start().await;
    let app = app_with(&mock, IdentityProviderKind::Oidc).await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let providers: Value = app
        .get("/auth/external/providers")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        providers,
        json!([{ "name": "corp", "display_name": "Corporate SSO" }])
    );

    // Unknown to auth-api: no account is created or matched by email.
    let (status, body) = sign_in(&app, &mock, "person-1").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("external_identity_not_linked"))
    );

    let (status, linked) = link(&app, &mock, &user, "person-1").await;
    assert_eq!(status, 201, "{linked}");
    assert_eq!(linked["provider"], "corp");

    let (status, tokens) = sign_in(&app, &mock, "person-1").await;
    assert_eq!(status, 200, "{tokens}");
    let me: Value = app
        .get_auth("/users/me", tokens["access_token"].as_str().unwrap())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me["id"], user.id.to_string());

    // Another person at the provider is not this account.
    assert_eq!(sign_in(&app, &mock, "person-2").await.0, 409);

    // Linked to one account, an identity cannot be linked to another.
    let other = fixtures::authenticated_user(&app, 2).await;
    let (status, body) = link(&app, &mock, &other, "person-1").await;
    assert_eq!(
        (status, body["code"].as_str()),
        (409, Some("external_identity_already_linked"))
    );

    let listed: Value = app
        .get_auth("/users/me/external-identities", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    let id = listed[0]["id"].as_str().unwrap();
    let response = app
        .delete_auth(
            &format!("/users/me/external-identities/{id}"),
            &user.access_token,
        )
        .await;
    assert_eq!(response.status(), 204);
    assert_eq!(sign_in(&app, &mock, "person-1").await.0, 409);
}

#[tokio::test]
async fn an_outcome_is_used_once_by_the_browser_that_started_it() {
    let mock = Provider::start().await;
    let app = app_with(&mock, IdentityProviderKind::Oidc).await;
    let user = fixtures::authenticated_user(&app, 1).await;
    assert_eq!(link(&app, &mock, &user, "person-1").await.0, 201);

    let (code, binding) = through_provider(
        &app,
        &mock,
        "corp",
        ("/auth/external/corp/start", None),
        "person-1",
    )
    .await;
    // Another browser (the victim of a forwarded callback) holds another binding.
    let (status, _) = post(
        &app,
        "/auth/external/complete",
        None,
        json!({ "code": code, "binding": "someone-else" }),
    )
    .await;
    assert_eq!(status, 401);
    // The attempt used the code up.
    let (status, _) = post(
        &app,
        "/auth/external/complete",
        None,
        json!({ "code": code, "binding": binding }),
    )
    .await;
    assert_eq!(status, 401);

    // A state is used once.
    let (_, started) = post(&app, "/auth/external/corp/start", None, json!({})).await;
    let url = started["authorization_url"].as_str().unwrap();
    mock.grant("replayed", "person-1", &param(url, "nonce"));
    callback(&app, "corp", "replayed", &param(url, "state")).await;
    let location = callback(&app, "corp", "replayed", &param(url, "state")).await;
    assert_eq!(param(&location, "error"), "expired");
}

#[tokio::test]
async fn an_id_token_that_does_not_verify_identifies_nobody() {
    let mock = Provider::start().await;
    let app = app_with(&mock, IdentityProviderKind::Oidc).await;
    let user = fixtures::authenticated_user(&app, 1).await;
    assert_eq!(link(&app, &mock, &user, "person-1").await.0, 201);

    // Signed with a key the provider does not publish.
    *mock.forge.lock().unwrap() = true;
    let (status, _) = sign_in(&app, &mock, "person-1").await;
    assert_eq!(status, 503);
    *mock.forge.lock().unwrap() = false;

    // A nonce from another sign-in.
    let (_, started) = post(&app, "/auth/external/corp/start", None, json!({})).await;
    let url = started["authorization_url"].as_str().unwrap();
    mock.grant("wrong-nonce", "person-1", "another-nonce");
    let location = callback(&app, "corp", "wrong-nonce", &param(url, "state")).await;
    let (status, _) = post(
        &app,
        "/auth/external/complete",
        None,
        json!({ "code": param(&location, "code"), "binding": started["binding"] }),
    )
    .await;
    assert_eq!(status, 503);

    assert_eq!(
        post(&app, "/auth/external/unknown/start", None, json!({}))
            .await
            .0,
        404
    );
}

#[tokio::test]
async fn a_github_identity_is_its_numeric_user_id() {
    let mock = Provider::start().await;
    let app = app_with(&mock, IdentityProviderKind::Github).await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let (code, binding) = through_provider(
        &app,
        &mock,
        "github",
        (
            "/users/me/external-identities/github/start",
            Some(&user.access_token),
        ),
        "4242",
    )
    .await;
    let (status, linked) = post(
        &app,
        "/users/me/external-identities/complete",
        Some(&user.access_token),
        json!({ "code": code, "binding": binding }),
    )
    .await;
    assert_eq!(status, 201, "{linked}");
    let subject: String =
        sqlx::query_scalar("SELECT subject FROM external_identities WHERE user_id = $1")
            .bind(user.id)
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(subject, "4242");

    let (code, binding) = through_provider(
        &app,
        &mock,
        "github",
        ("/auth/external/github/start", None),
        "4242",
    )
    .await;
    let (status, _) = post(
        &app,
        "/auth/external/complete",
        None,
        json!({ "code": code, "binding": binding }),
    )
    .await;
    assert_eq!(status, 200);
}
