//! Passwords found in known data breaches are refused (Pwned Passwords range
//! API, k-anonymity), against a local stand-in of the API.

use std::sync::{Arc, Mutex};

use axum::{Router, extract::Path, http::HeaderMap, routing::get};
use serde_json::{Value, json};

use crate::common::{app::TestApp, fixtures};

const BREACHED: &str = "Breached-Pass-1!";
const CLEAN: &str = "Unbreached-Pass-2!";

/// Range queries the stand-in received: the prefix and the padding header.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A range API that lists `BREACHED` (and a padding entry) for every prefix.
async fn range_api() -> (String, Seen) {
    let (_, suffix) = auth_api::domain::pwned::range_key(BREACHED);
    let seen: Seen = Arc::default();
    let recorded = seen.clone();
    let router = Router::new().route(
        "/range/{prefix}",
        get(move |Path(prefix): Path<String>, headers: HeaderMap| {
            let recorded = recorded.clone();
            let suffix = suffix.clone();
            async move {
                let padding = headers
                    .get("add-padding")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                recorded.lock().unwrap().push((prefix, padding));
                format!("{suffix}:42\r\n0000000000000000000000000000000000A:0\r\n")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, seen)
}

async fn app_checking(url: String, fail_open: bool) -> TestApp {
    TestApp::spawn_with_config(move |config| {
        config.pwned_passwords.enabled = true;
        config.pwned_passwords.api_url = url;
        config.pwned_passwords.fail_open = fail_open;
    })
    .await
}

async fn register(app: &TestApp, index: usize, password: &str) -> reqwest::Response {
    app.post(
        "/auth/register",
        &json!({
            "username": format!("pwned{index}"),
            "email": format!("pwned{index}@example.com"),
            "password": password,
        }),
    )
    .await
}

#[tokio::test]
async fn registration_refuses_a_breached_password() {
    let (url, _) = range_api().await;
    let app = app_checking(url, true).await;

    let res = register(&app, 1, BREACHED).await;
    assert_eq!(res.status().as_u16(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "password_compromised");

    let created: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = 'pwned1')")
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert!(!created);
}

#[tokio::test]
async fn only_the_hash_prefix_leaves_the_service_with_padding_asked() {
    let (url, seen) = range_api().await;
    let app = app_checking(url, true).await;

    let res = register(&app, 2, CLEAN).await;
    assert_eq!(res.status().as_u16(), 202);

    let (prefix, _) = auth_api::domain::pwned::range_key(CLEAN);
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [(prefix, Some("true".to_owned()))]
    );
}

#[tokio::test]
async fn an_unreachable_range_api_fails_open_only_when_configured() {
    // Nothing listens on the discard port.
    let open = app_checking("http://127.0.0.1:9".into(), true).await;
    assert_eq!(register(&open, 3, BREACHED).await.status().as_u16(), 202);

    let closed = app_checking("http://127.0.0.1:9".into(), false).await;
    assert_eq!(register(&closed, 4, BREACHED).await.status().as_u16(), 503);
}

#[tokio::test]
async fn a_breached_password_is_refused_on_change_and_on_reset() {
    let (url, _) = range_api().await;
    let app = app_checking(url, true).await;
    let user = fixtures::authenticated_user(&app, 5).await;

    let change = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &json!({ "new_password": BREACHED }),
        )
        .await;
    assert_eq!(change.status().as_u16(), 422);

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;
    let refused = app
        .post(
            "/auth/reset-password",
            &json!({ "token": token.raw, "new_password": BREACHED }),
        )
        .await;
    assert_eq!(refused.status().as_u16(), 422);
    let accepted = app
        .post(
            "/auth/reset-password",
            &json!({ "token": token.raw, "new_password": CLEAN }),
        )
        .await;
    assert_eq!(
        accepted.status().as_u16(),
        200,
        "a refused password leaves the reset link usable"
    );
}
