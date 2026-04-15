use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn refresh_returns_new_tokens() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    let new_access = body["access_token"].as_str().unwrap();
    let new_refresh = body["refresh_token"].as_str().unwrap();

    assert!(!new_access.is_empty());
    assert!(!new_refresh.is_empty());
    // Tokens must rotate
    assert_ne!(new_access, user.access_token);
    assert_ne!(new_refresh, user.refresh_token);
}

#[tokio::test]
async fn refresh_token_replay_is_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 2).await;

    // First refresh succeeds
    let res1 = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res1.status().as_u16(), 200);

    // Replaying the same refresh token must fail
    let res2 = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res2.status().as_u16(), 401);
}

#[tokio::test]
async fn refresh_invalid_token_rejected() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": "not-a-valid-token" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn new_access_token_is_usable() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 3).await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    let new_access = body["access_token"].as_str().unwrap();

    let profile_res = app.get_auth("/users/me", new_access).await;
    assert_eq!(profile_res.status().as_u16(), 200);
}

#[tokio::test]
async fn concurrent_refresh_only_allows_one_success() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 4).await;

    let client_a = app.client.clone();
    let client_b = app.client.clone();
    let url = format!("{}/auth/refresh", app.base_url);
    let payload = serde_json::json!({ "refresh_token": user.refresh_token });

    let req_a = client_a.post(&url).json(&payload).send();
    let req_b = client_b.post(&url).json(&payload).send();
    let (res_a, res_b) = tokio::join!(req_a, req_b);

    let status_a = res_a.unwrap().status().as_u16();
    let status_b = res_b.unwrap().status().as_u16();
    let success_count = [status_a, status_b]
        .into_iter()
        .filter(|status| *status == 200)
        .count();

    assert_eq!(
        success_count, 1,
        "expected exactly one successful refresh, got {status_a} and {status_b}"
    );
    assert!(
        [status_a, status_b].into_iter().all(|status| status == 200 || status == 401),
        "expected one success and one auth failure, got {status_a} and {status_b}"
    );
}
