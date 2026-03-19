use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn list_sessions_returns_current() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let res = app.get_auth("/users/me/sessions", &user.access_token).await;
    assert_eq!(res.status().as_u16(), 200);

    let sessions: serde_json::Value = res.json().await.unwrap();
    let list = sessions.as_array().unwrap();

    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["is_current"], true);
}

#[tokio::test]
async fn list_sessions_shows_multiple() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 2).await;
    fixtures::activate_user(&app.db, user.id).await;

    // Login twice to create two sessions
    let payload = serde_json::json!({ "identifier": user.email, "password": user.password });

    let r1 = app.post("/auth/login", &payload).await;
    assert_eq!(r1.status().as_u16(), 200);
    let b1: serde_json::Value = r1.json().await.unwrap();
    let token1 = b1["access_token"].as_str().unwrap().to_owned();

    let r2 = app.post("/auth/login", &payload).await;
    assert_eq!(r2.status().as_u16(), 200);

    let sessions: serde_json::Value = app
        .get_auth("/users/me/sessions", &token1)
        .await
        .json()
        .await
        .unwrap();

    assert_eq!(sessions.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn revoke_session() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 3).await;
    fixtures::activate_user(&app.db, user.id).await;

    // Create two sessions
    let r1: serde_json::Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();

    let r2: serde_json::Value = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": user.password }),
        )
        .await
        .json()
        .await
        .unwrap();

    let token1 = r1["access_token"].as_str().unwrap();
    let token2 = r2["access_token"].as_str().unwrap();

    // List sessions from session 1 and find session 2's id
    let sessions: serde_json::Value = app
        .get_auth("/users/me/sessions", token1)
        .await
        .json()
        .await
        .unwrap();

    let other_session_id = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["is_current"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Revoke session 2 from session 1
    let del = app
        .delete_auth(
            &format!("/users/me/sessions/{other_session_id}"),
            token1,
        )
        .await;
    assert_eq!(del.status().as_u16(), 204);

    // Token 2 should no longer list sessions (session revoked)
    let res = app.get_auth("/users/me/sessions", token2).await;
    // JWT is still valid but session is revoked
    assert!(
        res.status().as_u16() == 401 || res.status().as_u16() == 403,
        "expected auth error after session revocation, got {}",
        res.status()
    );
}

#[tokio::test]
async fn revoke_all_sessions() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 4).await;

    let res = app
        .delete_auth("/users/me/sessions", &user.access_token)
        .await;
    assert_eq!(res.status().as_u16(), 204);

    // Should not be able to list sessions anymore
    let res2 = app.get_auth("/users/me/sessions", &user.access_token).await;
    assert!(
        res2.status().as_u16() == 401 || res2.status().as_u16() == 403,
        "expected auth error after revoking all sessions, got {}",
        res2.status()
    );
}
