use crate::common::{app::TestApp, fixtures};

// POST /users/me/reauth

#[tokio::test]
async fn reauth_with_correct_password_returns_204() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    app.clear_recent_reauth(&user.access_token).await;

    let res = app
        .post_auth(
            "/users/me/reauth",
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 204);
}

#[tokio::test]
async fn reauth_with_wrong_password_returns_401() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 2).await;
    app.clear_recent_reauth(&user.access_token).await;

    let res = app
        .post_auth(
            "/users/me/reauth",
            &user.access_token,
            &serde_json::json!({ "current_password": "WrongPassword1!" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn reauth_marks_session_and_unlocks_sensitive_action() {
    // After a successful reauth, a sensitive action (e.g. revoke another session)
    // that previously required recent reauth should now succeed.
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 3).await;
    fixtures::activate_user(&app.db, user.id).await;

    // Create two sessions.
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

    let token1 = r1["access_token"].as_str().unwrap().to_owned();

    // Clear recent reauth so the revoke would fail without it.
    app.clear_recent_reauth(&token1).await;

    // Find session 2's id.
    let sessions: serde_json::Value = app
        .get_auth("/users/me/sessions", &token1)
        .await
        .json()
        .await
        .unwrap();
    let other_id = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["is_current"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Without reauth: revoke must be rejected.
    let before = app
        .delete_auth(&format!("/users/me/sessions/{other_id}"), &token1)
        .await;
    assert_eq!(before.status().as_u16(), 403);

    // Reauthenticate.
    let reauth = app
        .post_auth(
            "/users/me/reauth",
            &token1,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(reauth.status().as_u16(), 204);

    // Now the revoke must succeed.
    let after = app
        .delete_auth(&format!("/users/me/sessions/{other_id}"), &token1)
        .await;
    assert_eq!(after.status().as_u16(), 204);

    // Token from session 2 should now be invalid.
    let token2 = r2["access_token"].as_str().unwrap();
    let res = app.get_auth("/users/me", token2).await;
    assert!(
        res.status().as_u16() == 401 || res.status().as_u16() == 403,
        "expected 401/403 after session revocation, got {}",
        res.status()
    );
}

#[tokio::test]
async fn reauth_requires_authentication() {
    let app = TestApp::spawn().await;

    let res = app
        .client
        .post(format!("{}/users/me/reauth", app.base_url))
        .json(&serde_json::json!({ "current_password": "Password1!" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 401);
}
