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
        .delete_auth(&format!("/users/me/sessions/{other_session_id}"), token1)
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
        .delete_auth_json(
            "/users/me/sessions",
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
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

#[tokio::test]
async fn revoke_session_requires_recent_reauth() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 5).await;
    fixtures::activate_user(&app.db, user.id).await;

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

    app.clear_recent_reauth(token1).await;

    let res = app
        .delete_auth(&format!("/users/me/sessions/{other_session_id}"), token1)
        .await;
    assert_eq!(res.status().as_u16(), 403);

    let res = app
        .post_auth(
            "/users/me/reauth",
            token1,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let res = app
        .delete_auth(&format!("/users/me/sessions/{other_session_id}"), token1)
        .await;
    assert_eq!(res.status().as_u16(), 204);

    let res = app.get_auth("/users/me/sessions", token2).await;
    assert!(
        res.status().as_u16() == 401 || res.status().as_u16() == 403,
        "expected auth error after session revocation, got {}",
        res.status()
    );
}

#[tokio::test]
async fn cannot_revoke_another_users_session() {
    // User A must not be able to revoke a session that belongs to User B,
    // even when they know the session UUID.
    let app = TestApp::spawn().await;
    let user_a = fixtures::authenticated_user(&app, 6).await;
    let user_b = fixtures::authenticated_user(&app, 7).await;

    // Get user B's session id.
    let b_sessions: serde_json::Value = app
        .get_auth("/users/me/sessions", &user_b.access_token)
        .await
        .json()
        .await
        .unwrap();
    let b_session_id = b_sessions.as_array().unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // User A tries to revoke user B's session.
    let res = app
        .delete_auth(
            &format!("/users/me/sessions/{b_session_id}"),
            &user_a.access_token,
        )
        .await;

    // Must not succeed - 404 (not found for this user) is also acceptable.
    assert!(
        res.status().as_u16() == 403 || res.status().as_u16() == 404,
        "expected 403 or 404 when revoking another user's session, got {}",
        res.status()
    );

    // User B's session must still be alive.
    let check = app.get_auth("/users/me", &user_b.access_token).await;
    assert_eq!(
        check.status().as_u16(),
        200,
        "user B's session must still be valid"
    );
}

#[tokio::test]
async fn sessions_list_only_shows_own_sessions() {
    let app = TestApp::spawn().await;
    let user_a = fixtures::authenticated_user(&app, 8).await;
    let _user_b = fixtures::authenticated_user(&app, 9).await;

    let sessions: serde_json::Value = app
        .get_auth("/users/me/sessions", &user_a.access_token)
        .await
        .json()
        .await
        .unwrap();

    // User A should only see their own single session.
    let list = sessions.as_array().unwrap();
    assert_eq!(
        list.len(),
        1,
        "session list must only contain user A's session"
    );
    assert_eq!(list[0]["is_current"], true);
}

// P3: revoke_all via recent reauth

#[tokio::test]
async fn revoke_all_sessions_works_with_recent_reauth_no_password() {
    // revoke_all_sessions accepts either current_password OR a recent reauth mark.
    // This test confirms the recent-reauth path works (no password supplied).
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 10).await;

    // Reauth is already fresh from login; clear it and then re-establish it
    // via the reauth endpoint so we confirm the code path.
    app.clear_recent_reauth(&user.access_token).await;

    // Without reauth the revoke_all should be rejected.
    let before = app
        .delete_auth_json(
            "/users/me/sessions",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(
        before.status().as_u16(),
        403,
        "expected 403 without reauth or password"
    );

    // Re-establish reauth.
    let reauth = app
        .post_auth(
            "/users/me/reauth",
            &user.access_token,
            &serde_json::json!({ "current_password": user.password }),
        )
        .await;
    assert_eq!(reauth.status().as_u16(), 204);

    // Now revoke_all without supplying current_password should succeed.
    let after = app
        .delete_auth_json(
            "/users/me/sessions",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(
        after.status().as_u16(),
        204,
        "revoke_all should succeed with recent reauth"
    );

    // Token should no longer be valid.
    let check = app.get_auth("/users/me/sessions", &user.access_token).await;
    assert!(
        check.status().as_u16() == 401 || check.status().as_u16() == 403,
        "expected auth error after revoke_all, got {}",
        check.status()
    );
}
