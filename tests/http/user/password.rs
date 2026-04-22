use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn change_password_success() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &serde_json::json!({
                "current_password": user.password,
                "new_password": "NewSecurePass1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 204);

    // Old password no longer works
    let res2 = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(res2.status().as_u16(), 401);

    // New password works
    let res3 = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": "NewSecurePass1!",
            }),
        )
        .await;
    assert_eq!(res3.status().as_u16(), 200);
}

#[tokio::test]
async fn change_password_wrong_current() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 2).await;

    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &serde_json::json!({
                "current_password": "WrongCurrent!",
                "new_password": "NewSecurePass1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn change_password_too_short() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 3).await;

    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &serde_json::json!({
                "current_password": user.password,
                "new_password": "short",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn change_password_too_long() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 5).await;

    // 129-character password exceeds the 128-char cap.
    let too_long = "A".repeat(129);

    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &serde_json::json!({
                "current_password": user.password,
                "new_password": too_long,
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn change_password_revokes_current_access_token_immediately() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 4).await;

    let res = app
        .patch_auth(
            "/users/me/password",
            &user.access_token,
            &serde_json::json!({
                "current_password": user.password,
                "new_password": "ImmediateCutover1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 204);

    let res = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn concurrent_password_reset_token_use_only_succeeds_once() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 5).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_reset_password_rate_limit("127.0.0.1").await;

    let raw_token = "reset-race-token";
    let token_hash = auth_api::utils::crypto::sha256(raw_token.as_bytes());

    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '30 minutes')",
    )
    .bind(user.id)
    .bind(token_hash.as_slice())
    .execute(&app.db)
    .await
    .unwrap();

    let client_a = app.client.clone();
    let client_b = app.client.clone();
    let url = format!("{}/auth/reset-password", app.base_url);
    let payload_a = serde_json::json!({
        "token": raw_token,
        "new_password": "RaceWinner1!",
    });
    let payload_b = serde_json::json!({
        "token": raw_token,
        "new_password": "RaceWinner2!",
    });

    let req_a = client_a.post(&url).json(&payload_a).send();
    let req_b = client_b.post(&url).json(&payload_b).send();
    let (res_a, res_b) = tokio::join!(req_a, req_b);

    let status_a = res_a.unwrap().status().as_u16();
    let status_b = res_b.unwrap().status().as_u16();
    let success_count = [status_a, status_b]
        .into_iter()
        .filter(|status| *status == 200)
        .count();

    assert_eq!(
        success_count, 1,
        "expected exactly one successful reset, got {status_a} and {status_b}"
    );
    assert!(
        [status_a, status_b]
            .into_iter()
            .all(|status| status == 200 || status == 401),
        "expected one success and one auth failure, got {status_a} and {status_b}"
    );
}
