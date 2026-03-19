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
