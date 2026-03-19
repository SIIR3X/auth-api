use crate::common::app::TestApp;

#[tokio::test]
async fn register_success() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "alice",
                "email": "alice@example.com",
                "password": "SecurePass1!",
            }),
        )
        .await;

    let status = res.status().as_u16();
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(status, 201, "body: {body}");
    assert_eq!(body["username"], "alice");
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["status"], "pending_verification");
}

#[tokio::test]
async fn register_duplicate_email() {
    let app = TestApp::spawn().await;

    let payload = serde_json::json!({
        "username": "bob",
        "email": "bob@example.com",
        "password": "SecurePass1!",
    });

    let res1 = app.post("/auth/register", &payload).await;
    assert_eq!(res1.status().as_u16(), 201);

    // Same email, different username
    let res2 = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "bob2",
                "email": "bob@example.com",
                "password": "SecurePass1!",
            }),
        )
        .await;

    assert_eq!(res2.status().as_u16(), 409);
}

#[tokio::test]
async fn register_duplicate_username() {
    let app = TestApp::spawn().await;

    let res1 = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "carol",
                "email": "carol@example.com",
                "password": "SecurePass1!",
            }),
        )
        .await;
    assert_eq!(res1.status().as_u16(), 201);

    let res2 = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "carol",
                "email": "carol2@example.com",
                "password": "SecurePass1!",
            }),
        )
        .await;

    assert_eq!(res2.status().as_u16(), 409);
}

#[tokio::test]
async fn register_invalid_email() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "dave",
                "email": "not-an-email",
                "password": "SecurePass1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn register_password_too_short() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "eve",
                "email": "eve@example.com",
                "password": "short",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn register_username_too_short() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "x",
                "email": "x@example.com",
                "password": "SecurePass1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}
