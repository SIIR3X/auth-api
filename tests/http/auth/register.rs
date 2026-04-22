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

#[tokio::test]
async fn register_username_too_long() {
    let app = TestApp::spawn().await;
    // 31 characters - one over the 30-char maximum.
    let long_name = "a".repeat(31);

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": long_name,
                "email": "toolong@example.com",
                "password": "SecurePass1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn register_username_invalid_chars_rejected() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "bad name!",
                "email": "badchars@example.com",
                "password": "SecurePass1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn register_password_too_long() {
    let app = TestApp::spawn().await;
    // 129 characters - one over the 128-char maximum.
    let too_long = format!("{}A1!", "x".repeat(126));
    assert_eq!(too_long.len(), 129);

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "validuser",
                "email": "toolong@example.com",
                "password": too_long,
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn register_password_missing_digit_rejected() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "validuser",
                "email": "nodigit@example.com",
                "password": "NoDigitHere!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn register_password_missing_uppercase_rejected() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "validuser",
                "email": "noupper@example.com",
                "password": "nouppercase1!",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn register_password_missing_special_char_rejected() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "validuser",
                "email": "nospecial@example.com",
                "password": "NoSpecialChar1",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}
