//! Tests for account lockout after repeated login failures.

use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn account_locked_after_threshold_failures() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;

    // Exhaust the lockout threshold (configured to 3 in tests).
    for _ in 0..3 {
        let res = app
            .post(
                "/auth/login",
                &serde_json::json!({
                    "identifier": user.email,
                    "password": "WrongPassword!",
                }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 401);
    }

    // The next attempt — even with the correct password — should be locked.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;

    assert_eq!(
        res.status().as_u16(),
        403,
        "expected 403 account_locked after threshold, got {}",
        res.status()
    );

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["code"], "account_locked");
}

#[tokio::test]
async fn account_unlocked_after_lockout_expires() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 2).await;
    fixtures::activate_user(&app.db, user.id).await;

    // Trigger lockout.
    for _ in 0..3 {
        app.post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": "WrongPassword!",
            }),
        )
        .await;
    }

    // Expire the lockout directly in the DB (set locked_until to the past).
    sqlx::query("UPDATE users SET locked_until = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .expect("failed to expire lockout");

    // Login should now succeed.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;

    assert_eq!(
        res.status().as_u16(),
        200,
        "expected 200 after lockout expiry, got {}",
        res.status()
    );
}

#[tokio::test]
async fn successful_login_clears_lockout() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 3).await;
    fixtures::activate_user(&app.db, user.id).await;

    // Trigger lockout, then expire it.
    for _ in 0..3 {
        app.post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": "WrongPassword!",
            }),
        )
        .await;
    }

    sqlx::query("UPDATE users SET locked_until = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .expect("failed to expire lockout");

    // Successful login should clear locked_until.
    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let row: (Option<time::OffsetDateTime>,) =
        sqlx::query_as("SELECT locked_until FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&app.db)
            .await
            .expect("failed to query locked_until");

    assert!(
        row.0.is_none(),
        "locked_until should be NULL after successful login"
    );
}
