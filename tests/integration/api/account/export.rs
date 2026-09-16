//! `GET /users/me/export`: everything stored about the account.

use serde_json::Value;

use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn the_export_holds_the_account_its_history_and_no_secret() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let stranger = fixtures::authenticated_user(&app, 2).await;
    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified)
         VALUES ($1, 'email', TRUE, TRUE)",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();

    let response = app.get_auth("/users/me/export", &user.access_token).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"account-data.json\""
    );
    let text = response.text().await.unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();

    assert_eq!(document["account"]["email"], user.email);
    assert_eq!(document["account"]["status"], "active");
    assert_eq!(document["roles"][0]["name"], "user");
    assert_eq!(document["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(document["two_factor_methods"][0]["method_type"], "email");
    assert_eq!(document["recovery_codes"]["total"], 0);
    assert_eq!(document["sign_in_attempts"][0]["successful"], true);
    let actions: Vec<&str> = document["audit_log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"login"), "{actions:?}");
    assert!(actions.contains(&"data_exported"), "{actions:?}");

    for secret in [
        "password_hash",
        "token_hash",
        "totp_secret",
        "code_hash",
        "$argon2",
    ] {
        assert!(!text.contains(secret), "the export leaks {secret}");
    }
    assert!(!text.contains(&stranger.email));
    assert!(!text.contains(&stranger.id.to_string()));
}

#[tokio::test]
async fn exporting_needs_a_recent_reauthentication() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    app.clear_recent_reauth(&user.access_token).await;

    let response = app.get_auth("/users/me/export", &user.access_token).await;
    assert_eq!(response.status(), 403);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "reauthentication_required");
}
