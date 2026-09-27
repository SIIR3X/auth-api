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

#[tokio::test]
async fn the_export_names_no_administrator_nor_their_address() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let administrator = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, ip_address, metadata)
         VALUES ($1, 'account_suspended', '203.0.113.77',
                 jsonb_build_object('by', 'administrator', 'administrator_id', $2::text))",
    )
    .bind(user.id)
    .bind(administrator)
    .execute(&app.db)
    .await
    .unwrap();

    let text = app
        .get_auth("/users/me/export", &user.access_token)
        .await
        .text()
        .await
        .unwrap();
    assert!(!text.contains(&administrator.to_string()), "{text}");
    assert!(!text.contains("203.0.113.77"), "{text}");
    let document: Value = serde_json::from_str(&text).unwrap();
    let entry = document["audit_log"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["action"] == "account_suspended")
        .expect("the change stays in the history");
    assert_eq!(
        entry["metadata"],
        serde_json::json!({ "by": "administrator" })
    );
    assert_eq!(entry["ip_address"], Value::Null);
}

/// Failed sign-ins typed for the account may be anyone's: the export shows
/// their network, not a stranger's exact address (SEC-70).
#[tokio::test]
async fn the_export_shows_only_the_network_of_strangers() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    sqlx::query(
        "INSERT INTO login_attempts (user_id, attempted_identifier, was_successful, failure_reason, request_ip, request_user_agent)
         VALUES ($1, $2, FALSE, 'invalid_password', '203.0.113.77',
                 'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0 StrangerBuild/42')",
    )
    .bind(user.id)
    .bind(&user.email)
    .execute(&app.db)
    .await
    .unwrap();
    // A role granted from the command line names its operator in the audit
    // log, not in the owner's export (SEC-85).
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, metadata)
         VALUES ($1, 'role_assigned', '{\"by\": \"command_line\", \"operator\": \"opsuser\", \"host\": \"api-vps-1\", \"role\": \"admin\"}')",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();

    let text = app
        .get_auth("/users/me/export", &user.access_token)
        .await
        .text()
        .await
        .unwrap();
    assert!(!text.contains("203.0.113.77"), "{text}");
    assert!(text.contains("203.0.113.0"), "{text}");
    // Nor a stranger's full user agent: its family only (SEC-85).
    assert!(!text.contains("StrangerBuild"), "{text}");
    assert!(text.contains("Firefox on Linux"), "{text}");
    assert!(
        !text.contains("opsuser") && !text.contains("api-vps-1"),
        "{text}"
    );
}
