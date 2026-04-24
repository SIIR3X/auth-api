//! Two-factor method repository tests.
//!
//! Tests index range 970-979.
//!
//! Covers `find_by_type` and `find_all_by_type`, which are used by the
//! email-2FA flow but never directly tested.

use auth_api::{domain::two_factor::TwoFactorType, repositories::two_factor as tf_repo};

use crate::common::{app::TestApp, fixtures};

// Helpers

async fn insert_method(
    app: &TestApp,
    user_id: uuid::Uuid,
    method_type: TwoFactorType,
) -> uuid::Uuid {
    // TOTP requires a non-null totp_secret (constraint: two_factor_method_payload).
    // Email requires totp_secret IS NULL.
    let secret: Option<&str> = match method_type {
        TwoFactorType::Totp => Some("dummy-encrypted-secret-for-test"),
        TwoFactorType::Email => None,
    };
    sqlx::query_scalar(
        "INSERT INTO two_factor_methods (user_id, method_type, totp_secret)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(user_id)
    .bind(method_type)
    .bind(secret)
    .fetch_one(&app.db)
    .await
    .expect("failed to insert two_factor_method")
}

// find_by_type

#[tokio::test]
async fn find_by_type_returns_none_when_no_method_exists() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 970).await;

    let result = tf_repo::find_by_type(&app.db, user.id, TwoFactorType::Totp)
        .await
        .expect("find_by_type failed");

    assert!(
        result.is_none(),
        "must return None when user has no TOTP method"
    );
}

#[tokio::test]
async fn find_by_type_returns_method_of_requested_type() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 971).await;

    insert_method(&app, user.id, TwoFactorType::Email).await;

    let result = tf_repo::find_by_type(&app.db, user.id, TwoFactorType::Email)
        .await
        .expect("find_by_type failed");

    assert!(result.is_some(), "must return the Email method");
    assert_eq!(result.unwrap().method_type, TwoFactorType::Email);
}

#[tokio::test]
async fn find_by_type_does_not_return_method_of_other_type() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 972).await;

    insert_method(&app, user.id, TwoFactorType::Email).await;

    let result = tf_repo::find_by_type(&app.db, user.id, TwoFactorType::Totp)
        .await
        .expect("find_by_type failed");

    assert!(
        result.is_none(),
        "must not return Email method when querying for Totp"
    );
}

// find_all_by_type

#[tokio::test]
async fn find_all_by_type_returns_methods_of_correct_type_only() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 973).await;

    // Both types are unique per user (idx_2fa_user_totp / idx_2fa_user_email),
    // so we insert one of each and verify each query returns only its own type.
    insert_method(&app, user.id, TwoFactorType::Totp).await;
    insert_method(&app, user.id, TwoFactorType::Email).await;

    let totp_methods = tf_repo::find_all_by_type(&app.db, user.id, TwoFactorType::Totp)
        .await
        .expect("find_all_by_type(Totp) failed");
    assert_eq!(totp_methods.len(), 1);
    assert_eq!(totp_methods[0].method_type, TwoFactorType::Totp);

    let email_methods = tf_repo::find_all_by_type(&app.db, user.id, TwoFactorType::Email)
        .await
        .expect("find_all_by_type(Email) failed");
    assert_eq!(email_methods.len(), 1);
    assert_eq!(email_methods[0].method_type, TwoFactorType::Email);
}

#[tokio::test]
async fn find_all_by_type_returns_empty_when_no_match() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 974).await;

    let results = tf_repo::find_all_by_type(&app.db, user.id, TwoFactorType::Totp)
        .await
        .expect("find_all_by_type failed");

    assert!(
        results.is_empty(),
        "must return empty when user has no Totp methods"
    );
}
