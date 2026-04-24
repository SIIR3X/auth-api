//! Key-rotation service tests.
//!
//! Tests index range 900-919.

use auth_api::{services::key_rotation::rotate_totp_encryption_key, state::AppState};

use crate::common::{app::TestApp, fixtures};

// Two distinct valid 32-byte base64 keys for rotation tests.
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const KEY_B: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";

/// Build an AppState sharing `app`'s DB pool but with overridden crypto keys.
async fn rotation_state(app: &TestApp, active: &str, previous: &str) -> AppState {
    let mut config = (*app.state.config).clone();
    config.crypto.encryption_key = active.into();
    config.crypto.previous_encryption_key = Some(previous.into());
    AppState::from_config_with_pool(config, app.db.clone())
        .await
        .expect("failed to build rotation state")
}

// Error paths

#[tokio::test]
async fn rotate_fails_when_no_previous_key_configured() {
    let app = TestApp::spawn().await;
    let result = rotate_totp_encryption_key(&app.state).await;
    assert!(
        result.is_err(),
        "must fail when previous_encryption_key is absent"
    );
}

#[tokio::test]
async fn rotate_fails_when_keys_are_identical() {
    let app = TestApp::spawn_with_config(|c| {
        c.crypto.encryption_key = KEY_A.into();
        c.crypto.previous_encryption_key = Some(KEY_A.into());
    })
    .await;

    let result = rotate_totp_encryption_key(&app.state).await;
    assert!(
        result.is_err(),
        "must fail when old and new keys are identical"
    );
}

// Success paths

#[tokio::test]
async fn rotate_succeeds_with_no_totp_methods_returns_zero_counts() {
    let app = TestApp::spawn_with_config(|c| {
        c.crypto.encryption_key = KEY_B.into();
        c.crypto.previous_encryption_key = Some(KEY_A.into());
    })
    .await;

    let result = rotate_totp_encryption_key(&app.state)
        .await
        .expect("rotation must succeed on empty TOTP table");

    assert_eq!(result.rotated, 0);
    assert_eq!(result.failed, 0);
}

#[tokio::test]
async fn rotate_re_encrypts_totp_secret_with_new_key() {
    use auth_api::utils::crypto;

    let key_a = crypto::decode_encryption_key(KEY_A).unwrap();
    let key_b = crypto::decode_encryption_key(KEY_B).unwrap();

    // Set up TOTP with KEY_A as the active encryption key.
    let app = TestApp::spawn_with_config(|c| {
        c.crypto.encryption_key = KEY_A.into();
    })
    .await;

    let user = fixtures::authenticated_user(&app, 900).await;
    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(setup_res.status().as_u16(), 200);

    // Read the encrypted secret stored under KEY_A.
    let before: String = sqlx::query_scalar(
        "SELECT totp_secret FROM two_factor_methods
         WHERE user_id = $1 AND method_type = 'totp' LIMIT 1",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .expect("no TOTP method found");

    // Confirm it decrypts under KEY_A.
    let plaintext = crypto::decrypt(&before, &key_a).expect("must decrypt under KEY_A");

    // Rotate KEY_A --> KEY_B on the same isolated DB via a shared-pool state.
    let rot_state = rotation_state(&app, KEY_B, KEY_A).await;
    let result = rotate_totp_encryption_key(&rot_state)
        .await
        .expect("rotation must succeed");

    assert_eq!(result.rotated, 1);
    assert_eq!(result.failed, 0);

    // Read the updated encrypted secret.
    let after: String = sqlx::query_scalar(
        "SELECT totp_secret FROM two_factor_methods
         WHERE user_id = $1 AND method_type = 'totp' LIMIT 1",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .expect("no TOTP method after rotation");

    assert_ne!(before, after, "secret must change after rotation");

    let rotated_plaintext = crypto::decrypt(&after, &key_b).expect("must decrypt under KEY_B");
    assert_eq!(plaintext, rotated_plaintext, "plaintext must be preserved");
}

#[tokio::test]
async fn rotate_is_idempotent_when_run_twice() {
    // First run: A --> B (rotated=1, failed=0).
    // Second run: A --> B again, data already under B --> re_encrypt fails per method.
    let app = TestApp::spawn_with_config(|c| {
        c.crypto.encryption_key = KEY_A.into();
    })
    .await;

    let user = fixtures::authenticated_user(&app, 901).await;
    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(setup_res.status().as_u16(), 200);

    let rot_state = rotation_state(&app, KEY_B, KEY_A).await;

    let first = rotate_totp_encryption_key(&rot_state).await.unwrap();
    assert_eq!(first.rotated, 1);
    assert_eq!(first.failed, 0);

    // Second run with the same config: data is under B, decrypt with A fails.
    let second = rotate_totp_encryption_key(&rot_state).await.unwrap();
    assert_eq!(second.rotated, 0);
    assert_eq!(
        second.failed, 1,
        "re-running same rotation must fail per-method"
    );
}
