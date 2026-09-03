//! TOTP encryption key rotation (`auth-api --rotate-totp-keys`).
//!
//! The rotation runs on a second `AppState` sharing the app's database, as the
//! one-off command does next to a running service.

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
    let plaintext = crypto::Keyring::new(key_a, None)
        .decrypt(&before)
        .expect("must decrypt under KEY_A");

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

    let rotated_plaintext = crypto::Keyring::new(key_b, None)
        .decrypt(&after)
        .expect("must decrypt under KEY_B");
    assert_eq!(plaintext, rotated_plaintext, "plaintext must be preserved");
    assert!(
        crypto::Keyring::new(key_a, None).decrypt(&after).is_err(),
        "re-encrypted secret must not be readable with old key"
    );
}

#[tokio::test]
async fn rotate_totp_key_with_multiple_users_rotates_all() {
    let app = TestApp::spawn_with_config(|c| {
        c.crypto.encryption_key = KEY_A.into();
    })
    .await;

    for index in [903, 904] {
        let user = fixtures::authenticated_user(&app, index).await;
        let setup_res = app
            .post_auth(
                "/users/me/two-factor/totp/setup",
                &user.access_token,
                &serde_json::json!({}),
            )
            .await;
        assert_eq!(setup_res.status().as_u16(), 200);
    }

    let rot_state = rotation_state(&app, KEY_B, KEY_A).await;
    let result = rotate_totp_encryption_key(&rot_state)
        .await
        .expect("rotation must succeed");

    assert_eq!(result.rotated, 2, "expected both secrets rotated");
    assert_eq!(result.failed, 0);
}

#[tokio::test]
async fn rotate_is_idempotent_when_run_twice() {
    // First run: A --> B (rotated=1, failed=0).
    // Second run: A --> B again, the secret is already under B and is skipped.
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

    // An interrupted rotation is simply run again: finished rows are skipped.
    let second = rotate_totp_encryption_key(&rot_state).await.unwrap();
    assert_eq!(
        (second.rotated, second.skipped, second.failed),
        (0, 1, 0),
        "a second run must find nothing left to rotate"
    );
}

#[tokio::test]
async fn rotate_upgrades_secrets_written_before_ciphertexts_were_versioned() {
    use auth_api::utils::crypto;

    let key_a = crypto::decode_encryption_key(KEY_A).unwrap();
    let key_b = crypto::decode_encryption_key(KEY_B).unwrap();

    let app = TestApp::spawn_with_config(|c| {
        c.crypto.encryption_key = KEY_A.into();
    })
    .await;
    let user = fixtures::authenticated_user(&app, 902).await;
    let setup_res = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &serde_json::json!({}),
        )
        .await;
    assert_eq!(setup_res.status().as_u16(), 200);

    // Put the secret back in the pre-versioning format: bare base64, no key id.
    let stored: String = sqlx::query_scalar(
        "SELECT totp_secret FROM two_factor_methods WHERE user_id = $1 AND method_type = 'totp'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    let plaintext = crypto::Keyring::new(key_a, None).decrypt(&stored).unwrap();
    let legacy = crypto::encrypt(&plaintext, &key_a).unwrap();
    sqlx::query("UPDATE two_factor_methods SET totp_secret = $1 WHERE user_id = $2")
        .bind(&legacy)
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();

    let rot_state = rotation_state(&app, KEY_B, KEY_A).await;
    let result = rotate_totp_encryption_key(&rot_state).await.unwrap();
    assert_eq!((result.rotated, result.failed), (1, 0));

    let after: String = sqlx::query_scalar(
        "SELECT totp_secret FROM two_factor_methods WHERE user_id = $1 AND method_type = 'totp'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(after.starts_with("v1:"), "rotated secrets are versioned");
    assert_eq!(
        crypto::Keyring::new(key_b, None).decrypt(&after).unwrap(),
        plaintext
    );

    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'encryption_key_rotated'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(audited, 1, "a rotation is audited under its own action");
}
