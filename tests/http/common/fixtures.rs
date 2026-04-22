//! Database fixtures for HTTP integration tests.
//!
//! These functions insert data directly into the database, bypassing the HTTP
//! layer so that tests can set up preconditions without going through the API.

#![allow(dead_code)]

use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use super::app::TestApp;

pub struct RegisteredUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password: String,
}

pub struct AuthenticatedUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password: String,
    pub access_token: String,
    pub refresh_token: String,
}

pub struct PasswordResetToken {
    pub raw: String,
}

pub struct EmailVerificationToken {
    pub raw: String,
}

// Register a new user via the API and return their credentials.
pub async fn register_user(app: &TestApp, index: usize) -> RegisteredUser {
    let username = format!("testuser{index}");
    let email = format!("testuser{index}@example.com");
    let password = format!("Password{index}!ok");

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": username,
                "email": email,
                "password": password,
            }),
        )
        .await;

    let status = res.status().as_u16();
    if status != 201 {
        let body = res.text().await.unwrap_or_default();
        panic!("register failed for user {index}: status={status} body={body}");
    }

    let body: Value = res.json().await.unwrap();
    let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    RegisteredUser {
        id,
        username,
        email,
        password,
    }
}

/// Inserts a valid password reset token directly in the DB with a known raw value.
/// Returns the raw (plaintext) token to use in API calls.
pub async fn create_password_reset_token(pool: &PgPool, user_id: Uuid) -> PasswordResetToken {
    let raw = format!("test-reset-{}", user_id);
    let hash = rust_api::utils::crypto::sha256(raw.as_bytes());
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '30 minutes')",
    )
    .bind(user_id)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("failed to create password reset token");
    PasswordResetToken { raw }
}

/// Inserts an already-expired password reset token.
pub async fn create_expired_password_reset_token(
    pool: &PgPool,
    user_id: Uuid,
) -> PasswordResetToken {
    let raw = format!("test-expired-reset-{}", user_id);
    let hash = rust_api::utils::crypto::sha256(raw.as_bytes());
    // Override created_at so expires_at > created_at (satisfies CHECK constraint)
    // while both timestamps are in the past (token is expired).
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at)
         VALUES ($1, $2, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '2 hours')",
    )
    .bind(user_id)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("failed to create expired password reset token");
    PasswordResetToken { raw }
}

/// Inserts an already-consumed password reset token.
pub async fn create_used_password_reset_token(pool: &PgPool, user_id: Uuid) -> PasswordResetToken {
    let raw = format!("test-used-reset-{}", user_id);
    let hash = rust_api::utils::crypto::sha256(raw.as_bytes());
    sqlx::query(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used_at)
         VALUES ($1, $2, NOW() + INTERVAL '30 minutes', NOW())",
    )
    .bind(user_id)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("failed to create used password reset token");
    PasswordResetToken { raw }
}

/// Inserts a valid email verification token directly in the DB.
/// Revokes any existing active tokens first (only one active token per user is allowed).
pub async fn create_email_verification_token(
    pool: &PgPool,
    user_id: Uuid,
    email: &str,
) -> EmailVerificationToken {
    let raw = format!("test-verify-{}", user_id);
    let hash = rust_api::utils::crypto::sha256(raw.as_bytes());
    // register_user already creates an active token; mark it used before inserting ours.
    sqlx::query(
        "UPDATE email_verification_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .expect("failed to revoke existing email verification tokens");
    sqlx::query(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, target_email)
         VALUES ($1, $2, NOW() + INTERVAL '24 hours', $3)",
    )
    .bind(user_id)
    .bind(&hash)
    .bind(email)
    .execute(pool)
    .await
    .expect("failed to create email verification token");
    EmailVerificationToken { raw }
}

// Activate a user directly in the DB (skip email verification flow).
pub async fn activate_user(pool: &PgPool, user_id: Uuid) {
    sqlx::query("UPDATE users SET status = 'active', email_verified_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("failed to activate user");
}

// Register, activate, and login - returns tokens ready for authenticated requests.
pub async fn authenticated_user(app: &TestApp, index: usize) -> AuthenticatedUser {
    let user = register_user(app, index).await;
    activate_user(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200, "login failed for user {index}");

    let body: Value = res.json().await.unwrap();
    let access_token = body["access_token"].as_str().unwrap().to_owned();
    let refresh_token = body["refresh_token"].as_str().unwrap().to_owned();

    AuthenticatedUser {
        id: user.id,
        username: user.username,
        email: user.email,
        password: user.password,
        access_token,
        refresh_token,
    }
}
