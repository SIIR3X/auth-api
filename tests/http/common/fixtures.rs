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

    RegisteredUser { id, username, email, password }
}

// Activate a user directly in the DB (skip email verification flow).
pub async fn activate_user(pool: &PgPool, user_id: Uuid) {
    sqlx::query(
        "UPDATE users SET status = 'active', email_verified_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .expect("failed to activate user");
}

// Register, activate, and login — returns tokens ready for authenticated requests.
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
