//! `/admin`: administrators acting on other accounts.

mod audit;
mod clients;
mod roles;
mod users;

use auth_api::{domain::role::ADMIN_PERMISSIONS, repositories::role as role_repo};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

pub struct Admin {
    pub user: AuthenticatedUser,
    /// An access token carrying the administrative permissions, as signing in
    /// after the grant would issue.
    pub token: String,
}

/// An administrator: the `admin` role, a second factor, and a token with the
/// role's permissions.
pub async fn admin(app: &TestApp, index: usize) -> Admin {
    let user = fixtures::authenticated_user(app, index).await;
    let role = role_repo::find_by_name(&app.db, "admin")
        .await
        .unwrap()
        .unwrap();
    role_repo::assign_to_user(&app.db, user.id, role.id, None)
        .await
        .unwrap();
    enroll_second_factor(app, user.id).await;
    let token = token_with(app, &user, &ADMIN_PERMISSIONS);
    Admin { user, token }
}

pub async fn enroll_second_factor(app: &TestApp, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified)
         VALUES ($1, 'email', TRUE, TRUE)",
    )
    .bind(user_id)
    .execute(&app.db)
    .await
    .unwrap();
}

/// The user's own session, with `permissions` in the token.
pub fn token_with(app: &TestApp, user: &AuthenticatedUser, permissions: &[&str]) -> String {
    let mut claims = app.decode_access_token(&user.access_token);
    claims.roles = vec!["user".into(), "admin".into()];
    claims.permissions = permissions.iter().map(|p| (*p).to_owned()).collect();
    app.sign(&claims)
}

pub async fn body(response: reqwest::Response) -> (u16, Value) {
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

pub async fn sign_in(app: &TestApp, identifier: &str, password: &str) -> (u16, Value) {
    body(
        app.post(
            "/auth/login",
            &json!({ "identifier": identifier, "password": password }),
        )
        .await,
    )
    .await
}
