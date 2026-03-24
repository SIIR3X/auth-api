//! Repository for the `users` table.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::user::{User, UserStatus};

pub const FIND_BY_EMAIL_SQL: &str = "SELECT * FROM users WHERE email = $1::citext";
pub const FIND_BY_USERNAME_SQL: &str = "SELECT * FROM users WHERE username = $1::citext";

// Input types

pub struct NewUser<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub password_hash: &'a str,
    pub preferred_locale: &'a str,
}

// Writes

pub async fn create(pool: &PgPool, input: &NewUser<'_>) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (username, email, password_hash, preferred_locale)
         VALUES ($1, $2, $3, $4)
         RETURNING *",
    )
    .bind(input.username)
    .bind(input.email)
    .bind(input.password_hash)
    .bind(input.preferred_locale)
    .fetch_one(pool)
    .await
}

pub async fn update_password_hash(
    pool: &PgPool,
    id: Uuid,
    password_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(id)
        .bind(password_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_username(pool: &PgPool, id: Uuid, username: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET username = $2 WHERE id = $1")
        .bind(id)
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

/// Resets email verification state so the new address must be re-verified.
pub async fn update_email(pool: &PgPool, id: Uuid, email: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users
         SET email = $2,
             email_verified_at = NULL,
             status = 'pending_verification'::user_status
         WHERE id = $1",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_locale(pool: &PgPool, id: Uuid, locale: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET preferred_locale = $2 WHERE id = $1")
        .bind(id)
        .bind(locale)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_status(pool: &PgPool, id: Uuid, status: UserStatus) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_locked_until(
    pool: &PgPool,
    id: Uuid,
    locked_until: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET locked_until = $2 WHERE id = $1")
        .bind(id)
        .bind(locked_until)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn clear_lockout(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET locked_until = NULL WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_last_login(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Sets email_verified_at and transitions status to active.
pub async fn mark_email_verified(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users
         SET email_verified_at = NOW(),
             status = 'active'::user_status
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

// Reads

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(FIND_BY_EMAIL_SQL)
        .bind(email)
        .fetch_optional(pool)
        .await
}

pub async fn find_by_identifier(
    pool: &PgPool,
    identifier: &str,
) -> Result<Option<User>, sqlx::Error> {
    if identifier.contains('@') {
        find_by_email(pool, identifier).await
    } else {
        find_by_username(pool, identifier).await
    }
}

/// Permanently deletes a user and all associated data via CASCADE.
/// This is irreversible and fulfills GDPR right-to-erasure requests.
pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn find_by_username(pool: &PgPool, username: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(FIND_BY_USERNAME_SQL)
        .bind(username)
        .fetch_optional(pool)
        .await
}
