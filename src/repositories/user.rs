//! Repository for the `users` table.

use sqlx::{PgExecutor, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::user::{User, UserStatus};

pub const FIND_BY_EMAIL_SQL: &str = "SELECT * FROM users WHERE email = $1::citext";
/// Case-insensitive, like the uniqueness of usernames (`users_username_lower_key`).
pub const FIND_BY_USERNAME_SQL: &str = "SELECT * FROM users WHERE lower(username) = lower($1)";

// Input types

pub struct NewUser<'a> {
    pub username: &'a str,
    pub email: &'a str,
    pub password_hash: &'a str,
    pub preferred_locale: &'a str,
}

// Writes

pub async fn create<'e>(
    executor: impl PgExecutor<'e>,
    input: &NewUser<'_>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (username, email, password_hash, preferred_locale)
         VALUES ($1, $2, $3, $4)
         RETURNING *",
    )
    .bind(input.username)
    .bind(input.email)
    .bind(input.password_hash)
    .bind(input.preferred_locale)
    .fetch_one(executor)
    .await
}

/// Replace the hash only while it is still `current`: a rehash racing a
/// password change never brings the old password back.
pub async fn replace_password_hash(
    pool: &PgPool,
    id: Uuid,
    current: &str,
    replacement: &str,
) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("UPDATE users SET password_hash = $3 WHERE id = $1 AND password_hash = $2")
            .bind(id)
            .bind(current)
            .bind(replacement)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn update_password_hash<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
    password_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(id)
        .bind(password_hash)
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn update_username<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
    username: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET username = $2 WHERE id = $1")
        .bind(id)
        .bind(username)
        .execute(executor)
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

/// Stamp a completed sign-in, by any method: last login time, the end of any
/// lockout, and a fresh start for the count of wrong passwords.
pub async fn record_sign_in<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET last_login_at = NOW(), locked_until = NULL, lockout_cleared_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Whether another account already uses `email`.
pub async fn email_taken<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    email: &str,
    except: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1::citext AND id <> $2)")
        .bind(email)
        .bind(except)
        .fetch_one(executor)
        .await
}

/// Move an account to an address whose ownership was just proven. The status
/// is left alone: confirming an address must never reactivate a suspended or
/// inactive account.
pub async fn change_email<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: Uuid,
    email: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET email = $2, email_verified_at = NOW() WHERE id = $1")
        .bind(id)
        .bind(email)
        .execute(executor)
        .await?;
    Ok(())
}

/// Sets email_verified_at and activates an account that was pending
/// verification. Any other status (suspended, inactive) is left untouched.
pub async fn mark_email_verified<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users
         SET email_verified_at = NOW(),
             status = CASE
                 WHEN status = 'pending_verification' THEN 'active'::user_status
                 ELSE status
             END
         WHERE id = $1",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Verify the address of a pending account and activate it; any other account
/// is left untouched. Returns whether the account was pending.
/// Give a pending account the credentials its verification link carries. The
/// username changes only while no other account holds it; the password and the
/// locale always follow the link. Does nothing to an account already verified.
pub async fn adopt_pending_credentials<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
    credentials: &crate::domain::token::PendingCredentials,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users u
         SET password_hash = $2,
             preferred_locale = $4,
             username = CASE
                 WHEN EXISTS (SELECT 1 FROM users o WHERE lower(o.username) = lower($3) AND o.id <> u.id)
                     THEN u.username
                 ELSE $3
             END
         WHERE u.id = $1 AND u.status = 'pending_verification'",
    )
    .bind(id)
    .bind(&credentials.password_hash)
    .bind(&credentials.username)
    .bind(&credentials.preferred_locale)
    .execute(executor)
    .await?;
    Ok(())
}

/// Whether the account can prove a second factor: a verified TOTP or email
/// method, or a passkey.
pub async fn has_second_factor<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM two_factor_methods WHERE user_id = $1 AND is_verified)
             OR EXISTS (SELECT 1 FROM passkeys WHERE user_id = $1)",
    )
    .bind(id)
    .fetch_one(executor)
    .await
}

/// Delete every way into the account other than its password: second factors,
/// recovery codes, passkeys, external identities and personal access tokens.
/// Run on a pending account taken back by its owner.
pub async fn drop_access_factors<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "WITH methods AS (DELETE FROM two_factor_methods WHERE user_id = $1),
              codes AS (DELETE FROM recovery_codes WHERE user_id = $1),
              keys AS (DELETE FROM passkeys WHERE user_id = $1),
              identities AS (DELETE FROM external_identities WHERE user_id = $1)
         DELETE FROM personal_access_tokens WHERE user_id = $1",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Delete the second factors, passkeys and external identities added since
/// `since`, and return what went as `(kind, name)`: `totp`, `email`,
/// `passkey` with its name, `identity` with its provider. The remaining
/// verified method becomes primary if the primary went, and recovery codes go
/// when no verified method remains.
///
/// With `keep_a_second_factor`, an account left with no second factor older
/// than `since` keeps the oldest of its recent ones (a verified method or a
/// passkey): an administrator promoted in the window does not lose, to
/// whoever reads their mailbox, the factor the administration requires.
pub async fn drop_access_factors_since(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    since: OffsetDateTime,
    keep_a_second_factor: bool,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let kept: Option<(String, Uuid)> = if keep_a_second_factor {
        sqlx::query_as(
            "SELECT kind, factor_id FROM (
                 SELECT 'method' AS kind, id AS factor_id, created_at FROM two_factor_methods
                 WHERE user_id = $1 AND is_verified AND created_at > $2
                 UNION ALL
                 SELECT 'passkey', id, created_at FROM passkeys
                 WHERE user_id = $1 AND created_at > $2
             ) recent
             WHERE NOT EXISTS (SELECT 1 FROM two_factor_methods
                               WHERE user_id = $1 AND is_verified AND created_at <= $2)
               AND NOT EXISTS (SELECT 1 FROM passkeys WHERE user_id = $1 AND created_at <= $2)
             ORDER BY created_at
             LIMIT 1",
        )
        .bind(id)
        .bind(since)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        None
    };
    let kept_method = kept
        .as_ref()
        .filter(|(k, _)| k == "method")
        .map(|(_, f)| *f);
    let kept_passkey = kept
        .as_ref()
        .filter(|(k, _)| k == "passkey")
        .map(|(_, f)| *f);
    let mut removed: Vec<(String, String)> = sqlx::query_as(
        "DELETE FROM two_factor_methods
         WHERE user_id = $1 AND created_at > $2 AND id IS DISTINCT FROM $3
         RETURNING method_type::text, ''",
    )
    .bind(id)
    .bind(since)
    .bind(kept_method)
    .fetch_all(&mut *tx)
    .await?;
    removed.extend(
        sqlx::query_as::<_, (String, String)>(
            "DELETE FROM passkeys
             WHERE user_id = $1 AND created_at > $2 AND id IS DISTINCT FROM $3
             RETURNING 'passkey', name::text",
        )
        .bind(id)
        .bind(since)
        .bind(kept_passkey)
        .fetch_all(&mut *tx)
        .await?,
    );
    removed.extend(
        sqlx::query_as::<_, (String, String)>(
            "DELETE FROM external_identities WHERE user_id = $1 AND created_at > $2
             RETURNING 'identity', provider::text",
        )
        .bind(id)
        .bind(since)
        .fetch_all(&mut *tx)
        .await?,
    );
    sqlx::query(
        "UPDATE two_factor_methods SET is_primary = TRUE
         WHERE id = (SELECT id FROM two_factor_methods
                     WHERE user_id = $1 AND is_verified ORDER BY created_at LIMIT 1)
           AND NOT EXISTS (SELECT 1 FROM two_factor_methods WHERE user_id = $1 AND is_primary)",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM recovery_codes WHERE user_id = $1
           AND NOT EXISTS (SELECT 1 FROM two_factor_methods WHERE user_id = $1 AND is_verified)",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    Ok(removed)
}

pub async fn verify_if_pending<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE users
         SET email_verified_at = NOW(), status = 'active'::user_status
         WHERE id = $1 AND status = 'pending_verification'",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

// Reads

pub async fn find_by_id<'e>(
    executor: impl PgExecutor<'e>,
    id: Uuid,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(executor)
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

/// Delete the account and forget what it leaves outside its own rows: client
/// addresses in its audit entries and its sign-in attempts. One function, with
/// the owner's privileges, so it can never rewrite the traces of an account
/// that stays. Call it in the deletion's transaction, after the entries that
/// announce it.
pub async fn erase<'e>(executor: impl PgExecutor<'e>, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT forget_account_traces($1)")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Permanently deletes a user and all associated data via CASCADE.
/// This is irreversible and fulfills GDPR right-to-erasure requests.
pub async fn delete<'e>(executor: impl PgExecutor<'e>, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Whether an account holds the username, or a registration reserved it
/// (see `reserve_username`), whatever the case.
pub async fn username_unavailable(pool: &PgPool, username: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE lower(username) = lower($1))
             OR EXISTS (SELECT 1 FROM username_reservations
                        WHERE lower(username) = lower($1) AND expires_at > NOW())",
    )
    .bind(username)
    .fetch_one(pool)
    .await
}

/// Reserve the username for a registration on `account`'s address until
/// `expires_at`, replacing the account's previous reservation.
pub async fn reserve_username(
    pool: &PgPool,
    username: &str,
    account: Uuid,
    expires_at: time::OffsetDateTime,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM username_reservations WHERE reserved_for = $1")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO username_reservations (username, expires_at, reserved_for) VALUES ($1, $2, $3)
         ON CONFLICT (lower(username)) DO NOTHING",
    )
    .bind(username)
    .bind(expires_at)
    .bind(account)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// When a reset activates a pending account, the username and locale of the
/// latest registration that sent the account a link, if its username is free.
pub async fn adopt_latest_registration_identity(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users u
         SET username = latest.username, preferred_locale = latest.preferred_locale
         FROM (SELECT username, preferred_locale FROM email_verification_tokens
               WHERE user_id = $1 AND username IS NOT NULL AND used_at IS NULL
               ORDER BY created_at DESC LIMIT 1) latest
         WHERE u.id = $1 AND u.status = 'pending_verification'
           AND NOT EXISTS (SELECT 1 FROM users o
                           WHERE lower(o.username) = lower(latest.username) AND o.id <> $1)",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

pub async fn find_by_username(pool: &PgPool, username: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(FIND_BY_USERNAME_SQL)
        .bind(username)
        .fetch_optional(pool)
        .await
}

// Administration

/// One page of accounts, newest first, strictly older than `before` when given.
/// `pattern` is a `LIKE` pattern matched against the lower-cased address and
/// username (see `domain::user::prefix_pattern`).
pub async fn search(
    pool: &PgPool,
    pattern: Option<&str>,
    status: Option<&UserStatus>,
    before: Option<(OffsetDateTime, Uuid)>,
    limit: i64,
) -> Result<Vec<User>, sqlx::Error> {
    let (before_at, before_id) = before.unzip();
    sqlx::query_as::<_, User>(
        "SELECT * FROM users
         WHERE ($1::text IS NULL
                OR lower(email::text) LIKE $1
                OR lower(username::text) LIKE $1)
           AND ($2::user_status IS NULL OR status = $2)
           AND ($3::timestamptz IS NULL OR (created_at, id) < ($3, $4))
         ORDER BY created_at DESC, id DESC
         LIMIT $5",
    )
    .bind(pattern)
    .bind(status)
    .bind(before_at)
    .bind(before_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Suspend an active or inactive account. Returns whether it changed.
pub async fn suspend<'e>(executor: impl PgExecutor<'e>, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE users SET status = 'suspended'
         WHERE id = $1 AND status IN ('active', 'inactive')",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Reactivate a suspended or inactive account. Returns whether it changed.
pub async fn reactivate<'e>(executor: impl PgExecutor<'e>, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE users SET status = 'active'
         WHERE id = $1 AND status IN ('suspended', 'inactive')",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// End a lockout and forgive the failed sign-ins that caused it.
pub async fn clear_lockout<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET locked_until = NULL, lockout_cleared_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Lock the account's row until the transaction ends: checks made after it
/// (its second factors, its roles) cannot change underneath.
pub async fn lock_row<'e>(executor: impl PgExecutor<'e>, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}
