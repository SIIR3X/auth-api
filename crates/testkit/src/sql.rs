//! Helpers of the schema suites, which exercise the database directly:
//! row fixtures, constraint assertions and query plans.

use sqlx::{PgPool, postgres::PgArguments};
use uuid::Uuid;

pub const SAMPLE_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHlzYWx0$abcdefghijklmnopqrstuv";

pub const SAMPLE_TOKEN_HASH: [u8; 32] = [7; 32];
pub const SAMPLE_CODE_HASH: [u8; 32] = [9; 32];

/// Bind values of mixed types for [`explain_plan`] or `sqlx::query_with`:
/// `pg_args![&email, &cutoff, &limit]`.
#[macro_export]
macro_rules! pg_args {
    ($($value:expr),* $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::sqlx::Arguments as _;
        #[allow(unused_mut)]
        let mut args = $crate::sqlx::postgres::PgArguments::default();
        $( args.add($value).expect("encode query argument"); )*
        args
    }};
}

pub fn sample_email(index: usize) -> String {
    format!("user{index}@example.com")
}

pub fn sample_username(index: usize) -> String {
    format!("user_{index}")
}

pub fn fixed_hash(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

pub async fn insert_user(pool: &PgPool, index: usize) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(sample_username(index))
    .bind(sample_email(index))
    .bind(SAMPLE_PASSWORD_HASH)
    .fetch_one(pool)
    .await
    .expect("failed to insert test user")
}

pub async fn insert_active_user(pool: &PgPool, index: usize) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, status, email_verified_at)
         VALUES ($1, $2, $3, 'active', NOW())
         RETURNING id",
    )
    .bind(sample_username(index))
    .bind(sample_email(index))
    .bind(SAMPLE_PASSWORD_HASH)
    .fetch_one(pool)
    .await
    .expect("failed to insert active test user")
}

pub async fn insert_permission(pool: &PgPool, resource: &str, action: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO permissions (resource, action)
         VALUES ($1, $2)
         RETURNING id",
    )
    .bind(resource)
    .bind(action)
    .fetch_one(pool)
    .await
    .expect("failed to insert permission")
}

/// Assert that `error` is a violation of the database constraint `expected`.
pub fn assert_constraint_error(error: &sqlx::Error, expected: &str) {
    let Some(database_error) = error.as_database_error() else {
        panic!("expected a violation of `{expected}`, got: {error}");
    };
    assert_eq!(
        database_error.constraint(),
        Some(expected),
        "unexpected database error: {database_error}"
    );
}

/// Plan of `sql` with sequential and TID scans disabled, so a missing index
/// shows up as a plan without it rather than hiding behind a cheap scan of a
/// small fixture table.
pub async fn explain_plan(pool: &PgPool, sql: &str, args: PgArguments) -> String {
    let mut conn = pool.acquire().await.expect("acquire a connection");
    sqlx::raw_sql("SET enable_seqscan = off; SET enable_tidscan = off;")
        .execute(&mut *conn)
        .await
        .expect("configure planner guardrails for explain");

    let explain = format!("EXPLAIN (COSTS OFF) {sql}");
    let lines: Vec<String> = sqlx::query_scalar_with(&explain, args)
        .fetch_all(&mut *conn)
        .await
        .expect("failed to explain query plan");

    // The connection returns to the pool: leave no planner setting behind.
    sqlx::raw_sql("RESET enable_seqscan; RESET enable_tidscan;")
        .execute(&mut *conn)
        .await
        .expect("reset planner settings");
    lines.join("\n")
}

pub fn assert_plan_contains(plan: &str, needle: &str) {
    assert!(
        plan.contains(needle),
        "expected plan to contain `{needle}`, got:\n{plan}"
    );
}
