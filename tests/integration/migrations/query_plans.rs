use auth_api::repositories::{login_attempt, session as session_repo, user as user_repo};
use sqlx::PgPool;
use testkit::sql::{
    assert_plan_contains, explain_plan, fixed_hash, insert_active_user, insert_user, sample_email,
    sample_username,
};
use testkit::{TestDb, pg_args};
use time::OffsetDateTime;

#[tokio::test]
async fn identifier_lookup_plan_uses_user_indexes() {
    let db = TestDb::new().await;

    for index in 0..200 {
        insert_user(&db.pool, index).await;
    }

    let email = sample_email(42);
    let email_plan = explain_plan(&db.pool, user_repo::FIND_BY_EMAIL_SQL, pg_args![&email]).await;
    assert_plan_contains(&email_plan, "users_email_key");

    let username = sample_username(42);
    let username_plan = explain_plan(
        &db.pool,
        user_repo::FIND_BY_USERNAME_SQL,
        pg_args![&username],
    )
    .await;
    assert_plan_contains(&username_plan, "users_username_key");
}

#[tokio::test]
async fn session_lookup_plans_use_primary_and_token_hash_indexes() {
    let db = TestDb::new().await;

    let user_id = insert_active_user(&db.pool, 700).await;

    for seed in 1..=48u8 {
        let token_hash = fixed_hash(seed);
        sqlx::query(
            "INSERT INTO sessions (user_id, expires_at, token_hash)
                 VALUES ($1, NOW() + INTERVAL '30 days', $2)",
        )
        .bind(user_id)
        .bind(&token_hash)
        .execute(&db.pool)
        .await
        .expect("failed to insert session fixture");
    }

    let target_hash = fixed_hash(17);
    let token_plan = explain_plan(
        &db.pool,
        session_repo::FIND_BY_TOKEN_HASH_SQL,
        pg_args![&target_hash],
    )
    .await;
    assert_plan_contains(&token_plan, "sessions_token_hash_key");

    let session_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM sessions WHERE token_hash = $1")
            .bind(&target_hash)
            .fetch_one(&db.pool)
            .await
            .expect("failed to load target session");

    let validation_plan = explain_plan(
        &db.pool,
        session_repo::FIND_VALIDATION_BY_ID_SQL,
        pg_args![&session_id],
    )
    .await;
    assert_plan_contains(&validation_plan, "sessions_pkey");

    let active_plan = explain_plan(
        &db.pool,
        session_repo::FIND_ACTIVE_SUMMARY_BY_USER_SQL,
        pg_args![&user_id],
    )
    .await;
    assert_plan_contains(&active_plan, "idx_sessions_user_active");
}

#[tokio::test]
async fn brute_force_counter_plans_use_partial_failure_indexes() {
    let db = TestDb::new().await;

    let user_id = insert_active_user(&db.pool, 1000).await;
    let hot_identifier = sample_email(1000);
    let hot_ip = "203.0.113.10/32";

    insert_login_attempts(&db.pool, user_id, &hot_identifier, hot_ip).await;
    sqlx::raw_sql(
        "ANALYZE login_attempts;
             ANALYZE users;
             ANALYZE sessions;",
    )
    .execute(&db.pool)
    .await
    .expect("failed to analyze benchmark fixtures");

    let cutoff = OffsetDateTime::now_utc() - time::Duration::minutes(15);
    let identifier_limit = 10i64;
    let identifier_plan = explain_plan(
        &db.pool,
        login_attempt::COUNT_RECENT_FAILURES_BY_IDENTIFIER_SQL,
        pg_args![&hot_identifier, &cutoff, &identifier_limit],
    )
    .await;
    assert_plan_contains(
        &identifier_plan,
        "idx_login_attempts_failed_identifier_time",
    );

    let explain_ip_sql =
        login_attempt::COUNT_RECENT_FAILURES_BY_IP_SQL.replacen("$1::cidr", "$1::text::cidr", 1);
    let ip_limit = 30i64;
    let ip_plan = explain_plan(
        &db.pool,
        &explain_ip_sql,
        pg_args![&hot_ip, &cutoff, &ip_limit],
    )
    .await;
    assert_plan_contains(&ip_plan, "idx_login_attempts_failed_ip_time");
}

async fn insert_login_attempts(pool: &PgPool, user_id: uuid::Uuid, identifier: &str, ip: &str) {
    for offset in 0..180 {
        let was_successful = offset % 6 == 0;
        let other_identifier = format!("other-{offset}@example.com");
        let attempted_identifier = if offset % 2 == 0 {
            identifier
        } else {
            other_identifier.as_str()
        };
        let current_ip = if offset % 3 == 0 {
            ip
        } else {
            "198.51.100.200/32"
        };
        let failure_reason = if was_successful {
            None::<&str>
        } else {
            Some("invalid_password")
        };

        sqlx::query(
            "INSERT INTO login_attempts
                    (user_id, attempted_identifier, was_successful, failure_reason, request_ip, request_user_agent, attempted_at)
                 VALUES ($1, $2, $3, $4::text::login_failure_reason, $5::text::cidr, $6, NOW() - ($7::int * INTERVAL '1 minute'))",
        )
        .bind(Some(user_id))
        .bind(attempted_identifier)
        .bind(was_successful)
        .bind(failure_reason)
        .bind(current_ip)
        .bind(Some("perf-test-agent"))
        .bind(offset % 30)
        .execute(pool)
        .await
        .expect("failed to insert login attempt fixture");
    }
}
