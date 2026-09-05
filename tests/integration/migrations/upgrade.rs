//! Upgrading a database that holds data.
//!
//! The migrations from 0020 on were written for a service already deployed at
//! 0019. This test builds that database, fills it the way that version did,
//! applies everything after it, and checks nothing was lost or left
//! inconsistent. Every other test starts from an empty schema.

use std::borrow::Cow;

use sqlx::migrate::Migrator;
use testkit::{TestDb, sql::SAMPLE_PASSWORD_HASH};
use uuid::Uuid;

/// The last migration of the release before the hardening work.
const DEPLOYED_VERSION: i64 = 19;

async fn migrator() -> Migrator {
    Migrator::new(testkit::workspace_path("migrations"))
        .await
        .expect("load migrations")
}

#[tokio::test]
async fn a_populated_database_at_0019_upgrades_without_losing_data() {
    let db = TestDb::empty().await;

    // `migrations` is public for `sqlx::migrate!`; a prefix of it is the
    // deployed release.
    let mut deployed = migrator().await;
    deployed.migrations = Cow::Owned(
        deployed
            .iter()
            .filter(|migration| migration.version <= DEPLOYED_VERSION)
            .cloned()
            .collect(),
    );
    assert_eq!(deployed.iter().count(), DEPLOYED_VERSION as usize);
    deployed.run(&db.pool).await.expect("apply 0001 to 0019");

    // Data as 0019 stored it.
    let mut users = Vec::new();
    for index in 0..2 {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO users (username, email, password_hash, status, email_verified_at)
             VALUES ($1, $2, $3, 'active', NOW()) RETURNING id",
        )
        .bind(format!("deployed_{index}"))
        .bind(format!("deployed{index}@example.com"))
        .bind(SAMPLE_PASSWORD_HASH)
        .fetch_one(&db.pool)
        .await
        .unwrap();
        users.push(id);
    }

    // A session family rotated once: the first row started three days ago.
    let first: (Uuid, Uuid, time::OffsetDateTime) = sqlx::query_as(
        "INSERT INTO sessions (user_id, expires_at, created_at, token_hash)
         VALUES ($1, NOW() + INTERVAL '30 days', NOW() - INTERVAL '3 days', $2)
         RETURNING id, session_family_id, created_at",
    )
    .bind(users[0])
    .bind(vec![1u8; 32])
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let second: Uuid = sqlx::query_scalar(
        "INSERT INTO sessions (user_id, session_family_id, expires_at, created_at, token_hash)
         VALUES ($1, $2, NOW() + INTERVAL '30 days', NOW() - INTERVAL '1 day', $3)
         RETURNING id",
    )
    .bind(users[0])
    .bind(first.1)
    .bind(vec![2u8; 32])
    .fetch_one(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE sessions
         SET revoked_at = NOW() - INTERVAL '1 day', rotated_at = NOW() - INTERVAL '1 day',
             replaced_by_session_id = $2
         WHERE id = $1",
    )
    .bind(first.0)
    .bind(second)
    .execute(&db.pool)
    .await
    .unwrap();
    // A family of its own for the second user.
    sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
         VALUES ($1, NOW() + INTERVAL '30 days', $2)",
    )
    .bind(users[1])
    .bind(vec![3u8; 32])
    .execute(&db.pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified, totp_secret)
         VALUES ($1, 'totp', TRUE, TRUE, 'ciphertext-written-by-0019')",
    )
    .bind(users[1])
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO login_locations (user_id, country, city, user_agent, ip_address)
         VALUES ($1, 'FR', 'Lyon', 'curl/8', '203.0.113.7')",
    )
    .bind(users[0])
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO audit_log (user_id, action) VALUES ($1, 'login')")
        .bind(users[0])
        .execute(&db.pool)
        .await
        .unwrap();

    // The upgrade.
    migrator()
        .await
        .run(&db.pool)
        .await
        .expect("apply the migrations after 0019 to a populated database");

    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(applied, migrator().await.iter().count() as i64);

    let count = |table: &'static str| {
        let pool = db.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(count("users").await, 2);
    assert_eq!(count("sessions").await, 3);
    assert_eq!(count("two_factor_methods").await, 1);
    assert_eq!(count("audit_log").await, 1);

    // 0020: every row of a family inherits the start of its first sign-in.
    let starts: Vec<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT family_created_at FROM sessions WHERE session_family_id = $1")
            .bind(first.1)
            .fetch_all(&db.pool)
            .await
            .unwrap();
    assert_eq!(starts.len(), 2);
    assert!(
        starts.iter().all(|start| *start == first.2),
        "family start not backfilled from the first session: {starts:?}"
    );

    // 0021: the location history is gone, the accounts are not.
    let locations: bool = sqlx::query_scalar("SELECT to_regclass('login_locations') IS NULL")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(locations, "login_locations survived the upgrade");

    // TOTP secrets are carried over untouched: rotation happens in the service.
    let secret: String = sqlx::query_scalar("SELECT totp_secret FROM two_factor_methods")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(secret, "ciphertext-written-by-0019");

    // The upgraded database accepts what the current service writes.
    sqlx::query(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
         VALUES ($1, NOW() + INTERVAL '1 day', $2)",
    )
    .bind(users[1])
    .bind(vec![4u8; 32])
    .execute(&db.pool)
    .await
    .expect("a new session after the upgrade");
}
