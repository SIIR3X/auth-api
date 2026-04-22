//! Audit-log partition and append-only trigger tests.
//!
//! The `audit_log` table is a PostgreSQL partitioned table managed by the
//! `rotate_audit_log_partitions()` stored function.  These tests verify:
//!   1. Partitions for the current and future months exist after migration.
//!   2. A row inserted with a future date lands in the correct partition.
//!   3. `DELETE` on a committed row is blocked by the append-only trigger.
//!   4. `UPDATE` on a sensitive field is blocked by the append-only trigger.
//!   5. `rotate_audit_log_partitions()` is idempotent.

use crate::common::app::TestApp;

// helpers

/// Ask PostgreSQL to produce the `audit_log_YYYY_MM` partition name for a
/// date offset (in months) from now.
async fn partition_name(app: &TestApp, month_offset: i32) -> String {
    let sql = if month_offset >= 0 {
        format!(
            "SELECT 'audit_log_' || to_char(
                 date_trunc('month', NOW() + INTERVAL '{month_offset} months'),
                 'YYYY_MM')"
        )
    } else {
        let abs = month_offset.unsigned_abs();
        format!(
            "SELECT 'audit_log_' || to_char(
                 date_trunc('month', NOW() - INTERVAL '{abs} months'),
                 'YYYY_MM')"
        )
    };
    sqlx::query_scalar(&sql)
        .fetch_one(&app.db)
        .await
        .expect("failed to compute partition name")
}

// 1. Partitions exist after migration

#[tokio::test]
async fn audit_log_partitions_created_for_current_and_future_months() {
    let app = TestApp::spawn().await;

    let current_partition = partition_name(&app, 0).await;
    let next_partition = partition_name(&app, 1).await;

    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname
         FROM pg_class c
         JOIN pg_inherits i ON i.inhrelid = c.oid
         JOIN pg_class p    ON p.oid = i.inhparent
         WHERE p.relname = 'audit_log'
           AND c.relname ~ '^audit_log_[0-9]{4}_[0-9]{2}$'",
    )
    .fetch_all(&app.db)
    .await
    .expect("failed to query pg_class for audit_log partitions");

    assert!(
        rows.contains(&current_partition),
        "expected partition {current_partition} to exist, found: {rows:?}"
    );
    assert!(
        rows.contains(&next_partition),
        "expected partition {next_partition} to exist, found: {rows:?}"
    );
}

// 2. INSERT future date routes to correct partition

#[tokio::test]
async fn audit_log_insert_future_date_routes_to_correct_partition() {
    let app = TestApp::spawn().await;

    // 6 months ahead - the migration pre-creates 12 months of lookahead.
    let expected_partition = partition_name(&app, 6).await;

    sqlx::query(
        "INSERT INTO audit_log (action, ip_address, metadata, created_at)
         VALUES ('login_failed', '5.6.7.8/32', '{}',
                 date_trunc('month', NOW() + INTERVAL '6 months') + INTERVAL '12 hours')",
    )
    .execute(&app.db)
    .await
    .expect("INSERT into audit_log failed");

    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {expected_partition}
         WHERE action = 'login_failed' AND ip_address = '5.6.7.8/32'"
    ))
    .fetch_one(&app.db)
    .await
    .expect("query on child partition failed");

    assert_eq!(count, 1, "row must land in partition {expected_partition}");
}

// 3. DELETE blocked by append-only trigger

#[tokio::test]
async fn audit_log_delete_blocked_by_trigger() {
    let app = TestApp::spawn().await;

    let row_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO audit_log (action, ip_address, metadata)
         VALUES ('login_failed', '10.0.0.1/32', '{}')
         RETURNING id",
    )
    .fetch_one(&app.db)
    .await
    .expect("INSERT failed");

    let result = sqlx::query("DELETE FROM audit_log WHERE id = $1")
        .bind(row_id)
        .execute(&app.db)
        .await;

    assert!(
        result.is_err(),
        "DELETE on audit_log must be rejected by the append-only trigger"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("append-only"),
        "error must mention 'append-only', got: {err}"
    );
}

// 4. UPDATE blocked by append-only trigger

#[tokio::test]
async fn audit_log_update_blocked_by_trigger() {
    let app = TestApp::spawn().await;

    let row_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO audit_log (action, ip_address, metadata)
         VALUES ('login_failed', '10.0.0.2/32', '{}')
         RETURNING id",
    )
    .fetch_one(&app.db)
    .await
    .expect("INSERT failed");

    // Attempt UPDATE of the ip_address field - must fail.
    let result = sqlx::query("UPDATE audit_log SET ip_address = '9.9.9.9/32' WHERE id = $1")
        .bind(row_id)
        .execute(&app.db)
        .await;

    assert!(
        result.is_err(),
        "UPDATE on audit_log must be rejected by the append-only trigger"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("append-only"),
        "error must mention 'append-only', got: {err}"
    );
}

// 5. rotate_audit_log_partitions() is idempotent

#[tokio::test]
async fn rotate_audit_log_partitions_is_idempotent() {
    let app = TestApp::spawn().await;

    let before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_class c
         JOIN pg_inherits i ON i.inhrelid = c.oid
         JOIN pg_class p    ON p.oid = i.inhparent
         WHERE p.relname = 'audit_log'
           AND c.relname ~ '^audit_log_[0-9]{4}_[0-9]{2}$'",
    )
    .fetch_one(&app.db)
    .await
    .expect("partition count query failed");

    sqlx::query("SELECT rotate_audit_log_partitions()")
        .execute(&app.db)
        .await
        .expect("rotate_audit_log_partitions() failed on second call");

    let after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_class c
         JOIN pg_inherits i ON i.inhrelid = c.oid
         JOIN pg_class p    ON p.oid = i.inhparent
         WHERE p.relname = 'audit_log'
           AND c.relname ~ '^audit_log_[0-9]{4}_[0-9]{2}$'",
    )
    .fetch_one(&app.db)
    .await
    .expect("partition count query failed");

    assert_eq!(
        before, after,
        "rotate_audit_log_partitions() must be idempotent: before={before} after={after}"
    );
}
