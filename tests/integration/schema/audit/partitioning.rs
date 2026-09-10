use testkit::TestDb;

#[tokio::test]
async fn audit_log_rotation_function_is_installed() {
    let db = TestDb::new().await;

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
             FROM pg_proc
             WHERE proname = 'rotate_audit_log_partitions'",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to inspect pg_proc");

    assert_eq!(count, 1);
}

#[tokio::test]
async fn audit_log_accepts_valid_insertions() {
    let db = TestDb::new().await;

    let count: i64 = sqlx::query_scalar(
        "WITH inserted AS (
                INSERT INTO audit_log (action, metadata)
                VALUES ('register', '{\"source\":\"test\"}'::jsonb)
                RETURNING 1
             )
             SELECT COUNT(*) FROM inserted",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to insert audit row");

    assert_eq!(count, 1);
}

#[tokio::test]
async fn audit_log_default_partition_exists() {
    let db = TestDb::new().await;

    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
                SELECT 1
                FROM pg_class
                WHERE relname = 'audit_log_default'
            )",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to check default partition");

    assert!(exists);
}

#[tokio::test]
async fn audit_log_current_month_partition_exists() {
    let db = TestDb::new().await;

    let partition_name = sqlx::query_scalar::<_, String>(
        "SELECT format(
                'audit_log_%s',
                to_char(date_trunc('month', NOW()), 'YYYY_MM')
             )",
    )
    .fetch_one(&db.pool)
    .await
    .expect("failed to compute partition name");

    let exists = sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
        .bind(&partition_name)
        .fetch_one(&db.pool)
        .await
        .expect("failed to check monthly partition");

    assert!(exists);
}

#[tokio::test]
async fn retention_is_not_left_to_pg_cron() {
    // pg_cron ran the retention functions with their SQL defaults, ignoring the
    // configured retention; migration 0024 unschedules those jobs so the
    // application task is the only scheduler.
    let db = TestDb::new().await;

    let cron_available =
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('cron.job') IS NOT NULL")
            .fetch_one(&db.pool)
            .await
            .expect("failed to detect cron.job");

    if cron_available {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cron.job
                 WHERE jobname = 'audit_log_partition_rotation' OR jobname LIKE 'cleanup_%'",
        )
        .fetch_one(&db.pool)
        .await
        .expect("failed to inspect cron jobs");
        assert_eq!(count, 0);
        return;
    }

    // Without pg_cron, a stand-in `cron` schema records what the migration asks
    // of it, and the unscheduling block of 0024 runs against it.
    sqlx::raw_sql(
        "CREATE SCHEMA cron;
         CREATE TABLE cron.job (jobname TEXT PRIMARY KEY);
         CREATE FUNCTION cron.unschedule(job_name TEXT) RETURNS BOOLEAN
             LANGUAGE sql AS $$ DELETE FROM cron.job WHERE jobname = job_name RETURNING TRUE $$;
         INSERT INTO cron.job VALUES
             ('audit_log_partition_rotation'), ('cleanup_expired_sessions'),
             ('cleanup_old_login_attempts'), ('cleanup_used_totp_codes'), ('nightly_vacuum');",
    )
    .execute(&db.pool)
    .await
    .expect("failed to install a stand-in pg_cron");

    let migration = std::fs::read_to_string(testkit::workspace_path(
        "migrations/0024_query_performance.sql",
    ))
    .expect("failed to read migration 0024");
    let start = migration
        .find("-- One scheduler.")
        .expect("migration 0024 unschedules the pg_cron jobs");
    sqlx::raw_sql(&migration[start..])
        .execute(&db.pool)
        .await
        .expect("failed to run the unscheduling block");

    let left: Vec<String> = sqlx::query_scalar("SELECT jobname FROM cron.job ORDER BY jobname")
        .fetch_all(&db.pool)
        .await
        .expect("failed to read the remaining jobs");
    assert_eq!(
        left,
        ["nightly_vacuum"],
        "only retention jobs are unscheduled"
    );
}

#[tokio::test]
async fn audit_log_rotation_with_zero_retention_keeps_old_partitions() {
    let db = TestDb::new().await;

    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS audit_log_2001_01
             PARTITION OF audit_log
             FOR VALUES FROM ('2001-01-01') TO ('2001-02-01')",
    )
    .execute(&db.pool)
    .await
    .expect("failed to create old partition");

    sqlx::query("SELECT rotate_audit_log_partitions(0)")
        .execute(&db.pool)
        .await
        .expect("failed to rotate audit log partitions");

    let still_there =
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('audit_log_2001_01') IS NOT NULL")
            .fetch_one(&db.pool)
            .await
            .expect("failed to check old partition after rotation");

    assert!(still_there, "retention 0 means keep forever");
}

#[tokio::test]
async fn audit_log_rotation_can_drop_old_partition() {
    let db = TestDb::new().await;

    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS audit_log_2000_01
             PARTITION OF audit_log
             FOR VALUES FROM ('2000-01-01') TO ('2000-02-01')",
    )
    .execute(&db.pool)
    .await
    .expect("failed to create old partition");

    let exists_before =
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('audit_log_2000_01') IS NOT NULL")
            .fetch_one(&db.pool)
            .await
            .expect("failed to check old partition existence");
    assert!(exists_before);

    sqlx::query("SELECT rotate_audit_log_partitions(6, 0)")
        .execute(&db.pool)
        .await
        .expect("failed to rotate audit log partitions");

    let exists_after =
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('audit_log_2000_01') IS NOT NULL")
            .fetch_one(&db.pool)
            .await
            .expect("failed to check old partition after rotation");

    assert!(!exists_after);
}

/// No route searches the audit log by request id: the index cost every insert
/// 755 MB at 1 million accounts for nothing (migration 0026).
#[tokio::test]
async fn audit_log_request_index_is_dropped() {
    let db = TestDb::new().await;

    let exists =
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('idx_audit_log_request') IS NOT NULL")
            .fetch_one(&db.pool)
            .await
            .expect("failed to check request_id index");

    assert!(!exists);
}

#[tokio::test]
async fn audit_log_can_group_events_by_request_id() {
    let db = TestDb::new().await;

    let request_id = sqlx::query_scalar::<_, uuid::Uuid>("SELECT gen_random_uuid()")
        .fetch_one(&db.pool)
        .await
        .expect("failed to generate request_id");

    sqlx::query(
        "INSERT INTO audit_log (request_id, action, metadata)
             VALUES
             ($1, 'register', '{}'::jsonb),
             ($1, 'email_verified', '{}'::jsonb)",
    )
    .bind(request_id)
    .execute(&db.pool)
    .await
    .expect("failed to insert correlated audit rows");

    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE request_id = $1")
            .bind(request_id)
            .fetch_one(&db.pool)
            .await
            .expect("failed to load audit rows by request_id");

    assert_eq!(count, 2);
}
