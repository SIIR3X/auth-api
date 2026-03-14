use crate::common::db::TestDatabase;

#[test]
fn audit_log_rotation_function_is_installed() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*)
             FROM pg_proc
             WHERE proname = 'rotate_audit_log_partitions'",
            &[],
        )
        .expect("failed to inspect pg_proc")
        .get(0);

    assert_eq!(count, 1);
}

#[test]
fn audit_log_accepts_valid_insertions() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let count: i64 = db
        .client()
        .query_one(
            "WITH inserted AS (
                INSERT INTO audit_log (action, metadata)
                VALUES ('register', '{\"source\":\"test\"}'::jsonb)
                RETURNING 1
             )
             SELECT COUNT(*) FROM inserted",
            &[],
        )
        .expect("failed to insert audit row")
        .get(0);

    assert_eq!(count, 1);
}

#[test]
fn audit_log_default_partition_exists() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let exists = db
        .client()
        .query_one(
            "SELECT EXISTS (
                SELECT 1
                FROM pg_class
                WHERE relname = 'audit_log_default'
            )",
            &[],
        )
        .expect("failed to check default partition")
        .get::<_, bool>(0);

    assert!(exists);
}

#[test]
fn audit_log_current_month_partition_exists() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let partition_name = db
        .client()
        .query_one(
            "SELECT format(
                'audit_log_%s',
                to_char(date_trunc('month', NOW()), 'YYYY_MM')
             )",
            &[],
        )
        .expect("failed to compute partition name")
        .get::<_, String>(0);

    let exists = db
        .client()
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&partition_name])
        .expect("failed to check monthly partition")
        .get::<_, bool>(0);

    assert!(exists);
}

#[test]
fn audit_log_cron_job_is_registered_when_pg_cron_is_available() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let cron_available = db
        .client()
        .query_one("SELECT to_regclass('cron.job') IS NOT NULL", &[])
        .expect("failed to detect cron.job")
        .get::<_, bool>(0);

    if !cron_available {
        return;
    }

    let count: i64 = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM cron.job WHERE jobname = 'audit_log_partition_rotation'",
            &[],
        )
        .expect("failed to inspect cron jobs")
        .get(0);

    assert_eq!(count, 1);
}

#[test]
fn audit_log_rotation_can_drop_old_partition() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    db.client()
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS audit_log_2000_01
             PARTITION OF audit_log
             FOR VALUES FROM ('2000-01-01') TO ('2000-02-01')",
        )
        .expect("failed to create old partition");

    let exists_before = db
        .client()
        .query_one("SELECT to_regclass('audit_log_2000_01') IS NOT NULL", &[])
        .expect("failed to check old partition existence")
        .get::<_, bool>(0);
    assert!(exists_before);

    db.client()
        .execute("SELECT rotate_audit_log_partitions(6, 0)", &[])
        .expect("failed to rotate audit log partitions");

    let exists_after = db
        .client()
        .query_one("SELECT to_regclass('audit_log_2000_01') IS NOT NULL", &[])
        .expect("failed to check old partition after rotation")
        .get::<_, bool>(0);

    assert!(!exists_after);
}

#[test]
fn audit_log_request_index_exists() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let exists = db
        .client()
        .query_one("SELECT to_regclass('idx_audit_log_request') IS NOT NULL", &[])
        .expect("failed to check request_id index")
        .get::<_, bool>(0);

    assert!(exists);
}

#[test]
fn audit_log_can_group_events_by_request_id() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let request_id = db
        .client()
        .query_one("SELECT gen_random_uuid()", &[])
        .expect("failed to generate request_id")
        .get::<_, uuid::Uuid>(0);

    db.client()
        .execute(
            "INSERT INTO audit_log (request_id, action, metadata)
             VALUES
             ($1, 'register', '{}'::jsonb),
             ($1, 'email_verified', '{}'::jsonb)",
            &[&request_id],
        )
        .expect("failed to insert correlated audit rows");

    let count = db
        .client()
        .query_one(
            "SELECT COUNT(*) FROM audit_log WHERE request_id = $1",
            &[&request_id],
        )
        .expect("failed to load audit rows by request_id")
        .get::<_, i64>(0);

    assert_eq!(count, 2);
}
