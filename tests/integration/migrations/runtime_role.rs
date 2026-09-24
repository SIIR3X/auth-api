//! The runtime role of `deploy/db/auth-api-grants.sql` (SEC-48): it reads and
//! writes data, and nothing else. A compromised application or an SQL
//! injection cannot erase the audit trail, alter the schema, or change the
//! permission catalog.

use sqlx::{Connection, PgConnection};
use testkit::TestDb;

const RUNTIME_PASSWORD: &str = "runtime-role-test";

/// The two roles of the grants script, shared by every test database of the
/// cluster (roles are cluster-wide); creating them races between tests.
async fn ensure_roles(db: &TestDb) {
    for statement in [
        "CREATE ROLE auth_api_owner NOLOGIN".to_owned(),
        format!("CREATE ROLE auth_api LOGIN PASSWORD '{RUNTIME_PASSWORD}'"),
    ] {
        if let Err(e) = sqlx::query(&statement).execute(&db.pool).await {
            let duplicate = e
                .as_database_error()
                .and_then(|e| e.code())
                .is_some_and(|code| code == "42710" || code == "23505");
            assert!(duplicate, "{statement}: {e}");
        }
    }
}

async fn runtime_connection(db: &TestDb) -> PgConnection {
    ensure_roles(db).await;
    let grants =
        std::fs::read_to_string(testkit::workspace_path("deploy/db/auth-api-grants.sql")).unwrap();
    sqlx::raw_sql(&grants).execute(&db.pool).await.unwrap();

    let mut url = reqwest::Url::parse(&db.url).unwrap();
    url.set_username("auth_api").unwrap();
    url.set_password(Some(RUNTIME_PASSWORD)).unwrap();
    PgConnection::connect(url.as_str()).await.unwrap()
}

async fn refused(conn: &mut PgConnection, statement: &str) {
    let error = sqlx::raw_sql(statement)
        .execute(&mut *conn)
        .await
        .expect_err(statement);
    let code = error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "{statement} failed otherwise: {error}"
    );
}

#[tokio::test]
async fn the_runtime_role_cannot_erase_the_audit_trail_or_alter_the_schema() {
    let db = TestDb::new().await;
    let mut runtime = runtime_connection(&db).await;

    for statement in [
        "ALTER TABLE audit_log DISABLE TRIGGER ALL",
        "TRUNCATE audit_log",
        "DROP TABLE audit_log_default",
        "UPDATE audit_log SET metadata = '{}'",
        "DELETE FROM audit_log",
        "DELETE FROM audit_log_default",
        "DELETE FROM permissions",
        "UPDATE permissions SET description = 'planted'",
        "DELETE FROM _sqlx_migrations",
        "UPDATE maintenance_floors SET audit_retention_months = 1",
        "CREATE TABLE planted (id INT)",
        "ALTER TABLE users ADD COLUMN planted TEXT",
    ] {
        refused(&mut runtime, statement).await;
    }
}

#[tokio::test]
async fn the_runtime_role_does_everything_the_service_needs() {
    let db = TestDb::new().await;
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash)
         VALUES ('runtime_role', 'runtime.role@example.com', repeat('h', 60)) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let mut runtime = runtime_connection(&db).await;

    // Writes data, the audit log included.
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, ip_address) VALUES ($1, 'login', '203.0.113.9')",
    )
    .bind(user_id)
    .execute(&mut runtime)
    .await
    .unwrap();
    sqlx::query("UPDATE users SET preferred_locale = 'fr' WHERE id = $1")
        .bind(user_id)
        .execute(&mut runtime)
        .await
        .unwrap();

    // Runs the maintenance the service schedules, through the functions that
    // hold the owner's privileges.
    for statement in [
        "SELECT rotate_audit_log_partitions(12, 2)",
        "SELECT coarsen_audit_addresses('0 seconds'::interval, 100)",
        "SELECT purge_unverified_accounts('3650 days'::interval, 100)",
    ] {
        sqlx::raw_sql(statement)
            .execute(&mut runtime)
            .await
            .unwrap_or_else(|e| panic!("{statement}: {e}"));
    }

    // Erases an account: its traces through the function, then the row; the
    // audit entries lose their account through the foreign key.
    sqlx::query("SELECT forget_account_traces($1)")
        .bind(user_id)
        .execute(&mut runtime)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut runtime)
        .await
        .unwrap();
    let orphaned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE user_id IS NULL AND action = 'login'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(orphaned, 1);
}

/// The maintenance functions run with the owner's privileges but keep the
/// owner's floors: the runtime role cannot use them to drop recent audit
/// partitions, coarsen fresh addresses or purge new pending accounts (SEC-63).
#[tokio::test]
async fn the_maintenance_functions_keep_the_owners_floors() {
    let db = TestDb::new().await;
    let three_months_ago: String = sqlx::query_scalar(
        "SELECT to_char(date_trunc('month', NOW()) - INTERVAL '3 months', 'YYYY_MM')",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    sqlx::raw_sql(&format!(
        "CREATE TABLE IF NOT EXISTS audit_log_{three_months_ago} PARTITION OF audit_log
         FOR VALUES FROM (date_trunc('month', NOW()) - INTERVAL '3 months')
         TO (date_trunc('month', NOW()) - INTERVAL '2 months')"
    ))
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO users (username, email, password_hash)
         VALUES ('fresh_pending', 'fresh.pending@example.com', repeat('h', 60))",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let mut runtime = runtime_connection(&db).await;

    sqlx::raw_sql("SELECT rotate_audit_log_partitions(1)")
        .execute(&mut runtime)
        .await
        .unwrap();
    let kept: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("audit_log_{three_months_ago}"))
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(kept, "a partition within the floor was dropped");

    let purged: i32 =
        sqlx::query_scalar("SELECT purge_unverified_accounts('0 seconds'::interval, 10)")
            .fetch_one(&mut runtime)
            .await
            .unwrap();
    assert_eq!(purged, 0, "an account pending for minutes was purged");
}

/// Partitions created after the grants lose UPDATE and DELETE for the runtime
/// role, the lookahead is bounded, and erasing an account's traces deletes
/// the account: none rewrites the audit trail of an account that stays
/// (SEC-71).
#[tokio::test]
async fn the_audit_trail_stays_out_of_the_runtime_roles_reach() {
    let db = TestDb::new().await;
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash)
         VALUES ('trail_keeper', 'trail.keeper@example.com', repeat('h', 60)) RETURNING id",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let mut runtime = runtime_connection(&db).await;

    sqlx::raw_sql("SELECT rotate_audit_log_partitions(12, 1000)")
        .execute(&db.pool)
        .await
        .unwrap();
    let (partitions, writable): (i64, i64) = sqlx::query_as(
        "SELECT count(*),
                count(*) FILTER (WHERE has_table_privilege('auth_api', c.oid, 'UPDATE')
                                    OR has_table_privilege('auth_api', c.oid, 'DELETE'))
         FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
         JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname = 'audit_log'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert!(
        partitions <= 27,
        "{partitions} partitions: the lookahead is bounded"
    );
    assert_eq!(writable, 0, "a partition is writable by the runtime role");

    sqlx::query("SELECT forget_account_traces($1)")
        .bind(user_id)
        .execute(&mut runtime)
        .await
        .unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "the traces go only with the account");
}
