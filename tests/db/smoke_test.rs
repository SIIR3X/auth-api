mod common;

use common::db::{migration_files, migration_sql, test_database_url};

#[test]
fn migrations_are_sorted_and_contiguous() {
    let files = migration_files();
    let names = files
        .iter()
        .map(|file| file.file_name.as_str())
        .collect::<Vec<_>>();

    let expected = vec![
        "0001_extensions.sql",
        "0002_users.sql",
        "0003_roles.sql",
        "0004_permissions.sql",
        "0005_role_permissions.sql",
        "0006_user_roles.sql",
        "0007_sessions.sql",
        "0008_two_factor_methods.sql",
        "0009_email_2fa_codes.sql",
        "0010_email_verification_tokens.sql",
        "0011_password_reset_tokens.sql",
        "0012_recovery_codes.sql",
        "0013_login_attempts.sql",
        "0014_audit_log.sql",
        "0015_login_locations.sql",
        "0016_seed.sql",
        "0017_cleanup_schedule.sql",
    ];

    assert_eq!(names, expected);
}

#[test]
fn critical_migrations_contain_expected_objects() {
    let users_sql = migration_sql("0002_users.sql");
    let sessions_sql = migration_sql("0007_sessions.sql");
    let audit_sql = migration_sql("0014_audit_log.sql");
    let login_attempts_sql = migration_sql("0013_login_attempts.sql");
    let recovery_sql = migration_sql("0012_recovery_codes.sql");

    assert!(users_sql.contains("CREATE TABLE users"));
    assert!(sessions_sql.contains("CREATE TABLE sessions"));
    assert!(sessions_sql.contains("session_family_id"));
    assert!(sessions_sql.contains("revoke_session_family"));
    assert!(audit_sql.contains("PARTITION BY RANGE (created_at)"));
    assert!(audit_sql.contains("idx_audit_log_request"));
    assert!(login_attempts_sql.contains("CREATE TABLE login_attempts"));
    assert!(recovery_sql.contains("CREATE TABLE recovery_codes"));
}

#[test]
fn test_database_url_is_optional_for_now() {
    let _ = test_database_url();
}
