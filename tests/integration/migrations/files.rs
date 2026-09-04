use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationFile {
    file_name: String,
    path: PathBuf,
}

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
        "0018_registered_clients.sql",
        "0019_used_totp_codes.sql",
        "0020_session_family_created_at.sql",
        "0021_drop_login_locations.sql",
        "0022_client_registry.sql",
        "0023_authorization_codes.sql",
        "0024_query_performance.sql",
        "0025_encryption_key_rotated.sql",
        "0026_bounded_cleanups.sql",
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

fn migration_files() -> Vec<MigrationFile> {
    let dir = testkit::workspace_path("migrations");
    let mut entries = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("failed to read `{}`: {err}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| is_sql_file(path))
        .map(|path| MigrationFile {
            file_name: path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_else(|| panic!("invalid migration file name: {}", path.display()))
                .to_owned(),
            path,
        })
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    entries
}

fn migration_sql(file_name: &str) -> String {
    let path = testkit::workspace_path("migrations").join(file_name);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read migration `{}`: {err}", path.display()))
}

fn is_sql_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("sql"))
        .unwrap_or(false)
}
