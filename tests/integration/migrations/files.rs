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
    assert!(!files.is_empty(), "no migration found");

    for (index, file) in files.iter().enumerate() {
        let name = file.file_name.as_str();
        let (number, label) = name
            .strip_suffix(".sql")
            .and_then(|stem| stem.split_once('_'))
            .unwrap_or_else(|| panic!("`{name}` is not named NNNN_label.sql"));
        assert!(
            number.len() == 4 && number.bytes().all(|b| b.is_ascii_digit()),
            "`{name}` needs a four-digit number"
        );
        assert!(
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "`{name}` needs a snake_case label"
        );
        assert_eq!(
            number.parse::<usize>().unwrap(),
            index + 1,
            "`{name}` breaks the sequence"
        );
    }
}

#[test]
fn critical_migrations_contain_expected_objects() {
    let users_sql = migration_sql("0002_users.sql");
    let sessions_sql = migration_sql("0005_sessions.sql");
    let audit_sql = migration_sql("0010_audit_log.sql");
    let login_attempts_sql = migration_sql("0009_login_attempts.sql");
    let recovery_sql = migration_sql("0007_two_factor.sql");

    assert!(users_sql.contains("CREATE TABLE users"));
    assert!(sessions_sql.contains("CREATE TABLE sessions"));
    assert!(sessions_sql.contains("session_family_id"));
    assert!(sessions_sql.contains("revoke_session_family"));
    assert!(audit_sql.contains("PARTITION BY RANGE (created_at)"));
    assert!(audit_sql.contains("idx_audit_log_user"));
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
