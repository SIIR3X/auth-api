#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use postgres::types::ToSql;
use postgres::{Client, Config, Error, NoTls};

pub const MIGRATIONS_DIR: &str = "migrations";
static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);
static TEMPLATE_DB_NAME: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationFile {
    pub file_name: String,
    pub path: PathBuf,
}

pub struct TestDatabase {
    admin_config: Config,
    db_name: String,
    client: Option<Client>,
}

impl TestDatabase {
    pub fn new() -> Option<Self> {
        let database_url = test_database_url()?;
        let base_config = Config::from_str(&database_url)
            .unwrap_or_else(|err| panic!("invalid TEST_DATABASE_URL: {err}"));

        let mut admin_config = base_config.clone();
        if admin_config.get_dbname().is_none() {
            admin_config.dbname("postgres");
        }

        let mut admin = admin_config
            .connect(NoTls)
            .unwrap_or_else(|err| panic!("failed to connect to admin database: {err}"));

        let template_db = ensure_template_database(&admin_config, &base_config);
        let db_name = create_test_database(&mut admin, Some(&template_db));
        drop(admin);

        let mut test_config = base_config;
        test_config.dbname(&db_name);
        let client = test_config
            .connect(NoTls)
            .unwrap_or_else(|err| panic!("failed to connect to test database `{db_name}`: {err}"));

        Some(Self {
            admin_config,
            db_name,
            client: Some(client),
        })
    }

    pub fn client(&mut self) -> &mut Client {
        self.client
            .as_mut()
            .expect("test database client is not available")
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = self.client.take();

        let mut admin = match self.admin_config.connect(NoTls) {
            Ok(client) => client,
            Err(_) => return,
        };

        let terminate_sql = format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}' AND pid <> pg_backend_pid()",
            self.db_name
        );
        let drop_sql = format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", self.db_name);

        let _ = admin.batch_execute(&terminate_sql);
        let _ = admin.batch_execute(&drop_sql);
    }
}

pub fn migration_files() -> Vec<MigrationFile> {
    let mut entries = fs::read_dir(MIGRATIONS_DIR)
        .unwrap_or_else(|err| panic!("failed to read `{MIGRATIONS_DIR}`: {err}"))
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

pub fn migration_sql(file_name: &str) -> String {
    let path = Path::new(MIGRATIONS_DIR).join(file_name);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read migration `{}`: {err}", path.display()))
}

pub fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL").ok()
}

pub fn assert_constraint(err: &Error, expected: &str) {
    let Some(db_error) = err.as_db_error() else {
        panic!("expected database error with constraint `{expected}`, got: {err}");
    };

    let actual = db_error.constraint().unwrap_or("<no constraint>");
    assert_eq!(actual, expected, "unexpected constraint error: {db_error}");
}

pub fn explain_plan(client: &mut Client, sql: &str, params: &[&(dyn ToSql + Sync)]) -> String {
    client
        .batch_execute("SET enable_seqscan = off; SET enable_tidscan = off;")
        .expect("failed to configure planner guardrails for explain");

    let explain_sql = format!("EXPLAIN (COSTS OFF) {sql}");
    let rows = client
        .query(&explain_sql, params)
        .expect("failed to explain query plan");

    rows.into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn assert_plan_contains(plan: &str, needle: &str) {
    assert!(
        plan.contains(needle),
        "expected plan to contain `{needle}`, got:\n{plan}"
    );
}

fn unique_suffix() -> u128 {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH")
        .as_nanos();
    let counter = TEST_DB_COUNTER.fetch_add(1, Ordering::Relaxed) as u128;

    (timestamp << 16) | (counter & 0xffff)
}

fn is_sql_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("sql"))
        .unwrap_or(false)
}

fn create_test_database(admin: &mut Client, template_name: Option<&str>) -> String {
    let mut last_error = None;

    for _attempt in 0..5 {
        let db_name = format!("rust_api_test_{}_{}", std::process::id(), unique_suffix());
        let sql = match template_name {
            Some(template_name) => {
                format!("CREATE DATABASE \"{db_name}\" TEMPLATE \"{template_name}\"")
            }
            None => format!("CREATE DATABASE \"{db_name}\" TEMPLATE template0"),
        };

        match admin.batch_execute(&sql) {
            Ok(()) => return db_name,
            Err(err) => last_error = Some((db_name, err)),
        }
    }

    match last_error {
        Some((db_name, err)) => {
            panic!("failed to create test database `{db_name}` after retries: {err}")
        }
        None => panic!("failed to create test database: no attempts were made"),
    }
}

fn ensure_template_database(admin_config: &Config, base_config: &Config) -> String {
    TEMPLATE_DB_NAME
        .get_or_init(|| {
            let template_db = format!("rust_api_db_template_{}", std::process::id());

            let mut admin = admin_config
                .clone()
                .connect(NoTls)
                .unwrap_or_else(|err| panic!("failed to connect to admin database: {err}"));

            let _ = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS \"{template_db}\" WITH (FORCE)"
            ));
            admin
                .batch_execute(&format!(
                    "CREATE DATABASE \"{template_db}\" TEMPLATE template0"
                ))
                .unwrap_or_else(|err| {
                    panic!("failed to create template database `{template_db}`: {err}")
                });
            drop(admin);

            let mut template_config = base_config.clone();
            template_config.dbname(&template_db);
            let mut template_client = template_config.connect(NoTls).unwrap_or_else(|err| {
                panic!("failed to connect to template database `{template_db}`: {err}")
            });

            apply_migrations(&mut template_client);

            template_db
        })
        .clone()
}

fn apply_migrations(client: &mut Client) {
    for migration in migration_files() {
        let sql = fs::read_to_string(&migration.path).unwrap_or_else(|err| {
            panic!(
                "failed to read migration `{}`: {err}",
                migration.path.display()
            )
        });
        client.batch_execute(&sql).unwrap_or_else(|err| {
            panic!("failed to apply migration `{}`: {err}", migration.file_name)
        });
    }
}
