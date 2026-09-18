//! Test databases, cloned from a template migrated once per migration set.
//!
//! The template is named after a fingerprint of `migrations/`. The first test
//! process that needs it builds it under an advisory lock; every later process
//! reuses it until a migration changes. A test then clones it in milliseconds
//! instead of replaying every migration.
//!
//! A test database is dropped with its [`TestDb`]. A process killed before
//! that leaves its database behind: whichever process next takes the template
//! lock drops the databases of processes that no longer exist, and templates of
//! other migration sets once they are a day old.

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, PgConnection, PgPool, postgres::PgPoolOptions};
use tokio::sync::OnceCell;

pub const TEST_DB_PREFIX: &str = "auth_api_t_";
pub const TEMPLATE_PREFIX: &str = "auth_api_tpl_";

/// Templates of another migration set may belong to another checkout running
/// its own suites; they are kept this long.
const STALE_TEMPLATE_SECS: u64 = 24 * 3600;

/// Serializes template builds and sweeps across test processes.
const TEMPLATE_LOCK: i64 = 0x6175_7468_5f74_706c;

static TEMPLATE: OnceCell<String> = OnceCell::const_new();

pub struct TestDb {
    pub pool: PgPool,
    pub name: String,
    /// Connection URL of this database.
    pub url: String,
    admin_url: String,
}

impl TestDb {
    /// A database with every migration applied.
    pub async fn new() -> Self {
        let template = template().await;
        Self::create(&template).await
    }

    /// An empty database, for tests that apply migrations themselves.
    pub async fn empty() -> Self {
        Self::create("template0").await
    }

    async fn create(template: &str) -> Self {
        let admin_url = crate::env::database_url();
        let name = format!(
            "{TEST_DB_PREFIX}{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        );

        let mut admin = connect(&admin_url).await;
        admin
            .execute(format!(r#"CREATE DATABASE "{name}" TEMPLATE "{template}""#).as_str())
            .await
            .unwrap_or_else(|e| panic!("create test database {name}: {e}"));
        let _ = admin.close().await;

        let url = with_database(&admin_url, &name);
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .unwrap_or_else(|e| panic!("connect to test database {name}: {e}"));

        Self {
            pool,
            name,
            url,
            admin_url,
        }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        // Drop runs inside the test's runtime: finish on a thread of its own,
        // and wait for it so the database is gone before the process exits.
        let _ = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                if let Ok(mut admin) = PgConnection::connect(&admin_url).await {
                    drop_database(&mut admin, &name).await;
                }
            });
        })
        .join();
    }
}

/// Name of the migrated template, built on first use.
pub async fn template() -> String {
    TEMPLATE
        .get_or_init(|| async {
            let admin_url = crate::env::database_url();
            let name = format!("{TEMPLATE_PREFIX}{}", migrations_fingerprint());
            let mut admin = connect(&admin_url).await;

            sqlx::query("SELECT pg_advisory_lock($1)")
                .bind(TEMPLATE_LOCK)
                .execute(&mut admin)
                .await
                .expect("take the template lock");

            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
                    .bind(&name)
                    .fetch_one(&mut admin)
                    .await
                    .expect("look up the template");
            if !exists {
                build_template(&mut admin, &admin_url, &name).await;
            }
            sweep(&mut admin, &name).await;

            // Closing the connection releases the lock as well.
            let _ = admin.close().await;
            name
        })
        .await
        .clone()
}

/// Connection to the administrative database of the test server.
pub async fn admin() -> PgConnection {
    connect(&crate::env::database_url()).await
}

/// Apply every migration to `pool`, as the service does at deployment.
pub async fn migrate(pool: &PgPool) {
    sqlx::migrate::Migrator::new(crate::workspace_path("migrations"))
        .await
        .expect("load migrations")
        .run(pool)
        .await
        .expect("apply migrations");
}

/// Assert that `result` failed on the database constraint `expected`.
pub fn assert_constraint<T: std::fmt::Debug>(result: Result<T, sqlx::Error>, expected: &str) {
    match result {
        Ok(value) => {
            panic!("expected a violation of `{expected}`, the statement returned {value:?}")
        }
        Err(sqlx::Error::Database(error)) => assert_eq!(
            error.constraint(),
            Some(expected),
            "unexpected database error: {error}"
        ),
        Err(error) => panic!("expected a violation of `{expected}`, got: {error}"),
    }
}

async fn connect(url: &str) -> PgConnection {
    PgConnection::connect(url)
        .await
        .unwrap_or_else(|e| panic!("connect to the test PostgreSQL server: {e}"))
}

async fn build_template(admin: &mut PgConnection, admin_url: &str, name: &str) {
    let building = format!("{name}_build");
    drop_database(admin, &building).await;
    admin
        .execute(format!(r#"CREATE DATABASE "{building}" TEMPLATE template0"#).as_str())
        .await
        .unwrap_or_else(|e| panic!("create template {building}: {e}"));

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&with_database(admin_url, &building))
        .await
        .expect("connect to the template being built");
    migrate(&pool).await;
    pool.close().await;

    for statement in [
        format!(r#"ALTER DATABASE "{building}" RENAME TO "{name}""#),
        // No session may stay connected to a template, or cloning fails.
        format!(r#"ALTER DATABASE "{name}" WITH IS_TEMPLATE true ALLOW_CONNECTIONS false"#),
        format!(
            r#"COMMENT ON DATABASE "{name}" IS 'auth-api test template, created {}'"#,
            unix_now()
        ),
    ] {
        admin
            .execute(statement.as_str())
            .await
            .unwrap_or_else(|e| panic!("finish template {name}: {e}"));
    }
}

async fn sweep(admin: &mut PgConnection, current_template: &str) {
    let databases: Vec<(String, Option<String>)> = sqlx::query_as(
        r"SELECT datname, shobj_description(oid, 'pg_database') FROM pg_database
          WHERE datname LIKE 'auth\_api\_t\_%' OR datname LIKE 'auth\_api\_tpl\_%'",
    )
    .fetch_all(&mut *admin)
    .await
    .unwrap_or_default();

    for (name, comment) in databases {
        let stale = if let Some(rest) = name.strip_prefix(TEST_DB_PREFIX) {
            rest.split('_')
                .next()
                .and_then(|pid| pid.parse::<u32>().ok())
                .is_some_and(|pid| !process_alive(pid))
        } else if name == current_template {
            false
        } else {
            // Under the lock, no template is being built: a `_build` is left over.
            name.ends_with("_build")
                || template_age(comment.as_deref()).is_none_or(|age| age > STALE_TEMPLATE_SECS)
        };
        if stale {
            drop_database(admin, &name).await;
        }
    }
}

async fn drop_database(admin: &mut PgConnection, name: &str) {
    let _ = admin
        .execute(format!(r#"ALTER DATABASE "{name}" WITH IS_TEMPLATE false"#).as_str())
        .await;
    let _ = admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#).as_str())
        .await;
}

/// Hash of the migration file names and contents.
fn migrations_fingerprint() -> String {
    let dir = crate::workspace_path("migrations");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .collect();
    files.sort();

    let mut hasher = Sha256::new();
    for path in files {
        hasher.update(path.file_name().unwrap().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(std::fs::read(&path).expect("read migration"));
    }
    hasher.finalize()[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn template_age(comment: Option<&str>) -> Option<u64> {
    let created: u64 = comment?.rsplit(' ').next()?.parse().ok()?;
    Some(unix_now().saturating_sub(created))
}

fn process_alive(pid: u32) -> bool {
    let proc = Path::new("/proc");
    // Without procfs, liveness is unknown: keep the database.
    !proc.is_dir() || proc.join(pid.to_string()).exists()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// `url` pointing at database `name`.
pub fn with_database(url: &str, name: &str) -> String {
    let mut parsed = reqwest::Url::parse(url).expect("valid database URL");
    parsed.set_path(&format!("/{name}"));
    parsed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_url_keeps_credentials_and_options() {
        assert_eq!(
            with_database(
                "postgres://u:p@127.0.0.1:5433/postgres?sslmode=disable",
                "x"
            ),
            "postgres://u:p@127.0.0.1:5433/x?sslmode=disable"
        );
    }

    #[test]
    fn template_age_reads_the_creation_comment() {
        let created = unix_now() - 90;
        let age = template_age(Some(&format!("auth-api test template, created {created}")));
        assert!(age.is_some_and(|age| (90..100).contains(&age)));
        assert_eq!(template_age(Some("hand made")), None);
        assert_eq!(template_age(None), None);
    }

    #[test]
    fn own_process_is_alive() {
        assert!(process_alive(std::process::id()));
    }
}
