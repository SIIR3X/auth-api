#[path = "bench_support.rs"]
mod bench_support;

use std::{collections::BTreeSet, time::Instant};

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use rust_api::repositories::{
    login_attempt, login_location, session as session_repo, user as user_repo,
};

#[derive(Debug)]
struct SqlSeedData {
    hot_user_id: Uuid,
    hot_email: String,
    hot_username: String,
    hot_session_id: Uuid,
    hot_token_hash: Vec<u8>,
    hot_ip: IpNetwork,
    hot_history_days: i32,
    upsert_country: String,
    upsert_city: String,
    upsert_user_agent: String,
    upsert_ip: IpNetwork,
}

#[derive(Debug, Clone, Serialize)]
struct SqlPlanSummary {
    planning_time_ms: Option<f64>,
    execution_time_ms: Option<f64>,
    shared_hit_blocks: f64,
    shared_read_blocks: f64,
    shared_dirtied_blocks: f64,
    shared_written_blocks: f64,
    node_types: Vec<String>,
    relation_names: Vec<String>,
    index_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SqlScenarioReport {
    name: String,
    description: String,
    iterations: usize,
    warmup_iterations: usize,
    sql: String,
    parameters: Value,
    summary: bench_support::LatencySummary,
    samples_ms: Vec<f64>,
    plan: SqlPlanSummary,
}

#[derive(Debug, Serialize)]
struct SqlBenchmarkReport {
    generated_at_unix: i64,
    notes: Vec<String>,
    scenarios: Vec<SqlScenarioReport>,
}

#[tokio::main]
async fn main() -> Result<()> {
    bench_support::init_tracing_once();

    let iterations = bench_support::env_usize("BENCH_SQL_ITERATIONS", 200);
    let warmup = bench_support::env_usize("BENCH_SQL_WARMUP", 25);
    let admin_url = bench_support::required_admin_database_url()?;
    let report_dir = bench_support::report_section_dir("sql")?;

    let db = bench_support::EphemeralDatabase::create("rust_api_sql_bench", &admin_url).await?;
    let seed = seed_sql_dataset(&db.pool).await?;
    let brute_force_cutoff = OffsetDateTime::now_utc() - time::Duration::minutes(15);
    let consecutive_limit = 10_i64;
    let identifier_limit = 10_i64;
    let ip_limit = 30_i64;

    let scenarios = vec![
        bench_sql_scenario(
            "find_by_identifier_email",
            "Hot login lookup by email identifier on the real runtime query path.",
            user_repo::FIND_BY_EMAIL_SQL,
            json!([seed.hot_email]),
            iterations,
            warmup,
            || async {
                sqlx::query(user_repo::FIND_BY_EMAIL_SQL)
                    .bind(&seed.hot_email)
                    .fetch_optional(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    user_repo::FIND_BY_EMAIL_SQL
                ))
                .bind(&seed.hot_email)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "find_by_identifier_username",
            "Hot login lookup by username identifier on the real runtime query path.",
            user_repo::FIND_BY_USERNAME_SQL,
            json!([seed.hot_username]),
            iterations,
            warmup,
            || async {
                sqlx::query(user_repo::FIND_BY_USERNAME_SQL)
                    .bind(&seed.hot_username)
                    .fetch_optional(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    user_repo::FIND_BY_USERNAME_SQL
                ))
                .bind(&seed.hot_username)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "find_validation_by_id",
            "Session validation lookup on the authenticated request path.",
            session_repo::FIND_VALIDATION_BY_ID_SQL,
            json!([seed.hot_session_id]),
            iterations,
            warmup,
            || async {
                sqlx::query(session_repo::FIND_VALIDATION_BY_ID_SQL)
                    .bind(seed.hot_session_id)
                    .fetch_optional(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    session_repo::FIND_VALIDATION_BY_ID_SQL
                ))
                .bind(seed.hot_session_id)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "find_by_token_hash",
            "Refresh-token lookup by token hash.",
            session_repo::FIND_BY_TOKEN_HASH_SQL,
            json!(["<32-byte token hash>"]),
            iterations,
            warmup,
            || async {
                sqlx::query(session_repo::FIND_BY_TOKEN_HASH_SQL)
                    .bind(&seed.hot_token_hash)
                    .fetch_optional(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    session_repo::FIND_BY_TOKEN_HASH_SQL
                ))
                .bind(&seed.hot_token_hash)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "find_active_by_user",
            "Listing active sessions for the session management screen.",
            session_repo::FIND_ACTIVE_SUMMARY_BY_USER_SQL,
            json!([seed.hot_user_id]),
            iterations,
            warmup,
            || async {
                sqlx::query(session_repo::FIND_ACTIVE_SUMMARY_BY_USER_SQL)
                    .bind(seed.hot_user_id)
                    .fetch_all(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    session_repo::FIND_ACTIVE_SUMMARY_BY_USER_SQL
                ))
                .bind(seed.hot_user_id)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "find_recent_for_risk",
            "Risk-scoring history lookup over recent login locations.",
            login_location::FIND_RECENT_FOR_RISK_SQL,
            json!([seed.hot_user_id, seed.hot_history_days]),
            iterations,
            warmup,
            || async {
                sqlx::query(login_location::FIND_RECENT_FOR_RISK_SQL)
                    .bind(seed.hot_user_id)
                    .bind(seed.hot_history_days)
                    .fetch_all(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    login_location::FIND_RECENT_FOR_RISK_SQL
                ))
                .bind(seed.hot_user_id)
                .bind(seed.hot_history_days)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "count_recent_failures_by_identifier",
            "Brute-force counter by identifier.",
            login_attempt::COUNT_RECENT_FAILURES_BY_IDENTIFIER_SQL,
            json!([
                seed.hot_email,
                brute_force_cutoff.unix_timestamp(),
                identifier_limit
            ]),
            iterations,
            warmup,
            || async {
                sqlx::query(login_attempt::COUNT_RECENT_FAILURES_BY_IDENTIFIER_SQL)
                    .bind(&seed.hot_email)
                    .bind(brute_force_cutoff)
                    .bind(identifier_limit)
                    .fetch_one(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    login_attempt::COUNT_RECENT_FAILURES_BY_IDENTIFIER_SQL
                ))
                .bind(&seed.hot_email)
                .bind(brute_force_cutoff)
                .bind(identifier_limit)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "count_recent_failures_by_ip",
            "Brute-force counter by source IP.",
            login_attempt::COUNT_RECENT_FAILURES_BY_IP_SQL,
            json!([
                seed.hot_ip.to_string(),
                brute_force_cutoff.unix_timestamp(),
                ip_limit
            ]),
            iterations,
            warmup,
            || async {
                sqlx::query(login_attempt::COUNT_RECENT_FAILURES_BY_IP_SQL)
                    .bind(seed.hot_ip)
                    .bind(brute_force_cutoff)
                    .bind(ip_limit)
                    .fetch_one(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    login_attempt::COUNT_RECENT_FAILURES_BY_IP_SQL
                ))
                .bind(seed.hot_ip)
                .bind(brute_force_cutoff)
                .bind(ip_limit)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "count_consecutive_failures_by_user",
            "Consecutive failure counter used by lockout logic.",
            login_attempt::COUNT_CONSECUTIVE_FAILURES_BY_USER_SQL,
            json!([seed.hot_user_id, consecutive_limit]),
            iterations,
            warmup,
            || async {
                sqlx::query(login_attempt::COUNT_CONSECUTIVE_FAILURES_BY_USER_SQL)
                    .bind(seed.hot_user_id)
                    .bind(consecutive_limit)
                    .fetch_one(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    login_attempt::COUNT_CONSECUTIVE_FAILURES_BY_USER_SQL
                ))
                .bind(seed.hot_user_id)
                .bind(consecutive_limit)
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
        bench_sql_scenario(
            "login_location_upsert",
            "Upsert of the login-location tuple after a successful login.",
            login_location::UPSERT_LOGIN_LOCATION_SQL,
            json!([
                seed.hot_user_id,
                seed.upsert_country,
                seed.upsert_city,
                seed.upsert_user_agent,
                seed.upsert_ip.to_string()
            ]),
            iterations / 2,
            warmup / 2,
            || async {
                sqlx::query(login_location::UPSERT_LOGIN_LOCATION_SQL)
                    .bind(seed.hot_user_id)
                    .bind(&seed.upsert_country)
                    .bind(&seed.upsert_city)
                    .bind(&seed.upsert_user_agent)
                    .bind(seed.upsert_ip)
                    .bind(Some(48.8566_f64))
                    .bind(Some(2.3522_f64))
                    .execute(&db.pool)
                    .await?;
                Ok(())
            },
            || async {
                sqlx::query_scalar::<_, Value>(&format!(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
                    login_location::UPSERT_LOGIN_LOCATION_SQL
                ))
                .bind(seed.hot_user_id)
                .bind(&seed.upsert_country)
                .bind(&seed.upsert_city)
                .bind(&seed.upsert_user_agent)
                .bind(seed.upsert_ip)
                .bind(Some(48.8566_f64))
                .bind(Some(2.3522_f64))
                .fetch_one(&db.pool)
                .await
                .map_err(Into::into)
            },
        )
        .await?,
    ];

    let report = SqlBenchmarkReport {
        generated_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
        notes: vec![
            "SQL benchmarks execute against an isolated benchmark database created from migrations.".into(),
            "Each scenario captures both repeated client-side latency and a single EXPLAIN ANALYZE plan in JSON.".into(),
            "Read scenarios use realistic hot-spot rows plus background data; the login_location upsert scenario measures the steady-state update path.".into(),
        ],
        scenarios,
    };

    bench_support::write_json_pretty(&report_dir.join("sql_report.json"), &report)?;
    bench_support::write_markdown(&report_dir.join("sql_report.md"), &render_markdown(&report))?;

    println!(
        "SQL benchmark report written to {}",
        report_dir.join("sql_report.md").display()
    );

    Ok(())
}

async fn seed_sql_dataset(pool: &PgPool) -> Result<SqlSeedData> {
    const BENCH_PASSWORD_HASH: &str =
        "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHlzYWx0$abcdefghijklmnopqrstuv";

    sqlx::query(
        "INSERT INTO users (username, email, password_hash, status, email_verified_at, last_login_at)
         SELECT
            format('bulk_user_%s', gs),
            format('bulk_user_%s@example.com', gs),
            $1,
            'active'::user_status,
            NOW() - ((gs % 30) * INTERVAL '1 day'),
            NOW() - ((gs % 72) * INTERVAL '1 hour')
         FROM generate_series(1, 3000) AS gs",
    )
    .bind(BENCH_PASSWORD_HASH)
    .execute(pool)
    .await
    .context("failed to seed benchmark users")?;

    sqlx::query(
        "INSERT INTO sessions (user_id, session_family_id, expires_at, device_name, token_hash, user_agent)
         SELECT
            u.id,
            u.id,
            NOW() + INTERVAL '30 days',
            format('bulk-device-%s', gs),
            decode(md5(u.id::text || ':' || gs::text) || md5(gs::text || ':' || u.id::text), 'hex'),
            format('bulk-agent/%s', gs)
         FROM (
            SELECT id
            FROM users
            ORDER BY created_at
            LIMIT 1500
         ) AS u
         CROSS JOIN generate_series(1, 4) AS gs",
    )
    .execute(pool)
    .await
    .context("failed to seed benchmark sessions")?;

    sqlx::query(
        "INSERT INTO login_attempts
            (user_id, attempted_identifier, was_successful, failure_reason, request_ip, request_user_agent, attempted_at)
         SELECT
            u.id,
            u.email,
            (gs % 7 = 0),
            CASE WHEN gs % 7 = 0 THEN NULL ELSE 'invalid_password'::login_failure_reason END,
            format('203.0.%s.%s/32', ((u.seq % 200) + 1), ((gs % 200) + 1))::cidr,
            format('bulk-agent/%s', gs % 12),
            NOW() - ((gs % 1440) * INTERVAL '1 minute')
         FROM (
            SELECT id, email, row_number() OVER (ORDER BY created_at) AS seq
            FROM users
            ORDER BY created_at
            LIMIT 1000
         ) AS u
         CROSS JOIN generate_series(1, 12) AS gs",
    )
    .execute(pool)
    .await
    .context("failed to seed benchmark login attempts")?;

    sqlx::query(
        "INSERT INTO login_locations
            (user_id, country, city, user_agent, ip_address, latitude, longitude, last_seen, first_seen)
         SELECT
            u.id,
            format('C%s', gs % 5),
            format('City-%s-%s', u.seq, gs),
            format('bulk-agent/%s', gs % 8),
            format('198.19.%s.%s/32', ((u.seq % 200) + 1), ((gs % 200) + 1))::cidr,
            40.0 + (gs::double precision / 10.0),
            2.0 + (u.seq::double precision / 100.0),
            NOW() - ((gs % 240) * INTERVAL '1 hour'),
            NOW() - (((gs % 240) + 24) * INTERVAL '1 hour')
         FROM (
            SELECT id, row_number() OVER (ORDER BY created_at) AS seq
            FROM users
            ORDER BY created_at
            LIMIT 1000
         ) AS u
         CROSS JOIN generate_series(1, 8) AS gs",
    )
    .execute(pool)
    .await
    .context("failed to seed benchmark login locations")?;

    let hot_email = "hot_login_user@example.com".to_string();
    let hot_username = "hot_login_user".to_string();
    let hot_user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, status, email_verified_at, last_login_at)
         VALUES ($1, $2, $3, 'active', NOW(), NOW())
         RETURNING id",
    )
    .bind(&hot_username)
    .bind(&hot_email)
    .bind(BENCH_PASSWORD_HASH)
    .fetch_one(pool)
    .await
    .context("failed to insert hot benchmark user")?;

    let hot_token_hash = vec![17u8; 32];
    let hot_ip: IpNetwork = "203.0.113.77/32".parse().expect("valid hot ip");
    let hot_session_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sessions
            (user_id, session_family_id, expires_at, ip_address, device_name, token_hash, user_agent)
         VALUES ($1, $2, NOW() + INTERVAL '30 days', $3, 'hot-device', $4, 'hot-agent')
         RETURNING id",
    )
    .bind(hot_user_id)
    .bind(hot_user_id)
    .bind(hot_ip)
    .bind(&hot_token_hash)
    .fetch_one(pool)
    .await
    .context("failed to insert hot benchmark session")?;

    for offset in 0..11 {
        let token_hash = vec![((offset + 21) % 255) as u8; 32];
        sqlx::query(
            "INSERT INTO sessions
                (user_id, session_family_id, expires_at, device_name, token_hash, user_agent)
             VALUES ($1, $2, NOW() + INTERVAL '30 days', $3, $4, $5)",
        )
        .bind(hot_user_id)
        .bind(hot_user_id)
        .bind(format!("hot-device-{offset}"))
        .bind(token_hash)
        .bind(format!("hot-agent/{offset}"))
        .execute(pool)
        .await
        .context("failed to insert additional hot sessions")?;
    }

    sqlx::query(
        "INSERT INTO login_attempts
            (user_id, attempted_identifier, was_successful, failure_reason, request_ip, request_user_agent, attempted_at)
         VALUES
            ($1, $2, TRUE, NULL, $3, 'hot-agent', NOW() - INTERVAL '30 minutes')",
    )
    .bind(hot_user_id)
    .bind(&hot_email)
    .bind(hot_ip)
    .execute(pool)
    .await
    .context("failed to insert hot successful login attempt")?;

    for offset in 0..48 {
        sqlx::query(
            "INSERT INTO login_attempts
                (user_id, attempted_identifier, was_successful, failure_reason, request_ip, request_user_agent, attempted_at)
             VALUES ($1, $2, FALSE, 'invalid_password', $3, 'hot-agent', NOW() - ($4 * INTERVAL '30 seconds'))",
        )
        .bind(hot_user_id)
        .bind(&hot_email)
        .bind(hot_ip)
        .bind(offset)
        .execute(pool)
        .await
        .context("failed to insert hot failed login attempt")?;
    }

    let upsert_country = "FR".to_string();
    let upsert_city = "Paris-Hot".to_string();
    let upsert_user_agent = "hot-risk-agent/1.0".to_string();
    let upsert_ip: IpNetwork = "198.51.100.55/32".parse().expect("valid upsert ip");

    for offset in 0..36 {
        let country = if offset == 0 {
            upsert_country.clone()
        } else {
            "DE".to_string()
        };
        let city = if offset == 0 {
            upsert_city.clone()
        } else {
            format!("City-Hot-{offset}")
        };
        let user_agent = if offset == 0 {
            upsert_user_agent.clone()
        } else {
            format!("hot-agent/{offset}")
        };
        let ip = if offset == 0 {
            upsert_ip
        } else {
            "198.51.100.99/32"
                .parse::<IpNetwork>()
                .expect("valid fallback ip")
        };

        sqlx::query(
            "INSERT INTO login_locations
                (user_id, country, city, user_agent, ip_address, latitude, longitude, last_seen, first_seen)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() - ($8 * INTERVAL '2 hours'), NOW() - (($8 + 24) * INTERVAL '2 hours'))",
        )
        .bind(hot_user_id)
        .bind(country)
        .bind(city)
        .bind(user_agent)
        .bind(ip)
        .bind(Some(48.8566_f64 + (offset as f64 / 100.0)))
        .bind(Some(2.3522_f64 + (offset as f64 / 100.0)))
        .bind(offset)
        .execute(pool)
        .await
        .context("failed to insert hot login location")?;
    }

    sqlx::query("ANALYZE users")
        .execute(pool)
        .await
        .context("failed to analyze users benchmark table")?;
    sqlx::query("ANALYZE sessions")
        .execute(pool)
        .await
        .context("failed to analyze sessions benchmark table")?;
    sqlx::query("ANALYZE login_attempts")
        .execute(pool)
        .await
        .context("failed to analyze login_attempts benchmark table")?;
    sqlx::query("ANALYZE login_locations")
        .execute(pool)
        .await
        .context("failed to analyze login_locations benchmark table")?;

    Ok(SqlSeedData {
        hot_user_id,
        hot_email,
        hot_username,
        hot_session_id,
        hot_token_hash,
        hot_ip,
        hot_history_days: 90,
        upsert_country,
        upsert_city,
        upsert_user_agent,
        upsert_ip,
    })
}

#[allow(clippy::too_many_arguments)]
async fn bench_sql_scenario<MFut, MFn, EFut, EFn>(
    name: &str,
    description: &str,
    sql: &str,
    parameters: Value,
    iterations: usize,
    warmup: usize,
    mut measure: MFn,
    explain: EFn,
) -> Result<SqlScenarioReport>
where
    MFut: std::future::Future<Output = Result<()>>,
    MFn: FnMut() -> MFut,
    EFut: std::future::Future<Output = Result<Value>>,
    EFn: FnOnce() -> EFut,
{
    for _ in 0..warmup {
        measure().await?;
    }

    let started_at = Instant::now();
    let mut latencies = Vec::with_capacity(iterations);
    let mut samples_ms = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let op_started_at = Instant::now();
        measure().await?;
        let elapsed = op_started_at.elapsed();
        samples_ms.push(elapsed.as_secs_f64() * 1000.0);
        latencies.push(elapsed);
    }
    let wall_time = started_at.elapsed();

    let plan_json = explain().await?;
    let plan = summarize_plan(&plan_json);

    Ok(SqlScenarioReport {
        name: name.to_string(),
        description: description.to_string(),
        iterations,
        warmup_iterations: warmup,
        sql: sql.to_string(),
        parameters,
        summary: bench_support::summarize_latencies(&latencies, wall_time),
        samples_ms,
        plan,
    })
}

fn summarize_plan(plan_json: &Value) -> SqlPlanSummary {
    let root = plan_json
        .as_array()
        .and_then(|items| items.first())
        .unwrap_or(plan_json);
    let plan = root.get("Plan").unwrap_or(plan_json);

    let mut node_types = BTreeSet::new();
    let mut relation_names = BTreeSet::new();
    let mut index_names = BTreeSet::new();
    walk_plan(plan, &mut node_types, &mut relation_names, &mut index_names);

    SqlPlanSummary {
        planning_time_ms: root.get("Planning Time").and_then(Value::as_f64),
        execution_time_ms: root.get("Execution Time").and_then(Value::as_f64),
        shared_hit_blocks: sum_plan_metric(plan, "Shared Hit Blocks"),
        shared_read_blocks: sum_plan_metric(plan, "Shared Read Blocks"),
        shared_dirtied_blocks: sum_plan_metric(plan, "Shared Dirtied Blocks"),
        shared_written_blocks: sum_plan_metric(plan, "Shared Written Blocks"),
        node_types: node_types.into_iter().collect(),
        relation_names: relation_names.into_iter().collect(),
        index_names: index_names.into_iter().collect(),
    }
}

fn walk_plan(
    plan: &Value,
    node_types: &mut BTreeSet<String>,
    relation_names: &mut BTreeSet<String>,
    index_names: &mut BTreeSet<String>,
) {
    if let Some(node_type) = plan.get("Node Type").and_then(Value::as_str) {
        node_types.insert(node_type.to_string());
    }
    if let Some(relation_name) = plan.get("Relation Name").and_then(Value::as_str) {
        relation_names.insert(relation_name.to_string());
    }
    if let Some(index_name) = plan.get("Index Name").and_then(Value::as_str) {
        index_names.insert(index_name.to_string());
    }

    if let Some(children) = plan.get("Plans").and_then(Value::as_array) {
        for child in children {
            walk_plan(child, node_types, relation_names, index_names);
        }
    }
}

fn sum_plan_metric(plan: &Value, key: &str) -> f64 {
    let local_value = plan.get(key).and_then(Value::as_f64).unwrap_or_default();
    let children_value = plan
        .get("Plans")
        .and_then(Value::as_array)
        .map(|children| {
            children
                .iter()
                .map(|child| sum_plan_metric(child, key))
                .sum()
        })
        .unwrap_or(0.0);

    local_value + children_value
}

fn render_markdown(report: &SqlBenchmarkReport) -> String {
    let mut out = String::new();
    out.push_str("# SQL Benchmark Report\n\n");
    out.push_str(&format!(
        "- Generated at: `{}`\n\n",
        report.generated_at_unix
    ));
    out.push_str("## Notes\n\n");
    for note in &report.notes {
        out.push_str(&format!("- {note}\n"));
    }
    out.push_str("\n## Scenario Summary\n\n");
    out.push_str("| Scenario | Iterations | p50 ms | p95 ms | Mean ms | Req/s | Indexes |\n");
    out.push_str("| --- | ---: | ---: | ---: | ---: | ---: | --- |\n");
    for scenario in &report.scenarios {
        out.push_str(&format!(
            "| {} | {} | {:.3} | {:.3} | {:.3} | {:.2} | {} |\n",
            scenario.name,
            scenario.iterations,
            scenario.summary.p50_ms,
            scenario.summary.p95_ms,
            scenario.summary.mean_ms,
            scenario.summary.throughput_per_sec,
            if scenario.plan.index_names.is_empty() {
                "none".to_string()
            } else {
                scenario.plan.index_names.join(", ")
            }
        ));
    }
    out.push_str("\n## Scenario Details\n\n");
    for scenario in &report.scenarios {
        out.push_str(&format!("### {}\n\n", scenario.name));
        out.push_str(&format!("{}\n\n", scenario.description));
        out.push_str(&format!(
            "- Iterations: `{}`\n- p50/p95/p99: `{:.3} / {:.3} / {:.3} ms`\n- Mean throughput: `{:.2} req/s`\n- Planning / execution from EXPLAIN: `{:.3?} / {:.3?} ms`\n- Node types: `{}`\n- Relations: `{}`\n- Indexes: `{}`\n- Shared buffers hit/read/dirtied/written: `{:.0} / {:.0} / {:.0} / {:.0}`\n- Parameters: `{}`\n\n```sql\n{}\n```\n\n",
            scenario.iterations,
            scenario.summary.p50_ms,
            scenario.summary.p95_ms,
            scenario.summary.p99_ms,
            scenario.summary.throughput_per_sec,
            scenario.plan.planning_time_ms,
            scenario.plan.execution_time_ms,
            scenario.plan.node_types.join(", "),
            scenario.plan.relation_names.join(", "),
            if scenario.plan.index_names.is_empty() {
                "none".to_string()
            } else {
                scenario.plan.index_names.join(", ")
            },
            scenario.plan.shared_hit_blocks,
            scenario.plan.shared_read_blocks,
            scenario.plan.shared_dirtied_blocks,
            scenario.plan.shared_written_blocks,
            scenario.parameters,
            scenario.sql.trim(),
        ));
    }
    out
}
