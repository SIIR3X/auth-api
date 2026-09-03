//! Performance harness driven by `perf/run.sh`.
//!
//! Subcommands, every option given as `--name value`:
//!
//! - `hash`: print an Argon2id hash of `PERF_PASSWORD` with production parameters.
//! - `migrate`: apply `migrations/` to `DATABASE_URL`.
//! - `http`: closed-loop HTTP load against `BASE_URL`
//!   (`--scenario --concurrency --duration --warmup --users --label --out`).
//! - `db`: the application's own repository queries against `DATABASE_URL`, one
//!   pool connection per virtual user (same options).
//! - `explain`: query plans, relation sizes and cache ratio (`--users --label --out`).
//! - `cleanup`: time batches of the retention jobs (`--label --out`).
//! - `statements reset` / `statements dump`: `pg_stat_statements` snapshot.
//!
//! Users and sessions are addressed through the identifiers `perf/seed.sql`
//! derives from the user index. Results are appended to `--out`, one JSON object
//! per line, and turned into the report by `perf/report.py`.
//!
//! Environment: `BASE_URL`, `DATABASE_URL`, `APP_PUBLIC_URL`, `JWT_PRIVATE_KEY`,
//! `JWT_PUBLIC_KEY`, `PERF_PASSWORD`, `PERF_CPU_GROUPS`
//! (`postgres=0-2;cache=3;api=4-6;load=7`).

use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    net::IpAddr,
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use ipnetwork::IpNetwork;
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use time::OffsetDateTime;
use uuid::Uuid;

use auth_api::{
    config::CryptoConfig,
    domain::{audit::AuditAction, session::SessionType},
    repositories::{
        audit::{self, NewAuditEntry},
        login_attempt::{self, NewLoginAttempt},
        recovery_code, role,
        session::{self as session_repo, NewSession},
        two_factor as tf_repo, user as user_repo,
    },
    utils::{crypto, jwt, password},
};

// Arguments

struct Args(HashMap<String, String>);

impl Args {
    fn parse(raw: &[String]) -> Result<Self> {
        let mut map = HashMap::new();
        let mut it = raw.iter();
        while let Some(key) = it.next() {
            let name = key
                .strip_prefix("--")
                .ok_or_else(|| anyhow!("unexpected argument {key}"))?;
            let value = it.next().ok_or_else(|| anyhow!("--{name} needs a value"))?;
            map.insert(name.to_owned(), value.clone());
        }
        Ok(Self(map))
    }

    fn str(&self, name: &str) -> Result<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("missing --{name}"))
    }

    fn num<T: FromStr>(&self, name: &str) -> Result<T> {
        self.str(name)?
            .parse()
            .map_err(|_| anyhow!("--{name} must be a number"))
    }
}

fn env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

// Deterministic identifiers (mirrors perf/seed.sql)

fn perf_uuid(seed: &str) -> Uuid {
    let digest = crypto::sha256(seed.as_bytes());
    Uuid::from_slice(&digest[..16]).expect("16 bytes")
}

fn user_id(i: u64) -> Uuid {
    perf_uuid(&format!("perf-user-{i}"))
}

fn email(i: u64) -> String {
    format!("perf{i}@example.com")
}

/// Users without a second factor: a password sign-in completes for them.
fn is_single_factor(i: u64) -> bool {
    !i.is_multiple_of(5) && i % 20 != 1
}

// Random numbers without shared state

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn user(&mut self, users: u64) -> u64 {
        1 + self.below(users)
    }

    fn single_factor_user(&mut self, users: u64) -> u64 {
        loop {
            let i = self.user(users);
            if is_single_factor(i) {
                return i;
            }
        }
    }

    /// Client address from a pool of 262 144, so per-address budgets stay
    /// spread as they are with real traffic.
    fn client_ip(&mut self) -> String {
        format!(
            "100.{}.{}.{}",
            64 + self.below(4),
            self.below(256),
            1 + self.below(254)
        )
    }
}

// Latency histogram: 10 µs buckets below 1 ms, then 1 % wide buckets

const LINEAR_BUCKETS: usize = 100;
const BUCKETS: usize = LINEAR_BUCKETS + 1_200;

#[derive(Clone)]
struct Histogram {
    counts: Vec<u64>,
    total: u64,
    sum_us: u128,
    max_us: u64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            counts: vec![0; BUCKETS],
            total: 0,
            sum_us: 0,
            max_us: 0,
        }
    }

    fn index(us: u64) -> usize {
        if us < 1_000 {
            (us / 10) as usize
        } else {
            let i = LINEAR_BUCKETS + ((us as f64 / 1_000.0).ln() / 1.01f64.ln()) as usize;
            i.min(BUCKETS - 1)
        }
    }

    fn upper_us(index: usize) -> f64 {
        if index < LINEAR_BUCKETS {
            ((index + 1) * 10) as f64
        } else {
            1_000.0 * 1.01f64.powi((index - LINEAR_BUCKETS + 1) as i32)
        }
    }

    fn record(&mut self, elapsed: Duration) {
        let us = elapsed.as_micros() as u64;
        self.counts[Self::index(us)] += 1;
        self.total += 1;
        self.sum_us += u128::from(us);
        self.max_us = self.max_us.max(us);
    }

    fn merge(&mut self, other: &Histogram) {
        for (a, b) in self.counts.iter_mut().zip(&other.counts) {
            *a += b;
        }
        self.total += other.total;
        self.sum_us += other.sum_us;
        self.max_us = self.max_us.max(other.max_us);
    }

    fn percentile_ms(&self, p: f64) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let target = ((p / 100.0) * self.total as f64).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (i, count) in self.counts.iter().enumerate() {
            seen += count;
            if seen >= target {
                return (Self::upper_us(i).min(self.max_us as f64)) / 1_000.0;
            }
        }
        self.max_us as f64 / 1_000.0
    }

    fn summary(&self) -> Value {
        let mean = if self.total == 0 {
            0.0
        } else {
            self.sum_us as f64 / self.total as f64 / 1_000.0
        };
        json!({
            "mean": round3(mean),
            "p50": round3(self.percentile_ms(50.0)),
            "p90": round3(self.percentile_ms(90.0)),
            "p95": round3(self.percentile_ms(95.0)),
            "p99": round3(self.percentile_ms(99.0)),
            "p999": round3(self.percentile_ms(99.9)),
            "max": round3(self.max_us as f64 / 1_000.0),
        })
    }
}

fn round3(v: f64) -> f64 {
    (v * 1_000.0).round() / 1_000.0
}

// Per-operation results

enum Outcome {
    Ok,
    Status(u16),
    Failed,
}

#[derive(Clone)]
struct OpStats {
    latency: Histogram,
    ok: u64,
    errors: BTreeMap<String, u64>,
}

struct Recorder {
    measure_from: Instant,
    ops: BTreeMap<&'static str, OpStats>,
}

impl Recorder {
    fn new(measure_from: Instant) -> Self {
        Self {
            measure_from,
            ops: BTreeMap::new(),
        }
    }

    fn record(&mut self, op: &'static str, started: Instant, outcome: Outcome) {
        if started < self.measure_from {
            return;
        }
        let stats = self.ops.entry(op).or_insert_with(|| OpStats {
            latency: Histogram::new(),
            ok: 0,
            errors: BTreeMap::new(),
        });
        stats.latency.record(started.elapsed());
        match outcome {
            Outcome::Ok => stats.ok += 1,
            Outcome::Status(code) => *stats.errors.entry(code.to_string()).or_default() += 1,
            Outcome::Failed => *stats.errors.entry("failed".into()).or_default() += 1,
        }
    }

    fn merge(&mut self, other: Recorder) {
        for (op, stats) in other.ops {
            match self.ops.get_mut(op) {
                Some(mine) => {
                    mine.latency.merge(&stats.latency);
                    mine.ok += stats.ok;
                    for (k, v) in stats.errors {
                        *mine.errors.entry(k).or_default() += v;
                    }
                }
                None => {
                    self.ops.insert(op, stats);
                }
            }
        }
    }

    fn report(&self, duration: Duration) -> Value {
        let secs = duration.as_secs_f64();
        let mut total = Histogram::new();
        let mut ok = 0;
        let mut errors: BTreeMap<String, u64> = BTreeMap::new();
        let mut ops = serde_json::Map::new();
        for (op, stats) in &self.ops {
            total.merge(&stats.latency);
            ok += stats.ok;
            for (k, v) in &stats.errors {
                *errors.entry(k.clone()).or_default() += v;
            }
            ops.insert(
                (*op).to_owned(),
                json!({
                    "requests": stats.latency.total,
                    "ok": stats.ok,
                    "rps": round3(stats.latency.total as f64 / secs),
                    "errors": stats.errors,
                    "latency_ms": stats.latency.summary(),
                }),
            );
        }
        json!({
            "requests": total.total,
            "ok": ok,
            "rps": round3(total.total as f64 / secs),
            "error_rate": if total.total == 0 { 0.0 } else { round3((total.total - ok) as f64 / total.total as f64) },
            "errors": errors,
            "latency_ms": total.summary(),
            "operations": ops,
        })
    }
}

// System and database counters over the measurement window

fn cpu_times() -> Result<Vec<(u64, u64, u64)>> {
    let stat = std::fs::read_to_string("/proc/stat")?;
    let mut cpus = Vec::new();
    for line in stat.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let fields: Vec<u64> = rest
            .split_whitespace()
            .skip(1)
            .filter_map(|f| f.parse().ok())
            .collect();
        let total: u64 = fields.iter().take(8).sum();
        let idle = fields.get(3).copied().unwrap_or(0);
        let iowait = fields.get(4).copied().unwrap_or(0);
        cpus.push((total, total - idle - iowait, iowait));
    }
    Ok(cpus)
}

fn cpu_groups() -> Vec<(String, Vec<usize>)> {
    let spec = std::env::var("PERF_CPU_GROUPS")
        .unwrap_or_else(|_| "postgres=0-2;cache=3;api=4-6;load=7".into());
    spec.split(';')
        .filter_map(|group| {
            let (name, cpus) = group.split_once('=')?;
            let mut list = Vec::new();
            for part in cpus.split(',') {
                match part.split_once('-') {
                    Some((a, b)) => {
                        list.extend(a.parse::<usize>().ok()?..=b.parse::<usize>().ok()?)
                    }
                    None => list.push(part.parse().ok()?),
                }
            }
            Some((name.to_owned(), list))
        })
        .collect()
}

fn cpu_report(before: &[(u64, u64, u64)], after: &[(u64, u64, u64)]) -> Value {
    let mut report = serde_json::Map::new();
    for (name, cpus) in cpu_groups() {
        let (mut busy, mut iowait) = (0.0, 0.0);
        for cpu in cpus {
            let (Some(b), Some(a)) = (before.get(cpu), after.get(cpu)) else {
                continue;
            };
            let total = (a.0 - b.0).max(1) as f64;
            busy += (a.1 - b.1) as f64 / total;
            iowait += (a.2 - b.2) as f64 / total;
        }
        report.insert(
            name,
            json!({ "cores_busy": round3(busy), "cores_iowait": round3(iowait) }),
        );
    }
    Value::Object(report)
}

async fn db_counters(pool: &PgPool) -> Result<[i64; 6]> {
    let row = sqlx::query(
        "SELECT xact_commit, blks_hit, blks_read, tup_inserted, tup_fetched,
                (blk_read_time + blk_write_time)::bigint
         FROM pg_stat_database WHERE datname = current_database()",
    )
    .fetch_one(pool)
    .await?;
    Ok([
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
    ])
}

fn db_report(before: [i64; 6], after: [i64; 6], duration: Duration) -> Value {
    let secs = duration.as_secs_f64();
    let d = |i: usize| (after[i] - before[i]) as f64;
    let blocks = d(1) + d(2);
    json!({
        "commits_per_sec": round3(d(0) / secs),
        "cache_hit_ratio": if blocks == 0.0 { 1.0 } else { round3(d(1) / blocks) },
        "blocks_read_per_sec": round3(d(2) / secs),
        "rows_inserted_per_sec": round3(d(3) / secs),
        "rows_fetched_per_sec": round3(d(4) / secs),
        "io_time_ms_per_sec": round3(d(5) / secs),
    })
}

fn append_line(path: &str, value: &Value) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open {path}"))?;
    writeln!(file, "{value}")?;
    Ok(())
}

async fn stats_pool() -> Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .connect(&env("DATABASE_URL")?)
        .await?)
}

// HTTP load

#[derive(Clone, Copy)]
enum Op {
    Profile,
    Sessions,
    Audit,
    TwoFactor,
    Refresh,
    Login,
    Register,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Profile => "profile",
            Op::Sessions => "sessions",
            Op::Audit => "audit",
            Op::TwoFactor => "two_factor",
            Op::Refresh => "refresh",
            Op::Login => "login",
            Op::Register => "register",
        }
    }
}

/// Share of each operation in the `mixed` scenario, in percent. Refreshes
/// dominate: resource servers verify access tokens offline, so an auth API
/// mostly sees refreshes, then account pages, then sign-ins.
const MIXED: [(Op, u64); 7] = [
    (Op::Refresh, 50),
    (Op::Profile, 20),
    (Op::Sessions, 10),
    (Op::Audit, 5),
    (Op::TwoFactor, 5),
    (Op::Login, 8),
    (Op::Register, 2),
];

struct HttpCtx {
    client: reqwest::Client,
    base: String,
    users: u64,
    password: String,
    tokens: Vec<String>,
    run: String,
    scenario: String,
}

struct Vu {
    id: usize,
    rng: Rng,
    refresh_token: Option<String>,
    counter: u64,
}

fn needs_refresh_chain(scenario: &str) -> bool {
    matches!(scenario, "refresh" | "mixed")
}

fn needs_tokens(scenario: &str) -> bool {
    matches!(
        scenario,
        "profile" | "sessions" | "audit" | "two_factor" | "mixed"
    )
}

fn mint_tokens(count: usize, users: u64) -> Result<Vec<String>> {
    let public_url = env("APP_PUBLIC_URL")?;
    let private = env("JWT_PRIVATE_KEY")?.replace("\\n", "\n");
    let public = env("JWT_PUBLIC_KEY")?.replace("\\n", "\n");
    let key = jwt::parse_encoding_key(&private)?;
    let kid = jwt::compute_kid(&jwt::parse_p256_verifying_key(&public)?);
    let exp = OffsetDateTime::now_utc().unix_timestamp() + 4 * 3600;
    let mut rng = Rng::new(0xC0FFEE);
    (0..count)
        .map(|_| {
            let i = rng.user(users);
            let mut claims = jwt::Claims::new(
                user_id(i),
                perf_uuid(&format!("perf-session-{i}-1")),
                exp - 4 * 3600,
                exp,
            );
            // Issued a moment ago: `nbf` is checked without leeway.
            claims.nbf = Some(claims.iat - 60);
            claims.iss = Some(public_url.clone());
            claims.aud = vec![public_url.clone()];
            Ok(jwt::encode_token(&claims, &key, Some(&kid))?)
        })
        .collect()
}

async fn login(ctx: &HttpCtx, vu: &mut Vu) -> (Outcome, Option<String>) {
    let i = vu.rng.single_factor_user(ctx.users);
    let res = ctx
        .client
        .post(format!("{}/auth/login", ctx.base))
        .header("x-forwarded-for", vu.rng.client_ip())
        .json(&json!({ "identifier": email(i), "password": ctx.password, "device_name": "perf" }))
        .send()
        .await;
    match res {
        Ok(res) if res.status().as_u16() == 200 => match res.json::<Value>().await {
            Ok(body) => match body["refresh_token"].as_str() {
                Some(token) => (Outcome::Ok, Some(token.to_owned())),
                None => (Outcome::Status(299), None),
            },
            Err(_) => (Outcome::Failed, None),
        },
        Ok(res) => {
            let code = res.status().as_u16();
            let _ = res.bytes().await;
            (Outcome::Status(code), None)
        }
        Err(_) => (Outcome::Failed, None),
    }
}

async fn expect(res: reqwest::Result<reqwest::Response>, status: u16) -> Outcome {
    match res {
        Ok(res) => {
            let code = res.status().as_u16();
            let _ = res.bytes().await;
            if code == status {
                Outcome::Ok
            } else {
                Outcome::Status(code)
            }
        }
        Err(_) => Outcome::Failed,
    }
}

async fn step(ctx: &HttpCtx, vu: &mut Vu, op: Op) -> Outcome {
    let ip = vu.rng.client_ip();
    let token = || {
        ctx.tokens[vu.id.wrapping_mul(7_919).wrapping_add(vu.counter as usize) % ctx.tokens.len()]
            .clone()
    };
    match op {
        Op::Profile | Op::Sessions | Op::Audit | Op::TwoFactor => {
            let path = match op {
                Op::Profile => "/users/me",
                Op::Sessions => "/users/me/sessions",
                Op::Audit => "/users/me/audit?limit=50",
                _ => "/users/me/two-factor",
            };
            let res = ctx
                .client
                .get(format!("{}{path}", ctx.base))
                .bearer_auth(token())
                .header("x-forwarded-for", ip)
                .send()
                .await;
            expect(res, 200).await
        }
        Op::Refresh => {
            let Some(current) = vu.refresh_token.clone() else {
                return Outcome::Failed;
            };
            let res = ctx
                .client
                .post(format!("{}/auth/refresh", ctx.base))
                .header("x-forwarded-for", ip)
                .json(&json!({ "refresh_token": current }))
                .send()
                .await;
            match res {
                Ok(res) if res.status().as_u16() == 200 => match res.json::<Value>().await {
                    Ok(body) => {
                        vu.refresh_token = body["refresh_token"].as_str().map(str::to_owned);
                        Outcome::Ok
                    }
                    Err(_) => Outcome::Failed,
                },
                other => {
                    vu.refresh_token = None;
                    expect(other, 200).await
                }
            }
        }
        Op::Login => login(ctx, vu).await.0,
        Op::Register => {
            vu.counter += 1;
            let name = format!("r{}_{}_{}", ctx.run, vu.id, vu.counter);
            let res = ctx
                .client
                .post(format!("{}/auth/register", ctx.base))
                .header("x-forwarded-for", ip)
                .json(&json!({
                    "username": name,
                    "email": format!("{name}@example.com"),
                    "password": ctx.password,
                    "locale": "en",
                }))
                .send()
                .await;
            expect(res, 202).await
        }
    }
}

async fn http_vu(ctx: Arc<HttpCtx>, mut vu: Vu, measure_from: Instant, end: Instant) -> Recorder {
    let mut recorder = Recorder::new(measure_from);
    while Instant::now() < end {
        let op = match ctx.scenario.as_str() {
            "mixed" => {
                let mut roll = vu.rng.below(100);
                MIXED
                    .iter()
                    .find(|(_, weight)| {
                        if roll < *weight {
                            true
                        } else {
                            roll -= weight;
                            false
                        }
                    })
                    .map(|(op, _)| *op)
                    .unwrap_or(Op::Refresh)
            }
            "profile" => Op::Profile,
            "sessions" => Op::Sessions,
            "audit" => Op::Audit,
            "two_factor" => Op::TwoFactor,
            "refresh" => Op::Refresh,
            "login" => Op::Login,
            _ => Op::Register,
        };
        vu.counter += 1;
        let started = Instant::now();
        let outcome = step(&ctx, &mut vu, op).await;
        recorder.record(op.name(), started, outcome);
        // A broken refresh chain is re-established outside the measurement.
        if matches!(op, Op::Refresh) && vu.refresh_token.is_none() {
            vu.refresh_token = login(&ctx, &mut vu).await.1;
        }
    }
    recorder
}

async fn run_http(args: &Args) -> Result<()> {
    let scenario = args.str("scenario")?.to_owned();
    let concurrency: usize = args.num("concurrency")?;
    let duration = Duration::from_secs(args.num("duration")?);
    let warmup = Duration::from_secs(args.num("warmup")?);
    let users: u64 = args.num("users")?;
    let token_pool = users.min(100_000) as usize;

    let tokens = if needs_tokens(&scenario) {
        mint_tokens(token_pool, users)?
    } else {
        Vec::new()
    };
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(concurrency)
        .tcp_nodelay(true)
        .timeout(Duration::from_secs(60))
        .build()?;
    let ctx = Arc::new(HttpCtx {
        client,
        base: env("BASE_URL")?,
        users,
        password: env("PERF_PASSWORD")?,
        tokens,
        run: format!(
            "{:06x}",
            OffsetDateTime::now_utc().unix_timestamp() % 0xFF_FFFF
        ),
        scenario: scenario.clone(),
    });

    // Every virtual user signs in once before the clock starts, when its
    // scenario needs a refresh token of its own.
    let mut vus = Vec::with_capacity(concurrency);
    let preflight_started = Instant::now();
    let mut preflight = Vec::with_capacity(concurrency);
    for id in 0..concurrency {
        let ctx = ctx.clone();
        let scenario = scenario.clone();
        preflight.push(tokio::spawn(async move {
            let mut vu = Vu {
                id,
                rng: Rng::new(id as u64 + 1 + ctx.run.len() as u64 * 7_777),
                refresh_token: None,
                counter: 0,
            };
            if needs_refresh_chain(&scenario) {
                for _ in 0..3 {
                    vu.refresh_token = login(&ctx, &mut vu).await.1;
                    if vu.refresh_token.is_some() {
                        break;
                    }
                }
            }
            vu
        }));
    }
    for handle in preflight {
        vus.push(handle.await?);
    }
    let preflight_secs = preflight_started.elapsed().as_secs_f64();

    let stats = stats_pool().await.ok();
    let start = Instant::now();
    let measure_from = start + warmup;
    let end = measure_from + duration;
    let handles: Vec<_> = vus
        .into_iter()
        .map(|vu| tokio::spawn(http_vu(ctx.clone(), vu, measure_from, end)))
        .collect();

    tokio::time::sleep_until(measure_from.into()).await;
    let cpu_before = cpu_times()?;
    let db_before = match &stats {
        Some(pool) => db_counters(pool).await.ok(),
        None => None,
    };
    tokio::time::sleep_until(end.into()).await;
    let cpu_after = cpu_times()?;
    let db_after = match &stats {
        Some(pool) => db_counters(pool).await.ok(),
        None => None,
    };

    let mut recorder = Recorder::new(measure_from);
    for handle in handles {
        recorder.merge(handle.await?);
    }

    let mut line = recorder.report(duration);
    let obj = line.as_object_mut().expect("object");
    obj.insert("kind".into(), json!("http"));
    obj.insert("label".into(), json!(args.str("label")?));
    obj.insert("users".into(), json!(users));
    obj.insert("scenario".into(), json!(scenario));
    obj.insert("concurrency".into(), json!(concurrency));
    obj.insert("duration_secs".into(), json!(duration.as_secs()));
    obj.insert("preflight_secs".into(), json!(round3(preflight_secs)));
    obj.insert("cpu".into(), cpu_report(&cpu_before, &cpu_after));
    if let (Some(b), Some(a)) = (db_before, db_after) {
        obj.insert("db".into(), db_report(b, a, duration));
    }
    append_line(args.str("out")?, &line)?;
    println!(
        "http {scenario:<11} c={concurrency:<4} rps={:<10} p50={:<8} p99={:<8} errors={}",
        line["rps"], line["latency_ms"]["p50"], line["latency_ms"]["p99"], line["errors"]
    );
    Ok(())
}

// Database benchmark

async fn db_step(pool: &PgPool, scenario: &str, rng: &mut Rng, users: u64) -> Result<()> {
    let i = rng.user(users);
    let uid = user_id(i);
    let cutoff = OffsetDateTime::now_utc() - time::Duration::minutes(15);
    match scenario {
        "user_by_email" => {
            user_repo::find_by_identifier(pool, &email(i)).await?;
        }
        "session_by_token" => {
            let hash = crypto::sha256(format!("perf-rt-{i}-1").as_bytes());
            session_repo::find_by_token_hash(pool, &hash).await?;
        }
        "session_validation" => {
            session_repo::find_validation_by_id(pool, perf_uuid(&format!("perf-session-{i}-1")))
                .await?;
        }
        "active_sessions" => {
            session_repo::find_active_summary_by_user(pool, uid).await?;
        }
        "failures_by_identifier" => {
            login_attempt::count_recent_failures_by_identifier(pool, &email(i), cutoff, 10).await?;
        }
        "failures_by_ip" => {
            let ip: IpNetwork = format!("10.{}.{}.20/32", i % 250, (i / 250) % 250).parse()?;
            login_attempt::count_recent_failures_by_ip(pool, ip, cutoff, 30).await?;
        }
        "consecutive_failures" => {
            login_attempt::count_consecutive_failures_by_user(pool, uid, 10).await?;
        }
        "rbac" => {
            role::find_rbac_names(pool, uid).await?;
        }
        "audit_page" => {
            audit::find_page_by_user(pool, uid, None, 51).await?;
        }
        "two_factor_overview" => {
            tokio::try_join!(
                tf_repo::find_by_user(pool, uid),
                recovery_code::count_usable_by_user(pool, uid),
            )?;
        }
        "sign_in_write" => {
            // The four writes of a completed sign-in, in one transaction.
            let token_hash = crypto::sha256(Uuid::new_v4().as_bytes());
            let ip: IpNetwork = IpAddr::from([100, 64, (i % 256) as u8, 1]).into();
            let mut tx = pool.begin().await?;
            session_repo::create(
                &mut *tx,
                &NewSession {
                    user_id: uid,
                    session_family_id: Uuid::new_v4(),
                    expires_at: OffsetDateTime::now_utc() + time::Duration::days(1),
                    ip_address: Some(ip),
                    device_name: Some("perf"),
                    remember_me: false,
                    token_hash: &token_hash,
                    user_agent: Some("perf_load"),
                    session_type: SessionType::Web,
                    client_id: None,
                    family_created_at: None,
                    scopes: None,
                },
            )
            .await?;
            user_repo::record_sign_in(&mut *tx, uid).await?;
            login_attempt::record(
                &mut *tx,
                &NewLoginAttempt {
                    user_id: Some(uid),
                    attempted_identifier: &email(i),
                    was_successful: true,
                    failure_reason: None,
                    request_ip: Some(ip),
                    request_user_agent: None,
                },
            )
            .await?;
            audit::append(
                &mut *tx,
                &NewAuditEntry {
                    user_id: Some(uid),
                    request_id: None,
                    action: AuditAction::Login,
                    ip_address: Some(ip),
                    metadata: json!({}),
                },
            )
            .await?;
            tx.commit().await?;
        }
        other => bail!("unknown db scenario {other}"),
    }
    Ok(())
}

async fn run_db(args: &Args) -> Result<()> {
    let scenario = args.str("scenario")?.to_owned();
    let concurrency: usize = args.num("concurrency")?;
    let duration = Duration::from_secs(args.num("duration")?);
    let warmup = Duration::from_secs(args.num("warmup")?);
    let users: u64 = args.num("users")?;

    let pool = PgPoolOptions::new()
        .min_connections(concurrency as u32)
        .max_connections(concurrency as u32)
        .connect(&env("DATABASE_URL")?)
        .await?;
    let stats = stats_pool().await?;

    let start = Instant::now();
    let measure_from = start + warmup;
    let end = measure_from + duration;
    let handles: Vec<_> = (0..concurrency)
        .map(|id| {
            let pool = pool.clone();
            let scenario = scenario.clone();
            tokio::spawn(async move {
                let mut rng = Rng::new(id as u64 + 99);
                let mut recorder = Recorder::new(measure_from);
                while Instant::now() < end {
                    let started = Instant::now();
                    let outcome = match db_step(&pool, &scenario, &mut rng, users).await {
                        Ok(()) => Outcome::Ok,
                        Err(_) => Outcome::Failed,
                    };
                    recorder.record("query", started, outcome);
                }
                recorder
            })
        })
        .collect();

    tokio::time::sleep_until(measure_from.into()).await;
    let cpu_before = cpu_times()?;
    let db_before = db_counters(&stats).await?;
    tokio::time::sleep_until(end.into()).await;
    let cpu_after = cpu_times()?;
    let db_after = db_counters(&stats).await?;

    let mut recorder = Recorder::new(measure_from);
    for handle in handles {
        recorder.merge(handle.await?);
    }
    let mut line = recorder.report(duration);
    let obj = line.as_object_mut().expect("object");
    obj.insert("kind".into(), json!("db"));
    obj.insert("label".into(), json!(args.str("label")?));
    obj.insert("users".into(), json!(users));
    obj.insert("scenario".into(), json!(scenario));
    obj.insert("concurrency".into(), json!(concurrency));
    obj.insert("duration_secs".into(), json!(duration.as_secs()));
    obj.insert("cpu".into(), cpu_report(&cpu_before, &cpu_after));
    obj.insert("db".into(), db_report(db_before, db_after, duration));
    append_line(args.str("out")?, &line)?;
    println!(
        "db   {scenario:<22} c={concurrency:<3} qps={:<10} p50={:<8} p99={:<8} errors={}",
        line["rps"], line["latency_ms"]["p50"], line["latency_ms"]["p99"], line["errors"]
    );
    Ok(())
}

// Plans, sizes, retention

fn walk_plan(node: &Value, out: &mut Vec<String>) {
    let mut label = node["Node Type"].as_str().unwrap_or("?").to_owned();
    if let Some(index) = node["Index Name"].as_str() {
        label.push_str(&format!(" using {index}"));
    } else if let Some(relation) = node["Relation Name"].as_str() {
        label.push_str(&format!(" on {relation}"));
    }
    out.push(label);
    if let Some(children) = node["Plans"].as_array() {
        for child in children {
            walk_plan(child, out);
        }
    }
}

async fn explain_query(pool: &PgPool, name: &str, sql: &str, i: u64) -> Result<Value> {
    let uid = user_id(i);
    let cutoff = OffsetDateTime::now_utc() - time::Duration::minutes(15);
    let explain = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}");
    let mut timings = Vec::new();
    let mut last = Value::Null;
    for _ in 0..7 {
        let q = sqlx::query_scalar::<_, Value>(&explain);
        let q = match name {
            "user_by_email" | "failures_by_identifier" => {
                let q = q.bind(email(i));
                if name == "failures_by_identifier" {
                    q.bind(cutoff).bind(10i64)
                } else {
                    q
                }
            }
            "session_by_token" => {
                q.bind(crypto::sha256(format!("perf-rt-{i}-1").as_bytes()).to_vec())
            }
            "session_validation" => q.bind(perf_uuid(&format!("perf-session-{i}-1"))),
            "failures_by_ip" => {
                let ip: IpNetwork = format!("10.{}.{}.20/32", i % 250, (i / 250) % 250).parse()?;
                q.bind(ip).bind(cutoff).bind(30i64)
            }
            "consecutive_failures" => q.bind(uid).bind(10i64),
            "audit_page" => q.bind(uid).bind(51i64),
            _ => q.bind(uid),
        };
        last = q
            .fetch_one(pool)
            .await
            .with_context(|| format!("explain {name}"))?;
        timings.push(last[0]["Execution Time"].as_f64().unwrap_or(0.0));
    }
    timings.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    let root = &last[0];
    let mut nodes = Vec::new();
    walk_plan(&root["Plan"], &mut nodes);
    Ok(json!({
        "query": name,
        "execution_ms_median": round3(timings[timings.len() / 2]),
        "planning_ms": root["Planning Time"],
        "shared_hit_blocks": root["Plan"]["Shared Hit Blocks"],
        "shared_read_blocks": root["Plan"]["Shared Read Blocks"],
        "rows": root["Plan"]["Actual Rows"],
        "nodes": nodes,
    }))
}

async fn run_explain(args: &Args) -> Result<()> {
    let users: u64 = args.num("users")?;
    let pool = stats_pool().await?;
    // A single-factor user in the middle of the index range.
    let mut i = users / 2;
    while !is_single_factor(i) {
        i += 1;
    }
    let queries: [(&str, String); 11] = [
        ("user_by_email", user_repo::FIND_BY_EMAIL_SQL.into()),
        ("session_by_token", session_repo::FIND_BY_TOKEN_HASH_SQL.into()),
        ("session_validation", session_repo::FIND_VALIDATION_BY_ID_SQL.into()),
        ("active_sessions", session_repo::FIND_ACTIVE_SUMMARY_BY_USER_SQL.into()),
        ("failures_by_identifier", login_attempt::COUNT_RECENT_FAILURES_BY_IDENTIFIER_SQL.into()),
        ("failures_by_ip", login_attempt::COUNT_RECENT_FAILURES_BY_IP_SQL.into()),
        ("consecutive_failures", login_attempt::COUNT_CONSECUTIVE_FAILURES_BY_USER_SQL.into()),
        (
            "rbac",
            "SELECT COALESCE(ARRAY(SELECT r.name::TEXT FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 ORDER BY r.name), '{}'), COALESCE(ARRAY(SELECT DISTINCT p.name FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id JOIN permissions p ON p.id = rp.permission_id WHERE ur.user_id = $1 ORDER BY p.name), '{}')".into(),
        ),
        (
            "audit_page",
            "SELECT * FROM audit_log WHERE user_id = $1 AND created_at <= NOW() ORDER BY created_at DESC, id DESC LIMIT $2".into(),
        ),
        (
            "two_factor_methods",
            "SELECT * FROM two_factor_methods WHERE user_id = $1 ORDER BY created_at".into(),
        ),
        (
            "recovery_codes_usable",
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())".into(),
        ),
    ];
    let mut plans = Vec::new();
    for (name, sql) in &queries {
        plans.push(explain_query(&pool, name, sql, i).await?);
    }

    let relations: Vec<Value> = sqlx::query(
        "SELECT c.relname,
                CASE WHEN c.relkind = 'p'
                     THEN (SELECT COALESCE(SUM(s.n_live_tup), 0) FROM pg_partition_tree(c.oid) t
                           JOIN pg_stat_user_tables s ON s.relid = t.relid)
                     ELSE (SELECT n_live_tup FROM pg_stat_user_tables WHERE relid = c.oid) END::bigint,
                CASE WHEN c.relkind = 'p'
                     THEN (SELECT SUM(pg_relation_size(t.relid)) FROM pg_partition_tree(c.oid) t)
                     ELSE pg_relation_size(c.oid) END::bigint,
                CASE WHEN c.relkind = 'p'
                     THEN (SELECT SUM(pg_indexes_size(t.relid)) FROM pg_partition_tree(c.oid) t)
                     ELSE pg_indexes_size(c.oid) END::bigint
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition",
    )
    .fetch_all(&pool)
    .await?
    .into_iter()
    .map(|r| {
        json!({
            "relation": r.get::<String, _>(0),
            "rows": r.get::<Option<i64>, _>(1),
            "table_bytes": r.get::<Option<i64>, _>(2),
            "index_bytes": r.get::<Option<i64>, _>(3),
        })
    })
    .collect();

    let indexes: Vec<Value> = sqlx::query(
        "SELECT indexrelname::text, relname::text, pg_relation_size(indexrelid), idx_scan
         FROM pg_stat_user_indexes ORDER BY pg_relation_size(indexrelid) DESC LIMIT 25",
    )
    .fetch_all(&pool)
    .await?
    .into_iter()
    .map(|r| {
        json!({
            "index": r.get::<String, _>(0),
            "relation": r.get::<String, _>(1),
            "bytes": r.get::<i64, _>(2),
            "scans": r.get::<i64, _>(3),
        })
    })
    .collect();

    let database_bytes: i64 = sqlx::query_scalar("SELECT pg_database_size(current_database())")
        .fetch_one(&pool)
        .await?;
    let settings: Vec<Value> = sqlx::query(
        "SELECT name, setting, unit FROM pg_settings WHERE name IN
         ('shared_buffers','effective_cache_size','work_mem','fsync','synchronous_commit',
          'full_page_writes','max_wal_size','random_page_cost','max_connections','server_version')",
    )
    .fetch_all(&pool)
    .await?
    .into_iter()
    .map(|r| json!({ "name": r.get::<String, _>(0), "setting": r.get::<String, _>(1), "unit": r.get::<Option<String>, _>(2) }))
    .collect();

    let line = json!({
        "kind": "explain",
        "label": args.str("label")?,
        "users": users,
        "sample_user": i,
        "database_bytes": database_bytes,
        "plans": plans,
        "relations": relations,
        "indexes": indexes,
        "settings": settings,
    });
    append_line(args.str("out")?, &line)?;
    println!(
        "explain users={users} database={} MB",
        database_bytes / 1_048_576
    );
    Ok(())
}

async fn run_cleanup(args: &Args) -> Result<()> {
    let pool = stats_pool().await?;
    let jobs = [
        (
            "sessions",
            "SELECT cleanup_expired_sessions('7 days'::interval, 5000)",
        ),
        (
            "login_attempts",
            "SELECT cleanup_old_login_attempts('90 days'::interval, 5000)",
        ),
        (
            "email_verification_tokens",
            "SELECT cleanup_expired_email_verification_tokens('1 day'::interval, 5000)",
        ),
        (
            "password_reset_tokens",
            "SELECT cleanup_expired_password_reset_tokens('1 day'::interval, 5000)",
        ),
    ];
    let mut results = Vec::new();
    for (name, sql) in jobs {
        for batch in 1..=3 {
            let started = Instant::now();
            let deleted: i32 = sqlx::query_scalar(sql).fetch_one(&pool).await?;
            results.push(json!({
                "job": name,
                "batch": batch,
                "deleted": deleted,
                "ms": round3(started.elapsed().as_secs_f64() * 1_000.0),
            }));
        }
    }
    let started = Instant::now();
    sqlx::query("SELECT rotate_audit_log_partitions(12)")
        .execute(&pool)
        .await?;
    results.push(json!({
        "job": "rotate_audit_log_partitions",
        "batch": 1,
        "deleted": 0,
        "ms": round3(started.elapsed().as_secs_f64() * 1_000.0),
    }));
    append_line(
        args.str("out")?,
        &json!({ "kind": "cleanup", "label": args.str("label")?, "users": args.num::<u64>("users")?, "batches": results }),
    )?;
    println!("cleanup done");
    Ok(())
}

async fn run_statements(action: &str, args: &Args) -> Result<()> {
    let pool = stats_pool().await?;
    match action {
        "reset" => {
            sqlx::query("SELECT pg_stat_statements_reset()")
                .execute(&pool)
                .await?;
        }
        "dump" => {
            let rows: Vec<Value> = sqlx::query(
                "SELECT left(regexp_replace(query, '\\s+', ' ', 'g'), 240), calls,
                        total_exec_time, mean_exec_time, stddev_exec_time, rows,
                        shared_blks_hit, shared_blks_read
                 FROM pg_stat_statements
                 WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                 ORDER BY total_exec_time DESC LIMIT 20",
            )
            .fetch_all(&pool)
            .await?
            .into_iter()
            .map(|r| {
                json!({
                    "query": r.get::<String, _>(0),
                    "calls": r.get::<i64, _>(1),
                    "total_ms": round3(r.get::<f64, _>(2)),
                    "mean_ms": round3(r.get::<f64, _>(3)),
                    "stddev_ms": round3(r.get::<f64, _>(4)),
                    "rows": r.get::<i64, _>(5),
                    "shared_hit": r.get::<i64, _>(6),
                    "shared_read": r.get::<i64, _>(7),
                })
            })
            .collect();
            append_line(
                args.str("out")?,
                &json!({
                    "kind": "statements",
                    "label": args.str("label")?,
                    "users": args.num::<u64>("users")?,
                    "context": args.str("context")?,
                    "statements": rows,
                }),
            )?;
        }
        other => bail!("statements {other}: expected reset or dump"),
    }
    Ok(())
}

// Entry point

#[tokio::main]
async fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = argv.first() else {
        bail!("usage: perf_load hash|migrate|http|db|explain|cleanup|statements ...");
    };
    match command.as_str() {
        "hash" => {
            let crypto_cfg = CryptoConfig {
                argon2_memory_kib: 65_536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
                argon2_max_concurrency: 1,
                totp_issuer: "perf".into(),
                encryption_key: String::new(),
                previous_encryption_key: None,
                totp_skew: 1,
                recovery_code_expiry_days: 365,
            };
            println!("{}", password::hash(&env("PERF_PASSWORD")?, &crypto_cfg)?);
        }
        "migrate" => {
            let pool = stats_pool().await?;
            sqlx::migrate::Migrator::new(Path::new("migrations"))
                .await?
                .run(&pool)
                .await?;
            println!("migrations applied");
        }
        "http" => run_http(&Args::parse(&argv[1..])?).await?,
        "db" => run_db(&Args::parse(&argv[1..])?).await?,
        "explain" => run_explain(&Args::parse(&argv[1..])?).await?,
        "cleanup" => run_cleanup(&Args::parse(&argv[1..])?).await?,
        "statements" => {
            let action = argv
                .get(1)
                .ok_or_else(|| anyhow!("statements reset|dump"))?;
            run_statements(action, &Args::parse(&argv[2..])?).await?
        }
        other => bail!("unknown command {other}"),
    }
    Ok(())
}
