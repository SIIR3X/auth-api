#[path = "bench_support.rs"]
mod bench_support;

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use base64::Engine;
use deadpool_redis::redis::AsyncCommands;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use rust_api::{
    repositories::{
        email_2fa as email_2fa_repo,
        user::{self as user_repo, NewUser},
    },
    services::{email_2fa, two_factor},
    state::AppState,
    utils::{crypto, password, time as time_utils},
};

#[derive(Debug, Clone)]
struct Credential {
    user_id: Uuid,
    email: String,
    username: String,
    password: String,
}

#[derive(Debug, Clone)]
struct TotpCredential {
    credential: Credential,
    base32_secret: String,
}

#[derive(Debug, Clone)]
struct Email2faCredential {
    credential: Credential,
}

#[derive(Debug, Clone)]
struct Tokens {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug)]
struct HttpOutcome {
    status: u16,
    ok: bool,
    error: Option<String>,
}

#[derive(Debug)]
struct HttpObservation {
    latency: Duration,
    status: u16,
    ok: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct HttpScenarioReport {
    name: String,
    description: String,
    concurrency: usize,
    iterations_per_worker: usize,
    warmup_per_worker: usize,
    total_requests: usize,
    success_count: usize,
    failure_count: usize,
    status_histogram: BTreeMap<String, usize>,
    summary: bench_support::LatencySummary,
    samples_ms: Vec<f64>,
    failure_examples: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HttpBenchmarkReport {
    generated_at_unix: i64,
    base_url: String,
    concurrency: usize,
    iterations_per_worker: usize,
    warmup_per_worker: usize,
    notes: Vec<String>,
    scenarios: Vec<HttpScenarioReport>,
}

#[derive(Debug)]
struct BenchmarkDataset {
    login_users: Vec<Credential>,
    username_login_users: Vec<Credential>,
    wrong_password_users: Vec<Credential>,
    forgot_password_users: Vec<Credential>,
    refresh_users: Vec<Credential>,
    profile_users: Vec<Credential>,
    session_users: Vec<Credential>,
    reauth_users: Vec<Credential>,
    locale_users: Vec<Credential>,
    email_2fa_users: Vec<Email2faCredential>,
    totp_users: Vec<TotpCredential>,
    logout_users: Vec<Credential>,
    change_password_users: Vec<Credential>,
    revoke_session_users: Vec<Credential>,
    email_change_start_users: Vec<Credential>,
    email_change_full_users: Vec<Credential>,
}

static REGISTER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Fixed OTP code injected directly into Redis flow state for email-change benchmarks.
/// Bypasses the real OTP generation so we don't need a mail server or brute-force.
const BENCH_EMAIL_CHANGE_OTP: &str = "987654";

#[tokio::main]
async fn main() -> Result<()> {
    bench_support::init_tracing_once();

    let concurrency = bench_support::env_usize("BENCH_HTTP_CONCURRENCY", 8);
    let base_iterations = bench_support::env_usize("BENCH_HTTP_ITERATIONS", 16);
    let warmup = bench_support::env_usize("BENCH_HTTP_WARMUP", 3);

    let admin_url = bench_support::required_admin_database_url()?;
    let redis_url = bench_support::benchmark_redis_url();
    let report_dir = bench_support::report_section_dir("http")?;

    let db = bench_support::EphemeralDatabase::create("rust_api_http_bench", &admin_url).await?;
    let state = bench_support::build_state(&db.db_url, &redis_url, db.pool.clone()).await?;
    let dataset = seed_dataset(&state, concurrency).await?;
    let (base_url, client) = bench_support::spawn_app(state.clone()).await?;

    let mut scenarios = vec![
        bench_register(
            &base_url,
            &client,
            concurrency,
            scaled(base_iterations, 1, 2),
            warmup,
        )
        .await?,
        bench_login_success_email(
            &base_url,
            &client,
            dataset.login_users.clone(),
            scaled(base_iterations, 1, 1),
            warmup,
        )
        .await?,
        bench_login_success_username(
            &base_url,
            &client,
            dataset.username_login_users.clone(),
            scaled(base_iterations, 1, 1),
            warmup,
        )
        .await?,
        bench_login_wrong_password(
            &base_url,
            &client,
            state.clone(),
            dataset.wrong_password_users.clone(),
            scaled(base_iterations, 1, 1),
            warmup,
        )
        .await?,
    ];
    // Purge any residual login_attempts so the brute-force counters
    // (MAX_FAILURES_BY_IP = 30) don't bleed into subsequent scenarios
    // that need successful logins from 127.0.0.1.
    sqlx::query("DELETE FROM login_attempts")
        .execute(&state.db)
        .await
        .context("failed to purge login_attempts between scenarios")?;
    let scenarios2 = vec![
        bench_forgot_password(
            &base_url,
            &client,
            state.clone(),
            dataset.forgot_password_users.clone(),
            scaled(base_iterations, 3, 4),
            warmup,
        )
        .await?,
        bench_refresh(
            &base_url,
            &client,
            dataset.refresh_users.clone(),
            scaled(base_iterations, 1, 1),
            warmup,
        )
        .await?,
        bench_get_profile(
            &base_url,
            &client,
            dataset.profile_users.clone(),
            scaled(base_iterations, 2, 1),
            warmup,
        )
        .await?,
        bench_list_sessions(
            &base_url,
            &client,
            dataset.session_users.clone(),
            scaled(base_iterations, 3, 2),
            warmup,
        )
        .await?,
        bench_reauthenticate(
            &base_url,
            &client,
            dataset.reauth_users.clone(),
            scaled(base_iterations, 3, 4),
            warmup,
        )
        .await?,
        bench_change_locale(
            &base_url,
            &client,
            dataset.locale_users.clone(),
            scaled(base_iterations, 1, 1),
            warmup,
        )
        .await?,
        bench_email_2fa_challenge(
            &base_url,
            &client,
            state.clone(),
            dataset.email_2fa_users.clone(),
            scaled(base_iterations, 3, 4),
            warmup,
        )
        .await?,
        bench_email_2fa_complete(
            &base_url,
            &client,
            state.clone(),
            dataset.email_2fa_users.clone(),
            scaled(base_iterations, 1, 2),
            warmup,
        )
        .await?,
        bench_totp_challenge(
            &base_url,
            &client,
            dataset.totp_users.clone(),
            scaled(base_iterations, 3, 4),
            warmup,
        )
        .await?,
        bench_totp_complete(
            &base_url,
            &client,
            state.clone(),
            dataset.totp_users.clone(),
            scaled(base_iterations, 1, 2),
            warmup,
        )
        .await?,
        bench_logout(
            &base_url,
            &client,
            dataset.logout_users.clone(),
            scaled(base_iterations, 1, 1),
            warmup,
        )
        .await?,
        bench_change_password(
            &base_url,
            &client,
            dataset.change_password_users.clone(),
            // Argon2 is expensive - fewer iterations keep the bench fast while still sampling well.
            scaled(base_iterations, 1, 2),
            warmup,
        )
        .await?,
        bench_revoke_session(
            &base_url,
            &client,
            dataset.revoke_session_users.clone(),
            scaled(base_iterations, 2, 1),
            warmup,
        )
        .await?,
        bench_email_change_start(
            &base_url,
            &client,
            state.clone(),
            dataset.email_change_start_users.clone(),
            scaled(base_iterations, 3, 4),
            warmup,
        )
        .await?,
        bench_email_change_full(
            &base_url,
            &client,
            state.clone(),
            dataset.email_change_full_users.clone(),
            // Full 4-step pipeline - fewer iterations; each measures end-to-end flow latency.
            scaled(base_iterations, 1, 4).max(4),
            warmup,
        )
        .await?,
    ];
    scenarios.extend(scenarios2);

    let report = HttpBenchmarkReport {
        generated_at_unix: ::time::OffsetDateTime::now_utc().unix_timestamp(),
        base_url: base_url.clone(),
        concurrency,
        iterations_per_worker: base_iterations,
        warmup_per_worker: warmup,
        notes: vec![
            "HTTP benchmarks run against a real Axum server with Postgres and Redis.".into(),
            "Rate limits, CAPTCHA, and lockout thresholds are relaxed in benchmark mode to keep steady-state scenarios repeatable.".into(),
            "Email 2FA cooldown keys and TOTP anti-replay keys are cleared between iterations so challenge completion can be measured repeatedly.".into(),
            "logout: sessions are pre-created before the timed region so each iteration measures only the revocation path.".into(),
            "change_password: measures Argon2 rehash + session revocation; current_password is threaded through iterations.".into(),
            "revoke_session: extra sessions are pre-created before the timed region; DELETE latency is measured in isolation.".into(),
            "email_change_full: OTPs are injected directly into Redis flow state - no mail server required; includes all 4 HTTP round-trips.".into(),
        ],
        scenarios,
    };

    bench_support::write_json_pretty(&report_dir.join("http_report.json"), &report)?;
    bench_support::write_markdown(
        &report_dir.join("http_report.md"),
        &render_markdown(&report),
    )?;

    println!(
        "HTTP benchmark report written to {}",
        report_dir.join("http_report.md").display()
    );

    Ok(())
}

async fn seed_dataset(state: &AppState, concurrency: usize) -> Result<BenchmarkDataset> {
    Ok(BenchmarkDataset {
        login_users: create_credentials(state, "login", concurrency).await?,
        username_login_users: create_credentials(state, "login_username", concurrency).await?,
        wrong_password_users: create_credentials(state, "wrong_password", concurrency).await?,
        forgot_password_users: create_credentials(state, "forgot_password", concurrency).await?,
        refresh_users: create_credentials(state, "refresh", concurrency).await?,
        profile_users: create_credentials(state, "profile", concurrency).await?,
        session_users: create_credentials(state, "sessions", concurrency).await?,
        reauth_users: create_credentials(state, "reauth", concurrency).await?,
        locale_users: create_credentials(state, "locale", concurrency).await?,
        email_2fa_users: create_email_2fa_credentials(state, "email2fa", concurrency).await?,
        totp_users: create_totp_credentials(state, "totp", concurrency).await?,
        logout_users: create_credentials(state, "logout", concurrency).await?,
        change_password_users: create_credentials(state, "change_pw", concurrency).await?,
        revoke_session_users: create_credentials(state, "revoke_session", concurrency).await?,
        email_change_start_users: create_credentials(state, "email_change_start", concurrency)
            .await?,
        email_change_full_users: create_credentials(state, "email_change_full", concurrency)
            .await?,
    })
}

async fn create_credentials(
    state: &AppState,
    prefix: &str,
    count: usize,
) -> Result<Vec<Credential>> {
    let mut users = Vec::with_capacity(count);
    for index in 0..count {
        users.push(create_active_user(state, prefix, index).await?);
    }
    Ok(users)
}

async fn create_email_2fa_credentials(
    state: &AppState,
    prefix: &str,
    count: usize,
) -> Result<Vec<Email2faCredential>> {
    let mut users = Vec::with_capacity(count);
    for index in 0..count {
        let credential = create_active_user(state, prefix, index).await?;
        let method_id = email_2fa::setup(state, credential.user_id)
            .await
            .map_err(|error| {
                anyhow::anyhow!("failed to setup Email 2FA for benchmark user: {error:?}")
            })?;
        let known_code = format!("{:06}", 100_000 + index as u32);
        let hash = crypto::sha256(known_code.as_bytes());

        email_2fa_repo::create(
            &state.db,
            &email_2fa_repo::NewEmail2faCode {
                user_id: credential.user_id,
                code_hash: &hash,
                expires_at: time_utils::in_secs(600),
            },
        )
        .await?;

        let _ = email_2fa::verify_setup(state, credential.user_id, method_id, &known_code, None)
            .await
            .map_err(|error| {
                anyhow::anyhow!("failed to verify Email 2FA benchmark setup: {error:?}")
            })?;
        users.push(Email2faCredential { credential });
    }
    Ok(users)
}

async fn create_totp_credentials(
    state: &AppState,
    prefix: &str,
    count: usize,
) -> Result<Vec<TotpCredential>> {
    let mut users = Vec::with_capacity(count);
    for index in 0..count {
        let credential = create_active_user(state, prefix, index).await?;
        let setup = two_factor::setup_totp(state, credential.user_id)
            .await
            .map_err(|error| anyhow::anyhow!("failed to setup TOTP benchmark method: {error:?}"))?;
        let code = current_totp_code(&setup.base32_secret)?;
        let _ = two_factor::verify_setup(state, credential.user_id, setup.method_id, &code, None)
            .await
            .map_err(|error| anyhow::anyhow!("failed to verify TOTP benchmark setup: {error:?}"))?;

        users.push(TotpCredential {
            credential,
            base32_secret: setup.base32_secret,
        });
    }
    Ok(users)
}

async fn create_active_user(state: &AppState, prefix: &str, index: usize) -> Result<Credential> {
    let username = format!("{prefix}_{index}");
    let email = format!("{prefix}_{index}@example.com");
    let password_value = format!("BenchPass!{prefix}_{index}");

    let password_hash = password::hash(&password_value, &state.config.crypto)
        .context("failed to hash benchmark password")?;
    let user = user_repo::create(
        &state.db,
        &NewUser {
            username: &username,
            email: &email,
            password_hash: &password_hash,
            preferred_locale: "en",
        },
    )
    .await
    .context("failed to insert benchmark user")?;

    user_repo::mark_email_verified(&state.db, user.id)
        .await
        .context("failed to activate benchmark user")?;

    Ok(Credential {
        user_id: user.id,
        email,
        username,
        password: password_value,
    })
}

async fn bench_register(
    base_url: &str,
    client: &reqwest::Client,
    concurrency: usize,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();

    run_http_scenario(
        "register",
        "User registration including Argon2 hashing and verification token creation.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            async move {
                run_worker_loop(worker_id, warmup, iterations, (), move |_, _| {
                    let base_url = base_url.clone();
                    let client = client.clone();
                    boxed_http(async move {
                        let unique = REGISTER_COUNTER.fetch_add(1, Ordering::Relaxed);
                        let body = json!({
                            "username": format!("bench_register_{unique}"),
                            "email": format!("bench_register_{unique}@example.com"),
                            "password": format!("BenchRegister!{unique}"),
                            "locale": "en"
                        });
                        send_json_expect_status(
                            &client,
                            reqwest::Method::POST,
                            &format!("{base_url}/auth/register"),
                            Some(&body),
                            None,
                            201,
                        )
                        .await
                    })
                })
                .await
            }
        },
    )
    .await
}

async fn bench_login_success_email(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "login_success_email",
        "Successful login using the email identifier.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    credential,
                    move |credential, iteration| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let device_name = format!("bench-login-email-{worker_id}-{iteration}");
                        boxed_http(async move {
                            let body = json!({
                                "identifier": credential.email,
                                "password": credential.password,
                                "device_name": device_name
                            });
                            send_json_expect_login_complete(
                                &client,
                                &format!("{base_url}/auth/login"),
                                &body,
                                "login_success_email",
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_login_success_username(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "login_success_username",
        "Successful login using the username identifier.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    credential,
                    move |credential, iteration| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let device_name = format!("bench-login-username-{worker_id}-{iteration}");
                        boxed_http(async move {
                            let body = json!({
                                "identifier": credential.username,
                                "password": credential.password,
                                "device_name": device_name
                            });
                            send_json_expect_login_complete(
                                &client,
                                &format!("{base_url}/auth/login"),
                                &body,
                                "login_success_username",
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_login_wrong_password(
    base_url: &str,
    client: &reqwest::Client,
    state: AppState,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "login_wrong_password",
        "Rejected login with an incorrect password (one isolated attempt per timed iteration).",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let state = state.clone();
            let credential = credentials[worker_id].clone();
            async move {
                let mut observations = Vec::with_capacity(iterations);

                for run_index in 0..(warmup + iterations) {
                    // Purge accumulated login failures before each attempt so
                    // MAX_FAILURES_BY_IP (hardcoded at 30) is never reached
                    // mid-scenario and turns the expected 401 into a 429.
                    let _ = sqlx::query("DELETE FROM login_attempts")
                        .execute(&state.db)
                        .await;

                    let body = json!({
                        "identifier": credential.email,
                        "password": "DefinitelyWrongPassword!"
                    });

                    let started_at = Instant::now();
                    let outcome = send_json_expect_status(
                        &client,
                        reqwest::Method::POST,
                        &format!("{base_url}/auth/login"),
                        Some(&body),
                        None,
                        401,
                    )
                    .await;
                    let elapsed = started_at.elapsed();

                    if run_index >= warmup {
                        observations.push(HttpObservation {
                            latency: elapsed,
                            status: outcome.status,
                            ok: outcome.ok,
                            error: outcome.error,
                        });
                    }
                }

                Ok(observations)
            }
        },
    )
    .await
}

async fn bench_forgot_password(
    base_url: &str,
    client: &reqwest::Client,
    state: AppState,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let state = state.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "forgot_password",
        "Password reset token issuance for an existing user.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let state = state.clone();
            let credential = credentials[worker_id].clone();
            async move {
                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    credential,
                    move |credential, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let state = state.clone();
                        boxed_http(async move {
                            clear_forgot_password_rate_limit(&state).await;
                            let body = json!({ "email": credential.email });
                            send_json_expect_status(
                                &client,
                                reqwest::Method::POST,
                                &format!("{base_url}/auth/forgot-password"),
                                Some(&body),
                                None,
                                200,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_refresh(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "refresh_success",
        "Refresh token rotation on an active session family.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                let initial = login_complete(
                    &client,
                    &base_url,
                    &credential.email,
                    &credential.password,
                    "bench-refresh-setup",
                )
                .await
                .context("failed to create refresh benchmark session")?;

                run_worker_loop(worker_id, warmup, iterations, initial, move |tokens, _| {
                    let base_url = base_url.clone();
                    let client = client.clone();
                    boxed_http(async move {
                        let body = json!({ "refresh_token": tokens.refresh_token });
                        let response = send_json(
                            &client,
                            reqwest::Method::POST,
                            &format!("{base_url}/auth/refresh"),
                            Some(&body),
                            None,
                        )
                        .await;

                        match response {
                            Ok((status, payload)) if status == 200 => {
                                match parse_tokens(&payload) {
                                    Ok(new_tokens) => {
                                        *tokens = new_tokens;
                                        HttpOutcome {
                                            status,
                                            ok: true,
                                            error: None,
                                        }
                                    }
                                    Err(error) => HttpOutcome {
                                        status,
                                        ok: false,
                                        error: Some(format!(
                                            "failed to parse refresh tokens: {error}"
                                        )),
                                    },
                                }
                            }
                            Ok((status, payload)) => HttpOutcome {
                                status,
                                ok: false,
                                error: Some(format!(
                                    "unexpected refresh status {status}: {payload}"
                                )),
                            },
                            Err(error) => HttpOutcome {
                                status: 0,
                                ok: false,
                                error: Some(format!("refresh request failed: {error:#}")),
                            },
                        }
                    })
                })
                .await
            }
        },
    )
    .await
}

async fn bench_get_profile(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "get_profile",
        "Authenticated profile retrieval including JWT parsing, Redis checks and session validation.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                let tokens = login_complete(&client, &base_url, &credential.email, &credential.password, "bench-profile-setup")
                    .await
                    .context("failed to create profile benchmark token")?;

                run_worker_loop(worker_id, warmup, iterations, tokens, move |tokens, _| {
                    let base_url = base_url.clone();
                    let client = client.clone();
                    boxed_http(async move {
                        send_json_expect_status(
                            &client,
                            reqwest::Method::GET,
                            &format!("{base_url}/users/me"),
                            None,
                            Some(&tokens.access_token),
                            200,
                        )
                        .await
                    })
                })
                .await
            }
        },
    )
    .await
}

async fn bench_list_sessions(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "list_sessions",
        "Authenticated listing of active sessions for the current user.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                let tokens = login_complete(
                    &client,
                    &base_url,
                    &credential.email,
                    &credential.password,
                    "bench-sessions-current",
                )
                .await
                .context("failed to create current session token")?;

                for extra_index in 0..3 {
                    let _ = login_complete(
                        &client,
                        &base_url,
                        &credential.email,
                        &credential.password,
                        &format!("bench-sessions-extra-{worker_id}-{extra_index}"),
                    )
                    .await
                    .context("failed to create extra session")?;
                }

                run_worker_loop(worker_id, warmup, iterations, tokens, move |tokens, _| {
                    let base_url = base_url.clone();
                    let client = client.clone();
                    boxed_http(async move {
                        send_json_expect_status(
                            &client,
                            reqwest::Method::GET,
                            &format!("{base_url}/users/me/sessions"),
                            None,
                            Some(&tokens.access_token),
                            200,
                        )
                        .await
                    })
                })
                .await
            }
        },
    )
    .await
}

async fn bench_reauthenticate(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "reauthenticate",
        "Recent re-authentication marker refresh for sensitive actions.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                let tokens = login_complete(
                    &client,
                    &base_url,
                    &credential.email,
                    &credential.password,
                    "bench-reauth-setup",
                )
                .await
                .context("failed to create reauth session")?;

                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    (tokens, credential),
                    move |context, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        boxed_http(async move {
                            let body = json!({ "current_password": context.1.password });
                            send_json_expect_status(
                                &client,
                                reqwest::Method::POST,
                                &format!("{base_url}/users/me/reauth"),
                                Some(&body),
                                Some(&context.0.access_token),
                                204,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_change_locale(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "change_locale",
        "Authenticated profile write on a lightweight field update.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                let tokens = login_complete(
                    &client,
                    &base_url,
                    &credential.email,
                    &credential.password,
                    "bench-locale-setup",
                )
                .await
                .context("failed to create locale session")?;

                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    (tokens, false),
                    move |context, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        boxed_http(async move {
                            context.1 = !context.1;
                            let locale = if context.1 { "fr" } else { "en" };
                            let body = json!({ "locale": locale });
                            send_json_expect_status(
                                &client,
                                reqwest::Method::PATCH,
                                &format!("{base_url}/users/me/locale"),
                                Some(&body),
                                Some(&context.0.access_token),
                                204,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_email_2fa_challenge(
    base_url: &str,
    client: &reqwest::Client,
    state: AppState,
    credentials: Vec<Email2faCredential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "email_2fa_challenge",
        "Login first step when Email OTP is the primary second factor.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let state = state.clone();
            let credential = credentials[worker_id].clone();
            async move {
                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    credential,
                    move |credential, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let state = state.clone();
                        boxed_http(async move {
                            clear_email_2fa_cooldown(&state, credential.credential.user_id).await;
                            let body = json!({
                                "identifier": credential.credential.email,
                                "password": credential.credential.password
                            });
                            send_json_expect_two_factor(
                                &client,
                                &format!("{base_url}/auth/login"),
                                &body,
                                "email",
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_email_2fa_complete(
    base_url: &str,
    client: &reqwest::Client,
    state: AppState,
    credentials: Vec<Email2faCredential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "email_2fa_complete",
        "Email OTP challenge completion after the pre-auth login step.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let state = state.clone();
            let credential = credentials[worker_id].clone();
            async move {
                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    credential,
                    move |credential, iteration| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let state = state.clone();
                        boxed_http(async move {
                            clear_email_2fa_cooldown(&state, credential.credential.user_id).await;

                            let login_body = json!({
                                "identifier": credential.credential.email,
                                "password": credential.credential.password
                            });
                            let challenge = match login_two_factor(
                                &client,
                                &format!("{base_url}/auth/login"),
                                &login_body,
                                "email",
                            )
                            .await
                            {
                                Ok(challenge) => challenge,
                                Err(error) => {
                                    return HttpOutcome {
                                        status: 0,
                                        ok: false,
                                        error: Some(format!(
                                            "failed to obtain email challenge: {error:#}"
                                        )),
                                    };
                                }
                            };

                            let completion_code = fresh_email_2fa_bench_code(worker_id, iteration);
                            if let Err(error) = replace_email_code(
                                &state.db,
                                credential.credential.user_id,
                                &completion_code,
                            )
                            .await
                            {
                                return HttpOutcome {
                                    status: 0,
                                    ok: false,
                                    error: Some(format!(
                                        "failed to replace email OTP code: {error:#}"
                                    )),
                                };
                            }

                            let complete_body = json!({
                                "pre_auth_token": challenge.pre_auth_token,
                                "code": completion_code
                            });
                            send_json_expect_complete_tokens(
                                &client,
                                &format!("{base_url}/auth/two-factor/email/complete"),
                                &complete_body,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_totp_challenge(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<TotpCredential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "totp_challenge",
        "Login first step when TOTP is the primary second factor.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    credential,
                    move |credential, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        boxed_http(async move {
                            let body = json!({
                                "identifier": credential.credential.email,
                                "password": credential.credential.password
                            });
                            send_json_expect_two_factor(
                                &client,
                                &format!("{base_url}/auth/login"),
                                &body,
                                "totp",
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_totp_complete(
    base_url: &str,
    client: &reqwest::Client,
    state: AppState,
    credentials: Vec<TotpCredential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "totp_complete",
        "TOTP challenge completion after the pre-auth login step.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let state = state.clone();
            let credential = credentials[worker_id].clone();
            async move {
                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    credential,
                    move |credential, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let state = state.clone();
                        boxed_http(async move {
                            let login_body = json!({
                                "identifier": credential.credential.email,
                                "password": credential.credential.password
                            });
                            let challenge = match login_two_factor(
                                &client,
                                &format!("{base_url}/auth/login"),
                                &login_body,
                                "totp",
                            )
                            .await
                            {
                                Ok(challenge) => challenge,
                                Err(error) => {
                                    return HttpOutcome {
                                        status: 0,
                                        ok: false,
                                        error: Some(format!(
                                            "failed to obtain TOTP challenge: {error:#}"
                                        )),
                                    };
                                }
                            };

                            let code = match current_totp_code(&credential.base32_secret) {
                                Ok(code) => code,
                                Err(error) => {
                                    return HttpOutcome {
                                        status: 0,
                                        ok: false,
                                        error: Some(format!(
                                            "failed to generate TOTP code: {error:#}"
                                        )),
                                    };
                                }
                            };
                            clear_totp_reuse_key(&state, credential.credential.user_id, &code)
                                .await;

                            let complete_body = json!({
                                "pre_auth_token": challenge.pre_auth_token,
                                "code": code
                            });
                            send_json_expect_complete_tokens(
                                &client,
                                &format!("{base_url}/auth/two-factor/complete"),
                                &complete_body,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_logout(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "logout",
        "Session termination: JWT blocklisting and session row invalidation.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                // Pre-create one session per timed run (warmup + iterations) so each
                // iteration has a fresh, valid access token to revoke.
                let total = warmup + iterations;
                let mut token_queue: Vec<String> = Vec::with_capacity(total);
                for i in 0..total {
                    let device = format!("bench-logout-{worker_id}-{i}");
                    let tokens = login_complete(
                        &client,
                        &base_url,
                        &credential.email,
                        &credential.password,
                        &device,
                    )
                    .await
                    .context("failed to pre-create logout session")?;
                    token_queue.push(tokens.access_token);
                }

                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    (token_queue, 0usize),
                    move |ctx, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let token = ctx.0[ctx.1].clone();
                        ctx.1 += 1;
                        boxed_http(async move {
                            send_json_expect_status(
                                &client,
                                reqwest::Method::POST,
                                &format!("{base_url}/auth/logout"),
                                None,
                                Some(&token),
                                204,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_change_password(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "change_password",
        "Authenticated password change: Argon2 hash of the new password plus full session revocation. Re-login before each timed iteration because change_password revokes all sessions including the current one.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                // current_pw tracks the live password across iterations.
                let mut current_pw = credential.password.clone();
                let mut observations = Vec::with_capacity(iterations);

                for (counter, run_index) in (0..(warmup + iterations)).enumerate() {
                    // Re-login before each timed iteration: change_password calls
                    // revoke_all_by_user (all sessions, including the current one),
                    // so the previous token is always invalid for the next run.
                    let device = format!("bench-change-pw-{worker_id}-{run_index}");
                    let tokens = login_complete(
                        &client,
                        &base_url,
                        &credential.email,
                        &current_pw,
                        &device,
                    )
                    .await
                    .context("failed to re-login for change_password iteration")?;

                    let new_pw = format!("BenchNewPass!{worker_id}_{counter}");

                    let started_at = Instant::now();
                    let outcome = send_json_expect_status(
                        &client,
                        reqwest::Method::PATCH,
                        &format!("{base_url}/users/me/password"),
                        Some(&json!({
                            "current_password": current_pw,
                            "new_password": new_pw,
                        })),
                        Some(&tokens.access_token),
                        204,
                    )
                    .await;
                    let elapsed = started_at.elapsed();

                    if outcome.ok {
                        current_pw = new_pw;
                    }

                    if run_index >= warmup {
                        observations.push(HttpObservation {
                            latency: elapsed,
                            status: outcome.status,
                            ok: outcome.ok,
                            error: outcome.error,
                        });
                    }
                }

                Ok(observations)
            }
        },
    )
    .await
}

async fn bench_revoke_session(
    base_url: &str,
    client: &reqwest::Client,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "revoke_session",
        "Single-session revocation: authenticated DELETE on a specific session UUID.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let credential = credentials[worker_id].clone();
            async move {
                // Main session used to authenticate DELETE requests throughout the bench.
                let main_tokens = login_complete(
                    &client,
                    &base_url,
                    &credential.email,
                    &credential.password,
                    "bench-revoke-main",
                )
                .await
                .context("failed to create main revoke session")?;

                // Pre-create one extra session per timed run.
                let total = warmup + iterations;
                for i in 0..total {
                    login_complete(
                        &client,
                        &base_url,
                        &credential.email,
                        &credential.password,
                        &format!("bench-revoke-extra-{worker_id}-{i}"),
                    )
                    .await
                    .context("failed to pre-create extra session")?;
                }

                // Collect all non-current session IDs from the sessions list.
                let session_ids =
                    collect_non_current_session_ids(&client, &base_url, &main_tokens.access_token)
                        .await
                        .context("failed to collect session IDs for revoke bench")?;

                if session_ids.len() < total {
                    anyhow::bail!(
                        "expected at least {total} sessions, got {}",
                        session_ids.len()
                    );
                }

                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    (main_tokens, session_ids, 0usize),
                    move |ctx, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let token = ctx.0.access_token.clone();
                        let session_id = ctx.1[ctx.2];
                        ctx.2 += 1;
                        boxed_http(async move {
                            send_json_expect_status(
                                &client,
                                reqwest::Method::DELETE,
                                &format!("{base_url}/users/me/sessions/{session_id}"),
                                None,
                                Some(&token),
                                204,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_email_change_start(
    base_url: &str,
    client: &reqwest::Client,
    state: AppState,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "email_change_start",
        "Email change initiation: OTP generation, Redis flow state creation, and fire-and-forget email dispatch.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let state = state.clone();
            let credential = credentials[worker_id].clone();
            async move {
                let tokens = login_complete(
                    &client,
                    &base_url,
                    &credential.email,
                    &credential.password,
                    "bench-ecstart-setup",
                )
                .await
                .context("failed to create email_change_start session")?;

                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    (tokens, credential.user_id),
                    move |ctx, _| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let state = state.clone();
                        let token = ctx.0.access_token.clone();
                        let user_id = ctx.1;
                        boxed_http(async move {
                            // Clear cooldown set by a previous iteration's confirm step
                            // (or by the start step itself if the flow was abandoned).
                            clear_email_change_cooldown_bench(&state, user_id).await;
                            // Also cancel any lingering in-progress flow so the service
                            // doesn't return a conflict.
                            cancel_email_change_flow_bench(&state, user_id).await;
                            send_json_expect_status(
                                &client,
                                reqwest::Method::POST,
                                &format!("{base_url}/users/me/email/start"),
                                Some(&json!({})),
                                Some(&token),
                                200,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

async fn bench_email_change_full(
    base_url: &str,
    client: &reqwest::Client,
    state: AppState,
    credentials: Vec<Credential>,
    iterations: usize,
    warmup: usize,
) -> Result<HttpScenarioReport> {
    let base_url = base_url.to_string();
    let client = client.clone();
    let concurrency = credentials.len();

    run_http_scenario(
        "email_change_full",
        "Complete 4-step email change pipeline: start → verify-current → submit → confirm. OTPs are injected directly into Redis; email send is fire-and-forget.",
        concurrency,
        iterations,
        warmup,
        move |worker_id| {
            let base_url = base_url.clone();
            let client = client.clone();
            let state = state.clone();
            let credential = credentials[worker_id].clone();
            async move {
                let tokens = login_complete(
                    &client,
                    &base_url,
                    &credential.email,
                    &credential.password,
                    "bench-ecfull-setup",
                )
                .await
                .context("failed to create email_change_full session")?;

                run_worker_loop(
                    worker_id,
                    warmup,
                    iterations,
                    (tokens, credential.user_id),
                    move |ctx, run_index| {
                        let base_url = base_url.clone();
                        let client = client.clone();
                        let state = state.clone();
                        let token = ctx.0.access_token.clone();
                        let user_id = ctx.1;
                        // Unique new email per run to avoid conflicts across iterations.
                        let new_email = format!("bench_ecf_{worker_id}_{run_index}@bench.test");
                        boxed_http(async move {
                            // Step 0: clear cooldown from previous iteration's confirm step.
                            clear_email_change_cooldown_bench(&state, user_id).await;

                            // Step 1: start - creates the flow and returns flow_token.
                            let (status, payload) = match send_json(
                                &client,
                                reqwest::Method::POST,
                                &format!("{base_url}/users/me/email/start"),
                                Some(&json!({})),
                                Some(&token),
                            )
                            .await
                            {
                                Ok(r) => r,
                                Err(e) => {
                                    return HttpOutcome {
                                        status: 0,
                                        ok: false,
                                        error: Some(format!("start request failed: {e:#}")),
                                    };
                                }
                            };
                            if status != 200 {
                                return HttpOutcome {
                                    status,
                                    ok: false,
                                    error: Some(format!("start returned {status}: {payload}")),
                                };
                            }
                            let flow_token = match parse_flow_token(&payload) {
                                Ok(t) => t,
                                Err(e) => {
                                    return HttpOutcome {
                                        status,
                                        ok: false,
                                        error: Some(format!("failed to parse flow_token: {e:#}")),
                                    };
                                }
                            };

                            // Inject known OTP into the flow state so we don't need a mail server.
                            inject_known_otp_into_flow(&state.redis, &flow_token).await;

                            // Step 2: verify-current.
                            let outcome = send_json_expect_status(
                                &client,
                                reqwest::Method::POST,
                                &format!("{base_url}/users/me/email/verify-current"),
                                Some(&json!({"flow_token": flow_token, "code": BENCH_EMAIL_CHANGE_OTP})),
                                Some(&token),
                                204,
                            )
                            .await;
                            if !outcome.ok {
                                return outcome;
                            }

                            // Step 3: submit new address.
                            let outcome = send_json_expect_status(
                                &client,
                                reqwest::Method::POST,
                                &format!("{base_url}/users/me/email/submit"),
                                Some(&json!({"flow_token": flow_token, "new_email": new_email})),
                                Some(&token),
                                204,
                            )
                            .await;
                            if !outcome.ok {
                                return outcome;
                            }

                            // Inject known OTP into the updated flow state (now in NewVerify step).
                            inject_known_otp_into_flow(&state.redis, &flow_token).await;

                            // Step 4: confirm - commits the email change to the DB.
                            send_json_expect_status(
                                &client,
                                reqwest::Method::POST,
                                &format!("{base_url}/users/me/email/confirm"),
                                Some(&json!({"flow_token": flow_token, "code": BENCH_EMAIL_CHANGE_OTP})),
                                Some(&token),
                                204,
                            )
                            .await
                        })
                    },
                )
                .await
            }
        },
    )
    .await
}

// Email-change benchmark helpers

/// Parses `{"flow_token": "..."}` from the /email/start response body.
fn parse_flow_token(payload: &str) -> Result<String> {
    let val: Value =
        serde_json::from_str(payload).context("invalid JSON in /email/start response")?;
    val.get("flow_token")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .context("missing flow_token in /email/start response")
}

/// Replaces the `otp_hash` field inside `email_change_flow:{flow_token}` in Redis
/// with the SHA-256 hash of `BENCH_EMAIL_CHANGE_OTP`, encoded as base64url.
/// This lets the benchmark complete OTP verification steps without a real mail server.
async fn inject_known_otp_into_flow(redis: &deadpool_redis::Pool, flow_token: &str) {
    let key = format!("email_change_flow:{}", flow_token);
    if let Ok(mut conn) = redis.get().await
        && let Ok(raw) = conn.get::<_, String>(&key).await
        && let Ok(mut val) = serde_json::from_str::<Value>(&raw)
    {
        let hash = rust_api::utils::crypto::sha256(BENCH_EMAIL_CHANGE_OTP.as_bytes());
        let hash_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
        val["otp_hash"] = Value::String(hash_b64);
        if let Ok(updated) = serde_json::to_string(&val) {
            let ttl: i64 = conn.ttl(&key).await.unwrap_or(900);
            let _: Result<(), _> = conn.set_ex(&key, updated, ttl as u64).await;
        }
    }
}

/// Deletes the per-user email-change cooldown key so the next iteration can start a flow.
async fn clear_email_change_cooldown_bench(state: &AppState, user_id: Uuid) {
    if let Ok(mut conn) = state.redis.get().await {
        let key = format!("email_change_cd:{}", user_id);
        let _: Result<(), _> = conn.del(&key).await;
    }
}

/// Cancels any in-progress email-change flow for the user so a fresh start succeeds.
async fn cancel_email_change_flow_bench(state: &AppState, user_id: Uuid) {
    if let Ok(mut conn) = state.redis.get().await {
        let active_key = format!("email_change_active:{}", user_id);
        if let Ok(Some(old_token)) = conn.get::<_, Option<String>>(&active_key).await {
            let _: Result<(), _> = conn.del(format!("email_change_flow:{}", old_token)).await;
            let _: Result<(), _> = conn.del(format!("email_change_fail:{}", old_token)).await;
        }
        let _: Result<(), _> = conn.del(&active_key).await;
    }
}

// Session revocation helper

/// Returns the UUIDs of all sessions for the authenticated user excluding the current one.
async fn collect_non_current_session_ids(
    client: &reqwest::Client,
    base_url: &str,
    access_token: &str,
) -> Result<Vec<Uuid>> {
    let (status, payload) = send_json(
        client,
        reqwest::Method::GET,
        &format!("{base_url}/users/me/sessions"),
        None,
        Some(access_token),
    )
    .await?;

    if status != 200 {
        anyhow::bail!("GET /sessions returned {status}: {payload}");
    }

    let sessions: Value =
        serde_json::from_str(&payload).context("invalid JSON from GET /sessions")?;
    let ids = sessions
        .as_array()
        .context("expected JSON array from GET /sessions")?
        .iter()
        .filter(|s| {
            !s.get("is_current")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|s| s.get("id").and_then(Value::as_str))
        .filter_map(|id| Uuid::parse_str(id).ok())
        .collect();

    Ok(ids)
}

async fn run_http_scenario<WFut, WFn>(
    name: &str,
    description: &str,
    concurrency: usize,
    iterations: usize,
    warmup: usize,
    worker_factory: WFn,
) -> Result<HttpScenarioReport>
where
    WFut: std::future::Future<Output = Result<Vec<HttpObservation>>> + Send + 'static,
    WFn: Fn(usize) -> WFut + Send + Sync + 'static,
{
    let start = Instant::now();
    let mut all_observations = Vec::new();
    let mut workers = tokio::task::JoinSet::new();
    let worker_factory = Arc::new(worker_factory);

    for worker_id in 0..concurrency {
        let worker_factory = Arc::clone(&worker_factory);
        workers.spawn(async move { (worker_id, worker_factory(worker_id).await) });
    }

    while let Some(join_result) = workers.join_next().await {
        let (worker_id, observations) =
            join_result.with_context(|| format!("scenario `{name}` worker task panicked"))?;
        let mut observations =
            observations.with_context(|| format!("scenario `{name}` worker {worker_id} failed"))?;
        all_observations.append(&mut observations);
    }

    let wall_time = start.elapsed();
    Ok(build_http_report(
        name,
        description,
        concurrency,
        iterations,
        warmup,
        all_observations,
        wall_time,
    ))
}

async fn run_worker_loop<T, O>(
    _worker_id: usize,
    warmup: usize,
    iterations: usize,
    mut context: T,
    mut operation: O,
) -> Result<Vec<HttpObservation>>
where
    O: for<'a> FnMut(&'a mut T, usize) -> Pin<Box<dyn Future<Output = HttpOutcome> + Send + 'a>>,
{
    let mut observations = Vec::with_capacity(iterations);
    let total_runs = warmup + iterations;

    for run_index in 0..total_runs {
        let started_at = Instant::now();
        let outcome = operation(&mut context, run_index).await;
        let elapsed = started_at.elapsed();

        if run_index >= warmup {
            observations.push(HttpObservation {
                latency: elapsed,
                status: outcome.status,
                ok: outcome.ok,
                error: outcome.error,
            });
        }
    }

    Ok(observations)
}

fn boxed_http<'a, F>(future: F) -> Pin<Box<dyn Future<Output = HttpOutcome> + Send + 'a>>
where
    F: Future<Output = HttpOutcome> + Send + 'a,
{
    Box::pin(future)
}

fn build_http_report(
    name: &str,
    description: &str,
    concurrency: usize,
    iterations: usize,
    warmup: usize,
    observations: Vec<HttpObservation>,
    wall_time: Duration,
) -> HttpScenarioReport {
    let mut status_histogram = BTreeMap::new();
    let mut failures = Vec::new();
    let mut latencies = Vec::with_capacity(observations.len());
    let mut samples_ms = Vec::with_capacity(observations.len());
    let mut success_count = 0usize;

    for observation in observations {
        *status_histogram
            .entry(observation.status.to_string())
            .or_insert(0) += 1;
        if observation.ok {
            success_count += 1;
        } else if failures.len() < 10 {
            failures.push(
                observation
                    .error
                    .unwrap_or_else(|| format!("status {}", observation.status)),
            );
        }
        samples_ms.push(observation.latency.as_secs_f64() * 1000.0);
        latencies.push(observation.latency);
    }

    HttpScenarioReport {
        name: name.to_string(),
        description: description.to_string(),
        concurrency,
        iterations_per_worker: iterations,
        warmup_per_worker: warmup,
        total_requests: latencies.len(),
        success_count,
        failure_count: latencies.len().saturating_sub(success_count),
        status_histogram,
        summary: bench_support::summarize_latencies(&latencies, wall_time),
        samples_ms,
        failure_examples: failures,
    }
}

async fn login_complete(
    client: &reqwest::Client,
    base_url: &str,
    identifier: &str,
    password: &str,
    device_name: &str,
) -> Result<Tokens> {
    let body = json!({
        "identifier": identifier,
        "password": password,
        "device_name": device_name
    });

    let (status, payload) = send_json(
        client,
        reqwest::Method::POST,
        &format!("{base_url}/auth/login"),
        Some(&body),
        None,
    )
    .await?;

    if status != 200 {
        anyhow::bail!("unexpected login status {status}: {payload}");
    }

    parse_tokens(&payload)
}

async fn login_two_factor(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
    expected_method: &str,
) -> Result<TwoFactorChallenge> {
    let (status, payload) = send_json(client, reqwest::Method::POST, url, Some(body), None).await?;
    if status != 200 {
        anyhow::bail!("unexpected login challenge status {status}: {payload}");
    }

    parse_two_factor_challenge(&payload, expected_method)
}

async fn send_json_expect_login_complete(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
    scenario: &str,
) -> HttpOutcome {
    match send_json(client, reqwest::Method::POST, url, Some(body), None).await {
        Ok((status, payload)) if status == 200 => match parse_tokens(&payload) {
            Ok(_) => HttpOutcome {
                status,
                ok: true,
                error: None,
            },
            Err(error) => HttpOutcome {
                status,
                ok: false,
                error: Some(format!("{scenario}: invalid token payload: {error:#}")),
            },
        },
        Ok((status, payload)) => HttpOutcome {
            status,
            ok: false,
            error: Some(format!("{scenario}: unexpected status {status}: {payload}")),
        },
        Err(error) => HttpOutcome {
            status: 0,
            ok: false,
            error: Some(format!("{scenario}: request failed: {error:#}")),
        },
    }
}

async fn send_json_expect_two_factor(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
    expected_method: &str,
) -> HttpOutcome {
    match send_json(client, reqwest::Method::POST, url, Some(body), None).await {
        Ok((status, payload)) if status == 200 => {
            match parse_two_factor_challenge(&payload, expected_method) {
                Ok(_) => HttpOutcome {
                    status,
                    ok: true,
                    error: None,
                },
                Err(error) => HttpOutcome {
                    status,
                    ok: false,
                    error: Some(format!("invalid two-factor challenge payload: {error:#}")),
                },
            }
        }
        Ok((status, payload)) => HttpOutcome {
            status,
            ok: false,
            error: Some(format!(
                "unexpected two-factor challenge status {status}: {payload}"
            )),
        },
        Err(error) => HttpOutcome {
            status: 0,
            ok: false,
            error: Some(format!("two-factor challenge request failed: {error:#}")),
        },
    }
}

async fn send_json_expect_complete_tokens(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
) -> HttpOutcome {
    match send_json(client, reqwest::Method::POST, url, Some(body), None).await {
        Ok((status, payload)) if status == 200 => match parse_tokens(&payload) {
            Ok(_) => HttpOutcome {
                status,
                ok: true,
                error: None,
            },
            Err(error) => HttpOutcome {
                status,
                ok: false,
                error: Some(format!("invalid token completion payload: {error:#}")),
            },
        },
        Ok((status, payload)) => HttpOutcome {
            status,
            ok: false,
            error: Some(format!("unexpected completion status {status}: {payload}")),
        },
        Err(error) => HttpOutcome {
            status: 0,
            ok: false,
            error: Some(format!("completion request failed: {error:#}")),
        },
    }
}

async fn send_json_expect_status(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    body: Option<&Value>,
    bearer: Option<&str>,
    expected_status: u16,
) -> HttpOutcome {
    match send_json(client, method, url, body, bearer).await {
        Ok((status, _payload)) if status == expected_status => HttpOutcome {
            status,
            ok: true,
            error: None,
        },
        Ok((status, payload)) => HttpOutcome {
            status,
            ok: false,
            error: Some(format!(
                "unexpected status {status} (expected {expected_status}): {payload}"
            )),
        },
        Err(error) => HttpOutcome {
            status: 0,
            ok: false,
            error: Some(format!("request failed: {error:#}")),
        },
    }
}

async fn send_json(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    body: Option<&Value>,
    bearer: Option<&str>,
) -> Result<(u16, String)> {
    let mut request = client.request(method, url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(body);
    }

    let response = request.send().await.context("HTTP request failed")?;
    let status = response.status().as_u16();
    let payload = response
        .text()
        .await
        .context("failed to read response body")?;
    Ok((status, payload))
}

fn parse_tokens(payload: &str) -> Result<Tokens> {
    let value: Value = serde_json::from_str(payload).context("invalid JSON payload")?;
    Ok(Tokens {
        access_token: value
            .get("access_token")
            .and_then(Value::as_str)
            .context("missing access_token")?
            .to_string(),
        refresh_token: value
            .get("refresh_token")
            .and_then(Value::as_str)
            .context("missing refresh_token")?
            .to_string(),
    })
}

#[derive(Debug)]
struct TwoFactorChallenge {
    pre_auth_token: String,
}

fn parse_two_factor_challenge(payload: &str, expected_method: &str) -> Result<TwoFactorChallenge> {
    let value: Value = serde_json::from_str(payload).context("invalid JSON payload")?;
    let method = value
        .get("two_factor_method")
        .and_then(Value::as_str)
        .context("missing two_factor_method")?;
    if method != expected_method {
        anyhow::bail!("expected two_factor_method `{expected_method}`, got `{method}`");
    }

    Ok(TwoFactorChallenge {
        pre_auth_token: value
            .get("pre_auth_token")
            .and_then(Value::as_str)
            .context("missing pre_auth_token")?
            .to_string(),
    })
}

async fn replace_email_code(pool: &PgPool, user_id: Uuid, code: &str) -> Result<()> {
    let hash = crypto::sha256(code.as_bytes());
    email_2fa_repo::create(
        pool,
        &email_2fa_repo::NewEmail2faCode {
            user_id,
            code_hash: &hash,
            expires_at: time_utils::in_secs(600),
        },
    )
    .await
    .context("failed to replace active Email 2FA code")?;
    Ok(())
}

async fn clear_email_2fa_cooldown(state: &AppState, user_id: Uuid) {
    if let Ok(mut conn) = state.redis.get().await {
        let key = format!("email2fa_cd:{user_id}");
        let _: Result<(), _> = conn.del(&key).await;
    }
}

async fn clear_forgot_password_rate_limit(state: &AppState) {
    if let Ok(mut conn) = state.redis.get().await {
        let key = "fp_req:127.0.0.1";
        let _: Result<(), _> = conn.del(key).await;
    }
}

async fn clear_totp_reuse_key(state: &AppState, user_id: Uuid, code: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        let key = format!("totp_used:{user_id}:{code}");
        let _: Result<(), _> = conn.del(&key).await;
    }
}

fn current_totp_code(base32_secret: &str) -> Result<String> {
    let secret_bytes = Secret::Encoded(base32_secret.to_string())
        .to_bytes()
        .context("invalid base32 TOTP secret")?;
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .context("failed to build TOTP generator")?;
    totp.generate_current()
        .context("failed to generate current TOTP code")
}

fn scaled(base: usize, numerator: usize, denominator: usize) -> usize {
    base.saturating_mul(numerator).max(1) / denominator.max(1)
}

fn fresh_email_2fa_bench_code(worker_id: usize, iteration: usize) -> String {
    let suffix = (worker_id * 1_000 + iteration) % 100_000;
    format!("{:06}", 700_000 + suffix)
}

fn render_markdown(report: &HttpBenchmarkReport) -> String {
    let mut out = String::new();
    out.push_str("# HTTP Benchmark Report\n\n");
    out.push_str(&format!(
        "- Generated at: `{}`\n- Base URL: `{}`\n- Concurrency: `{}`\n- Base iterations per worker: `{}`\n- Warmup per worker: `{}`\n\n",
        report.generated_at_unix,
        report.base_url,
        report.concurrency,
        report.iterations_per_worker,
        report.warmup_per_worker
    ));
    out.push_str("## Notes\n\n");
    for note in &report.notes {
        out.push_str(&format!("- {note}\n"));
    }
    out.push_str("\n## Scenario Summary\n\n");
    out.push_str(
        "| Scenario | Requests | Success | p50 ms | p95 ms | p99 ms | Mean ms | Req/s |\n",
    );
    out.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for scenario in &report.scenarios {
        out.push_str(&format!(
            "| {} | {} | {}/{} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} |\n",
            scenario.name,
            scenario.total_requests,
            scenario.success_count,
            scenario.total_requests,
            scenario.summary.p50_ms,
            scenario.summary.p95_ms,
            scenario.summary.p99_ms,
            scenario.summary.mean_ms,
            scenario.summary.throughput_per_sec
        ));
    }
    out.push_str("\n## Scenario Details\n\n");
    for scenario in &report.scenarios {
        out.push_str(&format!("### {}\n\n", scenario.name));
        out.push_str(&format!("{}\n\n", scenario.description));
        out.push_str(&format!(
            "- Requests: `{}`\n- Success: `{}`\n- Failures: `{}`\n- Status histogram: `{}`\n- p50/p95/p99: `{:.2} / {:.2} / {:.2} ms`\n- Mean throughput: `{:.2} req/s`\n",
            scenario.total_requests,
            scenario.success_count,
            scenario.failure_count,
            scenario
                .status_histogram
                .iter()
                .map(|(status, count)| format!("{status}:{count}"))
                .collect::<Vec<_>>()
                .join(", "),
            scenario.summary.p50_ms,
            scenario.summary.p95_ms,
            scenario.summary.p99_ms,
            scenario.summary.throughput_per_sec,
        ));
        if !scenario.failure_examples.is_empty() {
            out.push_str("- Failure examples:\n");
            for failure in &scenario.failure_examples {
                out.push_str(&format!("  - `{failure}`\n"));
            }
        }
        out.push('\n');
    }

    out
}
