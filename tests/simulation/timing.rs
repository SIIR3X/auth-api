//! Response times must not tell an existing account from an unknown one.
//!
//! Wrong-password sign-ins and forgotten-password requests go to existing
//! accounts and to identifiers matching none, interleaved in the same batches
//! so the machine's load weighs on both sides alike; their medians must stay
//! close. Every request uses its own account or identifier, so no per-account
//! budget or backoff singles one side out, and the per-address budgets are
//! reset between batches.
//!
//! Long, and sensitive to a busy machine: `make test-sim` runs it, `make ci`
//! does not.

use std::time::{Duration, Instant};

use deadpool_redis::redis::AsyncCommands;
use futures::future::join_all;
use serde_json::json;

use crate::common::{app::TestApp, fixtures};

/// Sign-in batches, each with this many existing and as many unknown accounts.
const SIGN_IN_BATCHES: usize = 6;
const SIGN_IN_BATCH: usize = 10;
/// Password recovery requests per batch, per side: the per-address budget
/// allows five requests before it answers every request alike.
const RECOVERY_BATCH: usize = 2;
/// Largest gap tolerated between the medians of the two sides.
const MAX_MEDIAN_GAP: Duration = Duration::from_millis(25);

#[tokio::test]
#[ignore = "long: timed sign-ins and password recoveries for existing and unknown accounts"]
async fn response_times_do_not_reveal_which_accounts_exist() {
    let app = TestApp::spawn().await;
    let accounts = SIGN_IN_BATCHES * SIGN_IN_BATCH;
    let mut existing = Vec::with_capacity(accounts);
    for index in 0..accounts {
        let user = fixtures::register_user(&app, index + 1).await;
        fixtures::activate_user(&app.db, user.id).await;
        existing.push(user.email);
    }

    let mut sign_in = Samples::default();
    for (batch, emails) in existing.chunks(SIGN_IN_BATCH).enumerate() {
        reset_address_budgets(&app).await;
        let timed = join_all(sides(emails, batch).map(|(exists, identifier)| {
            let app = &app;
            async move {
                let started = Instant::now();
                let res = app
                    .post(
                        "/auth/login",
                        &json!({ "identifier": identifier, "password": "Wrong-Password-1!" }),
                    )
                    .await;
                (exists, res.status().as_u16(), started.elapsed())
            }
        }))
        .await;
        for (exists, status, elapsed) in timed {
            assert_eq!(status, 401, "a wrong password answered {status}");
            sign_in.push(exists, elapsed);
        }
    }

    let mut recovery = Samples::default();
    for (batch, emails) in existing.chunks(RECOVERY_BATCH).enumerate() {
        reset_address_budgets(&app).await;
        let timed = join_all(sides(emails, batch).map(|(exists, email)| {
            let app = &app;
            async move {
                let started = Instant::now();
                let res = app
                    .post("/auth/forgot-password", &json!({ "email": email }))
                    .await;
                (exists, res.status().as_u16(), started.elapsed())
            }
        }))
        .await;
        for (exists, status, elapsed) in timed {
            assert_eq!(status, 200, "a password recovery answered {status}");
            recovery.push(exists, elapsed);
        }
    }

    for (flow, samples) in [("sign-in", sign_in), ("password recovery", recovery)] {
        let (existing, unknown) = (median(samples.existing), median(samples.unknown));
        assert!(
            existing.abs_diff(unknown) <= MAX_MEDIAN_GAP,
            "{flow}: median {existing:?} for existing accounts, {unknown:?} for unknown ones"
        );
    }
}

#[derive(Default)]
struct Samples {
    existing: Vec<Duration>,
    unknown: Vec<Duration>,
}

impl Samples {
    fn push(&mut self, exists: bool, elapsed: Duration) {
        if exists {
            self.existing.push(elapsed);
        } else {
            self.unknown.push(elapsed);
        }
    }
}

/// Each existing address, followed by an address matching no account.
fn sides(emails: &[String], batch: usize) -> impl Iterator<Item = (bool, String)> + '_ {
    emails.iter().enumerate().flat_map(move |(i, email)| {
        [
            (true, email.clone()),
            (false, format!("nobody-{batch}-{i}@example.com")),
        ]
    })
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

/// Reset the per-address budgets: failed sign-ins, distinct identifiers tried
/// and password recoveries.
async fn reset_address_budgets(app: &TestApp) {
    sqlx::query("DELETE FROM login_attempts")
        .execute(&app.db)
        .await
        .unwrap();
    let mut conn = app.redis.get().await.unwrap();
    let _: () = conn.del(format!("cs_hll:{}", app.client_ip)).await.unwrap();
    app.clear_forgot_password_rate_limit(&app.client_ip).await;
}
