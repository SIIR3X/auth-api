use postgres::Client;
use rust_api::repositories::{
    login_attempt, login_location, session as session_repo, user as user_repo,
};
use time::OffsetDateTime;

use crate::common::{
    db::{TestDatabase, assert_plan_contains, explain_plan},
    fixtures::{fixed_hash, insert_active_user, insert_user, sample_email, sample_username},
};

#[test]
fn identifier_lookup_plan_uses_user_indexes() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let client = db.client();
    for index in 0..200 {
        insert_user(client, index);
    }

    let email = sample_email(42);
    let email_plan = explain_plan(client, user_repo::FIND_BY_EMAIL_SQL, &[&email]);
    assert_plan_contains(&email_plan, "users_email_key");

    let username = sample_username(42);
    let username_plan = explain_plan(client, user_repo::FIND_BY_USERNAME_SQL, &[&username]);
    assert_plan_contains(&username_plan, "users_username_key");
}

#[test]
fn session_lookup_plans_use_primary_and_token_hash_indexes() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let client = db.client();
    let user_id = insert_active_user(client, 700);

    for seed in 1..=48u8 {
        let token_hash = fixed_hash(seed);
        client
            .execute(
                "INSERT INTO sessions (user_id, expires_at, token_hash)
                 VALUES ($1, NOW() + INTERVAL '30 days', $2)",
                &[&user_id, &token_hash],
            )
            .expect("failed to insert session fixture");
    }

    let target_hash = fixed_hash(17);
    let token_plan = explain_plan(
        client,
        session_repo::FIND_BY_TOKEN_HASH_SQL,
        &[&target_hash],
    );
    assert_plan_contains(&token_plan, "sessions_token_hash_key");

    let session_id: uuid::Uuid = client
        .query_one(
            "SELECT id FROM sessions WHERE token_hash = $1",
            &[&target_hash],
        )
        .expect("failed to load target session")
        .get(0);

    let validation_plan = explain_plan(
        client,
        session_repo::FIND_VALIDATION_BY_ID_SQL,
        &[&session_id],
    );
    assert_plan_contains(&validation_plan, "sessions_pkey");

    let active_plan = explain_plan(
        client,
        session_repo::FIND_ACTIVE_SUMMARY_BY_USER_SQL,
        &[&user_id],
    );
    assert_plan_contains(&active_plan, "idx_sessions_user_active");
}

#[test]
fn risk_history_plan_uses_recent_login_location_index() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let client = db.client();
    let user_id = insert_active_user(client, 900);
    let other_user_id = insert_active_user(client, 901);

    insert_login_locations(client, user_id, 120, "user-agent/perf");
    insert_login_locations(client, other_user_id, 40, "user-agent/other");

    let history_days = 30i32;
    let plan = explain_plan(
        client,
        login_location::FIND_RECENT_FOR_RISK_SQL,
        &[&user_id, &history_days],
    );

    assert_plan_contains(&plan, "idx_login_locations_last_seen");
}

#[test]
fn brute_force_counter_plans_use_partial_failure_indexes() {
    let Some(mut db) = TestDatabase::new() else {
        return;
    };

    let client = db.client();
    let user_id = insert_active_user(client, 1000);
    let hot_identifier = sample_email(1000);
    let hot_ip = "203.0.113.10/32";

    insert_login_attempts(client, user_id, &hot_identifier, hot_ip);
    client
        .batch_execute(
            "ANALYZE login_attempts;
             ANALYZE users;
             ANALYZE sessions;
             ANALYZE login_locations;",
        )
        .expect("failed to analyze benchmark fixtures");

    let cutoff = OffsetDateTime::now_utc() - time::Duration::minutes(15);
    let identifier_limit = 10i64;
    let identifier_plan = explain_plan(
        client,
        login_attempt::COUNT_RECENT_FAILURES_BY_IDENTIFIER_SQL,
        &[&hot_identifier, &cutoff, &identifier_limit],
    );
    assert_plan_contains(
        &identifier_plan,
        "idx_login_attempts_failed_identifier_time",
    );

    let explain_ip_sql =
        login_attempt::COUNT_RECENT_FAILURES_BY_IP_SQL.replacen("$1::cidr", "$1::text::cidr", 1);
    let ip_limit = 30i64;
    let ip_plan = explain_plan(client, &explain_ip_sql, &[&hot_ip, &cutoff, &ip_limit]);
    assert_plan_contains(&ip_plan, "idx_login_attempts_failed_ip_time");
}

fn insert_login_locations(
    client: &mut Client,
    user_id: uuid::Uuid,
    count: usize,
    user_agent: &str,
) {
    let user_agent = user_agent.to_string();

    for offset in 0..count {
        let country = format!("FR{}", offset % 3);
        let city = format!("Paris-{offset}");
        let ip = format!("198.51.100.{}/32", (offset % 200) + 1);
        let hours_ago = (offset % 48) as i32;

        client
            .execute(
                "INSERT INTO login_locations
                    (user_id, country, city, user_agent, ip_address, latitude, longitude, last_seen, first_seen)
                 VALUES ($1, $2, $3, $4, $5::text::cidr, $6, $7, NOW() - ($8::int * INTERVAL '1 hour'), NOW() - ($8::int * INTERVAL '1 hour'))",
                &[
                    &user_id,
                    &country,
                    &city,
                    &user_agent,
                    &ip,
                    &48.8566_f64,
                    &2.3522_f64,
                    &hours_ago,
                ],
            )
            .expect("failed to insert login location fixture");
    }
}

fn insert_login_attempts(client: &mut Client, user_id: uuid::Uuid, identifier: &str, ip: &str) {
    for offset in 0..180 {
        let was_successful = offset % 6 == 0;
        let other_identifier = format!("other-{offset}@example.com");
        let attempted_identifier = if offset % 2 == 0 {
            identifier
        } else {
            other_identifier.as_str()
        };
        let current_ip = if offset % 3 == 0 {
            ip
        } else {
            "198.51.100.200/32"
        };
        let failure_reason = if was_successful {
            None::<&str>
        } else {
            Some("invalid_password")
        };

        client
            .execute(
                "INSERT INTO login_attempts
                    (user_id, attempted_identifier, was_successful, failure_reason, request_ip, request_user_agent, attempted_at)
                 VALUES ($1, $2, $3, $4::text::login_failure_reason, $5::text::cidr, $6, NOW() - ($7::int * INTERVAL '1 minute'))",
                &[
                    &Some(user_id),
                    &attempted_identifier,
                    &was_successful,
                    &failure_reason,
                    &current_ip,
                    &Some("perf-test-agent"),
                    &(offset % 30),
                ],
            )
            .expect("failed to insert login attempt fixture");
    }
}
