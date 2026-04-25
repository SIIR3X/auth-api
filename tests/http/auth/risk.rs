//! HTTP-level risk scoring integration tests.
//!
//! Most tests run without a GeoIP database (path empty) and rely on the two
//! signals that work without geo data:
//!   - new_device  (+20): user-agent not seen before
//!   - unusual_hour (+15): login between 00:00 and 05:59 UTC
//!
//! The geo-signal tests at the bottom of this file use the MaxMind
//! GeoIP2-City test database (`tests/fixtures/GeoIP2-City-Test.mmdb`) and
//! rely on `trusted_proxy_cidrs` so that the `X-Forwarded-For` header is
//! honoured by the extractor.

use crate::common::{app::TestApp, fixtures};

// helpers

/// Seed a `login_locations` row for a user directly in the DB so the risk scorer
/// sees a "known device" history entry.
async fn seed_known_location(app: &TestApp, user_id: uuid::Uuid, user_agent: &str) {
    sqlx::query(
        "INSERT INTO login_locations
            (user_id, country, city, user_agent, ip_address, last_seen, first_seen)
         VALUES ($1, '', '', $2, '127.0.0.1/32', NOW(), NOW())
         ON CONFLICT (user_id, country, city, user_agent) DO UPDATE SET last_seen = NOW()",
    )
    .bind(user_id)
    .bind(user_agent)
    .execute(&app.db)
    .await
    .expect("failed to seed login_location");
}

// Block decision

#[tokio::test]
async fn login_blocked_when_risk_score_exceeds_block_threshold() {
    // block_threshold = 15, new_device = +20 --> score 20 > 15 --> Block --> 403
    let app = TestApp::spawn_with_config(|c| {
        c.risk.alert_threshold = 5;
        c.risk.challenge_threshold = 10;
        c.risk.block_threshold = 15;
    })
    .await;

    let user = fixtures::register_user(&app, 300).await;
    fixtures::activate_user(&app.db, user.id).await;

    // First login: no history --> new_device fires (+20) --> blocked.
    let res = app
        .client
        .post(format!("{}/auth/login", app.base_url))
        .header(reqwest::header::USER_AGENT, "SuspiciousBrowser/99.0")
        .json(&serde_json::json!({
            "identifier": user.email,
            "password": user.password,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status().as_u16(),
        403,
        "expected 403 login_blocked for high-risk score"
    );
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["code"].as_str(), Some("login_blocked"));
}

#[tokio::test]
async fn login_allowed_for_known_device_below_threshold() {
    // Same thresholds as above, but seed the user-agent first.
    // score = 0 (known device, normal hour) --> Allow --> 200.
    // block_threshold must exceed SCORE_UNUSUAL_HOUR (15) so that a login
    // during 00:00-05:59 UTC does not cause a spurious block.
    let app = TestApp::spawn_with_config(|c| {
        c.risk.alert_threshold = 5;
        c.risk.challenge_threshold = 10;
        c.risk.block_threshold = 20;
    })
    .await;

    let user = fixtures::register_user(&app, 301).await;
    fixtures::activate_user(&app.db, user.id).await;

    let ua = "TrustedBrowser/1.0";
    seed_known_location(&app, user.id, ua).await;

    let res = app
        .client
        .post(format!("{}/auth/login", app.base_url))
        .header(reqwest::header::USER_AGENT, ua)
        .json(&serde_json::json!({
            "identifier": user.email,
            "password": user.password,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status().as_u16(),
        200,
        "known device should not be blocked even with tight thresholds"
    );
}

// Challenge decision

#[tokio::test]
async fn login_challenged_when_risk_score_exceeds_challenge_threshold() {
    // challenge_threshold = 15, new_device = +20 --> Challenge --> email 2FA required.
    // block_threshold is set high so we don't hit it.
    let app = TestApp::spawn_with_config(|c| {
        c.risk.alert_threshold = 5;
        c.risk.challenge_threshold = 15;
        c.risk.block_threshold = 100;
    })
    .await;

    let user = fixtures::register_user(&app, 302).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .client
        .post(format!("{}/auth/login", app.base_url))
        .header(reqwest::header::USER_AGENT, "UnknownBrowser/5.0")
        .json(&serde_json::json!({
            "identifier": user.email,
            "password": user.password,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status().as_u16(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(
        body["two_factor_required"].as_bool(),
        Some(true),
        "expected 2FA challenge for high-risk login"
    );
    assert_eq!(
        body["two_factor_method"].as_str(),
        Some("email"),
        "expected email 2FA fallback for challenge without configured TOTP"
    );
}

// Alert decision (audit log)

#[tokio::test]
async fn login_alert_creates_suspicious_login_audit_entry() {
    // alert_threshold = 15, challenge_threshold = 100 --> Alert only.
    // new_device (+20) > 15 --> Alert --> audit entry + login still succeeds.
    let app = TestApp::spawn_with_config(|c| {
        c.risk.alert_threshold = 15;
        c.risk.challenge_threshold = 100;
        c.risk.block_threshold = 200;
    })
    .await;

    let user = fixtures::register_user(&app, 303).await;
    fixtures::activate_user(&app.db, user.id).await;

    let res = app
        .client
        .post(format!("{}/auth/login", app.base_url))
        .header(reqwest::header::USER_AGENT, "NewBrowser/3.0")
        .json(&serde_json::json!({
            "identifier": user.email,
            "password": user.password,
        }))
        .send()
        .await
        .unwrap();

    // Alert does NOT block login - should return 200 (direct) or a pre_auth flow.
    assert!(
        res.status().as_u16() == 200,
        "alert decision must not block login, got {}",
        res.status()
    );

    // Verify a suspicious_login audit entry was written.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE user_id = $1 AND action = 'suspicious_login'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .expect("audit_log query failed");

    assert!(
        count >= 1,
        "expected at least one suspicious_login audit entry, got {count}"
    );
}

// Default thresholds: no block for normal logins

#[tokio::test]
async fn login_succeeds_normally_with_default_thresholds_and_no_history() {
    // Default config: alert=30, challenge=60, block=80.
    // new_device (+20) < alert (30) --> Allow with no extra steps.
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 304).await;
    assert!(!user.access_token.is_empty());
}

// GeoIP signal tests (real MaxMind test database)
//
// These tests use the GeoIP2-City test mmdb fixture and set
// trusted_proxy_cidrs = 127.0.0.1/32 so the X-Forwarded-For header is
// trusted and the geo lookup uses the spoofed IP.
//
// Known IPs in the test DB:
//   81.2.69.142  --> GB (United Kingdom), London
//   175.16.199.1 --> CN (China)

const GEOIP_TEST_DB: &str = "tests/fixtures/GeoIP2-City-Test.mmdb";

/// Seed a login_locations row from a specific country/city so the next login
/// from a different country triggers the new_country signal.
async fn seed_location_country(
    app: &TestApp,
    user_id: uuid::Uuid,
    country: &str,
    city: &str,
    user_agent: &str,
) {
    sqlx::query(
        "INSERT INTO login_locations
            (user_id, country, city, user_agent, ip_address, last_seen, first_seen)
         VALUES ($1, $2, $3, $4, '1.2.3.4/32', NOW(), NOW())
         ON CONFLICT (user_id, country, city, user_agent) DO UPDATE SET last_seen = NOW()",
    )
    .bind(user_id)
    .bind(country)
    .bind(city)
    .bind(user_agent)
    .execute(&app.db)
    .await
    .expect("failed to seed login_location");
}

#[tokio::test]
async fn geoip_new_country_signal_triggers_block_with_real_db() {
    // new_country (+40) via real geo lookup.
    // Seed history from CN, login with IP from GB --> new_country fires.
    // block_threshold = 35 --> 40 > 35 --> Block.
    let app = TestApp::spawn_with_config(|c| {
        c.risk.geoip_db_path = GEOIP_TEST_DB.into();
        c.risk.alert_threshold = 10;
        c.risk.challenge_threshold = 20;
        c.risk.block_threshold = 35;
        // Trust the test server (127.0.0.1) as a reverse proxy so that
        // X-Forwarded-For is used as the client IP.
        c.server.trusted_proxy_cidrs = vec!["127.0.0.1/32".parse().unwrap()];
    })
    .await;

    let user = fixtures::register_user(&app, 305).await;
    fixtures::activate_user(&app.db, user.id).await;

    let ua = "GeoTestBrowser/1.0";

    // Seed history: user was last seen from China (city irrelevant for country test).
    seed_location_country(&app, user.id, "CN", "", ua).await;

    // Login with X-Forwarded-For = 81.2.69.142 (GB, London).
    let res = app
        .client
        .post(format!("{}/auth/login", app.base_url))
        .header(reqwest::header::USER_AGENT, ua)
        .header("x-forwarded-for", "81.2.69.142")
        .json(&serde_json::json!({
            "identifier": user.email,
            "password": user.password,
        }))
        .send()
        .await
        .unwrap();

    // new_country (+40) > block_threshold (35) --> 403 login_blocked.
    assert_eq!(
        res.status().as_u16(),
        403,
        "expected 403 login_blocked for new-country login from GB after CN history"
    );
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["code"].as_str(), Some("login_blocked"));
}

#[tokio::test]
async fn geoip_known_country_does_not_add_score() {
    // Seed history from GB/London, login again from GB/London --> no geo signal.
    // new_device is also known --> score = 0 (or 15 if unusual_hour) --> Allow.
    // Thresholds are set above SCORE_UNUSUAL_HOUR (15) so that a login during
    // 00:00-05:59 UTC does not cause a spurious block or challenge.
    let app = TestApp::spawn_with_config(|c| {
        c.risk.geoip_db_path = GEOIP_TEST_DB.into();
        c.risk.alert_threshold = 20;
        c.risk.challenge_threshold = 30;
        c.risk.block_threshold = 40;
        c.server.trusted_proxy_cidrs = vec!["127.0.0.1/32".parse().unwrap()];
    })
    .await;

    let user = fixtures::register_user(&app, 306).await;
    fixtures::activate_user(&app.db, user.id).await;

    let ua = "GeoTestBrowser/2.0";
    // Seed history: user was last seen from GB/London with this same user-agent.
    // City must match the GeoIP lookup for 81.2.69.142 to avoid a new_city signal.
    seed_location_country(&app, user.id, "GB", "London", ua).await;

    let res = app
        .client
        .post(format!("{}/auth/login", app.base_url))
        .header(reqwest::header::USER_AGENT, ua)
        .header("x-forwarded-for", "81.2.69.142") // still GB
        .json(&serde_json::json!({
            "identifier": user.email,
            "password": user.password,
        }))
        .send()
        .await
        .unwrap();

    // score = 0 --> Allow --> 200 with tokens.
    assert_eq!(
        res.status().as_u16(),
        200,
        "login from known country/device must be allowed"
    );
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body["access_token"].as_str().is_some(),
        "expected access_token in response for known-country login"
    );
}
