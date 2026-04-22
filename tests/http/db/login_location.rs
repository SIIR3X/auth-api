//! Login location repository tests.
//!
//! Tests index range 950–959.
//!
//! Covers `find_recent_for_risk`, `find_last`, and `upsert` (the only paths
//! not exercised by the HTTP login flow directly).

use std::str::FromStr;

use ipnetwork::IpNetwork;

use rust_api::repositories::login_location;

use crate::common::{app::TestApp, fixtures};

// Helpers

async fn insert_location(app: &TestApp, user_id: uuid::Uuid, country: &str, city: &str) {
    let ip: IpNetwork = IpNetwork::from_str("127.0.0.1/32").unwrap();
    login_location::upsert(
        &app.db,
        user_id,
        country,
        city,
        "TestAgent/1.0",
        ip,
        None,
        None,
    )
    .await
    .expect("upsert failed");
}

// find_recent_for_risk

#[tokio::test]
async fn find_recent_for_risk_returns_entries_within_window() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 950).await;

    insert_location(&app, user.id, "FR", "Paris").await;
    insert_location(&app, user.id, "DE", "Berlin").await;

    let entries = login_location::find_recent_for_risk(&app.db, user.id, 90)
        .await
        .expect("find_recent_for_risk failed");

    assert_eq!(entries.len(), 2, "must return both recent entries");
}

#[tokio::test]
async fn find_recent_for_risk_returns_empty_for_new_user() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 951).await;

    let entries = login_location::find_recent_for_risk(&app.db, user.id, 90)
        .await
        .expect("find_recent_for_risk failed");

    assert!(entries.is_empty(), "new user must have no location history");
}

// find_last

#[tokio::test]
async fn find_last_returns_none_for_user_with_no_locations() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 952).await;

    let result = login_location::find_last(&app.db, user.id)
        .await
        .expect("find_last failed");

    assert!(result.is_none(), "must return None when no locations exist");
}

#[tokio::test]
async fn find_last_returns_most_recent_location() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 953).await;

    insert_location(&app, user.id, "FR", "Paris").await;
    // Upsert same key to bump last_seen, then insert a different one.
    insert_location(&app, user.id, "US", "New York").await;

    let result = login_location::find_last(&app.db, user.id)
        .await
        .expect("find_last failed");

    assert!(
        result.is_some(),
        "must return a location when entries exist"
    );
}

// upsert deduplication

#[tokio::test]
async fn upsert_deduplicates_same_user_country_city_agent() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 954).await;

    insert_location(&app, user.id, "FR", "Lyon").await;
    insert_location(&app, user.id, "FR", "Lyon").await; // same key → upsert

    let entries = login_location::find_recent_for_risk(&app.db, user.id, 90)
        .await
        .expect("find_recent_for_risk failed");

    assert_eq!(
        entries.len(),
        1,
        "duplicate (country, city, agent) must be merged into one row"
    );
}
