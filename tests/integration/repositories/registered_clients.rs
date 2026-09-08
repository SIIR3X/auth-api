//! The client registry written by `auth-api --register-client`.

use auth_api::repositories::registered_client::{self, NewRegisteredClient};
use testkit::TestDb;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[tokio::test]
async fn upsert_creates_then_updates_every_setting() {
    let db = TestDb::new().await;
    let scopes = strings(&["users:read"]);
    let redirects = strings(&["http://127.0.0.1/callback"]);

    let created = registered_client::upsert(
        &db.pool,
        &NewRegisteredClient {
            client_id: "native.app",
            display_name: "Native",
            is_primary: false,
            scopes: &scopes,
            redirect_uris: &redirects,
            allows_loopback_redirect: true,
            default_max_sessions: 3,
        },
    )
    .await
    .unwrap();
    assert_eq!(created.display_name, "Native");
    assert_eq!(created.scopes, scopes);
    assert_eq!(created.redirect_uris, redirects);
    assert!(created.allows_loopback_redirect);
    assert_eq!(created.default_max_sessions, 3);

    let no_scopes: Vec<String> = Vec::new();
    let new_redirects = strings(&["https://app.example.com/callback"]);
    let updated = registered_client::upsert(
        &db.pool,
        &NewRegisteredClient {
            client_id: "native.app",
            display_name: "Native 2",
            is_primary: false,
            scopes: &no_scopes,
            redirect_uris: &new_redirects,
            allows_loopback_redirect: false,
            default_max_sessions: 7,
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.client_id, "native.app");
    assert_eq!(updated.display_name, "Native 2");
    assert!(updated.scopes.is_empty(), "scopes are replaced, not merged");
    assert_eq!(updated.redirect_uris, new_redirects);
    assert!(!updated.allows_loopback_redirect);
    assert_eq!(updated.default_max_sessions, 7);
    assert_eq!(updated.created_at, created.created_at);

    let found = registered_client::find_by_id(&db.pool, "native.app")
        .await
        .unwrap()
        .expect("the client is registered");
    assert_eq!(found.display_name, "Native 2");
    assert!(
        registered_client::find_by_id(&db.pool, "unknown.app")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn only_one_client_can_be_primary() {
    let db = TestDb::new().await;
    let none: Vec<String> = Vec::new();
    let primary = |client_id: &'static str| NewRegisteredClient {
        client_id,
        display_name: "Primary",
        is_primary: true,
        scopes: &none,
        redirect_uris: &none,
        allows_loopback_redirect: false,
        default_max_sessions: 5,
    };

    registered_client::upsert(&db.pool, &primary("first.app"))
        .await
        .unwrap();
    let found = registered_client::find_primary(&db.pool)
        .await
        .unwrap()
        .expect("a primary client");
    assert_eq!(found.client_id, "first.app");

    let second = registered_client::upsert(&db.pool, &primary("second.app")).await;
    let error = second.expect_err("a second primary client must be refused");
    let database_error = error.as_database_error().expect("a database error");
    assert_eq!(database_error.code().as_deref(), Some("23505"));
}

#[tokio::test]
async fn client_ids_outside_the_allowed_format_are_refused() {
    let db = TestDb::new().await;
    let none: Vec<String> = Vec::new();
    for client_id in ["bad id", "tabs\tare\tout", "\u{1f600}.app", ""] {
        let result = registered_client::upsert(
            &db.pool,
            &NewRegisteredClient {
                client_id,
                display_name: "Bad",
                is_primary: false,
                scopes: &none,
                redirect_uris: &none,
                allows_loopback_redirect: false,
                default_max_sessions: 5,
            },
        )
        .await;
        testkit::sql::assert_constraint_error(
            &result.expect_err("a malformed client id must be refused"),
            "registered_clients_client_id_format",
        );
    }
}
