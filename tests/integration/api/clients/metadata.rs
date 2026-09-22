//! `/.well-known/oauth-authorization-server` (RFC 8414).

use serde_json::Value;

use crate::common::app::TestApp;

#[tokio::test]
async fn the_metadata_describes_the_endpoints_and_capabilities() {
    let app = TestApp::spawn().await;
    sqlx::query(
        "INSERT INTO registered_clients (client_id, display_name, scopes)
         VALUES ('reporting', 'Reporting', ARRAY['users:read'])",
    )
    .execute(&app.db)
    .await
    .unwrap();
    let response = app.get("/.well-known/oauth-authorization-server").await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "public, max-age=300");
    let metadata: Value = response.json().await.unwrap();

    let issuer = app.state.config.server.public_url.trim_end_matches('/');
    assert_eq!(metadata["issuer"], issuer);
    assert_eq!(metadata["token_endpoint"], format!("{issuer}/oauth/token"));
    assert_eq!(
        metadata["authorization_endpoint"],
        format!("{issuer}/oauth/authorize")
    );
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert!(
        metadata["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&"urn:ietf:params:oauth:grant-type:device_code".into())
    );
    // Only what some client may ask for: not the whole permission catalog.
    assert_eq!(
        metadata["scopes_supported"],
        serde_json::json!(["users:read"])
    );
    assert_eq!(
        metadata["authorization_response_iss_parameter_supported"],
        true
    );
}
