//! What an account can read about itself: its security history and its
//! second factors.

use serde_json::{Value, json};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::common::{app::TestApp, fixtures};

async fn audit_page(app: &TestApp, token: &str, query: &str) -> (u16, Value) {
    let res = app
        .get_auth(&format!("/users/me/audit{query}"), token)
        .await;
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_audit_history_pages_through_every_entry_once_newest_first() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 760).await;
    let other = fixtures::authenticated_user(&app, 761).await;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE user_id = $1")
        .bind(user.id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert!(total >= 2, "sign-up and sign-in are audited");

    let mut seen = Vec::new();
    let mut timestamps = Vec::new();
    let mut query = "?limit=1".to_owned();
    loop {
        let (status, page) = audit_page(&app, &user.access_token, &query).await;
        assert_eq!(status, 200);
        let entries = page["entries"].as_array().unwrap();
        assert!(entries.len() <= 1);
        for entry in entries {
            seen.push(entry["id"].as_str().unwrap().to_owned());
            timestamps.push(entry["created_at"].as_i64().unwrap());
        }
        match page["next_cursor"].as_str() {
            Some(cursor) => query = format!("?limit=1&cursor={cursor}"),
            None => break,
        }
    }

    assert_eq!(seen.len() as i64, total, "every entry exactly once");
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), seen.len(), "no entry repeated across pages");
    assert!(timestamps.windows(2).all(|w| w[0] >= w[1]), "newest first");

    // The most recent entry is the re-authentication done by the fixture.
    let (_, first) = audit_page(&app, &user.access_token, "?limit=1").await;
    assert_eq!(first["entries"][0]["action"], "reauthenticated");

    // Another account sees none of these entries.
    let (_, theirs) = audit_page(&app, &other.access_token, "?limit=200").await;
    let their_ids: Vec<&str> = theirs["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert!(seen.iter().all(|id| !their_ids.contains(&id.as_str())));
}

#[tokio::test]
async fn a_forged_cursor_is_refused_and_the_history_needs_a_session() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 762).await;

    let (status, _) = audit_page(&app, &user.access_token, "?cursor=bm90LWEtY3Vyc29y").await;
    assert_eq!(status, 422);

    let res = app
        .client
        .get(format!("{}/users/me/audit", app.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn the_two_factor_overview_lists_methods_and_remaining_recovery_codes() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 763).await;

    let overview: Value = app
        .get_auth("/users/me/two-factor", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        overview,
        json!({ "methods": [], "recovery_codes_remaining": 0 })
    );

    let setup: Value = app
        .post_auth(
            "/users/me/two-factor/totp/setup",
            &user.access_token,
            &json!({}),
        )
        .await
        .json()
        .await
        .unwrap();
    let method_id = setup["method_id"].as_str().unwrap().to_owned();
    let secret = Secret::Encoded(setup["base32_secret"].as_str().unwrap().to_owned())
        .to_bytes()
        .unwrap();
    let code = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)
        .unwrap()
        .generate_current()
        .unwrap();

    let verified: Value = app
        .post_auth(
            &format!("/users/me/two-factor/totp/{method_id}/verify"),
            &user.access_token,
            &json!({ "code": code }),
        )
        .await
        .json()
        .await
        .unwrap();
    let issued = verified["recovery_codes"].as_array().unwrap().len() as i64;

    let overview: Value = app
        .get_auth("/users/me/two-factor", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    let methods = overview["methods"].as_array().unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0]["id"], method_id.as_str());
    assert_eq!(methods[0]["method_type"], "totp");
    assert_eq!(methods[0]["is_verified"], true);
    assert_eq!(methods[0]["is_primary"], true);
    assert_eq!(overview["recovery_codes_remaining"], issued);
}
