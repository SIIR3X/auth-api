//! `/admin/audit`.

use serde_json::json;

use super::{admin, body, token_with};
use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn the_audit_log_of_every_account_is_filtered_and_paged() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let first = fixtures::authenticated_user(&app, 2).await;
    fixtures::authenticated_user(&app, 3).await;

    let (status, page) = body(
        app.get_auth("/admin/audit?action=login&limit=2", &admin.token)
            .await,
    )
    .await;
    assert_eq!(status, 200, "{page}");
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e["action"] == "login"));
    let cursor = page["next_cursor"].as_str().unwrap();

    let (_, next) = body(
        app.get_auth(
            &format!("/admin/audit?action=login&limit=2&cursor={cursor}"),
            &admin.token,
        )
        .await,
    )
    .await;
    assert_eq!(next["entries"].as_array().unwrap().len(), 1);
    assert!(next.get("next_cursor").is_none());

    let (_, mine) = body(
        app.get_auth(&format!("/admin/audit?user_id={}", first.id), &admin.token)
            .await,
    )
    .await;
    let mine = mine["entries"].as_array().unwrap();
    assert!(!mine.is_empty());
    assert!(mine.iter().all(|e| e["user_id"] == json!(first.id)));

    let (status, _) = body(app.get_auth("/admin/audit?cursor=nope", &admin.token).await).await;
    assert_eq!(status, 422);

    let without = token_with(&app, &admin.user, &["users:read"]);
    assert_eq!(app.get_auth("/admin/audit", &without).await.status(), 403);
}
