//! Audit repository read-function tests.
//!
//! Tests index range 940–949.
//!
//! `append` is exercised by every HTTP integration test that triggers an
//! auditable action; these tests cover the three read paths that are not
//! reached via the HTTP layer.

use auth_api::{
    domain::audit::AuditAction,
    repositories::audit::{self, NewAuditEntry},
};
use uuid::Uuid;

use crate::common::{app::TestApp, fixtures};

// Helpers

async fn append_entry(
    app: &TestApp,
    user_id: Option<Uuid>,
    action: AuditAction,
    request_id: Option<Uuid>,
) {
    audit::append(
        &app.db,
        &NewAuditEntry {
            user_id,
            request_id,
            action,
            ip_address: None,
            metadata: serde_json::json!({}),
        },
    )
    .await
    .expect("audit::append failed");
}

// find_by_user

#[tokio::test]
async fn find_by_user_returns_entries_for_that_user() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 940).await;
    let other = fixtures::register_user(&app, 941).await;

    // Snapshot count before we add our own entries (register_user itself creates
    // audit entries, so we measure the delta rather than an absolute count).
    let before = audit::find_by_user(&app.db, user.id, 100, 0)
        .await
        .expect("find_by_user (before) failed")
        .len();

    append_entry(&app, Some(user.id), AuditAction::Login, None).await;
    append_entry(&app, Some(user.id), AuditAction::PasswordChanged, None).await;
    append_entry(&app, Some(other.id), AuditAction::Login, None).await;

    let entries = audit::find_by_user(&app.db, user.id, 100, 0)
        .await
        .expect("find_by_user failed");

    assert_eq!(
        entries.len(),
        before + 2,
        "must return exactly 2 new entries for this user"
    );
    assert!(entries.iter().all(|e| e.user_id == Some(user.id)));
}

#[tokio::test]
async fn find_by_user_respects_limit_and_offset() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 942).await;

    // Snapshot existing entries then add 5 more so total = initial + 5.
    let initial = audit::find_by_user(&app.db, user.id, 100, 0)
        .await
        .expect("initial count failed")
        .len();

    for _ in 0..5 {
        append_entry(&app, Some(user.id), AuditAction::Login, None).await;
    }

    let total = initial + 5;

    let page1 = audit::find_by_user(&app.db, user.id, 3, 0)
        .await
        .expect("page1 failed");
    let page2 = audit::find_by_user(&app.db, user.id, 3, 3)
        .await
        .expect("page2 failed");

    assert_eq!(page1.len(), 3, "page1 must have 3 entries");
    assert_eq!(
        page2.len(),
        total - 3,
        "page2 must have the remaining entries"
    );
}

// find_by_action

#[tokio::test]
async fn find_by_action_returns_only_matching_action() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 943).await;
    append_entry(&app, Some(user.id), AuditAction::Register, None).await;
    append_entry(&app, Some(user.id), AuditAction::Register, None).await;
    append_entry(&app, Some(user.id), AuditAction::Login, None).await;

    let entries = audit::find_by_action(&app.db, AuditAction::Register, 10, 0)
        .await
        .expect("find_by_action failed");

    assert!(
        entries.len() >= 2,
        "must return at least the 2 Register entries"
    );
    assert!(
        entries.iter().all(|e| e.action == AuditAction::Register),
        "all returned entries must have action=Register"
    );
}

#[tokio::test]
async fn find_by_action_respects_limit() {
    let app = TestApp::spawn().await;

    let user = fixtures::register_user(&app, 944).await;
    for _ in 0..4 {
        append_entry(&app, Some(user.id), AuditAction::LoginFailed, None).await;
    }

    let entries = audit::find_by_action(&app.db, AuditAction::LoginFailed, 2, 0)
        .await
        .expect("find_by_action with limit failed");

    assert_eq!(entries.len(), 2, "limit=2 must return at most 2 entries");
}

// find_by_request_id

#[tokio::test]
async fn find_by_request_id_returns_all_events_for_request() {
    let app = TestApp::spawn().await;

    let req_id = Uuid::new_v4();
    let other_req = Uuid::new_v4();

    // user_id=None is allowed (no FK constraint when NULL)
    append_entry(&app, None, AuditAction::Login, Some(req_id)).await;
    append_entry(&app, None, AuditAction::TwoFactorVerified, Some(req_id)).await;
    append_entry(&app, None, AuditAction::Login, Some(other_req)).await;

    let entries = audit::find_by_request_id(&app.db, req_id)
        .await
        .expect("find_by_request_id failed");

    assert_eq!(
        entries.len(),
        2,
        "must return exactly the 2 entries for this request_id"
    );
    assert!(entries.iter().all(|e| e.request_id == Some(req_id)));
}

#[tokio::test]
async fn find_by_request_id_returns_empty_for_unknown_id() {
    let app = TestApp::spawn().await;

    let entries = audit::find_by_request_id(&app.db, Uuid::new_v4())
        .await
        .expect("find_by_request_id failed");

    assert!(
        entries.is_empty(),
        "unknown request_id must return empty list"
    );
}
