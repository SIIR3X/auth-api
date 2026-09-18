//! `/admin/users`.

use serde_json::{Value, json};
use uuid::Uuid;

use super::{admin, body, enroll_second_factor, sign_in, token_with};
use crate::common::{app::TestApp, fixtures};

async fn audit_metadata(app: &TestApp, user_id: Uuid, action: &str) -> Vec<Value> {
    sqlx::query_scalar(
        "SELECT metadata FROM audit_log WHERE user_id = $1 AND action = $2::audit_action
         ORDER BY created_at",
    )
    .bind(user_id)
    .bind(action)
    .fetch_all(&app.db)
    .await
    .unwrap()
}

async fn outbox_subjects(app: &TestApp, user_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT subject FROM event_outbox WHERE payload->>'user_id' = $1 ORDER BY seq",
    )
    .bind(user_id.to_string())
    .fetch_all(&app.db)
    .await
    .unwrap()
}

// Access

#[tokio::test]
async fn an_account_without_administrative_permission_is_refused() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let (status, response) = body(app.get_auth("/admin/users", &user.access_token).await).await;
    assert_eq!(status, 403);
    assert_eq!(response["code"], "forbidden");
}

#[tokio::test]
async fn an_administrator_without_a_second_factor_is_refused() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let token = token_with(&app, &user, &["users:read"]);

    let (status, response) = body(app.get_auth("/admin/users", &token).await).await;
    assert_eq!(status, 403);
    assert_eq!(response["code"], "two_factor_required");
}

#[tokio::test]
async fn a_permission_revoked_in_the_database_stops_working_before_the_token_expires() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    assert_eq!(
        app.get_auth("/admin/users", &admin.token).await.status(),
        200
    );

    sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
        .bind(admin.user.id)
        .execute(&app.db)
        .await
        .unwrap();

    assert_eq!(
        app.get_auth("/admin/users", &admin.token).await.status(),
        403
    );
}

#[tokio::test]
async fn each_action_requires_its_own_permission() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;
    let reader = token_with(&app, &admin.user, &["users:read"]);

    let path = format!("/admin/users/{}", target.id);
    assert_eq!(app.get_auth(&path, &reader).await.status(), 200);
    let (status, _) = body(
        app.post_auth(&format!("{path}/suspend"), &reader, &json!({}))
            .await,
    )
    .await;
    assert_eq!(status, 403);
}

// Reading

#[tokio::test]
async fn accounts_are_searched_by_prefix_and_status_page_by_page() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    for index in 10..13 {
        fixtures::authenticated_user(&app, index).await;
    }
    fixtures::register_user(&app, 20).await;

    let (status, page) = body(
        app.get_auth("/admin/users?query=TESTUSER1&limit=2", &admin.token)
            .await,
    )
    .await;
    assert_eq!(status, 200, "{page}");
    let first: Vec<&str> = page["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(first, ["testuser12", "testuser11"]);

    let cursor = page["next_cursor"].as_str().unwrap();
    let (_, next) = body(
        app.get_auth(
            &format!("/admin/users?query=testuser1&limit=2&cursor={cursor}"),
            &admin.token,
        )
        .await,
    )
    .await;
    let rest: Vec<&str> = next["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(rest, ["testuser10", "testuser1"]);
    assert!(next.get("next_cursor").is_none());

    let (_, pending) = body(
        app.get_auth("/admin/users?status=pending_verification", &admin.token)
            .await,
    )
    .await;
    let pending = pending["users"].as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["username"], "testuser20");

    // Wildcards match themselves.
    let (_, none) = body(app.get_auth("/admin/users?query=%25", &admin.token).await).await;
    assert!(none["users"].as_array().unwrap().is_empty());

    let (status, _) = body(
        app.get_auth("/admin/users?status=banned", &admin.token)
            .await,
    )
    .await;
    assert_eq!(status, 422);
}

#[tokio::test]
async fn an_account_detail_shows_roles_factors_and_sessions() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;
    enroll_second_factor(&app, target.id).await;

    let (status, detail) = body(
        app.get_auth(&format!("/admin/users/{}", target.id), &admin.token)
            .await,
    )
    .await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["email"], target.email);
    assert_eq!(detail["status"], "active");
    assert_eq!(detail["roles"], json!(["user"]));
    assert_eq!(detail["two_factor_methods"], 1);
    assert_eq!(detail["active_sessions"], 1);
    assert!(detail.get("password_hash").is_none());

    let (status, _) = body(
        app.get_auth(&format!("/admin/users/{}", Uuid::new_v4()), &admin.token)
            .await,
    )
    .await;
    assert_eq!(status, 404);
}

// Acting

#[tokio::test]
async fn a_suspended_account_is_signed_out_and_cannot_sign_in_until_reactivated() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;
    let path = format!("/admin/users/{}", target.id);

    for _ in 0..2 {
        let (status, response) = body(
            app.post_auth(&format!("{path}/suspend"), &admin.token, &json!({}))
                .await,
        )
        .await;
        assert_eq!(status, 204, "{response}");
    }

    assert_eq!(
        app.get_auth("/users/me", &target.access_token)
            .await
            .status(),
        401
    );
    let (status, response) = sign_in(&app, &target.email, &target.password).await;
    assert_eq!(status, 403);
    assert_eq!(response["code"], "account_suspended");

    let suspended = audit_metadata(&app, target.id, "account_suspended").await;
    assert_eq!(suspended.len(), 1, "suspending twice records one change");
    assert_eq!(suspended[0]["administrator_id"], admin.user.id.to_string());
    assert_eq!(suspended[0]["sessions_revoked"], 1);

    let (status, _) = body(
        app.post_auth(&format!("{path}/reactivate"), &admin.token, &json!({}))
            .await,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = sign_in(&app, &target.email, &target.password).await;
    assert_eq!(status, 200);

    let subjects = outbox_subjects(&app, target.id).await;
    assert!(
        subjects.contains(&"events.auth.user.suspended".to_owned()),
        "{subjects:?}"
    );
    assert!(
        subjects.contains(&"events.auth.user.reactivated".to_owned()),
        "{subjects:?}"
    );
}

#[tokio::test]
async fn an_administrator_cannot_suspend_their_own_account_or_a_pending_one() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let pending = fixtures::register_user(&app, 2).await;

    let (status, _) = body(
        app.post_auth(
            &format!("/admin/users/{}/suspend", admin.user.id),
            &admin.token,
            &json!({}),
        )
        .await,
    )
    .await;
    assert_eq!(status, 403);

    let (status, _) = body(
        app.post_auth(
            &format!("/admin/users/{}/suspend", pending.id),
            &admin.token,
            &json!({}),
        )
        .await,
    )
    .await;
    assert_eq!(status, 422);
}

#[tokio::test]
async fn unlocking_ends_the_lockout_and_forgives_the_failures() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;
    for _ in 0..3 {
        sign_in(&app, &target.email, "WrongPassword1!").await;
    }
    let (_, locked) = sign_in(&app, &target.email, &target.password).await;
    assert_eq!(locked["code"], "account_locked");

    let (status, _) = body(
        app.post_auth(
            &format!("/admin/users/{}/unlock", target.id),
            &admin.token,
            &json!({}),
        )
        .await,
    )
    .await;
    assert_eq!(status, 204);

    // One more mistake does not lock the account again at once.
    let (status, _) = sign_in(&app, &target.email, "WrongPassword1!").await;
    assert_eq!(status, 401);
    let (status, response) = sign_in(&app, &target.email, &target.password).await;
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        audit_metadata(&app, target.id, "account_unlocked")
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn revoking_the_sessions_of_an_account_signs_it_out_everywhere() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;

    let (status, response) = body(
        app.delete_auth(
            &format!("/admin/users/{}/sessions", target.id),
            &admin.token,
        )
        .await,
    )
    .await;
    assert_eq!(status, 200, "{response}");
    assert_eq!(response["revoked"], 1);
    assert_eq!(
        app.get_auth("/users/me", &target.access_token)
            .await
            .status(),
        401
    );
    let refresh = app
        .post(
            "/auth/refresh",
            &json!({ "refresh_token": target.refresh_token }),
        )
        .await;
    assert_eq!(refresh.status(), 401);
}

#[tokio::test]
async fn a_forced_reset_signs_the_account_out_and_mails_a_link() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;

    let (status, _) = body(
        app.post_auth(
            &format!("/admin/users/{}/password-reset", target.id),
            &admin.token,
            &json!({}),
        )
        .await,
    )
    .await;
    assert_eq!(status, 204);

    let mail = app
        .mail
        .wait_for(&target.email, "Reset your password")
        .await;
    assert!(mail.html.contains("reset"), "{}", mail.html);
    assert_eq!(
        app.get_auth("/users/me", &target.access_token)
            .await
            .status(),
        401
    );
    assert_eq!(
        audit_metadata(&app, target.id, "password_reset_forced").await[0]["sessions_revoked"],
        1
    );
}

#[tokio::test]
async fn deleting_an_account_needs_a_recent_reauthentication_and_announces_it() {
    let app = TestApp::spawn().await;
    let admin = admin(&app, 1).await;
    let target = fixtures::authenticated_user(&app, 2).await;
    let path = format!("/admin/users/{}", target.id);
    app.clear_recent_reauth(&admin.token).await;

    let (status, response) = body(app.delete_auth(&path, &admin.token).await).await;
    assert_eq!(status, 403);
    assert_eq!(response["code"], "reauthentication_required");

    let (status, response) = body(
        app.delete_auth_json(
            &path,
            &admin.token,
            &json!({ "current_password": admin.user.password }),
        )
        .await,
    )
    .await;
    assert_eq!(status, 204, "{response}");
    assert_eq!(app.get_auth(&path, &admin.token).await.status(), 404);

    let subjects = outbox_subjects(&app, target.id).await;
    assert!(
        subjects.contains(&"events.auth.user.deleted".to_owned()),
        "{subjects:?}"
    );
    let deletion: Vec<Value> = sqlx::query_scalar(
        "SELECT metadata FROM audit_log WHERE action = 'account_deleted' AND user_id IS NULL",
    )
    .fetch_all(&app.db)
    .await
    .unwrap();
    assert_eq!(deletion.len(), 1);
    assert_eq!(deletion[0]["administrator_id"], admin.user.id.to_string());

    let (status, _) = body(
        app.delete_auth_json(
            &format!("/admin/users/{}", admin.user.id),
            &admin.token,
            &json!({ "current_password": admin.user.password }),
        )
        .await,
    )
    .await;
    assert_eq!(
        status, 403,
        "an administrator does not delete their own account here"
    );
}
