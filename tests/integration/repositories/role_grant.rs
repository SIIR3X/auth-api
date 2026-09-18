//! `auth-api --grant-role`: granting a role from the command line.

use auth_api::cli::{RoleGrant, grant_role};

use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn granting_a_role_assigns_it_once_and_audits_it() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 980).await;
    let grant = RoleGrant {
        role: "admin".into(),
        email: user.email.clone(),
    };

    grant_role(&app.db, &grant).await.unwrap();
    grant_role(&app.db, &grant).await.unwrap();

    let holds: bool =
        auth_api::repositories::role::user_has_permission(&app.db, user.id, "users:manage")
            .await
            .unwrap();
    assert!(holds);
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE user_id = $1 AND action = 'role_assigned'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(audited, 1, "granting a role already held changes nothing");
}

#[tokio::test]
async fn an_unknown_role_or_account_is_refused() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 981).await;

    let unknown_role = grant_role(
        &app.db,
        &RoleGrant {
            role: "superuser".into(),
            email: user.email.clone(),
        },
    )
    .await;
    assert!(unknown_role.unwrap_err().contains("no role"));

    let unknown_account = grant_role(
        &app.db,
        &RoleGrant {
            role: "admin".into(),
            email: "nobody981@example.com".into(),
        },
    )
    .await;
    assert!(unknown_account.unwrap_err().contains("no account"));
}
