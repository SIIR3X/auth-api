//! Login attempt repository tests.

use auth_api::repositories::login_attempt;
use time::{Duration, OffsetDateTime};

use crate::common::{app::TestApp, fixtures};

/// Failures typed before the account was unlocked, reset or signed in no
/// longer count against its identifier: whoever typed them cannot keep the
/// owner out past that (SEC-76).
#[tokio::test]
async fn failures_before_an_unlock_no_longer_count_against_the_identifier() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 62).await;
    for _ in 0..4 {
        sqlx::query(
            "INSERT INTO login_attempts (user_id, attempted_identifier, was_successful, failure_reason)
             VALUES ($1, $2, FALSE, 'invalid_password')",
        )
        .bind(user.id)
        .bind(&user.email)
        .execute(&app.db)
        .await
        .unwrap();
    }
    let cutoff = OffsetDateTime::now_utc() - Duration::minutes(15);
    assert_eq!(
        login_attempt::count_recent_failures_by_identifier(&app.db, &user.email, cutoff, 10)
            .await
            .unwrap(),
        4
    );

    sqlx::query("UPDATE users SET lockout_cleared_at = NOW() WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();
    assert_eq!(
        login_attempt::count_recent_failures_by_identifier(&app.db, &user.email, cutoff, 10)
            .await
            .unwrap(),
        0
    );
}
