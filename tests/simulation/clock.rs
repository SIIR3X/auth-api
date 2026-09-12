//! The service over time, driven by the application clock instead of sleeps.

use serde_json::{Value, json};
use time::Duration;

use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn a_session_ends_at_its_absolute_lifetime_however_often_it_refreshes() {
    let app = TestApp::spawn_with_config(|config| {
        config.jwt.max_session_lifetime_secs = 3 * 86_400;
        config.jwt.refresh_expiry_secs = 30 * 86_400;
        config.jwt.short_session_expiry_secs = 30 * 86_400;
    })
    .await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let mut refresh_token = user.refresh_token;

    // A client refreshing every day stays signed in until the lifetime...
    for day in 1..3 {
        app.clock.advance(Duration::days(1));
        let res = app
            .post("/auth/refresh", &json!({ "refresh_token": refresh_token }))
            .await;
        assert_eq!(res.status().as_u16(), 200, "refresh refused on day {day}");
        let body: Value = res.json().await.unwrap();
        refresh_token = body["refresh_token"].as_str().unwrap().to_owned();
    }

    // ...and not a second longer.
    app.clock.advance(Duration::days(1));
    let res = app
        .post("/auth/refresh", &json!({ "refresh_token": refresh_token }))
        .await;
    assert_eq!(res.status().as_u16(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "token_expired");
}

#[tokio::test]
async fn a_lockout_lifts_when_its_duration_has_passed() {
    let app = TestApp::spawn_with_config(|config| {
        config.security.lockout_threshold = 3;
        config.security.lockout_duration_secs = 1800;
    })
    .await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;
    let login = |password: &str| json!({ "identifier": user.email.clone(), "password": password.to_owned() });

    for _ in 0..3 {
        let res = app.post("/auth/login", &login("Wrong-password1!")).await;
        assert_eq!(res.status().as_u16(), 401);
    }
    let locked = app.post("/auth/login", &login(&user.password)).await;
    assert_eq!(locked.status().as_u16(), 403);

    app.clock.advance(Duration::minutes(29));
    let still_locked = app.post("/auth/login", &login(&user.password)).await;
    assert_eq!(still_locked.status().as_u16(), 403);

    // Past the lockout and past the 15-minute brute-force window.
    app.clock.advance(Duration::minutes(2));
    let unlocked = app.post("/auth/login", &login(&user.password)).await;
    assert_eq!(unlocked.status().as_u16(), 200, "the lockout never lifted");
}

#[tokio::test]
async fn an_access_token_expires_with_the_application_clock() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    // The clock is the wall clock plus an offset and token times are whole
    // seconds, so the real time spent signing in blurs the last second: the
    // exact boundary is pinned by `time_claims_follow_the_supplied_clock`.
    app.clock.advance(Duration::seconds(890));
    let before = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(before.status().as_u16(), 200);

    app.clock.advance(Duration::seconds(11));
    let after = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(after.status().as_u16(), 401);
}

#[tokio::test]
async fn a_rotated_session_is_never_dated_past_its_absolute_lifetime() {
    let app = TestApp::spawn_with_config(|config| {
        config.jwt.max_session_lifetime_secs = 3 * 86_400;
        config.jwt.refresh_expiry_secs = 30 * 86_400;
        config.jwt.short_session_expiry_secs = 30 * 86_400;
    })
    .await;
    let user = fixtures::authenticated_user(&app, 2).await;

    app.clock.advance(Duration::days(1));
    let res = app
        .post(
            "/auth/refresh",
            &json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // The database clock does not follow the application clock: a minute of
    // slack covers the gap between them, not a 30-day refresh lifetime.
    let overdue: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sessions
         WHERE user_id = $1 AND expires_at > family_created_at + interval '3 days 1 minute'",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(overdue, 0, "a session outlives its sign-in");
}
