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

    app.clock.advance(Duration::seconds(899));
    let before = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(before.status().as_u16(), 200);

    app.clock.advance(Duration::seconds(1));
    let after = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(after.status().as_u16(), 401);
}
