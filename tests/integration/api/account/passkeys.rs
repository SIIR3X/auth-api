//! Passkeys: registration on an account, and signing in with them.

use serde_json::{Value, json};
use testkit::authenticator::SoftAuthenticator;

use crate::common::{
    app::TestApp,
    fixtures::{self, AuthenticatedUser},
};

async fn post(app: &TestApp, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
    let response = match token {
        Some(token) => app.post_auth(path, token, &body).await,
        None => app.post(path, &body).await,
    };
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn register(
    app: &TestApp,
    user: &AuthenticatedUser,
    authenticator: &mut SoftAuthenticator,
) -> (u16, Value) {
    let (status, options) = post(
        app,
        "/users/me/passkeys/options",
        Some(&user.access_token),
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{options}");
    let credential = authenticator.create(&options);
    post(
        app,
        "/users/me/passkeys",
        Some(&user.access_token),
        json!({ "name": "Laptop", "credential": credential }),
    )
    .await
}

async fn sign_in(app: &TestApp, authenticator: &mut SoftAuthenticator) -> (u16, Value) {
    let (_, options) = post(app, "/auth/passkeys/options", None, json!({})).await;
    let credential = authenticator.get(&options);
    post(
        app,
        "/auth/passkeys/sign-in",
        None,
        json!({ "credential": credential }),
    )
    .await
}

#[tokio::test]
async fn a_passkey_signs_in_without_password_or_second_factor() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    sqlx::query(
        "INSERT INTO two_factor_methods (user_id, method_type, is_primary, is_verified)
         VALUES ($1, 'email', TRUE, TRUE)",
    )
    .bind(user.id)
    .execute(&app.db)
    .await
    .unwrap();
    let mut authenticator = SoftAuthenticator::for_app(&app);

    let (status, registered) = register(&app, &user, &mut authenticator).await;
    assert_eq!(status, 201, "{registered}");
    assert_eq!(registered["passkey"]["name"], "Laptop");
    assert_eq!(registered["passkey"]["algorithm"], -7);
    assert_eq!(
        registered["recovery_codes"].as_array().unwrap().len(),
        10,
        "a first passkey comes with recovery codes"
    );

    let (status, tokens) = sign_in(&app, &mut authenticator).await;
    assert_eq!(status, 200, "{tokens}");
    let me: Value = app
        .get_auth("/users/me", tokens["access_token"].as_str().unwrap())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(me["id"], user.id.to_string());

    let login: Value = sqlx::query_scalar(
        "SELECT metadata FROM audit_log WHERE user_id = $1 AND action = 'login'
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(login["method"], "passkey");

    let listed: Value = app
        .get_auth("/users/me/passkeys", &user.access_token)
        .await
        .json()
        .await
        .unwrap();
    assert!(listed[0]["last_used_at"].is_number());

    // A second passkey: recovery codes already exist.
    let mut second = SoftAuthenticator::for_app(&app);
    let (status, registered) = register(&app, &user, &mut second).await;
    assert_eq!(status, 201);
    assert!(registered.get("recovery_codes").is_none());
}

#[tokio::test]
async fn a_registration_is_verified_before_it_is_stored() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let mut foreign = SoftAuthenticator::for_app(&app);
    foreign.origin = "https://evil.example.com".into();
    let (status, body) = register(&app, &user, &mut foreign).await;
    assert_eq!(status, 422, "{body}");

    let mut unverified = SoftAuthenticator::for_app(&app);
    unverified.flags = 0x01;
    assert_eq!(register(&app, &user, &mut unverified).await.0, 422);

    let mut authenticator = SoftAuthenticator::for_app(&app);
    let (_, options) = post(
        &app,
        "/users/me/passkeys/options",
        Some(&user.access_token),
        json!({}),
    )
    .await;
    let credential = authenticator.create(&options);
    let body = json!({ "name": "Laptop", "credential": credential });
    assert_eq!(
        post(
            &app,
            "/users/me/passkeys",
            Some(&user.access_token),
            body.clone()
        )
        .await
        .0,
        201
    );
    // The challenge was used: the same response cannot register again.
    assert_eq!(
        post(&app, "/users/me/passkeys", Some(&user.access_token), body)
            .await
            .0,
        422
    );

    // Another account cannot claim a credential already registered.
    let other = fixtures::authenticated_user(&app, 2).await;
    let (status, _) = register(&app, &other, &mut authenticator).await;
    assert_eq!(status, 409);

    app.clear_recent_reauth(&user.access_token).await;
    let (status, body) = post(
        &app,
        "/users/me/passkeys/options",
        Some(&user.access_token),
        json!({}),
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("reauthentication_required"))
    );
}

#[tokio::test]
async fn forged_replayed_or_cloned_assertions_are_refused() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let mut authenticator = SoftAuthenticator::for_app(&app);
    register(&app, &user, &mut authenticator).await;

    // Replay: the challenge is used once.
    let (_, options) = post(&app, "/auth/passkeys/options", None, json!({})).await;
    let credential = authenticator.get(&options);
    let body = json!({ "credential": credential });
    assert_eq!(
        post(&app, "/auth/passkeys/sign-in", None, body.clone())
            .await
            .0,
        200
    );
    let (status, refused) = post(&app, "/auth/passkeys/sign-in", None, body).await;
    assert_eq!(
        (status, refused["code"].as_str()),
        (401, Some("invalid_credentials"))
    );

    // A clone: the counter does not grow.
    authenticator.counter -= 1;
    assert_eq!(sign_in(&app, &mut authenticator).await.0, 401);
    authenticator.counter += 5;

    // Without user verification.
    authenticator.flags = 0x01;
    assert_eq!(sign_in(&app, &mut authenticator).await.0, 401);
    authenticator.flags = 0x05;

    // Another key claiming the same credential.
    let mut impostor = SoftAuthenticator::for_app(&app);
    impostor.credential_id = authenticator.credential_id.clone();
    impostor.user_handle = authenticator.user_handle.clone();
    impostor.counter = 100;
    assert_eq!(sign_in(&app, &mut impostor).await.0, 401);

    // Without the user handle, which a discoverable credential always carries.
    let (_, options) = post(&app, "/auth/passkeys/options", None, json!({})).await;
    let mut credential = authenticator.get(&options);
    credential["response"]
        .as_object_mut()
        .unwrap()
        .remove("userHandle");
    let (status, refused) = post(
        &app,
        "/auth/passkeys/sign-in",
        None,
        json!({ "credential": credential }),
    )
    .await;
    assert_eq!(
        (status, refused["code"].as_str()),
        (401, Some("invalid_credentials"))
    );

    // An unknown credential.
    let mut stranger = SoftAuthenticator::for_app(&app);
    stranger.user_handle = authenticator.user_handle.clone();
    assert_eq!(sign_in(&app, &mut stranger).await.0, 401);

    // The genuine authenticator still works.
    assert_eq!(sign_in(&app, &mut authenticator).await.0, 200);

    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .unwrap();
    let (status, body) = sign_in(&app, &mut authenticator).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("account_suspended"))
    );
}

#[tokio::test]
async fn a_removed_passkey_no_longer_signs_in() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let mut authenticator = SoftAuthenticator::for_app(&app);
    let (_, registered) = register(&app, &user, &mut authenticator).await;
    let id = registered["passkey"]["id"].as_str().unwrap();

    let other = fixtures::authenticated_user(&app, 2).await;
    let response = app
        .delete_auth(&format!("/users/me/passkeys/{id}"), &other.access_token)
        .await;
    assert_eq!(response.status(), 404);

    let response = app
        .delete_auth(&format!("/users/me/passkeys/{id}"), &user.access_token)
        .await;
    assert_eq!(response.status(), 204);
    assert_eq!(sign_in(&app, &mut authenticator).await.0, 401);
}

#[tokio::test]
async fn a_passkey_sign_in_is_the_second_factor_of_an_administrator() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;
    let role = auth_api::repositories::role::find_by_name(&app.db, "admin")
        .await
        .unwrap()
        .unwrap();
    auth_api::repositories::role::assign_to_user(&app.db, user.id, role.id, None)
        .await
        .unwrap();
    let mut authenticator = SoftAuthenticator::for_app(&app);
    register(&app, &user, &mut authenticator).await;

    // Enrolled is not enough: this session came from the password.
    let token = crate::api::admin::token_with(&app, &user, &["users:read"]);
    assert_eq!(app.get_auth("/admin/users", &token).await.status(), 403);

    let (_, signed_in) = sign_in(&app, &mut authenticator).await;
    let mut claims = app.decode_access_token(signed_in["access_token"].as_str().unwrap());
    claims.permissions = vec!["users:read".into()];
    let token = app.sign(&claims);
    assert_eq!(app.get_auth("/admin/users", &token).await.status(), 200);
}

/// The administration trusts a session only if its sign-in proved a second
/// factor: a passkey with user verification does, a password alone does not.
#[tokio::test]
async fn only_a_sign_in_with_a_second_factor_marks_its_session() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 40).await;
    let mut authenticator = SoftAuthenticator::for_app(&app);
    let (status, _) = register(&app, &user, &mut authenticator).await;
    assert_eq!(status, 201);

    let mfa_of = |token: String| {
        let app = &app;
        async move {
            let sid = app.decode_access_token(&token).sid;
            sqlx::query_scalar::<_, bool>("SELECT mfa FROM sessions WHERE id = $1")
                .bind(sid)
                .fetch_one(&app.db)
                .await
                .unwrap()
        }
    };
    assert!(!mfa_of(user.access_token.clone()).await, "password sign-in");

    let (status, signed_in) = sign_in(&app, &mut authenticator).await;
    assert_eq!(status, 200, "{signed_in}");
    let token = signed_in["access_token"].as_str().unwrap().to_owned();
    assert!(mfa_of(token).await, "passkey sign-in");

    // A refresh keeps it.
    let refreshed: Value = app
        .post(
            "/auth/refresh",
            &json!({ "refresh_token": signed_in["refresh_token"] }),
        )
        .await
        .json()
        .await
        .unwrap();
    let token = refreshed["access_token"].as_str().unwrap().to_owned();
    assert!(mfa_of(token).await, "rotation");
}
