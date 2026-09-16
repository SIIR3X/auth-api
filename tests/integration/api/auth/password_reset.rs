use crate::common::{app::TestApp, fixtures};

// forgot-password

#[tokio::test]
async fn forgot_password_returns_200_for_known_email() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_forgot_password_rate_limit(&app.client_ip).await;

    let res = app
        .post(
            "/auth/forgot-password",
            &serde_json::json!({ "email": user.email }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test]
async fn forgot_password_returns_200_for_unknown_email() {
    // Anti-enumeration: the endpoint must not reveal whether the email exists.
    let app = TestApp::spawn().await;
    app.clear_forgot_password_rate_limit(&app.client_ip).await;

    let res = app
        .post(
            "/auth/forgot-password",
            &serde_json::json!({ "email": "nobody@example.com" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);
}

// reset-password

#[tokio::test]
async fn reset_password_success_allows_login_with_new_password() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 2).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_reset_password_rate_limit(&app.client_ip).await;

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;
    let new_password = "NewPassword1!ok";

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": new_password,
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // Login with the new password must succeed.
    let login = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": new_password,
            }),
        )
        .await;
    assert_eq!(login.status().as_u16(), 200);

    // Login with the old password must fail.
    let old_login = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(old_login.status().as_u16(), 401);
}

#[tokio::test]
async fn reset_password_with_invalid_token_rejected() {
    let app = TestApp::spawn().await;
    app.clear_reset_password_rate_limit(&app.client_ip).await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": uuid::Uuid::new_v4().to_string(),
                "new_password": "NewPassword1!ok",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn reset_password_with_expired_token_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 3).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_reset_password_rate_limit(&app.client_ip).await;

    let token = fixtures::create_expired_password_reset_token(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "NewPassword1!ok",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn reset_password_with_already_used_token_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 4).await;
    fixtures::activate_user(&app.db, user.id).await;
    app.clear_reset_password_rate_limit(&app.client_ip).await;

    let token = fixtures::create_used_password_reset_token(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "NewPassword1!ok",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn reset_password_with_weak_password_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 5).await;
    fixtures::activate_user(&app.db, user.id).await;

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;

    // Too short - fails the validate_password check at handler level.
    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "short",
            }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 422);
}

#[tokio::test]
async fn reset_password_revokes_all_active_sessions() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 6).await;
    app.clear_reset_password_rate_limit(&app.client_ip).await;

    // Sanity: the token works before reset.
    let before = app.get_auth("/users/me", &user.access_token).await;
    assert_eq!(before.status().as_u16(), 200);

    let token = fixtures::create_password_reset_token(&app.db, user.id).await;

    let res = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({
                "token": token.raw,
                "new_password": "NewPassword1!ok",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // The old access token must no longer be valid (session revoked).
    let after = app.get_auth("/users/me", &user.access_token).await;
    assert!(
        after.status().as_u16() == 401 || after.status().as_u16() == 403,
        "expected 401 or 403 after password reset, got {}",
        after.status()
    );
}

// forgot-password rate limiting

#[tokio::test]
async fn forgot_password_rate_limited_after_5_requests() {
    // Use a unique virtual IP via X-Forwarded-For so the rate-limit counter is
    // completely isolated from other tests that share the real `fp_req:127.0.0.1` key.
    let app = TestApp::spawn_with_config(|c| {
        c.server.trusted_proxy_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
    })
    .await;

    let virtual_ip = "192.0.2.9"; // TEST-NET-1, unique to this test

    // Clear any leftover counter from a previous run sharing the same Redis.
    app.clear_forgot_password_rate_limit(virtual_ip).await;

    // Send 5 requests - all must succeed (limit rejects once count reaches 5).
    for _ in 0..5 {
        let res = app
            .client
            .post(format!("{}/auth/forgot-password", app.base_url))
            .header("X-Forwarded-For", virtual_ip)
            .json(&serde_json::json!({ "email": "anyone@example.com" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status().as_u16(),
            200,
            "requests before limit must succeed"
        );
    }

    // The 6th request must be rate-limited (429).
    let res = app
        .client
        .post(format!("{}/auth/forgot-password", app.base_url))
        .header("X-Forwarded-For", virtual_ip)
        .json(&serde_json::json!({ "email": "anyone@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status().as_u16(),
        429,
        "expected 429 after 5 forgot-password requests"
    );
}

// verify-email

#[tokio::test]
async fn verify_email_activates_unverified_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 7).await;
    app.clear_verify_email_rate_limit(&app.client_ip).await;

    // Account must be unverified initially (cannot login).
    let before = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(before.status().as_u16(), 403);

    let token = fixtures::create_email_verification_token(&app.db, user.id, &user.email).await;

    let res = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": token.raw }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    // After verification the user can log in.
    let after = app
        .post(
            "/auth/login",
            &serde_json::json!({
                "identifier": user.email,
                "password": user.password,
            }),
        )
        .await;
    assert_eq!(after.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_email_with_invalid_token_rejected() {
    let app = TestApp::spawn().await;
    app.clear_verify_email_rate_limit(&app.client_ip).await;

    let res = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": uuid::Uuid::new_v4().to_string() }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn verify_email_with_already_used_token_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 8).await;
    app.clear_verify_email_rate_limit(&app.client_ip).await;

    let token = fixtures::create_email_verification_token(&app.db, user.id, &user.email).await;

    // Use it once - succeeds.
    let first = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": token.raw }),
        )
        .await;
    assert_eq!(first.status().as_u16(), 200);

    // Clear rate limits so the second attempt reaches the "already consumed"
    // check instead of being blocked by rate limiting.
    app.clear_verify_email_token_hash_rate_limit(&token.raw)
        .await;
    app.clear_verify_email_rate_limit(&app.client_ip).await;
    app.clear_auth_rate_limit_key(&app.client_ip).await;

    // Use it again - must fail because it was already consumed.
    let second = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": token.raw }),
        )
        .await;
    assert_eq!(second.status().as_u16(), 401);
}

// resend verification

const VERIFICATION_SUBJECT: &str = "Verify your email address";

fn verification_mails(app: &TestApp, email: &str) -> Vec<testkit::mail::CapturedMail> {
    app.mail
        .messages_to(email)
        .into_iter()
        .filter(|mail| mail.subject == VERIFICATION_SUBJECT)
        .collect()
}

#[tokio::test]
async fn a_resent_verification_link_replaces_the_previous_one() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 900).await;
    let first = app
        .mail
        .wait_for(&user.email, VERIFICATION_SUBJECT)
        .await
        .value_after("token=")
        .expect("a verification link");

    let res = app
        .post(
            "/auth/verify-email/resend",
            &serde_json::json!({ "email": user.email }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let mails = app.mail.wait_for_count(&user.email, 2).await;
    let second = mails
        .last()
        .and_then(|mail| mail.value_after("token="))
        .expect("a second verification link");
    assert_ne!(first, second);

    app.clear_verify_email_rate_limit(&app.client_ip).await;
    let stale = app
        .post("/auth/verify-email", &serde_json::json!({ "token": first }))
        .await;
    assert_eq!(
        stale.status().as_u16(),
        401,
        "the previous link no longer works"
    );
    let fresh = app
        .post(
            "/auth/verify-email",
            &serde_json::json!({ "token": second }),
        )
        .await;
    assert_eq!(fresh.status().as_u16(), 200);
}

#[tokio::test]
async fn only_pending_accounts_receive_a_resent_verification() {
    let app = TestApp::spawn().await;
    let active = fixtures::register_user(&app, 901).await;
    fixtures::activate_user(&app.db, active.id).await;
    app.mail.wait_for(&active.email, VERIFICATION_SUBJECT).await;

    for email in [active.email.as_str(), "nobody901@example.com"] {
        let res = app
            .post(
                "/auth/verify-email/resend",
                &serde_json::json!({ "email": email }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 200);
    }

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(verification_mails(&app, &active.email).len(), 1);
    assert!(app.mail.messages_to("nobody901@example.com").is_empty());
}

#[tokio::test]
async fn resent_verifications_are_capped_per_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 902).await;
    app.mail.wait_for(&user.email, VERIFICATION_SUBJECT).await;

    for _ in 0..4 {
        let res = app
            .post(
                "/auth/verify-email/resend",
                &serde_json::json!({ "email": user.email }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 200, "the cap must stay silent");
    }

    app.mail.wait_for_count(&user.email, 4).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        verification_mails(&app, &user.email).len(),
        4,
        "the registration link and three resends"
    );
}

#[tokio::test]
async fn registering_again_on_a_pending_address_resends_the_verification() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 903).await;
    app.mail.wait_for(&user.email, VERIFICATION_SUBJECT).await;

    let res = app
        .post(
            "/auth/register",
            &serde_json::json!({
                "username": "testuser903bis",
                "email": user.email,
                "password": "Another-Password-903",
            }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 202);

    app.mail.wait_for_count(&user.email, 2).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let subjects: Vec<String> = app
        .mail
        .messages_to(&user.email)
        .into_iter()
        .map(|mail| mail.subject)
        .collect();
    assert_eq!(subjects, [VERIFICATION_SUBJECT, VERIFICATION_SUBJECT]);
}

#[tokio::test]
async fn a_password_reset_verifies_a_pending_account() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 904).await;
    app.clear_forgot_password_rate_limit(&app.client_ip).await;

    let res = app
        .post(
            "/auth/forgot-password",
            &serde_json::json!({ "email": user.email }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);
    let token = app
        .mail
        .wait_for(&user.email, "Reset your password")
        .await
        .value_after("token=")
        .expect("a reset link");

    let reset = app
        .post(
            "/auth/reset-password",
            &serde_json::json!({ "token": token, "new_password": "Owner-Chosen-904" }),
        )
        .await;
    assert_eq!(reset.status().as_u16(), 200);

    let login = app
        .post(
            "/auth/login",
            &serde_json::json!({ "identifier": user.email, "password": "Owner-Chosen-904" }),
        )
        .await;
    assert_eq!(
        login.status().as_u16(),
        200,
        "the owner of the address signs in with the password they chose"
    );
}

#[tokio::test]
async fn accounts_never_verified_are_purged_and_announced() {
    let app = TestApp::spawn().await;
    let old_pending = fixtures::register_user(&app, 905).await;
    let recent_pending = fixtures::register_user(&app, 906).await;
    let old_active = fixtures::register_user(&app, 907).await;
    fixtures::activate_user(&app.db, old_active.id).await;
    sqlx::query("UPDATE users SET created_at = NOW() - INTERVAL '8 days' WHERE id = ANY($1)")
        .bind(vec![old_pending.id, old_active.id])
        .execute(&app.db)
        .await
        .unwrap();

    auth_api::services::cleanup::run_once(&app.db, &app.state.config)
        .await
        .unwrap();

    let remaining: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE id = ANY($1) ORDER BY username")
            .bind(vec![old_pending.id, recent_pending.id, old_active.id])
            .fetch_all(&app.db)
            .await
            .unwrap();
    assert_eq!(remaining, [recent_pending.id, old_active.id]);

    let announced: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM event_outbox
         WHERE subject = 'events.auth.user.deleted' AND payload->>'user_id' = $1",
    )
    .bind(old_pending.id.to_string())
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(announced, 1, "downstream services erase the account too");

    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
         WHERE action = 'account_deleted' AND user_id IS NULL
           AND metadata->>'reason' = 'never_verified'",
    )
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(audited, 1);
}
