use crate::common::{app::TestApp, fixtures};

#[tokio::test]
async fn refresh_returns_new_tokens() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 1).await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    let new_access = body["access_token"].as_str().unwrap();
    let new_refresh = body["refresh_token"].as_str().unwrap();

    assert!(!new_access.is_empty());
    assert!(!new_refresh.is_empty());
    // Tokens must rotate
    assert_ne!(new_access, user.access_token);
    assert_ne!(new_refresh, user.refresh_token);
}

#[tokio::test]
async fn refresh_token_replay_is_rejected() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 2).await;

    // First refresh succeeds
    let res1 = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res1.status().as_u16(), 200);

    // Replaying the same refresh token must fail
    let res2 = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res2.status().as_u16(), 401);
}

#[tokio::test]
async fn refresh_invalid_token_rejected() {
    let app = TestApp::spawn().await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": "not-a-valid-token" }),
        )
        .await;

    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn new_access_token_is_usable() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 3).await;

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(res.status().as_u16(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    let new_access = body["access_token"].as_str().unwrap();

    let profile_res = app.get_auth("/users/me", new_access).await;
    assert_eq!(profile_res.status().as_u16(), 200);
}

#[tokio::test]
async fn concurrent_refresh_only_allows_one_success() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 4).await;

    let client_a = app.client.clone();
    let client_b = app.client.clone();
    let url = format!("{}/auth/refresh", app.base_url);
    let payload = serde_json::json!({ "refresh_token": user.refresh_token });

    let req_a = client_a.post(&url).json(&payload).send();
    let req_b = client_b.post(&url).json(&payload).send();
    let (res_a, res_b) = tokio::join!(req_a, req_b);

    let status_a = res_a.unwrap().status().as_u16();
    let status_b = res_b.unwrap().status().as_u16();
    let success_count = [status_a, status_b]
        .into_iter()
        .filter(|status| *status == 200)
        .count();

    assert_eq!(
        success_count, 1,
        "expected exactly one successful refresh, got {status_a} and {status_b}"
    );
    assert!(
        [status_a, status_b]
            .into_iter()
            .all(|status| status == 200 || status == 401),
        "expected one success and one auth failure, got {status_a} and {status_b}"
    );
}

// P3: token theft detection

#[tokio::test]
async fn refresh_token_theft_invalidates_entire_session_family() {
    // Scenario:
    //   1. Login → get refresh_token R0.
    //   2. Refresh with R0 → get R1 (R0 is now revoked).
    //   3. Replay R0 → server detects theft and revokes the whole family.
    //   4. R1 must also be rejected (family revoked).
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 6).await;

    // Step 2: first legitimate refresh.
    let r1_body: serde_json::Value = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await
        .json()
        .await
        .unwrap();
    let token_r1 = r1_body["refresh_token"].as_str().unwrap().to_owned();
    let access_r1 = r1_body["access_token"].as_str().unwrap().to_owned();

    // Verify R1 works before the theft detection.
    let check = app.get_auth("/users/me", &access_r1).await;
    assert_eq!(
        check.status().as_u16(),
        200,
        "R1 access token should be valid before theft"
    );

    // Step 3: replay the original token - triggers family revocation.
    let replay = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(
        replay.status().as_u16(),
        401,
        "replaying R0 must be rejected"
    );

    // Step 4: R1 must now also be rejected (family revoked).
    let r1_attempt = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": token_r1 }),
        )
        .await;
    assert_eq!(
        r1_attempt.status().as_u16(),
        401,
        "R1 must be rejected after family revocation due to theft detection"
    );
}

// P3: refresh edge cases

#[tokio::test]
async fn refresh_rate_limited_after_20_invalid_tokens() {
    // Use a unique virtual IP via X-Forwarded-For so the failure counter is
    // isolated from other tests. Spawn with loopback as a trusted proxy so the
    // extractor picks up the spoofed header.
    let app = TestApp::spawn_with_config(|c| {
        c.server.trusted_proxy_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
    })
    .await;

    let virtual_ip = "192.0.2.100"; // TEST-NET-1, unique to this test

    // Send 20 invalid tokens to reach the failure limit for the virtual IP.
    for i in 0..20 {
        app.client
            .post(format!("{}/auth/refresh", app.base_url))
            .header("X-Forwarded-For", virtual_ip)
            .json(&serde_json::json!({ "refresh_token": format!("invalid-{i}") }))
            .send()
            .await
            .unwrap();
    }

    // The 21st request must be rate-limited (429).
    let res = app
        .client
        .post(format!("{}/auth/refresh", app.base_url))
        .header("X-Forwarded-For", virtual_ip)
        .json(&serde_json::json!({ "refresh_token": "invalid-probe" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status().as_u16(),
        429,
        "expected 429 after 20 invalid refresh token attempts"
    );
}

#[tokio::test]
async fn refresh_blocked_after_logout() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 7).await;

    let refresh_token = user.refresh_token.clone();

    // Logout - this should blocklist the refresh token in Redis.
    let logout = app
        .post_auth("/auth/logout", &user.access_token, &serde_json::json!({}))
        .await;
    assert_eq!(logout.status().as_u16(), 204);

    // Attempt to use the old refresh token after logout - must fail.
    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": refresh_token }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        401,
        "refresh after logout must be rejected"
    );
}

#[tokio::test]
async fn refresh_fails_after_account_suspended() {
    let app = TestApp::spawn().await;
    let user = fixtures::authenticated_user(&app, 8).await;

    // Suspend the account after login.
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(user.id)
        .execute(&app.db)
        .await
        .expect("failed to suspend user");

    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        403,
        "expected 403 when refreshing with a suspended account"
    );
}

#[tokio::test]
async fn refresh_rejects_mismatched_ip_with_strict_binding() {
    // Spawn app with strict_session_binding=true.
    let app = TestApp::spawn_with_config(|c| {
        c.jwt.strict_session_binding = true;
    })
    .await;

    let user = fixtures::authenticated_user(&app, 9).await;

    // Forge a different IP in the session record to simulate an IP change.
    sqlx::query("UPDATE sessions SET ip_address = '10.0.0.1/32' WHERE token_hash = $1")
        .bind(rust_api::utils::crypto::sha256(user.refresh_token.as_bytes()).as_ref())
        .execute(&app.db)
        .await
        .expect("failed to update session IP");

    // Refresh from 127.0.0.1 (the test client IP) - session IP is now 10.0.0.1 → mismatch.
    let res = app
        .post(
            "/auth/refresh",
            &serde_json::json!({ "refresh_token": user.refresh_token }),
        )
        .await;
    assert_eq!(
        res.status().as_u16(),
        401,
        "expected 401 for IP mismatch with strict_session_binding"
    );
}
