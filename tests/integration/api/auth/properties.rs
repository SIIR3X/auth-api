//! Properties of what the API accepts against what the database stores.
//!
//! Inputs are generated around the boundaries of the validators and of the
//! SQL constraints. Whatever the API accepts must be stored exactly as sent;
//! whatever the database would refuse must be refused first, as a 422, and
//! never surface as a constraint violation. A failure prints its input.

use std::collections::HashSet;

use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};
use serde_json::json;

use crate::common::{app::TestApp, fixtures};

fn sample<S: Strategy>(strategy: S, count: usize) -> Vec<S::Value> {
    let mut runner = TestRunner::default();
    (0..count)
        .map(|_| strategy.new_tree(&mut runner).unwrap().current())
        .collect()
}

#[tokio::test]
async fn accepted_registrations_are_stored_as_sent() {
    let app = TestApp::spawn().await;
    let usernames = sample(
        proptest::prop_oneof![
            "[a-zA-Z0-9_]{0,55}",
            "[a-zA-Z0-9_]{1,10}[^a-zA-Z0-9_][a-zA-Z0-9_]{1,10}",
            "\\PC{0,35}",
        ],
        300,
    );
    let emails = sample(
        proptest::prop_oneof![
            "[A-Za-z0-9._%+-]{1,24}@[A-Za-z0-9.-]{1,24}\\.[A-Za-z]{2,6}",
            "[A-Za-z0-9._%+-]{0,24}@[A-Za-z0-9.-]{0,24}\\.[A-Za-z0-9]{0,6}",
            "\\PC{0,20}@\\PC{0,20}",
            "[a-z]{230,250}@example\\.com",
        ],
        300,
    );

    let mut taken = HashSet::new();
    for (username, email) in usernames.into_iter().zip(emails) {
        let res = app
            .post(
                "/auth/register",
                &json!({ "username": username, "email": email, "password": "Password1!ok" }),
            )
            .await;
        let status = res.status().as_u16();
        assert!(
            matches!(status, 202 | 409 | 422),
            "{status} for username {username:?}, email {email:?}"
        );
        if status != 202 || !taken.insert(email.to_lowercase()) {
            continue;
        }
        let stored: Option<(String, String)> =
            sqlx::query_as("SELECT username, email FROM users WHERE email = $1")
                .bind(&email)
                .fetch_optional(&app.db)
                .await
                .unwrap();
        if let Some((stored_username, stored_email)) = stored {
            assert_eq!(stored_username, username, "username altered on the way in");
            assert_eq!(stored_email, email, "email altered on the way in");
        }
    }
}

#[tokio::test]
async fn any_device_name_signs_in_and_is_stored_as_its_label() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 1).await;
    fixtures::activate_user(&app.db, user.id).await;

    let names = sample(
        proptest::prop_oneof![
            "\\PC{0,160}",
            "[\\x00-\\x1f ]{0,5}\\PC{0,120}[\\x00-\\x1f ]{0,5}"
        ],
        150,
    );
    for name in names {
        let res = app
            .post(
                "/auth/login",
                &json!({
                    "identifier": user.email,
                    "password": user.password,
                    "device_name": name,
                }),
            )
            .await;
        assert_eq!(res.status().as_u16(), 200, "device name {name:?}");

        let stored: Option<String> = sqlx::query_scalar(
            "SELECT device_name FROM sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(user.id)
        .fetch_one(&app.db)
        .await
        .unwrap();
        assert_eq!(
            stored,
            auth_api::domain::session::device_label(&name),
            "device name {name:?}"
        );
    }
}
