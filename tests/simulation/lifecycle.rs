//! Accounts through random sequences of what their owners do, checked against a
//! model after every step.
//!
//! Sequences of sign-ins, refreshes, sign-outs, password changes, revocations
//! and deletions are generated for a few accounts and played against the real
//! API. A model tracks which sessions must still work. After every step, every
//! session the model knows is tried, the database must hold exactly the live
//! sessions the model expects, and the audit log must never shrink. A failure
//! prints the sequence that led to it.

use proptest::{prelude::*, strategy::ValueTree, test_runner::TestRunner};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::{app::TestApp, fixtures};

const ACCOUNTS: usize = 3;
const SEQUENCES: usize = 6;
const STEPS: usize = 30;

#[derive(Debug, Clone, Copy)]
enum Action {
    SignIn,
    Refresh(usize),
    SignOut(usize),
    ChangePassword(usize),
    SignOutEverywhere(usize),
    Delete(usize),
}

/// The index an action carries picks one of the account's live sessions.
fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        4 => Just(Action::SignIn),
        5 => (0..8usize).prop_map(Action::Refresh),
        2 => (0..8usize).prop_map(Action::SignOut),
        1 => (0..8usize).prop_map(Action::ChangePassword),
        1 => (0..8usize).prop_map(Action::SignOutEverywhere),
        1 => (0..8usize).prop_map(Action::Delete),
    ]
}

struct Session {
    access: String,
    refresh: String,
    live: bool,
}

struct Account {
    id: Uuid,
    email: String,
    password: String,
    deleted: bool,
    sessions: Vec<Session>,
    password_changes: usize,
}

impl Account {
    fn live(&self) -> Vec<usize> {
        (0..self.sessions.len())
            .filter(|&i| self.sessions[i].live)
            .collect()
    }

    fn pick(&self, n: usize) -> Option<usize> {
        let live = self.live();
        (!live.is_empty()).then(|| live[n % live.len()])
    }
}

#[tokio::test]
async fn accounts_follow_their_model_through_random_lifecycles() {
    let mut runner = TestRunner::default();
    let plan = proptest::collection::vec((0..ACCOUNTS, action()), STEPS);
    for sequence in 0..SEQUENCES {
        let steps = plan.new_tree(&mut runner).unwrap().current();
        play(sequence, &steps).await;
    }
}

async fn play(sequence: usize, steps: &[(usize, Action)]) {
    let app = TestApp::spawn().await;
    let mut accounts = Vec::new();
    for index in 0..ACCOUNTS {
        let user = fixtures::register_user(&app, index + 1).await;
        fixtures::activate_user(&app.db, user.id).await;
        accounts.push(Account {
            id: user.id,
            email: user.email,
            password: user.password,
            deleted: false,
            sessions: Vec::new(),
            password_changes: 0,
        });
    }
    let mut audit_rows = count_audit_rows(&app).await;

    for (step, &(who, action)) in steps.iter().enumerate() {
        let context = format!(
            "sequence {sequence}, step {step}: {action:?} on account {who}; sequence {steps:?}"
        );
        apply(&app, &mut accounts[who], action, &context).await;
        check(&app, &accounts, &context).await;

        let rows = count_audit_rows(&app).await;
        assert!(rows >= audit_rows, "the audit log shrank at {context}");
        audit_rows = rows;
    }
}

async fn apply(app: &TestApp, account: &mut Account, action: Action, context: &str) {
    if account.deleted {
        return;
    }
    match action {
        Action::SignIn => {
            let res = sign_in(app, account).await;
            assert_eq!(res.status().as_u16(), 200, "sign-in refused at {context}");
            let body: Value = res.json().await.unwrap();
            account.sessions.push(Session {
                access: text(&body, "access_token"),
                refresh: text(&body, "refresh_token"),
                live: true,
            });
        }
        Action::Refresh(n) => {
            let Some(i) = account.pick(n) else { return };
            let res = app
                .post(
                    "/auth/refresh",
                    &json!({ "refresh_token": account.sessions[i].refresh }),
                )
                .await;
            assert_eq!(res.status().as_u16(), 200, "refresh refused at {context}");
            let body: Value = res.json().await.unwrap();
            account.sessions[i].access = text(&body, "access_token");
            account.sessions[i].refresh = text(&body, "refresh_token");
        }
        Action::SignOut(n) => {
            let Some(i) = account.pick(n) else { return };
            let res = app
                .post_auth("/auth/logout", &account.sessions[i].access, &json!({}))
                .await;
            assert_eq!(res.status().as_u16(), 204, "sign-out refused at {context}");
            end(app, account, &[i], context).await;
        }
        Action::ChangePassword(n) => {
            let Some(i) = account.pick(n) else { return };
            account.password_changes += 1;
            let new_password = format!("Lifecycle-{}-Pass!", account.password_changes);
            let res = app
                .patch_auth(
                    "/users/me/password",
                    &account.sessions[i].access,
                    &json!({ "current_password": account.password, "new_password": new_password }),
                )
                .await;
            assert_eq!(
                res.status().as_u16(),
                204,
                "password change refused at {context}"
            );
            account.password = new_password;
            // Every session ends, the one that changed the password included.
            let all = account.live();
            end(app, account, &all, context).await;
        }
        Action::SignOutEverywhere(n) => {
            let Some(i) = account.pick(n) else { return };
            let res = app
                .delete_auth_json(
                    "/users/me/sessions",
                    &account.sessions[i].access,
                    &json!({ "current_password": account.password }),
                )
                .await;
            assert_eq!(
                res.status().as_u16(),
                204,
                "revocation refused at {context}"
            );
            // Signing out everywhere includes the session that asked.
            let all = account.live();
            end(app, account, &all, context).await;
        }
        Action::Delete(n) => {
            let Some(i) = account.pick(n) else { return };
            let res = app
                .delete_auth_json(
                    "/users/me",
                    &account.sessions[i].access,
                    &json!({ "current_password": account.password }),
                )
                .await;
            assert_eq!(res.status().as_u16(), 204, "deletion refused at {context}");
            account.deleted = true;
            for j in account.live() {
                account.sessions[j].live = false;
            }
            let res = sign_in(app, account).await;
            assert_eq!(
                res.status().as_u16(),
                401,
                "a deleted account signed in at {context}"
            );
        }
    }
}

/// Mark sessions ended; each one's refresh token must be refused from now on.
async fn end(app: &TestApp, account: &mut Account, ended: &[usize], context: &str) {
    for &i in ended {
        account.sessions[i].live = false;
        let res = app
            .post(
                "/auth/refresh",
                &json!({ "refresh_token": account.sessions[i].refresh }),
            )
            .await;
        assert_eq!(
            res.status().as_u16(),
            401,
            "an ended session refreshed at {context}"
        );
    }
}

async fn check(app: &TestApp, accounts: &[Account], context: &str) {
    for account in accounts {
        for (i, session) in account.sessions.iter().enumerate() {
            let status = app
                .get_auth("/users/me", &session.access)
                .await
                .status()
                .as_u16();
            let expected = if session.live { 200 } else { 401 };
            assert_eq!(
                status, expected,
                "access token of session {i} (live: {}) of account {} at {context}",
                session.live, account.email
            );
        }

        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sessions
             WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()",
        )
        .bind(account.id)
        .fetch_one(&app.db)
        .await
        .unwrap();
        assert_eq!(
            usize::try_from(live).unwrap(),
            account.live().len(),
            "live sessions of {} in the database at {context}",
            account.email
        );
    }
}

async fn sign_in(app: &TestApp, account: &Account) -> reqwest::Response {
    app.post(
        "/auth/login",
        &json!({ "identifier": account.email, "password": account.password }),
    )
    .await
}

async fn count_audit_rows(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(&app.db)
        .await
        .unwrap()
}

fn text(body: &Value, key: &str) -> String {
    body[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} missing from {body}"))
        .to_owned()
}
