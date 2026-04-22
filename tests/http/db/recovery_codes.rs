//! Recovery code repository tests.
//!
//! Tests index range 960–969.
//!
//! Covers `create_batch`, `replace_all_by_user`, `find_unused_by_user`,
//! and the empty-batch early-return inside `insert_batch_in_tx`.

use auth_api::{repositories::recovery_code, utils::crypto};

use crate::common::{app::TestApp, fixtures};

// Helpers

/// Build N code entries: (position, hash_of_"code{i}").
/// Positions start at 1 to satisfy the `recovery_codes_position_range` CHECK (1..=20).
fn make_codes(n: usize) -> Vec<(i16, Vec<u8>)> {
    (1..=n)
        .map(|i| {
            let hash = crypto::sha256(format!("recovery-code-{i}").as_bytes());
            (i as i16, hash.to_vec())
        })
        .collect()
}

// create_batch

#[tokio::test]
async fn create_batch_inserts_all_codes() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 960).await;

    let owned = make_codes(10);
    let codes: Vec<(i16, &[u8])> = owned.iter().map(|(pos, h)| (*pos, h.as_slice())).collect();

    recovery_code::create_batch(&app.db, user.id, &codes, None)
        .await
        .expect("create_batch failed");

    let stored = recovery_code::find_unused_by_user(&app.db, user.id)
        .await
        .expect("find_unused_by_user failed");

    assert_eq!(stored.len(), 10, "must store all 10 codes");
}

#[tokio::test]
async fn create_batch_with_empty_slice_stores_nothing() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 961).await;

    // Empty slice triggers the early-return inside insert_batch_in_tx.
    recovery_code::create_batch(&app.db, user.id, &[], None)
        .await
        .expect("create_batch with empty slice must not error");

    let stored = recovery_code::find_unused_by_user(&app.db, user.id)
        .await
        .expect("find_unused_by_user failed");

    assert!(
        stored.is_empty(),
        "no codes must be stored for an empty batch"
    );
}

// replace_all_by_user

#[tokio::test]
async fn replace_all_by_user_replaces_existing_codes() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 962).await;

    // Insert initial set.
    let first_owned = make_codes(5);
    let first: Vec<(i16, &[u8])> = first_owned
        .iter()
        .map(|(p, h)| (*p, h.as_slice()))
        .collect();
    recovery_code::create_batch(&app.db, user.id, &first, None)
        .await
        .expect("initial create_batch failed");

    // Replace with a new set of 3 codes.
    let second_owned = make_codes(3);
    let second: Vec<(i16, &[u8])> = second_owned
        .iter()
        .map(|(p, h)| (*p, h.as_slice()))
        .collect();
    recovery_code::replace_all_by_user(&app.db, user.id, &second, None)
        .await
        .expect("replace_all_by_user failed");

    let stored = recovery_code::find_unused_by_user(&app.db, user.id)
        .await
        .expect("find_unused_by_user failed");

    assert_eq!(stored.len(), 3, "must have exactly the 3 replacement codes");
}

// delete_all_by_user

#[tokio::test]
async fn delete_all_by_user_removes_all_codes() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 963).await;

    let owned = make_codes(5);
    let codes: Vec<(i16, &[u8])> = owned.iter().map(|(p, h)| (*p, h.as_slice())).collect();
    recovery_code::create_batch(&app.db, user.id, &codes, None)
        .await
        .expect("create_batch failed");

    recovery_code::delete_all_by_user(&app.db, user.id)
        .await
        .expect("delete_all_by_user failed");

    let stored = recovery_code::find_unused_by_user(&app.db, user.id)
        .await
        .expect("find_unused_by_user failed");

    assert!(stored.is_empty(), "all codes must be deleted");
}

// consume

#[tokio::test]
async fn consume_returns_false_on_already_used_code() {
    let app = TestApp::spawn().await;
    let user = fixtures::register_user(&app, 964).await;

    let owned = make_codes(1);
    let codes: Vec<(i16, &[u8])> = owned.iter().map(|(p, h)| (*p, h.as_slice())).collect();
    recovery_code::create_batch(&app.db, user.id, &codes, None)
        .await
        .expect("create_batch failed");

    let stored = recovery_code::find_unused_by_user(&app.db, user.id)
        .await
        .unwrap();
    let id = stored[0].id;

    let first = recovery_code::consume(&app.db, id).await.unwrap();
    assert!(first, "first consume must return true");

    let second = recovery_code::consume(&app.db, id).await.unwrap();
    assert!(!second, "second consume of same code must return false");
}
