//! Email second-factor codes: one live code per user, scoped lookups, single use.

use auth_api::repositories::email_2fa::{self, NewEmail2faCode};
use testkit::{TestDb, sql::insert_active_user};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

async fn issue(db: &TestDb, user_id: Uuid, hash: &[u8; 32]) -> Uuid {
    email_2fa::create(
        &db.pool,
        &NewEmail2faCode {
            user_id,
            code_hash: hash,
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_new_code_replaces_the_live_one() {
    let db = TestDb::new().await;
    let user = insert_active_user(&db.pool, 1).await;

    issue(&db, user, &[1u8; 32]).await;
    let second = issue(&db, user, &[2u8; 32]).await;

    let live = email_2fa::find_active_by_user(&db.pool, user)
        .await
        .unwrap()
        .expect("a live code");
    assert_eq!(live.id, second);
    assert!(
        email_2fa::find_active_by_user_and_hash(&db.pool, user, &[1u8; 32])
            .await
            .unwrap()
            .is_none(),
        "the replaced code still verifies"
    );
    let unused: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_2fa_codes WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(unused, 1);
}

#[tokio::test]
async fn a_code_verifies_only_for_the_user_it_was_sent_to() {
    let db = TestDb::new().await;
    let owner = insert_active_user(&db.pool, 1).await;
    let other = insert_active_user(&db.pool, 2).await;
    let hash = [3u8; 32];
    issue(&db, owner, &hash).await;

    assert!(
        email_2fa::find_active_by_user_and_hash(&db.pool, owner, &hash)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        email_2fa::find_active_by_user_and_hash(&db.pool, other, &hash)
            .await
            .unwrap()
            .is_none(),
        "a six-digit code is not unique across accounts"
    );
}

#[tokio::test]
async fn a_code_is_consumed_once_however_many_attempts_race() {
    let db = TestDb::new().await;
    let user = insert_active_user(&db.pool, 1).await;
    let id = issue(&db, user, &[4u8; 32]).await;

    let attempts =
        futures::future::join_all((0..10).map(|_| email_2fa::consume(&db.pool, id))).await;
    let consumed = attempts
        .into_iter()
        .map(Result::unwrap)
        .filter(|won| *won)
        .count();
    assert_eq!(consumed, 1, "a code was consumed {consumed} times");
    assert!(!email_2fa::consume(&db.pool, id).await.unwrap());
}

#[tokio::test]
async fn an_expired_code_is_neither_found_nor_consumed() {
    let db = TestDb::new().await;
    let user = insert_active_user(&db.pool, 1).await;
    let hash = [5u8; 32];
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO email_2fa_codes (user_id, code_hash, created_at, expires_at)
         VALUES ($1, $2, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 minute')
         RETURNING id",
    )
    .bind(user)
    .bind(hash.as_slice())
    .fetch_one(&db.pool)
    .await
    .unwrap();

    assert!(
        email_2fa::find_active_by_user(&db.pool, user)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        email_2fa::find_active_by_user_and_hash(&db.pool, user, &hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!email_2fa::consume(&db.pool, id).await.unwrap());
}
