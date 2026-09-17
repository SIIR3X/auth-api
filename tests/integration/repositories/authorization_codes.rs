//! Authorization codes: single use even when redemptions race.

use auth_api::repositories::{
    authorization_code::{self, NewAuthorizationCode},
    registered_client::{self, NewRegisteredClient},
};
use testkit::{TestDb, sql::insert_active_user};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

async fn client(db: &TestDb) {
    let none: Vec<String> = Vec::new();
    let redirects = vec!["https://app.example.com/callback".to_string()];
    registered_client::upsert(
        &db.pool,
        &NewRegisteredClient {
            client_id: "web.app",
            display_name: "Web",
            is_primary: false,
            scopes: &none,
            redirect_uris: &redirects,
            allows_loopback_redirect: false,
            default_max_sessions: 5,
        },
    )
    .await
    .unwrap();
}

async fn code(db: &TestDb, user_id: Uuid, hash: &[u8; 32], expires_at: OffsetDateTime) -> Uuid {
    authorization_code::create(
        &db.pool,
        &NewAuthorizationCode {
            code_hash: hash,
            user_id,
            client_id: "web.app",
            redirect_uri: "https://app.example.com/callback",
            code_challenge: CHALLENGE,
            scopes: None,
            nonce: None,
            expires_at,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_code_is_redeemed_once_however_many_redemptions_race() {
    let db = TestDb::new().await;
    client(&db).await;
    let user = insert_active_user(&db.pool, 1).await;
    let hash = [7u8; 32];
    code(
        &db,
        user,
        &hash,
        OffsetDateTime::now_utc() + Duration::minutes(5),
    )
    .await;

    let redemptions =
        futures::future::join_all((0..10).map(|_| authorization_code::consume(&db.pool, &hash)))
            .await;
    let winners = redemptions
        .into_iter()
        .map(Result::unwrap)
        .filter(Option::is_some)
        .count();
    assert_eq!(winners, 1, "a code was redeemed {winners} times");

    let row = authorization_code::find(&db.pool, &hash)
        .await
        .unwrap()
        .expect("the code is kept after redemption");
    assert!(row.consumed_at.is_some());
}

#[tokio::test]
async fn an_expired_code_cannot_be_redeemed_but_can_be_told_apart() {
    let db = TestDb::new().await;
    client(&db).await;
    let user = insert_active_user(&db.pool, 1).await;
    let hash = [8u8; 32];
    code(
        &db,
        user,
        &hash,
        OffsetDateTime::now_utc() - Duration::seconds(1),
    )
    .await;

    assert!(
        authorization_code::consume(&db.pool, &hash)
            .await
            .unwrap()
            .is_none()
    );
    let row = authorization_code::find(&db.pool, &hash)
        .await
        .unwrap()
        .expect("an expired code is still found");
    assert!(row.consumed_at.is_none(), "an expired code was consumed");
    assert!(
        authorization_code::find(&db.pool, &[9u8; 32])
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_redeemed_code_remembers_its_session() {
    let db = TestDb::new().await;
    client(&db).await;
    let user = insert_active_user(&db.pool, 1).await;
    let hash = [10u8; 32];
    let id = code(
        &db,
        user,
        &hash,
        OffsetDateTime::now_utc() + Duration::minutes(5),
    )
    .await;
    let session: Uuid = sqlx::query_scalar(
        "INSERT INTO sessions (user_id, expires_at, token_hash)
         VALUES ($1, NOW() + INTERVAL '1 day', $2) RETURNING id",
    )
    .bind(user)
    .bind(vec![11u8; 32])
    .fetch_one(&db.pool)
    .await
    .unwrap();

    authorization_code::attach_session(&db.pool, id, session)
        .await
        .unwrap();

    let row = authorization_code::find(&db.pool, &hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.session_id, Some(session));
}
