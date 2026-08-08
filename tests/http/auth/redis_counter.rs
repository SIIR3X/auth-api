//! Atomic attempt budgets (`utils::redis_counter`) against a real Redis.
//!
//! These guard every brute-force limit, so the property that matters is the
//! one a read-then-increment implementation lacks: concurrent requests cannot
//! all slip under the limit together.

use auth_api::{
    error::AppError,
    utils::redis_counter::{self, Budget},
};
use deadpool_redis::{Config as RedisPoolConfig, Runtime, redis::AsyncCommands};

use crate::common::app::TestApp;

fn unique_key(label: &str) -> String {
    format!("test_budget:{label}:{}", uuid::Uuid::new_v4())
}

#[tokio::test]
async fn concurrent_attempts_never_exceed_the_budget() {
    let app = TestApp::spawn().await;
    let key = unique_key("concurrency");

    let attempts = (0..40).map(|_| {
        let redis = app.redis.clone();
        let key = key.clone();
        tokio::spawn(async move {
            let budget = Budget {
                key: &key,
                limit: 5,
                window_secs: 60,
            };
            redis_counter::consume(&redis, &[budget]).await.unwrap()
        })
    });

    let mut granted = 0;
    for attempt in attempts {
        if !attempt.await.unwrap().exceeded {
            granted += 1;
        }
    }

    assert_eq!(
        granted, 5,
        "exactly the budget must be granted under concurrency"
    );
}

#[tokio::test]
async fn any_exhausted_budget_refuses_the_attempt() {
    let app = TestApp::spawn().await;
    let per_token = unique_key("token");
    let per_user = unique_key("user");
    let budgets = [
        Budget {
            key: &per_token,
            limit: 5,
            window_secs: 60,
        },
        Budget {
            key: &per_user,
            limit: 2,
            window_secs: 60,
        },
    ];

    let first = redis_counter::consume(&app.redis, &budgets).await.unwrap();
    let second = redis_counter::consume(&app.redis, &budgets).await.unwrap();
    let third = redis_counter::consume(&app.redis, &budgets).await.unwrap();

    assert!(!first.exceeded && !second.exceeded);
    assert!(third.exceeded, "the per-user budget of 2 is exhausted");
    assert_eq!(third.counts, vec![3, 3]);
    assert_eq!(third.max_count(), 3);
}

#[tokio::test]
async fn window_is_armed_on_first_attempt_and_reset_clears_it() {
    let app = TestApp::spawn().await;
    let key = unique_key("window");
    let budget = Budget {
        key: &key,
        limit: 3,
        window_secs: 120,
    };

    redis_counter::consume(&app.redis, &[budget]).await.unwrap();
    let mut conn = app.redis.get().await.unwrap();
    let ttl: i64 = conn.ttl(&key).await.unwrap();
    assert!((1..=120).contains(&ttl), "TTL must be armed, got {ttl}");
    assert_eq!(redis_counter::peek(&app.redis, &key).await.unwrap(), 1);

    redis_counter::reset(&app.redis, &[&key]).await;
    assert_eq!(redis_counter::peek(&app.redis, &key).await.unwrap(), 0);
}

#[tokio::test]
async fn unreachable_redis_fails_closed() {
    let mut cfg = RedisPoolConfig::from_url("redis://127.0.0.1:1");
    let mut pool_cfg = deadpool_redis::PoolConfig::new(1);
    pool_cfg.timeouts.wait = Some(std::time::Duration::from_millis(200));
    pool_cfg.timeouts.create = Some(std::time::Duration::from_millis(200));
    cfg.pool = Some(pool_cfg);
    let dead = cfg.create_pool(Some(Runtime::Tokio1)).unwrap();

    let key = unique_key("dead");
    let result = redis_counter::consume(
        &dead,
        &[Budget {
            key: &key,
            limit: 1,
            window_secs: 60,
        }],
    )
    .await;

    assert!(matches!(result, Err(AppError::ServiceUnavailable(_))));
}
