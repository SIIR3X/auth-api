//! Building the application state: a dependency or a key that cannot be used
//! stops the start with an error naming it.

use auth_api::{
    config::Config,
    state::{AppState, AppStateError},
};

use crate::common::app::TestApp;

/// Build a second state next to a running app, from its configuration changed
/// by `configure`.
async fn build(configure: impl FnOnce(&mut Config)) -> Result<AppState, AppStateError> {
    let app = TestApp::spawn().await;
    let mut config = (*app.state.config).clone();
    configure(&mut config);
    AppState::from_config_with_pool(config, app.db.clone()).await
}

async fn refusal(configure: impl FnOnce(&mut Config)) -> AppStateError {
    match build(configure).await {
        Ok(_) => panic!("the state was built"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn the_test_configuration_builds() {
    assert!(build(|_| {}).await.is_ok());
}

#[tokio::test]
async fn an_invalid_configuration_is_refused_before_connecting() {
    let error = refusal(|config| {
        config.security.lockout_threshold = 0;
        config.nats.url = "nats://127.0.0.1:1".into();
    })
    .await;
    assert!(matches!(error, AppStateError::Config(_)), "{error}");
}

#[tokio::test]
async fn an_unreachable_nats_server_does_not_stop_the_start() {
    let state = match build(|config| {
        config.nats.url = "nats://auth-api-test-token@127.0.0.1:1".into();
    })
    .await
    {
        Ok(state) => state,
        Err(error) => panic!("only account deletion needs NATS, the start must go on: {error}"),
    };
    assert_ne!(
        state.nats.connection_state(),
        async_nats::connection::State::Connected
    );
}

#[tokio::test]
async fn a_broker_refusing_the_credentials_stops_the_start() {
    let error = refusal(|config| {
        let mut url = reqwest::Url::parse(&config.nats.url).unwrap();
        url.set_username("not-the-broker-token").unwrap();
        config.nats.url = url.to_string();
    })
    .await;
    assert!(matches!(error, AppStateError::Nats(_)), "{error}");
}

#[tokio::test]
async fn an_unusable_redis_url_stops_the_start() {
    let error = refusal(|config| config.redis.url = "not a url".into()).await;
    assert!(matches!(error, AppStateError::Redis(_)), "{error}");
}

#[tokio::test]
async fn a_broken_template_stops_the_start() {
    let dir = std::env::temp_dir().join(format!("auth-api-templates-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("emails/en")).unwrap();
    std::fs::write(dir.join("emails/en/broken.html"), "{% if %}").unwrap();
    let templates_dir = dir.to_str().unwrap().to_owned();

    let result = build(move |config| config.mail.templates_dir = templates_dir).await;
    std::fs::remove_dir_all(&dir).ok();

    match result {
        Err(AppStateError::Templates(_)) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("a broken template was accepted"),
    }
}

#[tokio::test]
async fn an_unreadable_signing_key_names_its_variable() {
    let error = refusal(|config| {
        config.jwt.private_key =
            "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----".into();
    })
    .await;
    assert!(
        matches!(error, AppStateError::Config(_)) && error.to_string().contains("JWT_PRIVATE_KEY"),
        "{error}"
    );
}

#[tokio::test]
async fn an_unreadable_previous_public_key_names_its_variable() {
    let error = refusal(|config| config.jwt.previous_public_key = Some("not a key".into())).await;
    assert!(
        matches!(error, AppStateError::Config(_))
            && error.to_string().contains("JWT_PREVIOUS_PUBLIC_KEY"),
        "{error}"
    );
}
