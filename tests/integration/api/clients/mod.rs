//! Client applications: OAuth 2.1 flows through the standard endpoints.

mod authorization_code;
mod client_credentials;
mod confidential;
mod device_flow;
mod introspection;
mod metadata;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;

use crate::common::app::TestApp;

/// `POST` a form to an OAuth endpoint, optionally with Basic client credentials.
pub async fn form(
    app: &TestApp,
    path: &str,
    parameters: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> (u16, Value) {
    let mut request = app.client.post(app.url(path)).form(parameters);
    if let Some((id, secret)) = basic {
        request = request.basic_auth(id, Some(secret));
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

/// `GET /oauth/authorize` without following the redirect: the status and the
/// `Location`, or the body of a direct error.
pub async fn authorize(app: &TestApp, parameters: &[(&str, &str)]) -> (u16, String, Value) {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&app.client_ip).unwrap(),
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .build()
        .unwrap();
    let mut url = reqwest::Url::parse(&app.url("/oauth/authorize")).unwrap();
    url.query_pairs_mut().extend_pairs(parameters);
    let response = client.get(url).send().await.unwrap();
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get("location")
        .map(|l| l.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (
        status,
        location,
        response.json().await.unwrap_or(Value::Null),
    )
}

/// The value of `name` in the query of `url`.
pub fn query_param(url: &str, name: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

pub fn pkce() -> Pkce {
    let verifier = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let challenge = B64URL.encode(auth_api::utils::crypto::sha256(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

pub fn claims(access_token: &str) -> Value {
    let payload = access_token.split('.').nth(1).unwrap();
    serde_json::from_slice(&B64URL.decode(payload).unwrap()).unwrap()
}
