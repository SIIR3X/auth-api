//! Signing in through an external identity provider: which responses identify
//! a person, and how a sign-in started in one browser is finished in the same.

use serde_json::Value;

/// Provider names in routes and configuration.
pub fn is_valid_provider_name(name: &str) -> bool {
    (1..=50).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// What an ID token must say to identify a person to this client.
pub struct IdTokenExpectations<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// Unix seconds.
    pub now: i64,
}

/// Seconds of clock difference tolerated with the provider.
const LEEWAY_SECS: i64 = 60;

/// The subject of ID token claims whose signature was verified, when they are
/// meant for this client, for this sign-in, and current (OIDC Core 3.1.3.7).
pub fn id_token_subject(
    claims: &Value,
    expected: &IdTokenExpectations<'_>,
) -> Result<String, &'static str> {
    if claims["iss"].as_str().map(|iss| iss.trim_end_matches('/'))
        != Some(expected.issuer.trim_end_matches('/'))
    {
        return Err("issuer mismatch");
    }
    let audiences: Vec<&str> = match &claims["aud"] {
        Value::String(aud) => vec![aud.as_str()],
        Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
        _ => return Err("missing audience"),
    };
    if !audiences.contains(&expected.client_id) {
        return Err("audience mismatch");
    }
    if audiences.len() > 1 && claims["azp"].as_str() != Some(expected.client_id) {
        return Err("authorized party mismatch");
    }
    match claims["exp"].as_i64() {
        Some(exp) if exp + LEEWAY_SECS > expected.now => {}
        _ => return Err("expired"),
    }
    if claims["iat"]
        .as_i64()
        .is_some_and(|iat| iat > expected.now + LEEWAY_SECS)
    {
        return Err("issued in the future");
    }
    if claims["nonce"].as_str() != Some(expected.nonce) {
        return Err("nonce mismatch");
    }
    match claims["sub"].as_str() {
        Some(sub) if (1..=255).contains(&sub.len()) => Ok(sub.to_owned()),
        _ => Err("missing subject"),
    }
}

/// The subject of a GitHub user: its numeric id, which survives renames.
pub fn github_subject(user: &Value) -> Option<String> {
    user["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .map(|id| id.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn expected() -> IdTokenExpectations<'static> {
        IdTokenExpectations {
            issuer: "https://sso.example.com",
            client_id: "auth-api",
            nonce: "n-1",
            now: 1_000_000,
        }
    }

    fn claims() -> Value {
        json!({
            "iss": "https://sso.example.com/",
            "aud": "auth-api",
            "exp": 1_000_300,
            "iat": 1_000_000,
            "nonce": "n-1",
            "sub": "person-42",
        })
    }

    #[test]
    fn a_current_token_for_this_client_and_sign_in_names_its_subject() {
        assert_eq!(
            id_token_subject(&claims(), &expected()),
            Ok("person-42".into())
        );

        let mut several = claims();
        several["aud"] = json!(["other", "auth-api"]);
        assert_eq!(
            id_token_subject(&several, &expected()),
            Err("authorized party mismatch")
        );
        several["azp"] = json!("auth-api");
        assert!(id_token_subject(&several, &expected()).is_ok());
    }

    #[test]
    fn a_token_for_something_else_is_refused() {
        for (field, value, reason) in [
            ("iss", json!("https://evil.example.com"), "issuer mismatch"),
            ("aud", json!("other-client"), "audience mismatch"),
            ("aud", json!(null), "missing audience"),
            ("exp", json!(999_000), "expired"),
            ("iat", json!(1_001_000), "issued in the future"),
            ("nonce", json!("n-2"), "nonce mismatch"),
            ("sub", json!(""), "missing subject"),
        ] {
            let mut token = claims();
            token[field] = value;
            assert_eq!(
                id_token_subject(&token, &expected()),
                Err(reason),
                "{field}"
            );
        }
    }

    #[test]
    fn provider_names_and_github_subjects() {
        assert!(is_valid_provider_name("corp-sso_2"));
        assert!(!is_valid_provider_name("Corp"));
        assert!(!is_valid_provider_name(""));
        assert_eq!(
            github_subject(&json!({ "id": 42, "login": "octo" })),
            Some("42".into())
        );
        assert_eq!(github_subject(&json!({ "login": "octo" })), None);
        assert_eq!(github_subject(&json!({ "id": 0 })), None);
    }
}
