//! OAuth 2.1 vocabulary: error codes, scopes, client credentials and the
//! redirects that carry an authorization response.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use percent_encoding::percent_decode_str;

/// RFC 6749 section 5.2 and 4.1.2.1, RFC 8628 section 3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    AccessDenied,
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
        }
    }
}

pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";
pub const GRANT_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub const GRANT_CLIENT_CREDENTIALS: &str = "client_credentials";

/// The `sub` of a client credentials token: a UUID derived from the issuer and
/// the client id, stable across tokens and distinct from every user id (those
/// are random, version 4).
pub fn client_subject(issuer: &str, client_id: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("{}/clients/{client_id}", issuer.trim_end_matches('/')).as_bytes(),
    )
}

/// Longest `state` echoed back to a client.
pub const MAX_STATE_LEN: usize = 512;

/// Marks a client secret, so scanners and people recognize a leaked one.
pub const CLIENT_SECRET_PREFIX: &str = "aacs_";

/// The parameters of a form-encoded request, refusing a repeated parameter
/// (RFC 6749 section 3.1) and dropping empty values, which count as absent.
pub fn form_parameters(body: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut parameters: Vec<(String, String)> = Vec::new();
    for (name, value) in form_urlencoded::parse(body) {
        if parameters.iter().any(|(seen, _)| *seen == name) {
            return Err(format!("{name} is repeated"));
        }
        if !value.is_empty() {
            parameters.push((name.into_owned(), value.into_owned()));
        }
    }
    Ok(parameters)
}

/// The value of `name` among `parameters`.
pub fn parameter<'a>(parameters: &'a [(String, String)], name: &str) -> Option<&'a str> {
    parameters
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

/// A `scope` parameter: space-separated tokens of printable ASCII other than
/// `"` and `\` (RFC 6749 section 3.3), sorted and deduplicated. `Ok(None)` when
/// absent or blank.
pub fn parse_scope(scope: Option<&str>) -> Result<Option<Vec<String>>, String> {
    let Some(scope) = scope.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let mut scopes = Vec::new();
    for token in scope.split(' ').filter(|t| !t.is_empty()) {
        if !token
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
        {
            return Err("scope holds a character outside RFC 6749 scope tokens".into());
        }
        scopes.push(token.to_owned());
    }
    scopes.sort();
    scopes.dedup();
    Ok(Some(scopes))
}

/// The scopes a request asks for, checked against the client's registration:
/// a restricted client may ask for a subset of its scopes only, plus the
/// OpenID Connect scopes, which any client may ask for. Without a
/// `scope` parameter the client's scopes apply (`None`: unrestricted).
pub fn requested_scopes(
    requested: Option<Vec<String>>,
    client_scopes: &[String],
) -> Result<Option<Vec<String>>, Vec<String>> {
    match requested {
        None => Ok((!client_scopes.is_empty()).then(|| client_scopes.to_vec())),
        Some(requested) if client_scopes.is_empty() => Ok(Some(requested)),
        Some(requested) => {
            let outside: Vec<String> = requested
                .iter()
                .filter(|scope| {
                    !super::oidc::is_oidc_scope(scope) && !client_scopes.contains(scope)
                })
                .cloned()
                .collect();
            if outside.is_empty() {
                Ok(Some(requested))
            } else {
                Err(outside)
            }
        }
    }
}

/// Client credentials from an `Authorization: Basic` header: the client id and
/// secret, each form-urlencoded before being joined (RFC 6749 section 2.3.1).
pub fn basic_credentials(header: &str) -> Option<(String, String)> {
    let encoded = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let decoded = String::from_utf8(B64.decode(encoded.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let unescape = |s: &str| {
        percent_decode_str(&s.replace('+', " "))
            .decode_utf8()
            .ok()
            .map(|v| v.into_owned())
    };
    let (id, secret) = (unescape(id)?, unescape(secret)?);
    (!id.is_empty()).then_some((id, secret))
}

/// A new client secret as handed to the administrator.
pub fn format_client_secret(random: &str) -> String {
    format!("{CLIENT_SECRET_PREFIX}{random}")
}

/// The redirect carrying an authorization response or error: the parameters
/// appended after any query the registered redirect URI already has.
pub fn redirect_with(redirect_uri: &str, parameters: &[(&str, &str)]) -> Option<String> {
    let mut url = reqwest::Url::parse(redirect_uri).ok()?;
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in parameters {
            query.append_pair(name, value);
        }
    }
    Some(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_parameters_refuse_repetition_and_drop_empty_values() {
        assert_eq!(
            form_parameters(b"grant_type=refresh_token&scope=a+b&empty="),
            Ok(vec![
                ("grant_type".to_owned(), "refresh_token".to_owned()),
                ("scope".to_owned(), "a b".to_owned()),
            ])
        );
        assert!(form_parameters(b"code=1&code=2").is_err());
    }

    #[test]
    fn scopes_are_rfc_6749_tokens() {
        assert_eq!(
            parse_scope(Some(" docs:read  audit:read docs:read ")),
            Ok(Some(vec!["audit:read".to_owned(), "docs:read".to_owned()]))
        );
        assert_eq!(parse_scope(Some("  ")), Ok(None));
        assert_eq!(parse_scope(None), Ok(None));
        assert!(parse_scope(Some("docs:\"read\"")).is_err());
        assert!(parse_scope(Some("caf\u{e9}")).is_err());
    }

    #[test]
    fn a_restricted_client_asks_for_a_subset_of_its_scopes() {
        let client = vec!["audit:read".to_owned(), "docs:read".to_owned()];
        assert_eq!(requested_scopes(None, &client), Ok(Some(client.clone())));
        assert_eq!(requested_scopes(None, &[]), Ok(None));
        assert_eq!(
            requested_scopes(Some(vec!["docs:read".into()]), &client),
            Ok(Some(vec!["docs:read".to_owned()]))
        );
        assert_eq!(
            requested_scopes(Some(vec!["users:manage".into()]), &client),
            Err(vec!["users:manage".to_owned()])
        );
        assert_eq!(
            requested_scopes(Some(vec!["openid".into(), "docs:read".into()]), &client),
            Ok(Some(vec!["openid".to_owned(), "docs:read".to_owned()]))
        );
        assert_eq!(
            requested_scopes(Some(vec!["users:manage".into()]), &[]),
            Ok(Some(vec!["users:manage".to_owned()]))
        );
    }

    #[test]
    fn basic_credentials_are_form_decoded() {
        let header = format!("Basic {}", B64.encode("my%20app:s%3Acret+x"));
        assert_eq!(
            basic_credentials(&header),
            Some(("my app".to_owned(), "s:cret x".to_owned()))
        );
        assert_eq!(basic_credentials("Bearer abc"), None);
        assert_eq!(basic_credentials("Basic !!!"), None);
        assert_eq!(
            basic_credentials(&format!("Basic {}", B64.encode(":secret"))),
            None
        );
    }

    #[test]
    fn a_client_subject_is_stable_and_never_a_user_id() {
        let subject = client_subject("https://auth.example.com/", "backend");
        assert_eq!(
            subject,
            client_subject("https://auth.example.com", "backend")
        );
        assert_ne!(subject, client_subject("https://auth.example.com", "other"));
        assert_eq!(subject.get_version_num(), 5);
    }

    #[test]
    fn redirects_keep_the_registered_query() {
        assert_eq!(
            redirect_with(
                "https://app.example.com/cb?tenant=acme",
                &[("code", "a b"), ("state", "x&y")]
            )
            .as_deref(),
            Some("https://app.example.com/cb?tenant=acme&code=a+b&state=x%26y")
        );
        assert_eq!(redirect_with("not a url", &[]), None);
    }
}
