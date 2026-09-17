//! axum integration: `Authenticated` rejects a request without a valid token.

use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};

use crate::{VerifiedToken, Verifier, VerifyError};

/// A handler argument holding the verified token of the request. The state
/// must provide an `Arc<Verifier>` (`FromRef`).
pub struct Authenticated(pub VerifiedToken);

impl<S> FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
    Arc<Verifier>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| challenge(StatusCode::UNAUTHORIZED, None))?;
        Arc::<Verifier>::from_ref(state)
            .verify(token)
            .await
            .map(Authenticated)
            .map_err(|error| match error {
                VerifyError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                _ => challenge(StatusCode::UNAUTHORIZED, Some("invalid_token")),
            })
    }
}

/// RFC 6750 section 3.
fn challenge(status: StatusCode, error: Option<&str>) -> Response {
    let value = match error {
        Some(error) => format!("Bearer error=\"{error}\""),
        None => "Bearer".to_owned(),
    };
    (status, [(header::WWW_AUTHENTICATE, value)]).into_response()
}
