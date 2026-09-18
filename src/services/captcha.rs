//! CAPTCHA verification service (hCaptcha-compatible).
//!
//! If `CAPTCHA_SECRET` is not configured, verification is skipped entirely.
//! This allows the feature to be disabled in development and tests without
//! code changes.
//!
//! To enable: set CAPTCHA_SECRET in the environment and require clients to
//! submit a `captcha_token` field obtained from the hCaptcha widget.

use serde::Deserialize;

use crate::{
    domain::captcha::{CaptchaUpstream, CaptchaVerdict, captcha_verdict},
    error::AppError,
    state::AppState,
};

#[derive(Deserialize)]
struct HCaptchaResponse {
    success: bool,
}

/// Verifies a CAPTCHA token against the hCaptcha API.
/// Returns Ok(()) if verification succeeds or if CAPTCHA is not configured.
/// Returns Err(AppError::CaptchaFailed) if the token is invalid.
pub async fn verify(state: &AppState, token: &str) -> Result<(), AppError> {
    let config = &state.config.captcha;

    let secret = match config.secret.as_deref() {
        Some(s) if !s.is_empty() => s,
        // CAPTCHA not configured - skip verification.
        _ => return Ok(()),
    };

    if token.trim().is_empty() {
        return Err(AppError::CaptchaFailed);
    }

    let upstream = ask_upstream(state, secret, token).await;
    match captcha_verdict(upstream, config.fail_open_on_error) {
        CaptchaVerdict::Accepted => {
            if !matches!(upstream, CaptchaUpstream::Answered { .. }) {
                tracing::warn!(?upstream, "captcha upstream gave no answer, failing open");
            }
            Ok(())
        }
        CaptchaVerdict::Rejected => Err(AppError::CaptchaFailed),
        CaptchaVerdict::Unavailable => Err(AppError::ServiceUnavailable("captcha")),
    }
}

/// Ask the verification endpoint about `token`.
async fn ask_upstream(state: &AppState, secret: &str, token: &str) -> CaptchaUpstream {
    let response = match state
        .http_client
        .post(&state.config.captcha.verify_url)
        .form(&[("secret", secret), ("response", token)])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "captcha upstream unreachable");
            return CaptchaUpstream::Unreachable;
        }
    };

    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), "captcha upstream returned a non-success status");
        return CaptchaUpstream::Failed;
    }

    match response.json::<HCaptchaResponse>().await {
        Ok(body) => CaptchaUpstream::Answered {
            success: body.success,
        },
        Err(error) => {
            tracing::warn!(%error, "captcha response could not be parsed");
            CaptchaUpstream::Unreadable
        }
    }
}
