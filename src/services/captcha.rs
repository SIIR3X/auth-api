//! CAPTCHA verification service (hCaptcha-compatible).
//!
//! If `CAPTCHA_SECRET` is not configured, verification is skipped entirely.
//! This allows the feature to be disabled in development and tests without
//! code changes.
//!
//! To enable: set CAPTCHA_SECRET in the environment and require clients to
//! submit a `captcha_token` field obtained from the hCaptcha widget.

use serde::Deserialize;

use crate::{error::AppError, state::AppState};

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
        // CAPTCHA not configured — skip verification.
        _ => return Ok(()),
    };

    if token.trim().is_empty() {
        return Err(AppError::CaptchaFailed);
    }

    let resp = match state
        .http_client
        .post(&config.verify_url)
        .form(&[("secret", secret), ("response", token)])
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) if config.fail_open_on_error => {
            tracing::warn!(error = %e, "captcha upstream unavailable, failing open");
            return Ok(());
        }
        Err(_) => return Err(AppError::ServiceUnavailable("captcha")),
    };

    if !resp.status().is_success() {
        if config.fail_open_on_error {
            tracing::warn!(
                status = %resp.status(),
                "captcha upstream returned non-success status, failing open"
            );
            return Ok(());
        }

        return Err(AppError::ServiceUnavailable("captcha"));
    }

    let body: HCaptchaResponse = match resp.json().await {
        Ok(body) => body,
        Err(e) if config.fail_open_on_error => {
            tracing::warn!(error = %e, "captcha response parse failed, failing open");
            return Ok(());
        }
        Err(_) => return Err(AppError::ServiceUnavailable("captcha")),
    };

    if body.success {
        Ok(())
    } else {
        Err(AppError::CaptchaFailed)
    }
}
