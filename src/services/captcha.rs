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
    /// Site the challenge was solved on.
    #[serde(default)]
    hostname: Option<String>,
}

/// Verifies a CAPTCHA token against the hCaptcha API.
/// Returns Ok(()) if verification succeeds or if CAPTCHA is not configured.
/// Returns Err(AppError::CaptchaFailed) if the token is invalid.
pub async fn verify(
    state: &AppState,
    token: &str,
    remote_ip: Option<ipnetwork::IpNetwork>,
) -> Result<(), AppError> {
    let config = &state.config.captcha;

    let secret = match config.secret.as_deref() {
        Some(s) if !s.is_empty() => s,
        // CAPTCHA not configured - skip verification.
        _ => return Ok(()),
    };

    if token.trim().is_empty() {
        return Err(AppError::CaptchaFailed);
    }

    let upstream = ask_upstream(state, secret, token, remote_ip).await;
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

/// Whether a challenge solved on `hostname` counts for this deployment: one of
/// `CAPTCHA_EXPECTED_HOSTNAMES`, or the host of `FRONTEND_URL` when none is
/// set. A provider that names no hostname is taken at its word.
fn solved_here(state: &AppState, hostname: Option<&str>) -> bool {
    let Some(hostname) = hostname else {
        return true;
    };
    let expected = &state.config.captcha.expected_hostnames;
    let accepted = if expected.is_empty() {
        reqwest::Url::parse(&state.config.server.frontend_url)
            .ok()
            .and_then(|url| {
                url.host_str()
                    .map(|host| host.eq_ignore_ascii_case(hostname))
            })
            .unwrap_or(false)
    } else {
        expected
            .iter()
            .any(|host| host.eq_ignore_ascii_case(hostname))
    };
    if !accepted {
        tracing::warn!(hostname, "captcha solved on an unexpected hostname");
    }
    accepted
}

/// Ask the verification endpoint about `token`, with the client's address and
/// the widget's site key: a token solved elsewhere, or for another site key,
/// is refused.
async fn ask_upstream(
    state: &AppState,
    secret: &str,
    token: &str,
    remote_ip: Option<ipnetwork::IpNetwork>,
) -> CaptchaUpstream {
    let remote_ip = remote_ip.map(|ip| ip.ip().to_string());
    let mut form = vec![("secret", secret), ("response", token)];
    if let Some(ip) = remote_ip.as_deref() {
        form.push(("remoteip", ip));
    }
    if let Some(site_key) = state.config.captcha.site_key.as_deref() {
        form.push(("sitekey", site_key));
    }
    let response = match state
        .http_client
        .post(&state.config.captcha.verify_url)
        .form(&form)
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
            success: body.success && solved_here(state, body.hostname.as_deref()),
        },
        Err(error) => {
            tracing::warn!(%error, "captcha response could not be parsed");
            CaptchaUpstream::Unreadable
        }
    }
}
