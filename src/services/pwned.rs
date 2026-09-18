//! Refuse passwords that appear in known data breaches (Pwned Passwords range
//! API, k-anonymity: see `domain::pwned`).

use std::time::Duration;

use crate::{
    domain::pwned::{self, Verdict},
    error::AppError,
    state::AppState,
};

/// Check `password` before it is set: at registration, on a change and on a
/// reset. Does nothing when the check is disabled.
pub async fn ensure_not_breached(state: &AppState, password: &str) -> Result<(), AppError> {
    let config = &state.config.pwned_passwords;
    if !config.enabled {
        return Ok(());
    }

    let (prefix, suffix) = pwned::range_key(password);
    let count = fetch_range(state, &prefix)
        .await
        .map(|range| pwned::breach_count(&range, &suffix));

    match pwned::verdict(count, config.fail_open) {
        Verdict::Accepted => {
            let outcome = if count.is_some() {
                "clean"
            } else {
                "unavailable"
            };
            metrics::counter!("auth_pwned_password_checks_total", "outcome" => outcome)
                .increment(1);
            Ok(())
        }
        Verdict::Compromised => {
            metrics::counter!("auth_pwned_password_checks_total", "outcome" => "compromised")
                .increment(1);
            Err(AppError::PasswordCompromised)
        }
        Verdict::Unavailable => {
            metrics::counter!("auth_pwned_password_checks_total", "outcome" => "unavailable")
                .increment(1);
            Err(AppError::ServiceUnavailable("pwned_passwords"))
        }
    }
}

/// The range answer for `prefix`, or `None` when the API gave no usable answer.
async fn fetch_range(state: &AppState, prefix: &str) -> Option<String> {
    let config = &state.config.pwned_passwords;
    let url = format!("{}/range/{prefix}", config.api_url.trim_end_matches('/'));
    let response = state
        .http_client
        .get(&url)
        // Every answer is padded to a similar size, so its length does not
        // reveal the prefix to an observer of the connection.
        .header("Add-Padding", "true")
        .timeout(Duration::from_millis(config.timeout_ms))
        .send()
        .await;
    let response = match response {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            tracing::warn!(status = %response.status(), "pwned passwords API refused the range query");
            return None;
        }
        Err(error) => {
            tracing::warn!(%error, "pwned passwords API unreachable");
            return None;
        }
    };
    match response.text().await {
        Ok(body) => Some(body),
        Err(error) => {
            tracing::warn!(%error, "pwned passwords answer could not be read");
            None
        }
    }
}
