//! Signing in with a link sent by email, when `MAGIC_LINK_ENABLED` is on.
//!
//! The link proves the mailbox, like a password reset does, and stands for the
//! password only: an account with a second factor still answers its challenge.
//! Requesting a link answers alike for every address.

use super::*;
use crate::domain::token::MagicLinkToken;

/// Mail a sign-in link to the account at `email`, if it can sign in. Answers
/// the same, in the same time, whatever the address.
pub async fn request_magic_link(
    state: &AppState,
    email: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    ensure_magic_links_enabled(state)?;
    if let Some(ip_val) = ip {
        let key = format!("ml_req:{}", ip_bucket(ip_val.ip()));
        if budget_exhausted(
            state,
            &key,
            MAX_MAGIC_LINKS_BY_IP,
            MAGIC_LINK_IP_WINDOW_SECS,
        )
        .await
        {
            return Err(AppError::RateLimitExceeded);
        }
    }

    let started = std::time::Instant::now();
    let result = match user_repo::find_by_email(&state.db, email).await? {
        Some(user) if user.status == UserStatus::Active => {
            send_link(state, &user, ip, user_agent, request_id).await
        }
        _ => Ok(()),
    };
    let elapsed = started.elapsed();
    if elapsed < FORGOT_PASSWORD_MIN_DURATION {
        tokio::time::sleep(FORGOT_PASSWORD_MIN_DURATION - elapsed).await;
    }
    result
}

async fn send_link(
    state: &AppState,
    user: &User,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let account_key = format!("ml_account:{}", user.id);
    if budget_exhausted(
        state,
        &account_key,
        MAX_MAGIC_LINKS_BY_ACCOUNT,
        MAGIC_LINK_ACCOUNT_WINDOW_SECS,
    )
    .await
    {
        return Ok(());
    }

    let raw_token = crypto::generate_token();
    token::replace_magic_link(
        &state.db,
        user.id,
        &crypto::sha256(raw_token.as_bytes()),
        state.clock.in_secs(MAGIC_LINK_EXPIRY_SECS),
        ip,
        user_agent,
    )
    .await?;

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(user.id),
            request_id,
            action: AuditAction::MagicLinkSent,
            ip_address: ip,
            metadata: json!({}),
        },
    )
    .await?;

    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let email_to = user.email.clone();
    let username = user.username.clone();
    let locale = user.preferred_locale.clone();
    let frontend_url = state.config.server.frontend_url.clone();
    email::dispatch_best_effort("magic_link_email", async move {
        email::send_magic_link(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &email_to,
            &username,
            &locale,
            &raw_token,
            &frontend_url,
            MAGIC_LINK_EXPIRY_SECS / 60,
        )
        .await
    });
    Ok(())
}

/// Sign in with a link: tokens, or the second-factor challenge of the account.
#[allow(clippy::too_many_arguments)]
pub async fn complete_magic_link(
    state: &AppState,
    raw_token: &str,
    ip: Option<IpNetwork>,
    user_agent: Option<&str>,
    device_name: Option<&str>,
    remember_me: bool,
    request_id: Option<Uuid>,
) -> Result<LoginResult, AppError> {
    ensure_magic_links_enabled(state)?;
    let hash = crypto::sha256(raw_token.as_bytes());
    guard_token_submission(state, "ml", ip, &hash).await?;

    let record: MagicLinkToken =
        check_one_time_token(state, token::find_magic_link_by_hash(&state.db, &hash)).await?;
    if !token::consume_magic_link(&state.db, record.id).await? {
        return Err(AppError::TokenInvalid);
    }

    let user = user_repo::find_by_id(&state.db, record.user_id)
        .await?
        .ok_or(AppError::TokenInvalid)?;
    ensure_account_usable(&user, state.clock.now())?;

    first_factor_proven(
        state,
        &user,
        None,
        ip,
        user_agent,
        device_name,
        remember_me,
        request_id,
        json!({ "method": "magic_link" }),
    )
    .await
}

/// A deployment that did not enable sign-in links does not have these routes.
fn ensure_magic_links_enabled(state: &AppState) -> Result<(), AppError> {
    if state.config.security.magic_links {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}
