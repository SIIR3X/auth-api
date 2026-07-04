//! Email delivery service.
//!
//! Renders Tera templates and sends messages via SMTP.
//! Template lookup order: emails/{locale}/{name}.html -> emails/{default_locale}/{name}.html.
//! The caller supplies only the data; this module handles rendering and transport.

#![allow(clippy::too_many_arguments)]

use std::future::Future;

use lettre::{
    AsyncTransport,
    message::{Mailbox, Message, header::ContentType},
};
use tera::{Context, Tera};

use ipnetwork::IpNetwork;

use crate::{
    config::{MailConfig, SmtpConfig},
    error::AppError,
    services::risk_score::RiskResult,
    state::Mailer,
};

// Template names (without locale prefix or extension)
const TNAME_VERIFICATION: &str = "verification";
const TNAME_EMAIL_CHANGE_OTP: &str = "email_change_otp";
const TNAME_PASSWORD_RESET: &str = "password_reset";
const TNAME_SUSPICIOUS_LOGIN: &str = "suspicious_login";
const TNAME_EMAIL_OTP: &str = "email_otp";
const TNAME_NEW_DEVICE_LOGIN: &str = "new_device_login";
const TNAME_PASSWORD_CHANGED: &str = "password_changed";
const TNAME_TWO_FACTOR_DISABLED: &str = "two_factor_disabled";
const TNAME_RECOVERY_CODE_USED: &str = "recovery_code_used";

pub fn dispatch_best_effort<F>(label: &'static str, future: F)
where
    F: Future<Output = Result<(), AppError>> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = future.await {
            tracing::warn!(error = ?error, task = label, "background notification failed");
        }
    });
}

pub async fn send_verification_email(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    token: &str,
    public_url: &str,
) -> Result<(), AppError> {
    // Use URL fragment (`#token=...`) instead of query string (`?token=...`).
    // Fragments are not sent in the Referer header, not stored in CDN/proxy
    // access logs, and are kept out of most browser-history sync mechanisms,
    // which prevents leaking the single-use verification token.
    // The frontend SPA reads it via `window.location.hash` (not URLSearchParams).
    let verification_url = format!("{}/verify-email#token={}", public_url, token);

    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("verification_url", &verification_url);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);
    ctx.insert("expires_in_hours", &24i32);

    let body = render_with_fallback(
        templates,
        TNAME_VERIFICATION,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "Verify your email address",
        body,
    )
    .await
}

pub async fn send_password_reset_email(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    token: &str,
    public_url: &str,
) -> Result<(), AppError> {
    // Use URL fragment (`#token=...`) instead of query string (`?token=...`)
    // for the same reasons as `send_verification_email`: fragments stay
    // client-side and avoid Referer / log / history leakage of the reset token.
    let reset_url = format!("{}/reset-password#token={}", public_url, token);

    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("reset_url", &reset_url);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);
    ctx.insert("expires_in_minutes", &30i32);

    let body = render_with_fallback(
        templates,
        TNAME_PASSWORD_RESET,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "Reset your password",
        body,
    )
    .await
}

pub async fn send_email_change_otp(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    code: &str,
) -> Result<(), AppError> {
    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("code", code);
    ctx.insert("expires_in_minutes", &15i32);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);

    let body = render_with_fallback(
        templates,
        TNAME_EMAIL_CHANGE_OTP,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "Your email change verification code",
        body,
    )
    .await
}

pub async fn send_email_otp(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    code: &str,
) -> Result<(), AppError> {
    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("code", code);
    ctx.insert("expires_in_minutes", &10i32);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);

    let body = render_with_fallback(
        templates,
        TNAME_EMAIL_OTP,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "Your login verification code",
        body,
    )
    .await
}

pub async fn send_new_device_login(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    ip: Option<IpNetwork>,
    user_agent: &str,
    country: &str,
    city: &str,
) -> Result<(), AppError> {
    let ip_str = ip.map(|i| i.ip().to_string()).unwrap_or_default();

    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("ip", &ip_str);
    ctx.insert("user_agent", user_agent);
    ctx.insert("country", country);
    ctx.insert("city", city);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);

    let body = render_with_fallback(
        templates,
        TNAME_NEW_DEVICE_LOGIN,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "New device login detected",
        body,
    )
    .await
}

pub async fn send_suspicious_login_alert(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    ip: Option<IpNetwork>,
    risk: &RiskResult,
) -> Result<(), AppError> {
    let ip_str = ip.map(|i| i.ip().to_string()).unwrap_or_default();
    let (country, city) =
        risk.signals
            .iter()
            .fold((String::new(), String::new()), |(mut co, mut ci), s| {
                if let Some(v) = s.strip_prefix("new_country:") {
                    co = v.to_string();
                }
                if let Some(v) = s.strip_prefix("new_city:") {
                    ci = v.to_string();
                }
                (co, ci)
            });

    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("ip", &ip_str);
    ctx.insert("country", &country);
    ctx.insert("city", &city);
    ctx.insert("signals", &risk.signals);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);

    let body = render_with_fallback(
        templates,
        TNAME_SUSPICIOUS_LOGIN,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "Unusual login detected on your account",
        body,
    )
    .await
}

pub async fn send_password_changed(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
) -> Result<(), AppError> {
    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);

    let body = render_with_fallback(
        templates,
        TNAME_PASSWORD_CHANGED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "Your password has been changed",
        body,
    )
    .await
}

pub async fn send_two_factor_disabled(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    method: &str,
) -> Result<(), AppError> {
    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("method", method);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);

    let body = render_with_fallback(
        templates,
        TNAME_TWO_FACTOR_DISABLED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "Two-factor authentication disabled",
        body,
    )
    .await
}

pub async fn send_recovery_code_used(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
) -> Result<(), AppError> {
    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);

    let body = render_with_fallback(
        templates,
        TNAME_RECOVERY_CODE_USED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(
        mailer,
        &mail_cfg.smtp,
        to_email,
        username,
        "A recovery code was used on your account",
        body,
    )
    .await
}

// Tries locale template first, falls back to default_locale.
fn render_with_fallback(
    templates: &Tera,
    name: &str,
    locale: &str,
    default_locale: &str,
    ctx: &Context,
) -> Result<String, AppError> {
    let primary = format!("emails/{}/{}.html", locale, name);
    let fallback = format!("emails/{}/{}.html", default_locale, name);

    templates
        .render(&primary, ctx)
        .or_else(|_| templates.render(&fallback, ctx))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("template render error: {}", e)))
}

async fn send(
    mailer: &Mailer,
    cfg: &SmtpConfig,
    to_email: &str,
    to_name: &str,
    subject: &str,
    html_body: String,
) -> Result<(), AppError> {
    // Skip silently when no SMTP host is configured (e.g. in tests without mailpit).
    if cfg.host.is_empty() {
        return Ok(());
    }

    let from: Mailbox = format!("{} <{}>", cfg.from_name, cfg.from_address)
        .parse()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid from address: {}", e)))?;

    let to: Mailbox = format!("{} <{}>", to_name, to_email)
        .parse()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid to address: {}", e)))?;

    let msg = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html_body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("failed to build email: {}", e)))?;

    mailer
        .send(msg)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp send failed: {}", e)))?;

    Ok(())
}
