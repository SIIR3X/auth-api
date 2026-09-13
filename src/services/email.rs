//! Email delivery service.
//!
//! Renders Tera templates and sends messages via SMTP.
//! Template lookup order: emails/{locale}/{name}.html -> emails/{default_locale}/{name}.html;
//! subjects live next to their bodies as `{name}.subject`, with the same fallback.
//! The caller supplies only the data; this module handles rendering and transport.

#![allow(clippy::too_many_arguments)]

use std::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
};

use lettre::message::{Mailbox, Message, header::ContentType};
use tera::{Context, Tera};

use crate::{
    config::{MailConfig, SmtpConfig},
    error::AppError,
    services::mailer::Mailer,
};

// Template names (without locale prefix or extension)
const TNAME_VERIFICATION: &str = "verification";
const TNAME_EMAIL_CHANGE_OTP: &str = "email_change_otp";
const TNAME_PASSWORD_RESET: &str = "password_reset";
const TNAME_EMAIL_OTP: &str = "email_otp";
const TNAME_PASSWORD_CHANGED: &str = "password_changed";
const TNAME_TWO_FACTOR_DISABLED: &str = "two_factor_disabled";
const TNAME_TWO_FACTOR_ENABLED: &str = "two_factor_enabled";
const TNAME_ACCOUNT_EXISTS: &str = "account_exists";
const TNAME_EMAIL_CHANGED: &str = "email_changed";
const TNAME_RECOVERY_CODE_USED: &str = "recovery_code_used";

/// Notifications waiting or being sent, past which new ones are dropped: a slow
/// or unreachable relay must not pile up tasks in step with traffic.
const MAX_PENDING_NOTIFICATIONS: usize = 1_000;

static PENDING_NOTIFICATIONS: AtomicUsize = AtomicUsize::new(0);

/// Send a notification in the background: counted for the shutdown drain,
/// bounded, and measured (`auth_notifications_pending`,
/// `auth_notifications_failed_total`, `auth_notifications_dropped_total`).
pub fn dispatch_best_effort<F>(label: &'static str, future: F)
where
    F: Future<Output = Result<(), AppError>> + Send + 'static,
{
    if PENDING_NOTIFICATIONS.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_NOTIFICATIONS {
        PENDING_NOTIFICATIONS.fetch_sub(1, Ordering::SeqCst);
        metrics::counter!("auth_notifications_dropped_total", "task" => label).increment(1);
        tracing::warn!(
            task = label,
            "notification queue full; notification dropped"
        );
        return;
    }
    metrics::gauge!("auth_notifications_pending").increment(1.0);

    crate::utils::background::spawn(async move {
        let _pending = Pending;
        if let Err(error) = future.await {
            metrics::counter!("auth_notifications_failed_total", "task" => label).increment(1);
            tracing::warn!(error = ?error, task = label, "background notification failed");
        }
    });
}

/// Releases a notification slot when its task ends, panic included.
struct Pending;

impl Drop for Pending {
    fn drop(&mut self) {
        PENDING_NOTIFICATIONS.fetch_sub(1, Ordering::SeqCst);
        metrics::gauge!("auth_notifications_pending").decrement(1.0);
    }
}

pub async fn send_verification_email(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    token: &str,
    frontend_url: &str,
) -> Result<(), AppError> {
    // Use URL fragment (`#token=...`) instead of query string (`?token=...`).
    // Fragments are not sent in the Referer header, not stored in CDN/proxy
    // access logs, and are kept out of most browser-history sync mechanisms,
    // which prevents leaking the single-use verification token.
    // The frontend SPA reads it via `window.location.hash` (not URLSearchParams).
    let verification_url = format!("{}/verify-email#token={}", frontend_url, token);

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
    let subject = render_subject(
        templates,
        TNAME_VERIFICATION,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
}

pub async fn send_password_reset_email(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    token: &str,
    frontend_url: &str,
) -> Result<(), AppError> {
    // Use URL fragment (`#token=...`) instead of query string (`?token=...`)
    // for the same reasons as `send_verification_email`: fragments stay
    // client-side and avoid Referer / log / history leakage of the reset token.
    let reset_url = format!("{}/reset-password#token={}", frontend_url, token);

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
    let subject = render_subject(
        templates,
        TNAME_PASSWORD_RESET,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
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
    let subject = render_subject(
        templates,
        TNAME_EMAIL_CHANGE_OTP,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
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
    let subject = render_subject(
        templates,
        TNAME_EMAIL_OTP,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
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
    let subject = render_subject(
        templates,
        TNAME_PASSWORD_CHANGED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
}

/// Mask an address for display in a notification: `j***@example.com`.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        None => "***".to_owned(),
    }
}

pub async fn send_email_changed(
    mailer: &Mailer,
    templates: &Tera,
    mail_cfg: &MailConfig,
    to_email: &str,
    username: &str,
    locale: &str,
    new_email_masked: &str,
) -> Result<(), AppError> {
    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("new_email_masked", new_email_masked);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);

    let body = render_with_fallback(
        templates,
        TNAME_EMAIL_CHANGED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    let subject = render_subject(
        templates,
        TNAME_EMAIL_CHANGED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
}

pub async fn send_account_exists(
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
        TNAME_ACCOUNT_EXISTS,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    let subject = render_subject(
        templates,
        TNAME_ACCOUNT_EXISTS,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
}

pub async fn send_two_factor_enabled(
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
        TNAME_TWO_FACTOR_ENABLED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    let subject = render_subject(
        templates,
        TNAME_TWO_FACTOR_ENABLED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
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
    let subject = render_subject(
        templates,
        TNAME_TWO_FACTOR_DISABLED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
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
    let subject = render_subject(
        templates,
        TNAME_RECOVERY_CODE_USED,
        locale,
        &mail_cfg.default_locale,
        &ctx,
    )?;
    send(mailer, &mail_cfg.smtp, to_email, username, &subject, body).await
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

/// Subject line of `name`, from `emails/{locale}/{name}.subject` with the same
/// locale fallback as the body.
fn render_subject(
    templates: &Tera,
    name: &str,
    locale: &str,
    default_locale: &str,
    ctx: &Context,
) -> Result<String, AppError> {
    let primary = format!("emails/{locale}/{name}.subject");
    let fallback = format!("emails/{default_locale}/{name}.subject");

    templates
        .render(&primary, ctx)
        .or_else(|_| templates.render(&fallback, ctx))
        .map(|subject| subject.trim().to_owned())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("subject render error: {e}")))
}

async fn send(
    mailer: &Mailer,
    cfg: &SmtpConfig,
    to_email: &str,
    to_name: &str,
    subject: &str,
    html_body: String,
) -> Result<(), AppError> {
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
        .map_err(|e| AppError::Internal(e.context("mail send failed")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_TEMPLATES: [&str; 10] = [
        TNAME_VERIFICATION,
        TNAME_EMAIL_CHANGE_OTP,
        TNAME_PASSWORD_RESET,
        TNAME_EMAIL_OTP,
        TNAME_PASSWORD_CHANGED,
        TNAME_TWO_FACTOR_DISABLED,
        TNAME_TWO_FACTOR_ENABLED,
        TNAME_ACCOUNT_EXISTS,
        TNAME_EMAIL_CHANGED,
        TNAME_RECOVERY_CODE_USED,
    ];

    #[test]
    fn every_email_has_a_subject_in_every_locale() {
        let mut templates = Tera::new();
        templates
            .load_from_glob("templates/**/*")
            .expect("templates load");
        let ctx = Context::new();

        for name in ALL_TEMPLATES {
            for locale in ["en", "fr"] {
                let subject = templates
                    .render(&format!("emails/{locale}/{name}.subject"), &ctx)
                    .unwrap_or_else(|e| panic!("{locale}/{name}.subject: {e}"));
                assert!(
                    !subject.trim().is_empty(),
                    "{locale}/{name}.subject is empty"
                );
                assert!(
                    !subject.trim().contains('\n'),
                    "{locale}/{name}.subject spans lines"
                );
            }
        }
    }

    #[test]
    fn mask_email_keeps_only_the_first_character_and_domain() {
        assert_eq!(mask_email("jane.doe@example.com"), "j***@example.com");
        assert_eq!(mask_email("not-an-address"), "***");
    }
}
