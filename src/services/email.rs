//! Email delivery service.
//!
//! Renders Tera templates and sends messages via SMTP.
//! Template lookup order: emails/{locale}/{name}.html -> emails/{default_locale}/{name}.html.
//! The caller supplies only the data; this module handles rendering and transport.

use lettre::{
    message::{header::ContentType, Mailbox, Message},
    AsyncTransport,
};
use tera::{Context, Tera};

use crate::{
    config::{MailConfig, SmtpConfig},
    error::AppError,
    state::Mailer,
};

// Template names (without locale prefix or extension)
const TNAME_VERIFICATION: &str = "verification";
const TNAME_PASSWORD_RESET: &str = "password_reset";

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
    let verification_url = format!("{}/auth/verify-email?token={}", public_url, token);

    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("verification_url", &verification_url);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);
    ctx.insert("expires_in_hours", &24i32);

    let body = render_with_fallback(templates, TNAME_VERIFICATION, locale, &mail_cfg.default_locale, &ctx)?;
    send(mailer, &mail_cfg.smtp, to_email, username, "Verify your email address", body).await
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
    let reset_url = format!("{}/auth/reset-password?token={}", public_url, token);

    let mut ctx = Context::new();
    ctx.insert("username", username);
    ctx.insert("reset_url", &reset_url);
    ctx.insert("app_name", &mail_cfg.smtp.from_name);
    ctx.insert("expires_in_minutes", &30i32);

    let body = render_with_fallback(templates, TNAME_PASSWORD_RESET, locale, &mail_cfg.default_locale, &ctx)?;
    send(mailer, &mail_cfg.smtp, to_email, username, "Reset your password", body).await
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
