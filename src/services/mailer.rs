//! Mail transport: how rendered messages leave the service.
//!
//! The service sends through SMTP. The transport sits behind a trait object so
//! the test suites can capture messages in memory instead of polling a mail
//! server; no other implementation ships in the binary.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};

use crate::config::SmtpConfig;

pub type SendFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;

pub trait MailTransport: Send + Sync + 'static {
    fn send(&self, message: Message) -> SendFuture<'_>;
}

/// Cheap to clone: notifications are sent from background tasks.
#[derive(Clone)]
pub struct Mailer(Arc<dyn MailTransport>);

impl Mailer {
    pub fn new(transport: impl MailTransport) -> Self {
        Self(Arc::new(transport))
    }

    pub async fn send(&self, message: Message) -> anyhow::Result<()> {
        self.0.send(message).await
    }
}

/// Longest a single SMTP conversation may take. lettre's default is a minute.
const SMTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Waits before the second and third attempts of a message the relay refused
/// temporarily (a dropped connection, a 4xx reply).
const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(8)];

/// The wait before retrying after the `failed_attempts`-th failure, or `None`
/// when the message must not be retried: the refusal was permanent (5xx), or
/// every attempt is spent.
fn retry_delay(failed_attempts: usize, permanent: bool) -> Option<Duration> {
    if permanent {
        return None;
    }
    failed_attempts
        .checked_sub(1)
        .and_then(|i| RETRY_DELAYS.get(i).copied())
}

pub struct SmtpMailer {
    /// `None` when no SMTP host is configured (local development): messages
    /// are then dropped.
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
}

impl SmtpMailer {
    pub fn from_config(cfg: &SmtpConfig) -> Result<Self, lettre::transport::smtp::Error> {
        if cfg.host.is_empty() {
            return Ok(Self { transport: None });
        }

        // Plain transport for a local relay without credentials (Mailpit on
        // port 1025), STARTTLS for authenticated production relays.
        let transport = if cfg.username.is_empty() {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host)
                .port(cfg.port)
                .timeout(Some(SMTP_TIMEOUT))
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?
                .port(cfg.port)
                .credentials(Credentials::new(cfg.username.clone(), cfg.password.clone()))
                .timeout(Some(SMTP_TIMEOUT))
                .build()
        };

        Ok(Self {
            transport: Some(transport),
        })
    }
}

impl MailTransport for SmtpMailer {
    fn send(&self, message: Message) -> SendFuture<'_> {
        Box::pin(async move {
            let Some(transport) = &self.transport else {
                return Ok(());
            };
            // Connections are pooled and reused; a temporary refusal is
            // retried, a permanent one is reported at once.
            let mut failed_attempts = 0;
            loop {
                match transport.send(message.clone()).await {
                    Ok(_) => return Ok(()),
                    Err(error) => {
                        failed_attempts += 1;
                        match retry_delay(failed_attempts, error.is_permanent()) {
                            Some(delay) => {
                                tracing::warn!(error = %error, attempt = failed_attempts, "SMTP send failed; retrying");
                                tokio::time::sleep(delay).await;
                            }
                            None => return Err(error.into()),
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_failures_are_retried_twice_then_reported() {
        assert_eq!(retry_delay(1, false), Some(Duration::from_secs(2)));
        assert_eq!(retry_delay(2, false), Some(Duration::from_secs(8)));
        assert_eq!(retry_delay(3, false), None);
        assert_eq!(retry_delay(0, false), None);
    }

    #[test]
    fn permanent_refusals_are_never_retried() {
        assert_eq!(retry_delay(1, true), None);
    }
}
