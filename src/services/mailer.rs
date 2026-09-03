//! Mail transport: how rendered messages leave the service.
//!
//! The service sends through SMTP. The transport sits behind a trait object so
//! the test suites can capture messages in memory instead of polling a mail
//! server; no other implementation ships in the binary.

use std::{future::Future, pin::Pin, sync::Arc};

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
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?
                .port(cfg.port)
                .credentials(Credentials::new(cfg.username.clone(), cfg.password.clone()))
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
            if let Some(transport) = &self.transport {
                transport.send(message).await?;
            }
            Ok(())
        })
    }
}
