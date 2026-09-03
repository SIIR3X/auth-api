//! In-memory mail transport: every message the application sends, decoded.
//!
//! Notifications are sent from background tasks, so a test waits for the
//! message it expects with [`MailOutbox::wait_for`] rather than reading the
//! outbox right after the request.

use std::sync::{Arc, Mutex};

use auth_api::services::mailer::{MailTransport, SendFuture};
use base64::{Engine, engine::general_purpose::STANDARD};
use lettre::Message;
use tokio::sync::Notify;

/// How long `wait_for` waits before failing the test.
pub const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct CapturedMail {
    /// Envelope recipients.
    pub to: Vec<String>,
    pub subject: String,
    /// Decoded HTML body.
    pub html: String,
}

impl CapturedMail {
    pub fn is_for(&self, address: &str) -> bool {
        self.to.iter().any(|to| to.eq_ignore_ascii_case(address))
    }

    /// The first run of exactly six ASCII digits in the body: the one-time
    /// code of a code email.
    pub fn six_digit_code(&self) -> Option<String> {
        let bytes = self.html.as_bytes();
        let mut start = None;
        for (i, b) in bytes.iter().chain(std::iter::once(&b' ')).enumerate() {
            match (b.is_ascii_digit(), start) {
                (true, None) => start = Some(i),
                (false, Some(s)) if i - s == 6 => return Some(self.html[s..i].to_owned()),
                (false, Some(_)) => start = None,
                _ => {}
            }
        }
        None
    }

    /// The URL-safe token following `marker` in the body, such as the value
    /// after `#token=` in a link.
    pub fn value_after(&self, marker: &str) -> Option<String> {
        let start = self.html.find(marker)? + marker.len();
        let value: String = self.html[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        (!value.is_empty()).then_some(value)
    }
}

#[derive(Clone, Default)]
pub struct MailOutbox {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    messages: Mutex<Vec<CapturedMail>>,
    arrived: Notify,
}

impl MailOutbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn messages(&self) -> Vec<CapturedMail> {
        self.inner.messages.lock().unwrap().clone()
    }

    pub fn messages_to(&self, address: &str) -> Vec<CapturedMail> {
        self.messages()
            .into_iter()
            .filter(|m| m.is_for(address))
            .collect()
    }

    /// The latest message to `address` whose subject contains `subject`,
    /// waiting up to [`WAIT`] for it to be sent.
    pub async fn wait_for(&self, address: &str, subject: &str) -> CapturedMail {
        self.wait_until(|messages| {
            messages
                .iter()
                .rev()
                .find(|m| m.is_for(address) && m.subject.contains(subject))
                .cloned()
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "no message to {address} with a subject containing {subject:?} within {WAIT:?}; sent: {:?}",
                self.summary()
            )
        })
    }

    /// Wait until `count` messages were sent to `address`.
    pub async fn wait_for_count(&self, address: &str, count: usize) -> Vec<CapturedMail> {
        self.wait_until(|messages| {
            let matching: Vec<_> = messages
                .iter()
                .filter(|m| m.is_for(address))
                .cloned()
                .collect();
            (matching.len() >= count).then_some(matching)
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "expected {count} messages to {address} within {WAIT:?}; sent: {:?}",
                self.summary()
            )
        })
    }

    /// Subjects and recipients of everything sent, for failure messages.
    pub fn summary(&self) -> Vec<(Vec<String>, String)> {
        self.messages()
            .into_iter()
            .map(|m| (m.to, m.subject))
            .collect()
    }

    async fn wait_until<T>(&self, find: impl Fn(&[CapturedMail]) -> Option<T>) -> Option<T> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let arrived = self.inner.arrived.notified();
            tokio::pin!(arrived);
            arrived.as_mut().enable();

            if let Some(found) = find(&self.inner.messages.lock().unwrap()) {
                return Some(found);
            }
            if tokio::time::timeout_at(deadline, arrived).await.is_err() {
                return None;
            }
        }
    }

    fn record(&self, mail: CapturedMail) {
        self.inner.messages.lock().unwrap().push(mail);
        self.inner.arrived.notify_waiters();
    }
}

impl MailTransport for MailOutbox {
    fn send(&self, message: Message) -> SendFuture<'_> {
        Box::pin(async move {
            self.record(decode(&message)?);
            Ok(())
        })
    }
}

/// Recipients, subject and body of a message as a mail client would show them.
pub fn decode(message: &Message) -> anyhow::Result<CapturedMail> {
    let to = message
        .envelope()
        .to()
        .iter()
        .map(ToString::to_string)
        .collect();
    let headers = message.headers();
    // Raw header values are kept unencoded; encoding happens when formatting.
    let subject = headers.get_raw("Subject").unwrap_or_default().to_owned();
    let encoding = headers
        .get_raw("Content-Transfer-Encoding")
        .unwrap_or("7bit")
        .to_ascii_lowercase();

    let formatted = message.formatted();
    let body_start = formatted
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| anyhow::anyhow!("message without a body"))?;
    let raw = &formatted[body_start..];

    let bytes = match encoding.as_str() {
        "base64" => {
            let compact: Vec<u8> = raw
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            STANDARD.decode(compact)?
        }
        "quoted-printable" => decode_quoted_printable(raw)?,
        _ => raw.to_vec(),
    };

    Ok(CapturedMail {
        to,
        subject,
        html: String::from_utf8(bytes)?,
    })
}

/// RFC 2045 section 6.7: `=XX` escapes and `=` soft line breaks.
fn decode_quoted_printable(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'=' if input[i + 1..].starts_with(b"\r\n") => i += 3,
            b'=' if input[i + 1..].starts_with(b"\n") => i += 2,
            b'=' => {
                let hex = input
                    .get(i + 1..i + 3)
                    .ok_or_else(|| anyhow::anyhow!("truncated quoted-printable escape"))?;
                out.push(u8::from_str_radix(std::str::from_utf8(hex)?, 16)?);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use lettre::message::header::ContentType;

    use super::*;

    fn message(subject: &str, body: &str) -> Message {
        Message::builder()
            .from("App <app@example.com>".parse().unwrap())
            .to("Jane <jane@example.com>".parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body.to_owned())
            .unwrap()
    }

    #[test]
    fn decodes_non_ascii_subjects_and_bodies() {
        let body = format!(
            "<p>Votre code : <b>042917</b>. Réessayez. {}</p>",
            "é".repeat(200)
        );
        let mail = decode(&message("Vérifiez votre adresse", &body)).unwrap();

        assert_eq!(mail.to, vec!["jane@example.com"]);
        assert_eq!(mail.subject, "Vérifiez votre adresse");
        assert_eq!(mail.html, body);
        assert_eq!(mail.six_digit_code().as_deref(), Some("042917"));
    }

    #[test]
    fn decodes_ascii_bodies() {
        let mail = decode(&message(
            "Reset",
            "<a href=\"https://app/reset#token=abc-DEF_123\">go</a>",
        ))
        .unwrap();
        assert_eq!(mail.value_after("#token=").as_deref(), Some("abc-DEF_123"));
    }

    #[test]
    fn six_digit_code_ignores_longer_digit_runs() {
        let mail = CapturedMail {
            to: vec![],
            subject: String::new(),
            html: "order 1234567 then 12345 then 654321".into(),
        };
        assert_eq!(mail.six_digit_code().as_deref(), Some("654321"));
    }

    #[test]
    fn quoted_printable_handles_escapes_and_soft_breaks() {
        assert_eq!(
            decode_quoted_printable(b"caf=C3=A9 =\r\nau lait=3D").unwrap(),
            "café au lait=".as_bytes()
        );
        assert!(decode_quoted_printable(b"broken=4").is_err());
    }

    #[tokio::test]
    async fn waiting_sees_messages_sent_later() {
        let outbox = MailOutbox::new();
        let sender = outbox.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            sender.send(message("Welcome", "<p>hi</p>")).await.unwrap();
        });

        let mail = outbox.wait_for("jane@example.com", "Welcome").await;
        assert_eq!(mail.html, "<p>hi</p>");
    }
}
