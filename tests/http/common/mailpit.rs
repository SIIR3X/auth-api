//! Mailpit helper - connects to the shared Mailpit instance started by the
//! test infrastructure (docker-compose.test.yml) and exposes a typed client
//! to query captured messages.
//!
//! Usage:
//! ```
//! let app = TestApp::spawn_with_mailpit().await;
//! // ... trigger an action that sends an email ...
//! let msg = app.mailpit().wait_for_message("user@example.com", "Subject").await.unwrap();
//! assert!(msg.html.contains("verify"));
//! ```

use serde::Deserialize;
use time;

/// Fixed ports matching docker-compose.test.yml.
pub struct MailpitPorts {
    pub smtp_port: u16,
    pub api_port: u16,
}

/// Returns the ports of the shared Mailpit instance (Docker service).
pub fn mailpit_ports() -> MailpitPorts {
    MailpitPorts {
        smtp_port: 1026,
        api_port: 8026,
    }
}

// Response types

#[derive(Deserialize)]
struct SearchResult {
    messages: Vec<MessageSummary>,
}

#[derive(Deserialize)]
struct MessageSummary {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Subject")]
    subject: String,
    #[serde(rename = "Created")]
    created: String,
}

#[derive(Deserialize)]
pub struct MessageDetail {
    #[serde(rename = "Subject")]
    pub subject: String,
    #[serde(rename = "HTML")]
    pub html: String,
}

// Client

pub struct MailpitClient {
    base_url: String,
    http: reqwest::Client,
}

impl MailpitClient {
    pub fn new(api_port: u16) -> Self {
        Self {
            base_url: format!("http://127.0.0.1:{api_port}"),
            http: reqwest::Client::new(),
        }
    }

    /// Poll (up to 5 s) until a message addressed to `email` with `subject`
    /// arrives **after** the moment this method is called.  Filtering by
    /// subject and timestamp prevents parallel tests from stealing each other's
    /// messages or picking up stale emails left over from previous test runs.
    pub async fn wait_for_message(&self, email: &str, subject: &str) -> Option<MessageDetail> {
        // Record "now" before we start polling so we can discard any pre-existing
        // messages that happen to match the same email + subject.
        let not_before = time::OffsetDateTime::now_utc() - time::Duration::milliseconds(500); // small back-buffer for clock skew

        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(5_000);
        while std::time::Instant::now() < deadline {
            if let Some(m) = self.find_by_subject(email, subject, not_before).await {
                return Some(m);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        None
    }

    async fn find_by_subject(
        &self,
        email: &str,
        subject: &str,
        not_before: time::OffsetDateTime,
    ) -> Option<MessageDetail> {
        // Search by recipient email, then filter by subject and timestamp in Rust.
        let encoded_email = email.replace('@', "%40");
        let url = format!("{}/api/v1/search?query=to:{}", self.base_url, encoded_email);
        let search: SearchResult = self.http.get(url).send().await.ok()?.json().await.ok()?;

        // Collect candidates: matching subject, timestamp parseable and >= not_before.
        let mut candidates: Vec<(time::OffsetDateTime, &MessageSummary)> = search
            .messages
            .iter()
            .filter(|m| m.subject == subject)
            .filter_map(|m| {
                let created = time::OffsetDateTime::parse(
                    &m.created,
                    &time::format_description::well_known::Rfc3339,
                )
                .ok()?;
                if created < not_before {
                    return None;
                }
                Some((created, m))
            })
            .collect();

        // Newest first - ensures we pick the message that matches the latest DB code
        // when multiple OTP emails for the same recipient exist (e.g. setup + explicit send).
        candidates.sort_by(|a, b| b.0.cmp(&a.0));

        if let Some((_, msg)) = candidates.first() {
            return self.get_detail(&msg.id).await;
        }
        None
    }

    async fn get_detail(&self, id: &str) -> Option<MessageDetail> {
        self.http
            .get(format!("{}/api/v1/message/{id}", self.base_url))
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()
    }
}
