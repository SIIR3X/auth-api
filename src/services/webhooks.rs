//! Webhooks: endpoints registered by administrators, and the dispatcher that
//! delivers the events recorded for them.
//!
//! A delivery is recorded in the transaction of the change (see
//! `events::enqueue`), claimed by one dispatcher for a lease, sent to an
//! address checked after resolution, signed, and retried with backoff until
//! `MAX_ATTEMPTS`. Endpoints receive events at least once and may receive them
//! out of order: `event_id` deduplicates, `occurred_at` orders.

use std::{net::SocketAddr, time::Duration};

use serde_json::{Value, json};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::{
    domain::{audit::AuditAction, outbox, webhook},
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        webhook::{self as webhook_repo, ClaimedDelivery, EndpointSettings, WebhookEndpoint},
    },
    services::admin::Actor,
    state::AppState,
    utils::crypto,
};

/// Wait between two dispatcher rounds when nothing woke it.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Deliveries claimed per round, sent concurrently.
const BATCH: i64 = 20;
/// How long a claimed delivery stays invisible to other dispatchers.
const LEASE: Duration = Duration::from_secs(300);
/// Response bodies are not read: only the status counts.
const USER_AGENT: &str = "auth-api-webhooks/1";

static WAKE: Notify = Notify::const_new();

/// Tell this process's dispatcher that deliveries may be due.
pub fn wake() {
    WAKE.notify_one();
}

/// Deliver webhooks for the life of the process. Like the event relay, each
/// round waits first, so a short-lived process never reaches for a connection.
pub fn spawn_dispatcher(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(POLL_INTERVAL) => {}
                () = WAKE.notified() => {}
            }
            loop {
                match deliver_once(&state).await {
                    Ok(sent) if sent == BATCH as usize => continue,
                    Ok(_) => break,
                    Err(e) => {
                        tracing::warn!(error = %e, "webhook dispatcher run failed");
                        break;
                    }
                }
            }
        }
    })
}

/// One round: claim the due deliveries and attempt each. Returns how many were
/// attempted.
pub async fn deliver_once(state: &AppState) -> Result<usize, sqlx::Error> {
    let pending = webhook_repo::pending_count(&state.db).await?;
    metrics::gauge!("auth_webhook_deliveries_pending").set(pending as f64);
    if pending == 0 {
        return Ok(0);
    }
    let claimed = webhook_repo::claim_due(&state.db, BATCH, LEASE).await?;
    let attempted = claimed.len();
    let mut tasks = tokio::task::JoinSet::new();
    for delivery in claimed {
        let state = state.clone();
        tasks.spawn(async move {
            let outcome = attempt(&state, &delivery).await;
            record(&state, &delivery, outcome).await
        });
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(recorded) => recorded?,
            Err(e) => tracing::error!(error = %e, "webhook delivery task failed"),
        }
    }
    Ok(attempted)
}

enum Outcome {
    Delivered(u16),
    Failed { status: Option<u16>, error: String },
}

async fn attempt(state: &AppState, delivery: &ClaimedDelivery) -> Outcome {
    let failed = |status, error: String| Outcome::Failed { status, error };
    let key = match state
        .keyring
        .decrypt(&delivery.secret, delivery.endpoint_id.as_bytes())
        .ok()
        .and_then(|secret| webhook::secret_bytes(&secret))
    {
        Some(key) => key,
        None => return failed(None, "signing secret unreadable".into()),
    };
    let url = match webhook::check_url(&delivery.url, state.config.webhooks.allow_http) {
        Ok(url) => url,
        Err(error) => return failed(None, error),
    };
    let address = match resolve(state, &url).await {
        Ok(address) => address,
        Err(error) => return failed(None, error),
    };

    let mut message = outbox::envelope(
        delivery.payload.clone(),
        delivery.event_id,
        delivery.occurred_at,
    );
    if let Value::Object(object) = &mut message {
        object.insert("event".into(), Value::String(delivery.event_name.clone()));
    }
    let body = match serde_json::to_vec(&message) {
        Ok(body) => body,
        Err(e) => return failed(None, e.to_string()),
    };
    let id = delivery.event_id.to_string();
    let timestamp = state.clock.now().unix_timestamp();

    let host = url.host_str().unwrap_or_default().to_owned();
    // The connection goes to the address that was checked, not to a second
    // resolution an attacker's DNS could answer differently.
    let client = match reqwest::Client::builder()
        .resolve(&host, address)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_millis(state.config.webhooks.timeout_ms))
        .user_agent(USER_AGENT)
        .build()
    {
        Ok(client) => client,
        Err(e) => return failed(None, e.to_string()),
    };
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("webhook-id", &id)
        .header("webhook-timestamp", timestamp.to_string())
        .header(
            "webhook-signature",
            webhook::signature(&key, &id, timestamp, &body),
        )
        .body(body)
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            Outcome::Delivered(response.status().as_u16())
        }
        Ok(response) => failed(
            Some(response.status().as_u16()),
            format!("endpoint answered {}", response.status()),
        ),
        // Fixed messages: the error of the HTTP client carries the full URL,
        // whose path or query may hold a token of the endpoint's own.
        Err(e) if e.is_timeout() => failed(None, "timed out".into()),
        Err(e) if e.is_connect() => failed(None, "connection failed".into()),
        Err(e) if e.is_redirect() => failed(None, "redirect refused".into()),
        Err(_) => failed(None, "request failed".into()),
    }
}

/// The address to connect to: every address the host resolves to must be
/// public, unless private networks are allowed.
async fn resolve(state: &AppState, url: &reqwest::Url) -> Result<SocketAddr, String> {
    let host = url.host_str().ok_or("url has no host")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = url.port_or_known_default().ok_or("url has no port")?;
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .collect();
    if addresses.is_empty() {
        return Err(format!("{host} resolves to no address"));
    }
    if !state.config.webhooks.allow_private_networks
        && addresses
            .iter()
            .any(|address| !webhook::is_public_address(address.ip()))
    {
        return Err(format!("{host} resolves to a blocked address"));
    }
    Ok(addresses[0])
}

async fn record(
    state: &AppState,
    delivery: &ClaimedDelivery,
    outcome: Outcome,
) -> Result<(), sqlx::Error> {
    match outcome {
        Outcome::Delivered(status) => {
            metrics::counter!("auth_webhook_deliveries_total", "outcome" => "delivered")
                .increment(1);
            webhook_repo::mark_delivered(&state.db, delivery.id, status).await
        }
        Outcome::Failed { status, error } => {
            let attempts = delivery.attempts.saturating_add(1);
            let retry_in =
                (attempts < webhook::MAX_ATTEMPTS).then(|| webhook::retry_delay(attempts));
            let outcome = if retry_in.is_some() {
                "retry"
            } else {
                "failed"
            };
            metrics::counter!("auth_webhook_deliveries_total", "outcome" => outcome).increment(1);
            tracing::warn!(
                delivery_id = %delivery.id,
                event = delivery.event_name,
                attempts,
                error,
                "webhook delivery failed"
            );
            webhook_repo::mark_attempt_failed(&state.db, delivery.id, status, &error, retry_in)
                .await
        }
    }
}

// Administration

pub struct SavedEndpoint {
    pub endpoint: WebhookEndpoint,
    /// Present when a secret was generated: shown once.
    pub secret: Option<String>,
}

pub struct EndpointInput<'a> {
    pub url: &'a str,
    pub description: Option<&'a str>,
    pub events: &'a [String],
    pub enabled: bool,
}

fn checked<'a>(
    state: &AppState,
    input: &'a EndpointInput<'a>,
) -> Result<(Vec<String>, Option<&'a str>), AppError> {
    webhook::check_url(input.url, state.config.webhooks.allow_http)
        .map_err(AppError::Validation)?;
    let events = webhook::check_events(input.events).map_err(AppError::Validation)?;
    let description = input.description.map(str::trim).filter(|d| !d.is_empty());
    if description.is_some_and(|d| d.chars().count() > 200) {
        return Err(AppError::Validation(
            "description must be at most 200 characters".into(),
        ));
    }
    Ok((events, description))
}

/// A new signing secret for endpoint `id`, and its ciphertext bound to it.
fn new_secret(state: &AppState, id: Uuid) -> Result<(String, String), AppError> {
    let secret = webhook::format_secret(&crypto::random_bytes::<32>());
    let encrypted = state
        .keyring
        .encrypt(&secret, id.as_bytes())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("cannot encrypt webhook secret: {e:?}")))?;
    Ok((secret, encrypted))
}

/// Pointing a webhook somewhere sends it every account event of its
/// subscription: creating one, changing where it points and rotating its
/// secret need a recent re-authentication, like granting a role.
async fn require_reauth(
    state: &AppState,
    actor: &Actor,
    reason: &'static str,
) -> Result<(), AppError> {
    crate::services::reauth::require_recent_reauth_or_password(
        state,
        actor.user_id,
        actor.session_id,
        None,
        actor.ip,
        actor.request_id,
        reason,
    )
    .await
}

/// The host of a webhook URL, for the audit log: enough to trace where events
/// went, without the path or query, which may carry a token of their own.
fn url_host(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
}

pub async fn create(
    state: &AppState,
    actor: &Actor,
    input: &EndpointInput<'_>,
) -> Result<SavedEndpoint, AppError> {
    let (events, description) = checked(state, input)?;
    require_reauth(state, actor, "admin_create_webhook").await?;
    let id = Uuid::new_v4();
    let (secret, encrypted) = new_secret(state, id)?;
    let mut tx = state.db.begin().await?;
    let endpoint = webhook_repo::create_endpoint(
        &mut *tx,
        id,
        &EndpointSettings {
            url: input.url,
            description,
            events: &events,
            enabled: input.enabled,
        },
        &encrypted,
    )
    .await?;
    audit_change(
        &mut tx,
        actor,
        AuditAction::WebhookCreated,
        endpoint.id,
        json!({ "host": url_host(input.url) }),
    )
    .await?;
    tx.commit().await?;
    Ok(SavedEndpoint {
        endpoint,
        secret: Some(secret),
    })
}

pub async fn update(
    state: &AppState,
    actor: &Actor,
    id: Uuid,
    input: &EndpointInput<'_>,
) -> Result<WebhookEndpoint, AppError> {
    let (events, description) = checked(state, input)?;
    require_reauth(state, actor, "admin_update_webhook").await?;
    let previous = webhook_repo::find_endpoint(&state.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mut tx = state.db.begin().await?;
    let endpoint = webhook_repo::update_endpoint(
        &mut *tx,
        id,
        &EndpointSettings {
            url: input.url,
            description,
            events: &events,
            enabled: input.enabled,
        },
    )
    .await?
    .ok_or(AppError::NotFound)?;
    audit_change(
        &mut tx,
        actor,
        AuditAction::WebhookUpdated,
        id,
        json!({
            "previous_host": url_host(&previous.url),
            "host": url_host(input.url),
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(endpoint)
}

pub async fn rotate_secret(state: &AppState, actor: &Actor, id: Uuid) -> Result<String, AppError> {
    require_reauth(state, actor, "admin_webhook_secret").await?;
    let (secret, encrypted) = new_secret(state, id)?;
    let mut tx = state.db.begin().await?;
    if !webhook_repo::replace_secret(&mut *tx, id, &encrypted).await? {
        return Err(AppError::NotFound);
    }
    audit_change(
        &mut tx,
        actor,
        AuditAction::WebhookSecretRotated,
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(secret)
}

/// Deleting an endpoint drops its pending deliveries: a recent
/// re-authentication, like every other change to where events go.
pub async fn delete(state: &AppState, actor: &Actor, id: Uuid) -> Result<(), AppError> {
    require_reauth(state, actor, "admin_delete_webhook").await?;
    let previous = webhook_repo::find_endpoint(&state.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mut tx = state.db.begin().await?;
    if !webhook_repo::delete_endpoint(&mut *tx, id).await? {
        return Err(AppError::NotFound);
    }
    audit_change(
        &mut tx,
        actor,
        AuditAction::WebhookDeleted,
        id,
        json!({ "host": url_host(&previous.url) }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Send a delivery again: audited like every change an administrator makes,
/// since it replays account events to the endpoint.
pub async fn redeliver(
    state: &AppState,
    actor: &Actor,
    endpoint_id: Uuid,
    delivery_id: Uuid,
) -> Result<(), AppError> {
    require_reauth(state, actor, "admin_redeliver_webhook").await?;
    let mut tx = state.db.begin().await?;
    if !webhook_repo::redeliver(&mut *tx, endpoint_id, delivery_id).await? {
        return Err(AppError::NotFound);
    }
    audit_change(
        &mut tx,
        actor,
        AuditAction::WebhookUpdated,
        endpoint_id,
        json!({ "redelivered": delivery_id }),
    )
    .await?;
    tx.commit().await?;
    wake();
    Ok(())
}

/// Audited in the change's transaction. The URL itself is left out, only its
/// host is kept: the path or query may carry a token of its own.
async fn audit_change(
    tx: &mut sqlx::PgConnection,
    actor: &Actor,
    action: AuditAction,
    id: Uuid,
    extra: serde_json::Value,
) -> Result<(), AppError> {
    let mut metadata = json!({ "webhook_id": id });
    if let (Some(metadata), Some(extra)) = (metadata.as_object_mut(), extra.as_object()) {
        metadata.extend(extra.clone());
    }
    audit::append(
        &mut *tx,
        &NewAuditEntry {
            user_id: Some(actor.user_id),
            request_id: actor.request_id,
            action,
            ip_address: actor.ip,
            metadata: actor.metadata(metadata),
        },
    )
    .await?;
    Ok(())
}
