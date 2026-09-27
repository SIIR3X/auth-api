//! Administration of other accounts, roles and client applications. Handlers
//! check the administrator's permission; these functions act and audit.
//!
//! Every audit entry of an administrative change is written on the account it
//! changed, with the administrator's id in its metadata: the owner sees it in
//! their history, and investigators see who acted.

pub mod clients;
pub mod roles;
pub mod users;

use ipnetwork::IpNetwork;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{repositories::user as user_repo, services::email, state::AppState};

/// The administrator making a request.
#[derive(Debug, Clone, Copy)]
pub struct Actor {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub ip: Option<IpNetwork>,
    pub request_id: Option<Uuid>,
}

impl Actor {
    /// Audit metadata naming the administrator, merged with `extra`.
    pub fn metadata(&self, extra: Value) -> Value {
        let mut metadata = json!({ "by": "administrator", "administrator_id": self.user_id });
        if let (Some(target), Value::Object(extra)) = (metadata.as_object_mut(), extra) {
            target.extend(extra);
        }
        metadata
    }
}

/// Record, in the administrator's own history, that they read accounts or the
/// audit log: personal data read with a stolen administrator token leaves a
/// trace, like the owner's own export does. The read fails if it cannot be
/// recorded.
pub(crate) async fn record_read(
    state: &AppState,
    actor: &Actor,
    extra: Value,
) -> Result<(), crate::error::AppError> {
    crate::repositories::audit::append(
        &state.db,
        &crate::repositories::audit::NewAuditEntry {
            user_id: Some(actor.user_id),
            request_id: actor.request_id,
            action: crate::domain::audit::AuditAction::AdminDataRead,
            ip_address: actor.ip,
            metadata: actor.metadata(extra),
        },
    )
    .await?;
    Ok(())
}

/// Tell the owner an administrator changed their account: a compromised
/// administrator acting on it must not go unnoticed by the person it affects.
/// Best effort, after the change committed.
pub(crate) async fn notify_owner(
    state: &AppState,
    user_id: Uuid,
    change: &'static str,
    role: Option<&str>,
) {
    let Ok(Some(user)) = user_repo::find_by_id(&state.db, user_id).await else {
        return;
    };
    let mailer = state.mailer.clone();
    let templates = state.templates.clone();
    let mail_cfg = state.config.mail.clone();
    let role = role.map(str::to_owned);
    email::dispatch_best_effort("changed_by_administrator_email", async move {
        email::send_changed_by_administrator(
            &mailer,
            templates.as_ref(),
            &mail_cfg,
            &user.email,
            &user.username,
            &user.preferred_locale,
            change,
            role.as_deref(),
        )
        .await
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_metadata_names_the_administrator() {
        let actor = Actor {
            user_id: Uuid::nil(),
            session_id: Uuid::nil(),
            ip: None,
            request_id: None,
        };
        assert_eq!(
            actor.metadata(json!({ "count": 2 })),
            json!({ "by": "administrator", "administrator_id": Uuid::nil(), "count": 2 })
        );
        assert_eq!(
            actor.metadata(Value::Null),
            json!({ "by": "administrator", "administrator_id": Uuid::nil() })
        );
    }
}
