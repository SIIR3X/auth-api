//! Administration of other accounts, roles and client applications. Handlers
//! check the administrator's permission; these functions act and audit.
//!
//! Every audit entry of an administrative change is written on the account it
//! changed, with the administrator's id in its metadata: the owner sees it in
//! their history, and investigators see who acted.

pub mod users;

use ipnetwork::IpNetwork;
use serde_json::{Value, json};
use uuid::Uuid;

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
