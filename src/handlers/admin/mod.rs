//! Administration routes, under `/admin`. Each requires an access token
//! carrying the permission of its action, a second factor enrolled on the
//! administrator's account, and the permission still granted in the database.

pub mod audit;
pub mod clients;
pub mod roles;
pub mod users;

use crate::services::admin::Actor;

use super::extractors::AdminUser;

pub(crate) fn actor(admin: &AdminUser, ip: Option<ipnetwork::IpNetwork>) -> Actor {
    Actor {
        user_id: admin.auth.user_id,
        session_id: admin.auth.session_id,
        ip,
        request_id: admin.auth.request_id,
    }
}
