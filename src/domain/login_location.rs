//! Login location domain type.
//!
//! Maps the `login_locations` table used for risk scoring.

use ipnetwork::IpNetwork;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginLocation {
    pub id: Uuid,
    pub user_id: Uuid,
    pub country: String,
    pub city: String,
    pub user_agent: String,
    pub ip_address: IpNetwork,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub last_seen: OffsetDateTime,
    pub first_seen: OffsetDateTime,
}
