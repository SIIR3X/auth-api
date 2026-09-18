//! Login attempt domain type.
//!
//! Maps the `login_attempts` table used for brute-force detection,
//! lockout logic, and security investigations.

use ipnetwork::IpNetwork;

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
#[sqlx(type_name = "login_failure_reason", rename_all = "snake_case")]
pub enum LoginFailureReason {
    UnknownIdentifier,
    InvalidPassword,
    EmailNotVerified,
    AccountInactive,
    AccountSuspended,
    AccountDisabled,
    TwoFactorRequired,
    TwoFactorFailed,
    RateLimited,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginAttempt {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub attempted_at: OffsetDateTime,
    pub attempted_identifier: String,
    pub was_successful: bool,
    pub failure_reason: Option<LoginFailureReason>,
    pub request_ip: Option<IpNetwork>,
    pub request_user_agent: Option<String>,
}

/// Recent failures counted before a password is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecentFailures {
    /// Failed sign-ins from the client's address (its /64 for IPv6).
    pub by_ip: i64,
    /// Distinct identifiers tried from that address.
    pub distinct_identifiers_by_ip: i64,
    /// Failed sign-ins for the identifier, from any address.
    pub by_identifier: i64,
}

/// Ceilings on [`RecentFailures`].
#[derive(Debug, Clone, Copy)]
pub struct FailureCeilings {
    pub by_ip: i64,
    pub distinct_identifiers_by_ip: i64,
    pub by_identifier: i64,
}

impl RecentFailures {
    /// Whether an attempt is refused before any password work. A ceiling is
    /// reached at equality: a ceiling of 10 lets ten failures through, and
    /// refuses the attempt after them.
    pub fn reach(&self, ceilings: &FailureCeilings) -> bool {
        self.by_ip >= ceilings.by_ip
            || self.distinct_identifiers_by_ip >= ceilings.distinct_identifiers_by_ip
            || self.by_identifier >= ceilings.by_identifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CEILINGS: FailureCeilings = FailureCeilings {
        by_ip: 30,
        distinct_identifiers_by_ip: 50,
        by_identifier: 10,
    };

    const BELOW: RecentFailures = RecentFailures {
        by_ip: 29,
        distinct_identifiers_by_ip: 49,
        by_identifier: 9,
    };

    #[test]
    fn attempts_below_every_ceiling_go_through() {
        assert!(!BELOW.reach(&CEILINGS));
    }

    #[test]
    fn each_ceiling_refuses_on_its_own_at_equality() {
        let at_ip = RecentFailures { by_ip: 30, ..BELOW };
        let at_distinct = RecentFailures {
            distinct_identifiers_by_ip: 50,
            ..BELOW
        };
        let at_identifier = RecentFailures {
            by_identifier: 10,
            ..BELOW
        };
        assert!(at_ip.reach(&CEILINGS));
        assert!(at_distinct.reach(&CEILINGS));
        assert!(at_identifier.reach(&CEILINGS));
    }
}
