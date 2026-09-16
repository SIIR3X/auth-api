//! Authentication service: register, login, logout, token refresh, email verification,
//! password reset, and 2FA challenge completion.
//!
//! Security notes:
//! - Password verification always runs even when the user does not exist (timing safety).
//! - Brute-force limits are checked before any credential lookup.
//! - Refresh token replay is detected via session family revocation.
//! - Pre-auth tokens (2FA challenge) are stored in Redis with a 5-minute TTL.
//!
//! Layout:
//! - `register`: registration and email verification;
//! - `login`: password sign-in, brute-force limits, lockout, hand-off to 2FA;
//! - `second_factor`: completing a paused sign-in (TOTP, email code, recovery code);
//! - `session`: refresh token rotation and logout;
//! - `password_reset`: forgotten password;
//! - `tokens`: issuing sessions and access tokens, revocation, token state checks;
//! - `guards`: attempt budgets, failure records, backoff;
//! - `pre_auth`: the short-lived state between a password and its second factor.

use deadpool_redis::redis::AsyncCommands;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{
        audit::AuditAction,
        login_attempt::LoginFailureReason,
        session::{RefreshPolicy, RefreshVerdict, Session, SessionType, TokenState, token_state},
        user::{User, UserStatus},
    },
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        login_attempt::{self, NewLoginAttempt},
        recovery_code, role,
        session::{self as session_repo, NewSession},
        token::{self, NewEmailVerificationToken, NewPasswordResetToken},
        two_factor as tf_repo,
        user::{self as user_repo, NewUser},
    },
    state::AppState,
    utils::{crypto, jwt::Claims, password, totp},
};

use ::time::Duration as TimeDuration;

use super::{email, email_2fa, events, reauth};
use crate::middleware::rate_limit::ip_bucket;
use crate::utils::{
    backoff,
    redis_counter::{self, Budget},
};

mod guards;
mod login;
mod password_reset;
mod pre_auth;
mod register;
mod second_factor;
mod session;
mod tokens;

use guards::*;
pub(crate) use guards::{ensure_account_usable, ensure_status_allows_sign_in};
pub use login::*;
pub use password_reset::*;
pub use pre_auth::*;
pub use register::*;
pub use second_factor::*;
pub use session::*;
pub use tokens::*;

/// Redis key prefix for the JTI blocklist.
const JTI_BLOCKLIST_PREFIX: &str = "jti_block:";

/// Redis key prefix for the session validity cache.
const SESSION_CACHE_PREFIX: &str = "sess_valid:";

/// TTL for cached session validity checks (seconds).
/// Short TTL ensures revocations (admin, bulk) propagate within this window.
/// Explicit logouts always invalidate the cache key immediately.
const SESSION_CACHE_TTL_SECS: u64 = 5;

/// Max failed attempts per identifier within the window before lockout.
const MAX_FAILURES_BY_IDENTIFIER: i64 = 10;

/// Max failed attempts per IP within the window before lockout.
const MAX_FAILURES_BY_IP: i64 = 30;

/// Lookback window for brute-force counting (15 minutes).
const BRUTE_FORCE_WINDOW_SECS: i64 = 900;

/// Redis key prefix for the credential-stuffing HyperLogLog counter (per IP).
const CS_HLL_PREFIX: &str = "cs_hll:";

/// Sliding window for the credential-stuffing counter (5 minutes).
const CS_WINDOW_SECS: u64 = 300;

/// Max distinct identifiers attempted from a single IP within CS_WINDOW_SECS before blocking.
const CS_MAX_DISTINCT_IDENTIFIERS: i64 = 50;

/// Max invalid refresh token attempts per IP within the window.
const MAX_REFRESH_FAILURES_BY_IP: i64 = 20;

/// TTL for the refresh failure counter in Redis (seconds).
const REFRESH_FAILURE_WINDOW_SECS: u64 = 900;

/// A rotated refresh token presented again within this window is treated as a
/// concurrent refresh from the same client (two tabs, a retried request): it is
/// refused without revoking the family. Later, it is a replay and the whole
/// family is revoked. Kept short: inside the window a replay goes undetected.
const REFRESH_REUSE_GRACE: TimeDuration = TimeDuration::seconds(2);

/// Pre-auth (2FA challenge) token TTL in Redis.
const PRE_AUTH_TTL_SECS: u64 = 300;

/// Redis key prefix for pre-auth state.
const PRE_AUTH_PREFIX: &str = "pre_auth:";

/// Redis key prefix for the per-user pre-auth token index (Set of active flow tokens).
/// Used to purge pre-auth tokens belonging to a user on sensitive events
/// (e.g. password reset) without resorting to SCAN.
const USER_PRE_AUTH_PREFIX: &str = "user_pre_auth:";

/// Max TOTP code failures per pre-auth token before the challenge is permanently rejected.
const MAX_TOTP_FAILURES: i64 = 5;

/// Max TOTP code failures per account per window, across every pre-auth token.
/// A new token only costs the password, so the per-token budget alone does not
/// bound a search of the code space.
const MAX_TOTP_FAILURES_BY_USER: i64 = 20;

/// Redis key prefix for the per-account TOTP failure budget.
const TOTP_USER_FAIL_PREFIX: &str = "totp_user_fail:";

/// Rolling window of the per-account second-factor budgets (1 hour).
const SECOND_FACTOR_USER_WINDOW_SECS: u64 = 3600;

/// Redis key prefix for consumed TOTP codes (prevents code reuse within the 30-second window).
const TOTP_USED_PREFIX: &str = "totp_used:";

/// Max recovery code failures per pre-auth token (same limit as TOTP).
const MAX_RECOVERY_FAILURES: i64 = 5;

/// Max recovery code failures per user in a rolling window (cross-session protection).
pub(crate) const MAX_RECOVERY_FAILURES_BY_USER: i64 = 10;

/// Rolling window for the per-user recovery code failure counter (24 hours).
pub(crate) const RECOVERY_FAILURE_USER_WINDOW_SECS: u64 = 86400;

/// Redis key prefix for the per-user recovery code failure counter. Recovery
/// codes guessed at sign-in and through the authenticated route share it.
pub(crate) const RC_USER_FAIL_PREFIX: &str = "rc_user_fail:";

/// Redis key prefixes of the per-challenge failure budgets, followed by the
/// pre-auth token.
pub(crate) const TOTP_FAIL_PREFIX: &str = "totp_fail:";
pub(crate) const RC_FAIL_PREFIX: &str = "rc_fail:";
pub(crate) const EMAIL_2FA_FAIL_PREFIX: &str = "email2fa_fail:";

/// Max verify-email or reset-password token submission attempts per IP within the window.
/// High enough that users sharing an egress IP (CGNAT, corporate proxies) do not
/// lock each other out; the per-token-hash cap below is what actually stops
/// brute-force against a specific token.
const MAX_TOKEN_SUBMIT_BY_IP: i64 = 10;

/// Max submission attempts per token hash, across every IP. Three rather than
/// one: a double-click or a retried request must not burn a valid link.
const MAX_TOKEN_SUBMIT_BY_HASH: i64 = 3;

/// Sliding window for token submission rate limiting (1 hour).
const TOKEN_SUBMIT_WINDOW_SECS: u64 = 3600;

/// Email verification token lifetime.
const EMAIL_TOKEN_EXPIRY_SECS: u64 = 60 * 60 * 24; // 24h

/// Password reset token lifetime.
const RESET_TOKEN_EXPIRY_SECS: u64 = 60 * 30; // 30 min

/// Forgot-password requests per IP per window.
const MAX_FORGOT_PASSWORD_BY_IP: i64 = 5;

/// Window of the per-IP forgot-password budget (15 minutes).
const FORGOT_PASSWORD_IP_WINDOW_SECS: u64 = 900;

/// Reset emails per account per window, across every IP.
const MAX_FORGOT_PASSWORD_BY_ACCOUNT: i64 = 3;

/// Window of the per-account forgot-password budget (1 hour).
const FORGOT_PASSWORD_ACCOUNT_WINDOW_SECS: u64 = 3600;

/// Verification e-mail requests per client address (IPv6 /64) per window.
const MAX_VERIFICATION_RESENDS_BY_IP: i64 = 5;
const VERIFICATION_RESEND_IP_WINDOW_SECS: u64 = 900;

/// Verification e-mails per account per window, across every address:
/// registrations on the same pending address count too.
const MAX_VERIFICATION_RESENDS_BY_ACCOUNT: i64 = 3;
const VERIFICATION_RESEND_ACCOUNT_WINDOW_SECS: u64 = 3600;

/// Every forgot-password response takes at least this long, known address or not.
const FORGOT_PASSWORD_MIN_DURATION: std::time::Duration = std::time::Duration::from_millis(250);

const DUMMY_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

/// A hash no password can match, verified when the identifier is unknown so a
/// login costs the same either way.
///
/// Built from the configured parameters rather than written down: Argon2 reads
/// its cost from the PHC string, so a hard-coded decoy costs what *it* says,
/// not what real hashes cost, and turns into an enumeration oracle as soon as
/// `ARGON2_*` differs from it. The plaintext is random, drawn once per process.
fn dummy_hash(cfg: &crate::config::CryptoConfig) -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        password::hash(&crypto::generate_token(), cfg).unwrap_or_else(|e| {
            tracing::error!(error = ?e, "could not build a decoy hash from the Argon2 parameters");
            DUMMY_HASH.to_owned()
        })
    })
}

pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub session: Session,
}

#[allow(clippy::large_enum_variant)]
pub enum LoginResult {
    Complete(AuthTokens),
    /// 2FA is required; submit this token with the code to complete login.
    /// method: "totp" or "email"
    TwoFactorRequired {
        pre_auth_token: String,
        method: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthState {
    pub user_id: Uuid,
    /// Propagated from the login request so the correct token TTL is used after 2FA completes.
    #[serde(default)]
    pub remember_me: bool,
    /// Second factor this challenge was issued for. Each completion endpoint
    /// accepts only its own method, so a TOTP challenge cannot be answered with
    /// an email code. `None` only for tokens minted before the field existed,
    /// which are refused (they expire within `PRE_AUTH_TTL_SECS` anyway).
    #[serde(default)]
    pub method: Option<ChallengeMethod>,
}

/// Second factor demanded by a login challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeMethod {
    Totp,
    Email,
}

impl ChallengeMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Email => "email",
        }
    }
}

impl PreAuthState {
    /// Refuse a completion endpoint that does not match the challenge.
    pub fn expect_method(&self, expected: ChallengeMethod) -> Result<(), AppError> {
        if self.method == Some(expected) {
            Ok(())
        } else {
            Err(AppError::TokenInvalid)
        }
    }
}

/// Redis key prefix for the refresh token blocklist.
const RT_BLOCKLIST_PREFIX: &str = "rt_block:";
