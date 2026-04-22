//! Behavioral anomaly detection / risk scoring for login events.
//!
//! Computes a numeric risk score from context signals observed at login time.
//! Based on the score the caller should:
//!   score < alert_threshold      - allow normally
//!   score >= alert_threshold     - send an alert email and allow
//!   score >= challenge_threshold - force 2FA challenge (even without TOTP)
//!   score >= block_threshold     - reject the login entirely
//!
//! Signals and weights:
//!   new country (never seen before)              +40
//!   new city (country known, city is new)        +15
//!   new device (user-agent never seen)           +20
//!   unusual hour (00:00 to 05:59 UTC)            +15
//!   impossible travel (> 500 km/h since last)    +50

use std::collections::HashSet;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::RiskConfig,
    domain::audit::AuditAction,
    error::AppError,
    repositories::{
        audit::{self, NewAuditEntry},
        login_location::{self, RiskHistoryEntry},
    },
    state::AppState,
    utils::geoip::GeoLocation,
};

// Signal weights
const SCORE_NEW_COUNTRY: u32 = 40;
const SCORE_NEW_CITY: u32 = 15;
const SCORE_NEW_DEVICE: u32 = 20;
const SCORE_UNUSUAL_HOUR: u32 = 15;
const SCORE_IMPOSSIBLE_TRAVEL: u32 = 50;

// Approximate max speed in km/h considered normal travel
const MAX_NORMAL_SPEED_KMH: f64 = 500.0;

// --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginContext {
    pub user_id: Uuid,
    pub ip: IpNetwork,
    pub user_agent: String,
    pub geo: Option<GeoLocation>,
    pub login_time: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RiskDecision {
    Allow,
    Alert,
    Challenge,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskResult {
    pub score: u32,
    pub decision: RiskDecision,
    pub signals: Vec<String>,
}

// --

pub async fn evaluate(state: &AppState, ctx: &LoginContext) -> Result<RiskResult, AppError> {
    let cfg = &state.config.risk;
    let history = login_location::find_recent_for_risk(&state.db, ctx.user_id, cfg.history_days)
        .await
        .map_err(AppError::from)?;

    let (score, signals) = compute_score(ctx, &history);
    let decision = decide(score, cfg);

    Ok(RiskResult {
        score,
        decision,
        signals,
    })
}

/// Upsert the current login context into location history (called after the login is allowed).
pub async fn record_login(state: &AppState, ctx: &LoginContext) -> Result<(), AppError> {
    let (country, city, lat, lon) = ctx
        .geo
        .as_ref()
        .map_or(("".to_string(), "".to_string(), None, None), |g| {
            (g.country.clone(), g.city.clone(), g.latitude, g.longitude)
        });

    login_location::upsert(
        &state.db,
        ctx.user_id,
        &country,
        &city,
        &ctx.user_agent[..ctx.user_agent.len().min(512)],
        ctx.ip,
        lat,
        lon,
    )
    .await
    .map_err(AppError::from)
}

/// Write a SuspiciousLogin audit entry and return Ok(()).
pub async fn audit_suspicious(
    state: &AppState,
    ctx: &LoginContext,
    result: &RiskResult,
    request_id: Option<Uuid>,
) -> Result<(), AppError> {
    let metadata = serde_json::json!({
        "score": result.score,
        "signals": result.signals,
        "country": ctx.geo.as_ref().map(|g| &g.country),
        "city": ctx.geo.as_ref().map(|g| &g.city),
        "user_agent": &ctx.user_agent,
    });

    audit::append(
        &state.db,
        &NewAuditEntry {
            user_id: Some(ctx.user_id),
            request_id,
            action: AuditAction::SuspiciousLogin,
            ip_address: Some(ctx.ip),
            metadata,
        },
    )
    .await
    .map_err(AppError::from)
}

// --

pub fn compute_score(ctx: &LoginContext, history: &[RiskHistoryEntry]) -> (u32, Vec<String>) {
    let mut score = 0u32;
    let mut signals: Vec<String> = Vec::new();

    let country = ctx.geo.as_ref().map(|g| g.country.as_str()).unwrap_or("");
    let city = ctx.geo.as_ref().map(|g| g.city.as_str()).unwrap_or("");

    let known_countries: HashSet<&str> = history.iter().map(|l| l.country.as_str()).collect();
    let known_cities: HashSet<&str> = history.iter().map(|l| l.city.as_str()).collect();
    let known_uas: HashSet<&str> = history.iter().map(|l| l.user_agent.as_str()).collect();

    // New country
    if !country.is_empty() && !known_countries.contains(&country) {
        score += SCORE_NEW_COUNTRY;
        signals.push(format!("new_country:{}", country));
    }
    // New city (country was already seen)
    else if !city.is_empty()
        && known_countries.contains(&country)
        && !known_cities.contains(&city)
    {
        score += SCORE_NEW_CITY;
        signals.push(format!("new_city:{}", city));
    }

    // New device (user-agent)
    let ua = &ctx.user_agent[..ctx.user_agent.len().min(512)];
    if !ua.is_empty() && !known_uas.contains(&ua) {
        score += SCORE_NEW_DEVICE;
        signals.push("new_device".to_string());
    }

    // Unusual hour (00:00 to 05:59 UTC)
    let hour = ctx.login_time.hour();
    if hour < 6 {
        score += SCORE_UNUSUAL_HOUR;
        signals.push(format!("unusual_hour:{}", hour));
    }

    // Impossible travel
    if let Some(geo) = &ctx.geo
        && let (Some(lat), Some(lon)) = (geo.latitude, geo.longitude)
        && let Some(impossible) = check_impossible_travel(lat, lon, ctx.login_time, history)
        && impossible
    {
        score += SCORE_IMPOSSIBLE_TRAVEL;
        signals.push("impossible_travel".to_string());
    }

    (score, signals)
}

fn decide(score: u32, cfg: &RiskConfig) -> RiskDecision {
    if score >= cfg.block_threshold {
        RiskDecision::Block
    } else if score >= cfg.challenge_threshold {
        RiskDecision::Challenge
    } else if score >= cfg.alert_threshold {
        RiskDecision::Alert
    } else {
        RiskDecision::Allow
    }
}

/// Returns Some(true) if travel speed since the most recent known location exceeds
/// MAX_NORMAL_SPEED_KMH. Returns None if there is no previous location with coordinates.
///
/// Uses max_by_key on last_seen so the result is independent of slice ordering;
/// the caller must not rely on the query ordering to guarantee correctness.
fn check_impossible_travel(
    lat: f64,
    lon: f64,
    now: OffsetDateTime,
    history: &[RiskHistoryEntry],
) -> Option<bool> {
    let prev = history
        .iter()
        .filter(|l| l.latitude.is_some() && l.longitude.is_some())
        .max_by_key(|l| l.last_seen)?;

    let prev_lat = prev.latitude?;
    let prev_lon = prev.longitude?;
    let elapsed_hours = (now - prev.last_seen).as_seconds_f64() / 3600.0;

    if elapsed_hours <= 0.0 {
        return None;
    }

    let distance_km = haversine_km(prev_lat, prev_lon, lat, lon);
    let speed = distance_km / elapsed_hours;

    Some(speed > MAX_NORMAL_SPEED_KMH)
}

fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0; // Earth radius in km
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    R * c
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::*;
    use crate::config::RiskConfig;

    fn default_cfg() -> RiskConfig {
        RiskConfig {
            geoip_db_path: String::new(),
            geoip_required: false,
            alert_threshold: 30,
            challenge_threshold: 60,
            block_threshold: 80,
            history_days: 90,
        }
    }

    fn history_entry(
        country: &str,
        city: &str,
        user_agent: &str,
        lat: Option<f64>,
        lon: Option<f64>,
        secs_ago: i64,
    ) -> RiskHistoryEntry {
        RiskHistoryEntry {
            country: country.to_owned(),
            city: city.to_owned(),
            user_agent: user_agent.to_owned(),
            latitude: lat,
            longitude: lon,
            last_seen: OffsetDateTime::now_utc() - time::Duration::seconds(secs_ago),
        }
    }

    fn ctx(
        country: &str,
        city: &str,
        ua: &str,
        lat: Option<f64>,
        lon: Option<f64>,
        hour: u8,
    ) -> LoginContext {
        use ipnetwork::IpNetwork;
        use uuid::Uuid;

        // Build a login_time at the requested UTC hour today.
        let now = OffsetDateTime::now_utc();
        let login_time = now
            .replace_hour(hour)
            .unwrap()
            .replace_minute(0)
            .unwrap()
            .replace_second(0)
            .unwrap();

        let geo = if country.is_empty() {
            None
        } else {
            Some(GeoLocation {
                country: country.to_owned(),
                city: city.to_owned(),
                latitude: lat,
                longitude: lon,
            })
        };

        LoginContext {
            user_id: Uuid::new_v4(),
            ip: "127.0.0.1/32".parse::<IpNetwork>().unwrap(),
            user_agent: ua.to_owned(),
            geo,
            login_time,
        }
    }

    // compute_score

    #[test]
    fn compute_score_empty_history_no_geo_no_ua_returns_zero() {
        // No history, no geo, empty UA, normal hour → zero signals.
        let login_ctx = ctx("", "", "", None, None, 10);
        let (score, signals) = compute_score(&login_ctx, &[]);
        assert_eq!(score, 0, "expected zero score, got signals: {signals:?}");
    }

    #[test]
    fn compute_score_new_country_adds_40() {
        let history = vec![history_entry("DE", "Berlin", "agent/1.0", None, None, 3600)];
        let login_ctx = ctx("FR", "Paris", "agent/1.0", None, None, 10);
        let (score, signals) = compute_score(&login_ctx, &history);
        assert!(
            signals.iter().any(|s| s.starts_with("new_country:")),
            "expected new_country signal"
        );
        assert_eq!(
            score, SCORE_NEW_COUNTRY,
            "expected only new_country (+{SCORE_NEW_COUNTRY}), got {score}"
        );
    }

    #[test]
    fn compute_score_new_city_known_country_adds_15() {
        // Country (FR) is already in history but city (Lyon) is new.
        let history = vec![history_entry("FR", "Paris", "agent/1.0", None, None, 3600)];
        let login_ctx = ctx("FR", "Lyon", "agent/1.0", None, None, 10);
        let (score, signals) = compute_score(&login_ctx, &history);
        assert!(
            signals.iter().any(|s| s.starts_with("new_city:")),
            "expected new_city signal"
        );
        assert_eq!(
            score, SCORE_NEW_CITY,
            "expected only new_city (+{SCORE_NEW_CITY}), got {score}"
        );
    }

    #[test]
    fn compute_score_known_country_and_city_no_geo_signal() {
        // Exact country+city match → no geo signal.
        let history = vec![history_entry("FR", "Paris", "agent/1.0", None, None, 3600)];
        let login_ctx = ctx("FR", "Paris", "agent/1.0", None, None, 10);
        let (score, signals) = compute_score(&login_ctx, &history);
        assert!(
            !signals
                .iter()
                .any(|s| s.starts_with("new_country") || s.starts_with("new_city")),
            "unexpected geo signal with known country+city: {signals:?}"
        );
        assert_eq!(score, 0);
    }

    #[test]
    fn compute_score_new_device_adds_20() {
        let history = vec![history_entry("", "", "known-agent/1.0", None, None, 3600)];
        let login_ctx = ctx("", "", "new-browser/2.0", None, None, 10);
        let (score, signals) = compute_score(&login_ctx, &history);
        assert!(
            signals.contains(&"new_device".to_string()),
            "expected new_device signal"
        );
        assert_eq!(score, SCORE_NEW_DEVICE);
    }

    #[test]
    fn compute_score_known_device_no_device_signal() {
        let ua = "same-agent/1.0";
        let history = vec![history_entry("", "", ua, None, None, 3600)];
        let login_ctx = ctx("", "", ua, None, None, 10);
        let (score, signals) = compute_score(&login_ctx, &history);
        assert!(
            !signals.contains(&"new_device".to_string()),
            "unexpected new_device for known agent"
        );
        assert_eq!(score, 0);
    }

    #[test]
    fn compute_score_unusual_hour_adds_15() {
        // Hour 3 is within the 00–05 window.
        let login_ctx = ctx("", "", "", None, None, 3);
        let (score, signals) = compute_score(&login_ctx, &[]);
        assert!(
            signals.iter().any(|s| s.starts_with("unusual_hour:")),
            "expected unusual_hour signal"
        );
        assert_eq!(score, SCORE_UNUSUAL_HOUR);
    }

    #[test]
    fn compute_score_hour_6_is_not_unusual() {
        let login_ctx = ctx("", "", "", None, None, 6);
        let (_, signals) = compute_score(&login_ctx, &[]);
        assert!(!signals.iter().any(|s| s.starts_with("unusual_hour")));
    }

    #[test]
    fn compute_score_multiple_signals_accumulate() {
        // new_country (+40) + new_device (+20) + unusual_hour (+15) = 75
        let history = vec![history_entry("DE", "Berlin", "agent/1.0", None, None, 3600)];
        let login_ctx = ctx("FR", "Paris", "new-browser/2.0", None, None, 2);
        let (score, signals) = compute_score(&login_ctx, &history);
        assert!(
            score >= SCORE_NEW_COUNTRY + SCORE_NEW_DEVICE + SCORE_UNUSUAL_HOUR,
            "expected ≥{} for 3 signals, got {score}: {signals:?}",
            SCORE_NEW_COUNTRY + SCORE_NEW_DEVICE + SCORE_UNUSUAL_HOUR
        );
    }

    #[test]
    fn compute_score_impossible_travel_adds_50() {
        // Previous location: Tokyo (35.6°N, 139.7°E), 1 hour ago.
        // Current location: New York (40.7°N, -74.0°W).
        // Distance ≈ 10,838 km, elapsed = 1 h → speed ≈ 10,838 km/h >> 500 km/h limit.
        let history = vec![history_entry(
            "JP",
            "Tokyo",
            "agent/1.0",
            Some(35.6762),
            Some(139.6503),
            3600, // 1 hour ago
        )];
        let login_ctx = LoginContext {
            user_id: uuid::Uuid::new_v4(),
            ip: "127.0.0.1/32".parse().unwrap(),
            user_agent: "agent/1.0".to_owned(),
            geo: Some(GeoLocation {
                country: "JP".to_owned(), // same country - won't add country signal
                city: "Tokyo".to_owned(), // same city - won't add city signal
                latitude: Some(40.7128),  // but coordinates are New York's
                longitude: Some(-74.0060),
            }),
            login_time: OffsetDateTime::now_utc(),
        };

        let (score, signals) = compute_score(&login_ctx, &history);
        assert!(
            signals.contains(&"impossible_travel".to_string()),
            "expected impossible_travel signal, got: {signals:?}"
        );
        assert!(score >= SCORE_IMPOSSIBLE_TRAVEL);
    }

    #[test]
    fn compute_score_normal_speed_no_impossible_travel() {
        // Paris to Lyon: ≈ 392 km, 2 hours ago → speed ≈ 196 km/h (well below 500 km/h).
        let history = vec![history_entry(
            "FR",
            "Paris",
            "agent/1.0",
            Some(48.8566),
            Some(2.3522),
            7200, // 2 hours ago
        )];
        let login_ctx = LoginContext {
            user_id: uuid::Uuid::new_v4(),
            ip: "127.0.0.1/32".parse().unwrap(),
            user_agent: "agent/1.0".to_owned(),
            geo: Some(GeoLocation {
                country: "FR".to_owned(),
                city: "Lyon".to_owned(),
                latitude: Some(45.7640),
                longitude: Some(4.8357),
            }),
            login_time: OffsetDateTime::now_utc(),
        };

        let (_, signals) = compute_score(&login_ctx, &history);
        assert!(
            !signals.contains(&"impossible_travel".to_string()),
            "unexpected impossible_travel for normal-speed travel: {signals:?}"
        );
    }

    // decide

    #[test]
    fn decide_below_alert_is_allow() {
        let cfg = default_cfg(); // alert=30
        assert_eq!(decide(0, &cfg), RiskDecision::Allow);
        assert_eq!(decide(29, &cfg), RiskDecision::Allow);
    }

    #[test]
    fn decide_at_alert_threshold_is_alert() {
        let cfg = default_cfg(); // alert=30, challenge=60
        assert_eq!(decide(30, &cfg), RiskDecision::Alert);
        assert_eq!(decide(59, &cfg), RiskDecision::Alert);
    }

    #[test]
    fn decide_at_challenge_threshold_is_challenge() {
        let cfg = default_cfg(); // challenge=60, block=80
        assert_eq!(decide(60, &cfg), RiskDecision::Challenge);
        assert_eq!(decide(79, &cfg), RiskDecision::Challenge);
    }

    #[test]
    fn decide_at_block_threshold_is_block() {
        let cfg = default_cfg(); // block=80
        assert_eq!(decide(80, &cfg), RiskDecision::Block);
        assert_eq!(decide(100, &cfg), RiskDecision::Block);
    }
}
