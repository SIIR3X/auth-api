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

/// Returns Some(true) if travel speed since last known location exceeds MAX_NORMAL_SPEED_KMH.
/// Returns None if there is no previous location with coordinates.
fn check_impossible_travel(
    lat: f64,
    lon: f64,
    now: OffsetDateTime,
    history: &[RiskHistoryEntry],
) -> Option<bool> {
    let prev = history
        .iter()
        .find(|l| l.latitude.is_some() && l.longitude.is_some())?;

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
