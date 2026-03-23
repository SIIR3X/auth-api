//! GeoIP lookup using the MaxMind GeoLite2-City database.
//!
//! Wraps `maxminddb::Reader` in an `Arc` so it can be shared across threads.
//! If the database path is empty or the file is missing the module degrades
//! gracefully: all lookups return `None` (fail-open).

use std::{net::IpAddr, path::Path, sync::Arc};

use ipnetwork::IpNetwork;

#[derive(Debug, Clone)]
pub struct GeoIp(Option<Arc<maxminddb::Reader<Vec<u8>>>>);

impl GeoIp {
    /// Load the GeoLite2-City.mmdb file. Returns an empty reader if the path
    /// is blank or the file cannot be opened.
    pub fn open(path: &str) -> Self {
        if path.is_empty() || !Path::new(path).exists() {
            return Self(None);
        }
        match maxminddb::Reader::open_readfile(path) {
            Ok(reader) => Self(Some(Arc::new(reader))),
            Err(e) => {
                tracing::warn!(path, error = %e, "failed to open GeoIP database, risk signals disabled");
                Self(None)
            }
        }
    }

    pub fn is_available(&self) -> bool {
        self.0.is_some()
    }

    /// Look up the country ISO code and city name for an IP.
    /// Returns `None` if GeoIP is unavailable or the IP is not found.
    pub fn lookup(&self, ip: &IpNetwork) -> Option<GeoLocation> {
        let reader = self.0.as_ref()?;

        let ip_addr: IpAddr = ip.ip();

        let result = reader.lookup(ip_addr).ok()?;
        if !result.has_data() {
            return None;
        }

        let record: maxminddb::geoip2::City<'_> = result.decode().ok()??;

        let country = record.country.iso_code.unwrap_or("").to_string();

        let city = record.city.names.english.unwrap_or("").to_string();

        let latitude = record.location.latitude;
        let longitude = record.location.longitude;

        Some(GeoLocation {
            country,
            city,
            latitude,
            longitude,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GeoLocation {
    pub country: String,
    pub city: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}
