//! GeoIP lookup using the MaxMind GeoLite2-City database.
//!
//! Wraps `maxminddb::Reader` in an `Arc` so it can be shared across threads.
//! If the database path is empty or the file is missing the module degrades
//! gracefully: all lookups return `None` (fail-open).

use std::{net::IpAddr, path::Path, sync::Arc};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub city: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_empty_path_returns_unavailable_instance() {
        let geoip = GeoIp::open("");
        assert!(
            !geoip.is_available(),
            "empty path must produce an unavailable GeoIp"
        );
    }

    #[test]
    fn open_nonexistent_path_returns_unavailable_instance() {
        let geoip = GeoIp::open("/tmp/does_not_exist_rust_api_test.mmdb");
        assert!(!geoip.is_available());
    }

    #[test]
    fn lookup_on_unavailable_instance_returns_none() {
        let geoip = GeoIp::open("");
        let ip: ipnetwork::IpNetwork = "8.8.8.8/32".parse().unwrap();
        assert!(
            geoip.lookup(&ip).is_none(),
            "lookup on unavailable GeoIp must return None"
        );
    }

    #[test]
    fn lookup_loopback_returns_none_without_database() {
        let geoip = GeoIp::open("");
        let ip: ipnetwork::IpNetwork = "127.0.0.1/32".parse().unwrap();
        assert!(geoip.lookup(&ip).is_none());
    }

    // Tests using the MaxMind GeoIP2-City test database
    // The test fixture is checked in at tests/fixtures/GeoIP2-City-Test.mmdb.
    // It is the free test database published by MaxMind at
    // https://github.com/maxmind/MaxMind-DB/tree/main/test-data
    // and requires no license key.

    const TEST_DB: &str = "tests/fixtures/GeoIP2-City-Test.mmdb";

    #[test]
    fn open_real_db_is_available() {
        let geoip = GeoIp::open(TEST_DB);
        assert!(
            geoip.is_available(),
            "GeoIp::open({TEST_DB}) must return an available instance"
        );
    }

    /// 81.2.69.142 is a well-known test IP in the MaxMind test DB that maps to
    /// GB (United Kingdom), London.
    #[test]
    fn lookup_known_ip_returns_gb_country() {
        let geoip = GeoIp::open(TEST_DB);
        let ip: ipnetwork::IpNetwork = "81.2.69.142/32".parse().unwrap();
        let loc = geoip
            .lookup(&ip)
            .expect("81.2.69.142 must resolve to a location in the test DB");

        assert_eq!(
            loc.country, "GB",
            "expected country GB, got '{}'",
            loc.country
        );
        assert!(
            !loc.city.is_empty(),
            "expected a city name for 81.2.69.142, got empty string"
        );
    }

    /// 175.16.199.1 maps to CN (China) in the MaxMind test DB.
    #[test]
    fn lookup_chinese_ip_returns_cn_country() {
        let geoip = GeoIp::open(TEST_DB);
        let ip: ipnetwork::IpNetwork = "175.16.199.1/32".parse().unwrap();
        let loc = geoip
            .lookup(&ip)
            .expect("175.16.199.1 must resolve to a location in the test DB");

        assert_eq!(
            loc.country, "CN",
            "expected country CN, got '{}'",
            loc.country
        );
    }

    /// RFC-1918 addresses are not in the geo database.
    #[test]
    fn lookup_private_ip_returns_none_with_real_db() {
        let geoip = GeoIp::open(TEST_DB);
        let ip: ipnetwork::IpNetwork = "192.168.1.1/32".parse().unwrap();
        assert!(
            geoip.lookup(&ip).is_none(),
            "private IPs must not appear in the geo database"
        );
    }

    /// Loopback is not in the geo database either.
    #[test]
    fn lookup_loopback_returns_none_with_real_db() {
        let geoip = GeoIp::open(TEST_DB);
        let ip: ipnetwork::IpNetwork = "127.0.0.1/32".parse().unwrap();
        assert!(geoip.lookup(&ip).is_none());
    }
}
