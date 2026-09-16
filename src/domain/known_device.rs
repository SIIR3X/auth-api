//! What counts as "the same device" for new-device sign-in alerts: the browser
//! and operating system families of the user agent. Versions change with every
//! update and network addresses with every mobile network; neither makes a new
//! device.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceFamily {
    pub browser: &'static str,
    pub os: &'static str,
}

impl DeviceFamily {
    /// Readable description for the alert, such as "Firefox on Linux".
    pub fn describe(&self) -> String {
        format!("{} on {}", self.browser, self.os)
    }

    /// Stored instead of the user agent itself.
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(format!("{}|{}", self.browser, self.os).as_bytes()).into()
    }
}

/// The families of `user_agent`. Order matters: many browsers carry the tokens
/// of the ones they derive from (Edge says Chrome and Safari, Chrome says Safari).
pub fn device_family(user_agent: Option<&str>) -> DeviceFamily {
    let ua = user_agent.unwrap_or("").trim();
    let has = |token: &str| ua.contains(token);

    let os = if has("Android") {
        "Android"
    } else if has("iPhone") || has("iPad") || has("iPod") {
        "iOS"
    } else if has("CrOS") {
        "ChromeOS"
    } else if has("Windows") {
        "Windows"
    } else if has("Macintosh") || has("Mac OS X") {
        "macOS"
    } else if has("Linux") {
        "Linux"
    } else {
        "an unknown system"
    };

    let browser = if ua.is_empty() {
        "an unknown client"
    } else if has("Edg/") || has("Edge/") || has("EdgiOS") || has("EdgA/") {
        "Edge"
    } else if has("OPR/") || has("Opera") {
        "Opera"
    } else if has("Firefox/") || has("FxiOS") {
        "Firefox"
    } else if has("SamsungBrowser") {
        "Samsung Internet"
    } else if has("Chrome/") || has("CriOS") {
        "Chrome"
    } else if has("Safari/") {
        "Safari"
    } else {
        "another client"
    };

    DeviceFamily { browser, os }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family(ua: &str) -> String {
        device_family(Some(ua)).describe()
    }

    #[test]
    fn common_user_agents_get_their_families() {
        for (ua, expected) in [
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
                "Firefox on Linux",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
                "Chrome on Windows",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0",
                "Edge on Windows",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
                "Safari on macOS",
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/139.0 Mobile/15E148 Safari/604.1",
                "Chrome on iOS",
            ),
            (
                "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0 Mobile Safari/537.36",
                "Samsung Internet on Android",
            ),
            ("curl/8.9.1", "another client on an unknown system"),
        ] {
            assert_eq!(family(ua), expected, "{ua}");
        }
        assert_eq!(
            device_family(None).describe(),
            "an unknown client on an unknown system"
        );
    }

    #[test]
    fn versions_do_not_make_a_new_device() {
        let old = device_family(Some("Mozilla/5.0 (X11; Linux x86_64) Firefox/139.0"));
        let new = device_family(Some("Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"));
        assert_eq!(old.fingerprint(), new.fingerprint());
        assert_ne!(
            old.fingerprint(),
            device_family(Some("Mozilla/5.0 (Windows NT 10.0) Firefox/140.0")).fingerprint()
        );
    }
}
