//! Breached-password check through the Pwned Passwords range API, with
//! k-anonymity: only the first five hexadecimal characters of the password's
//! SHA-1 leave the service, and the match happens here.

use sha1::{Digest, Sha1};

/// The prefix sent to the range API and the suffix looked up in its answer:
/// the uppercase hexadecimal SHA-1 of the password, split after five
/// characters.
pub fn range_key(password: &str) -> (String, String) {
    let hex: String = Sha1::digest(password.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    let (prefix, suffix) = hex.split_at(5);
    (prefix.to_owned(), suffix.to_owned())
}

/// How many known breaches contain the password, read from a range answer
/// (`SUFFIX:COUNT` per line). Padding entries (count 0), malformed lines and an
/// absent suffix all count as 0.
pub fn breach_count(range: &str, suffix: &str) -> u64 {
    range
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(suffix))
        .and_then(|(_, count)| count.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    /// The password appears in at least one known breach.
    Compromised,
    /// The range API gave no usable answer and the check does not fail open.
    Unavailable,
}

/// `count` is `None` when the range API could not be asked.
pub fn verdict(count: Option<u64>, fail_open: bool) -> Verdict {
    match count {
        Some(0) => Verdict::Accepted,
        Some(_) => Verdict::Compromised,
        None if fail_open => Verdict::Accepted,
        None => Verdict::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_range_key_splits_the_uppercase_sha1() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(
            range_key("password"),
            (
                "5BAA6".to_owned(),
                "1E4C9B93F3F0682250B6CF8331B7EE68FD8".to_owned()
            )
        );
    }

    #[test]
    fn the_count_of_the_matching_suffix_is_read() {
        let range = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                     1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n\
                     011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n";
        assert_eq!(
            breach_count(range, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            9_659_365
        );
        assert_eq!(
            breach_count(range, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"),
            9_659_365
        );
    }

    #[test]
    fn padding_malformed_lines_and_absent_suffixes_count_as_zero() {
        let range = "011053FD0102E94D6AE2F8B83D76FAF94F6:0\nnot a line\nABC:many\n";
        assert_eq!(
            breach_count(range, "011053FD0102E94D6AE2F8B83D76FAF94F6"),
            0
        );
        assert_eq!(breach_count(range, "ABC"), 0);
        assert_eq!(breach_count(range, "FFFFF"), 0);
        assert_eq!(breach_count("", "FFFFF"), 0);
    }

    #[test]
    fn an_unavailable_range_api_fails_open_only_when_configured() {
        assert_eq!(verdict(Some(0), false), Verdict::Accepted);
        assert_eq!(verdict(Some(3), true), Verdict::Compromised);
        assert_eq!(verdict(None, true), Verdict::Accepted);
        assert_eq!(verdict(None, false), Verdict::Unavailable);
    }
}
