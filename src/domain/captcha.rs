//! CAPTCHA verdicts, apart from the HTTP call that obtains an answer.

/// What the verification endpoint gave back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaUpstream {
    /// No response: connection failure or timeout.
    Unreachable,
    /// A response with a non-success HTTP status.
    Failed,
    /// A success status with a body that does not parse.
    Unreadable,
    /// A readable answer.
    Answered { success: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaVerdict {
    Accepted,
    Rejected,
    Unavailable,
}

/// Judge an answer. A negative answer is a rejection whatever the fallback;
/// only a missing answer is subject to `fail_open`.
pub fn captcha_verdict(upstream: CaptchaUpstream, fail_open: bool) -> CaptchaVerdict {
    match upstream {
        CaptchaUpstream::Answered { success: true } => CaptchaVerdict::Accepted,
        CaptchaUpstream::Answered { success: false } => CaptchaVerdict::Rejected,
        _ if fail_open => CaptchaVerdict::Accepted,
        _ => CaptchaVerdict::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MISSING: [CaptchaUpstream; 3] = [
        CaptchaUpstream::Unreachable,
        CaptchaUpstream::Failed,
        CaptchaUpstream::Unreadable,
    ];

    #[test]
    fn an_answer_decides_whatever_the_fallback() {
        for fail_open in [false, true] {
            assert_eq!(
                captcha_verdict(CaptchaUpstream::Answered { success: true }, fail_open),
                CaptchaVerdict::Accepted
            );
            assert_eq!(
                captcha_verdict(CaptchaUpstream::Answered { success: false }, fail_open),
                CaptchaVerdict::Rejected,
                "a negative answer is never accepted, even failing open"
            );
        }
    }

    #[test]
    fn a_missing_answer_follows_the_fallback() {
        for upstream in MISSING {
            assert_eq!(captcha_verdict(upstream, true), CaptchaVerdict::Accepted);
            assert_eq!(
                captcha_verdict(upstream, false),
                CaptchaVerdict::Unavailable
            );
        }
    }
}
