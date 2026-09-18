//! Rate limiter verdicts, apart from the Redis script that counts requests.

/// What the limiter answered for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimiterAnswer {
    /// Under every limit.
    Clear,
    /// Over a limit, which frees a slot in `ms` milliseconds.
    Wait { ms: u64 },
    /// The limiter could not be asked.
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitVerdict {
    Allow,
    Refuse { retry_after_secs: u64 },
    Unavailable,
}

pub fn rate_limit_verdict(answer: LimiterAnswer, fail_open: bool) -> RateLimitVerdict {
    match answer {
        LimiterAnswer::Clear => RateLimitVerdict::Allow,
        LimiterAnswer::Wait { ms } => RateLimitVerdict::Refuse {
            retry_after_secs: retry_after_secs(ms),
        },
        LimiterAnswer::Unreachable if fail_open => RateLimitVerdict::Allow,
        LimiterAnswer::Unreachable => RateLimitVerdict::Unavailable,
    }
}

/// `Retry-After` in whole seconds: rounded up, so a client waiting that long
/// finds a free slot, and never 0, which would invite an immediate retry.
pub fn retry_after_secs(wait_ms: u64) -> u64 {
    wait_ms.div_ceil(1000).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_rounds_up_to_a_whole_second() {
        for (wait_ms, secs) in [
            (0, 1),
            (1, 1),
            (999, 1),
            (1000, 1),
            (1001, 2),
            (59_999, 60),
            (u64::MAX, u64::MAX.div_ceil(1000)),
        ] {
            assert_eq!(retry_after_secs(wait_ms), secs, "{wait_ms} ms");
        }
    }

    #[test]
    fn an_answer_decides_and_only_an_outage_follows_the_fallback() {
        for fail_open in [false, true] {
            assert_eq!(
                rate_limit_verdict(LimiterAnswer::Clear, fail_open),
                RateLimitVerdict::Allow
            );
            assert_eq!(
                rate_limit_verdict(LimiterAnswer::Wait { ms: 1500 }, fail_open),
                RateLimitVerdict::Refuse {
                    retry_after_secs: 2
                },
                "a refusal is never waived"
            );
        }
        assert_eq!(
            rate_limit_verdict(LimiterAnswer::Unreachable, true),
            RateLimitVerdict::Allow
        );
        assert_eq!(
            rate_limit_verdict(LimiterAnswer::Unreachable, false),
            RateLimitVerdict::Unavailable
        );
    }
}
