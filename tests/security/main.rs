//! Security suite: the controls of `docs/dev/security-model.md`, attacked
//! through the API.

#[allow(unused_imports)]
mod common {
    pub use testkit::{app, fixtures, mailpit};
}

mod authentication;
mod edge;
mod headers;
mod rate_limits;
mod regressions;
