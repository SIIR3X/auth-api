//! Security suite: the controls of `docs/dev/security-model.md`, attacked
//! through the API.

#[allow(unused_imports)]
mod common {
    pub use testkit::{app, fixtures, mailpit};
}

mod authentication;
mod authorization;
mod catalog;
mod edge;
mod headers;
mod logs;
mod rate_limits;
mod regressions;
mod static_guards;
