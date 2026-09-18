//! Simulation suite: the service while its dependencies fail, under
//! concurrency, and over time.

#[allow(unused_imports)]
mod common {
    pub use testkit::{app, fixtures, mailpit};
}

mod clock;
mod dependencies;
mod lifecycle;
mod redis_outage;
mod timing;
