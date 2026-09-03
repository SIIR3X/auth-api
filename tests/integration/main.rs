//! Integration suite: the HTTP API end to end, the repositories and the
//! services, against real PostgreSQL, Redis and NATS.

#[allow(unused_imports)]
mod common {
    pub use testkit::{app, fixtures, mailpit};
}

mod api;
mod repositories;
mod services;
