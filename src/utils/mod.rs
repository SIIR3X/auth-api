//! Self-contained utilities shared by the services.
//!
//! Everything here is free of application state; only `redis_counter` performs
//! I/O, against the Redis pool it is handed, and `redis_pool` builds that pool.

pub mod backoff;
pub mod crypto;
pub mod jwt;
pub mod password;
pub mod redis_counter;
pub mod redis_pool;
pub mod time;
pub mod totp;
