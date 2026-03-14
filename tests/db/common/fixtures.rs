#![allow(dead_code)]

use postgres::Client;
use uuid::Uuid;

pub const SAMPLE_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHlzYWx0$abcdefghijklmnopqrstuv";

pub const SAMPLE_TOKEN_HASH: [u8; 32] = [7; 32];
pub const SAMPLE_CODE_HASH: [u8; 32] = [9; 32];

pub fn sample_email(index: usize) -> String {
    format!("user{index}@example.com")
}

pub fn sample_username(index: usize) -> String {
    format!("user_{index}")
}

pub fn insert_user(client: &mut Client, index: usize) -> Uuid {
    let username = sample_username(index);
    let email = sample_email(index);

    client
        .query_one(
            "INSERT INTO users (username, email, password_hash)
             VALUES ($1, $2, $3)
             RETURNING id",
            &[&username, &email, &SAMPLE_PASSWORD_HASH],
        )
        .expect("failed to insert test user")
        .get(0)
}

pub fn insert_active_user(client: &mut Client, index: usize) -> Uuid {
    let username = sample_username(index);
    let email = sample_email(index);

    client
        .query_one(
            "INSERT INTO users (username, email, password_hash, status, email_verified_at)
             VALUES ($1, $2, $3, 'active', NOW())
             RETURNING id",
            &[&username, &email, &SAMPLE_PASSWORD_HASH],
        )
        .expect("failed to insert active test user")
        .get(0)
}

pub fn insert_permission(client: &mut Client, resource: &str, action: &str) -> Uuid {
    client
        .query_one(
            "INSERT INTO permissions (resource, action)
             VALUES ($1, $2)
             RETURNING id",
            &[&resource, &action],
        )
        .expect("failed to insert permission")
        .get(0)
}

pub fn fixed_hash(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}
