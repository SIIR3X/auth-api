//! Print the OpenAPI document generated from the code.
//!
//! cargo run --quiet --bin openapi > docs/dev/api/openapi.yaml

fn main() {
    print!("{}", auth_api::openapi::yaml());
}
