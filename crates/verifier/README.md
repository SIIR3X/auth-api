# auth-api-verifier

Verify auth-api access tokens in a Rust resource server. Internal crate, not
published: depend on it by path or git revision.

```toml
[dependencies]
auth-api-verifier = { git = "ssh://git@github.com/<org>/auth-api", features = ["axum"] }
```

```rust
use std::sync::Arc;

use auth_api_verifier::{Authenticated, Verifier, VerifierConfig};
use axum::{Router, routing::get};

let verifier = Arc::new(Verifier::new(VerifierConfig::new(
    "https://auth.example.com",   // auth-api's APP_PUBLIC_URL
    "https://api.example.com",    // this service, listed in auth-api's JWT_AUDIENCE
)));

let app = Router::new()
    .route("/invoices", get(|Authenticated(token): Authenticated| async move {
        if !token.has_permission("invoices:read") {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }
        Ok(format!("invoices of {}", token.subject))
    }))
    .with_state(verifier);
```

Checked on every call, without contacting auth-api: the ES256 signature against
the published keys (fetched once, refetched when a token names an unknown key,
at most once a minute), `iss`, `aud`, `exp` and `nbf`.

Not checked offline: a revocation (logout, password change, revoked session)
before the token expires, 15 minutes by default. For the operations where that
matters, register the service as a confidential client in auth-api and enable
introspection; answers are cached 30 seconds per token:

```rust
use auth_api_verifier::Introspection;

let mut config = VerifierConfig::new("https://auth.example.com", "https://api.example.com");
config.introspection = Some(Introspection::new("invoices-api", std::env::var("AUTH_CLIENT_SECRET")?));
```

`VerifiedToken::is_client_token` tells a token a client obtained for itself
(client credentials: no user, `client_id` set) from a user's.
