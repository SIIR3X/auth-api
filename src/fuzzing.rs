//! Entry points of the fuzz targets (`fuzz/`) and of their replay on stable
//! (`tests/fuzz_corpus.rs`).
//!
//! Compiled only with the `fuzzing` feature, which no deployment enables. Each
//! function feeds raw untrusted bytes to a production parser and panics when a
//! security property does not hold: a panic is what the fuzzer reports.

use std::{net::IpAddr, sync::OnceLock};

use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnetwork::IpNetwork;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    cli::parse_client_registration,
    domain::{
        registered_client::RegisteredClient,
        session::{DEVICE_NAME_MAX_CHARS, device_label},
        user::{is_storable_email, is_valid_username},
    },
    handlers::{
        audit::{decode_cursor, encode_cursor},
        auth::{validate_email, validate_username},
        device::validate_user_code,
        user::{validate_locale, validate_password},
    },
    middleware::client_ip::resolve_client_ip,
    services::{
        auth::{ChallengeMethod, parse_pre_auth_state},
        authorize::{validate_challenge, validate_redirect, verifier_matches},
        email::mask_email,
    },
    utils::{
        crypto::{Keyring, sha256},
        jwt::{self, Claims},
        totp,
    },
};

fn text(data: &[u8]) -> Option<&str> {
    std::str::from_utf8(data).ok()
}

/// Audit history cursors: whatever is accepted re-encodes to the same position.
pub fn audit_cursor(data: &[u8]) {
    let Some(input) = text(data) else { return };
    if let Ok((created_at, id)) = decode_cursor(input) {
        let again =
            decode_cursor(&encode_cursor(created_at, id)).expect("an encoded cursor decodes");
        assert_eq!(again, (created_at, id), "{input:?} does not round-trip");
    }
}

/// Pre-auth state read back from Redis: a challenge completes only with the
/// method it was issued for.
pub fn pre_auth_state(data: &[u8]) {
    let Some(input) = text(data) else { return };
    let Ok(state) = parse_pre_auth_state(input) else {
        return;
    };
    for method in [ChallengeMethod::Totp, ChallengeMethod::Email] {
        assert_eq!(
            state.expect_method(method).is_ok(),
            state.method == Some(method),
            "{input:?} completes with {method:?}"
        );
    }
}

/// Client address: an untrusted peer is always the client; behind a trusted
/// proxy, the client is the peer or an address the headers carry.
///
/// Layout: flags (bit 0: IPv6 peer, bit 1: the peer's own network is trusted),
/// the peer address, then header values separated by 0xFF: X-Forwarded-For,
/// X-Real-IP, a second X-Forwarded-For line.
pub fn client_ip(data: &[u8]) {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let (peer, rest): (IpAddr, &[u8]) = if flags & 1 == 0 {
        let Some((octets, rest)) = rest.split_first_chunk::<4>() else {
            return;
        };
        (IpAddr::from(*octets), rest)
    } else {
        let Some((octets, rest)) = rest.split_first_chunk::<16>() else {
            return;
        };
        (IpAddr::from(*octets), rest)
    };
    let trusted: Vec<IpNetwork> = if flags & 2 != 0 {
        let prefix = if peer.is_ipv4() { 24 } else { 64 };
        vec![IpNetwork::new(peer, prefix).expect("valid prefix")]
    } else {
        vec!["10.0.0.0/8".parse().expect("valid network")]
    };

    let mut headers = HeaderMap::new();
    let mut values = rest.split(|b| *b == 0xFF);
    for name in ["x-forwarded-for", "x-real-ip", "x-forwarded-for"] {
        if let Some(Ok(value)) = values.next().map(HeaderValue::from_bytes) {
            headers.append(name, value);
        }
    }

    let resolved = resolve_client_ip(Some(peer), &headers, &trusted)
        .expect("a request with a peer always has a client address");
    if !trusted.iter().any(|network| network.contains(peer)) {
        assert_eq!(resolved, peer, "an untrusted peer chose its client address");
        return;
    }
    let carried: Vec<IpAddr> = headers
        .values()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|hop| hop.trim().parse().ok())
        .collect();
    assert!(
        resolved == peer || carried.contains(&resolved),
        "{resolved} was resolved from nowhere"
    );
}

/// Redirect URIs: a registered URI exactly, or a loopback URI on a registered
/// loopback path for a client that allows it. Layout: a flags line (`L` allows
/// loopback), the candidate, then the registered URIs, one per line.
pub fn redirect_uri(data: &[u8]) {
    let Some(input) = text(data) else { return };
    let mut lines = input.split('\n');
    let loopback = lines.next().is_some_and(|flags| flags.starts_with('L'));
    let candidate = lines.next().unwrap_or_default();
    let registered: Vec<String> = lines.map(str::to_owned).collect();
    let client = RegisteredClient {
        client_id: "fuzz".into(),
        display_name: "Fuzz".into(),
        is_primary: false,
        created_at: OffsetDateTime::UNIX_EPOCH,
        scopes: Vec::new(),
        redirect_uris: registered.clone(),
        allows_loopback_redirect: loopback,
        default_max_sessions: 1,
    };

    if validate_redirect(&client, candidate).is_err() || registered.iter().any(|r| r == candidate) {
        return;
    }
    assert!(loopback, "{candidate:?} accepted without being registered");
    let url = reqwest::Url::parse(candidate).expect("an accepted redirect parses");
    assert_eq!(
        url.as_str(),
        candidate,
        "accepted a URI that is not in canonical form"
    );
    assert_eq!(url.scheme(), "http");
    assert!(
        matches!(url.host_str(), Some("127.0.0.1" | "[::1]")),
        "{candidate:?} is not a loopback literal"
    );
    assert!(
        url.port().is_some_and(|port| port != 0),
        "{candidate:?} has no usable port"
    );
    assert!(url.username().is_empty() && url.password().is_none());
    assert!(url.query().is_none() && url.fragment().is_none());
    assert!(
        registered
            .iter()
            .filter_map(|r| reqwest::Url::parse(r).ok())
            .any(|r| matches!(r.host_str(), Some("127.0.0.1" | "[::1]")) && r.path() == url.path()),
        "{candidate:?} matches no registered loopback path"
    );
}

const VERIFIER_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// PKCE: challenges are accepted only well-formed, verifiers only when they
/// hash to the challenge, and a well-formed verifier matches its own challenge.
/// Layout: challenge, newline, verifier.
pub fn pkce(data: &[u8]) {
    let Some(input) = text(data) else { return };
    let (challenge, verifier) = input.split_once('\n').unwrap_or((input, ""));

    if validate_challenge(challenge, "S256").is_ok() {
        assert!(
            challenge.len() == 43
                && challenge
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{challenge:?} accepted as a challenge"
        );
    }
    if verifier_matches(challenge, verifier) {
        assert!((43..=128).contains(&verifier.len()));
        assert_eq!(
            URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes())),
            challenge
        );
    }

    let derived: String = verifier
        .bytes()
        .take(128)
        .map(|b| VERIFIER_ALPHABET[usize::from(b) % VERIFIER_ALPHABET.len()] as char)
        .collect();
    if derived.len() >= 43 {
        let own = URL_SAFE_NO_PAD.encode(sha256(derived.as_bytes()));
        assert!(validate_challenge(&own, "S256").is_ok());
        assert!(
            verifier_matches(&own, &derived),
            "{derived:?} does not match its challenge"
        );
    }
}

const TOKEN_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgL+1qOaZ7C+H1mGbV\njUP83/W450N4GfOnZSrQ7P//4Y2hRANCAAR4BApTJy8Anvp+O7YNVlTeCbBZ+1YJ\nk+r5ELHGFIXciAEGSrCTOkCm3yChSYroYWLE3ZN4reh6JDbIMX/QnBGx\n-----END PRIVATE KEY-----";
const TOKEN_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeAQKUycvAJ76fju2DVZU3gmwWftW\nCZPq+RCxxhSF3IgBBkqwkzpApt8goUmK6GFixN2TeK3oeiQ2yDF/0JwRsQ==\n-----END PUBLIC KEY-----";
const TOKEN_ISSUED_AT: i64 = 1_700_000_000;

struct TokenFixture {
    verifying: jsonwebtoken::DecodingKey,
    claims: Claims,
    token: String,
}

fn token_fixture() -> &'static TokenFixture {
    static FIXTURE: OnceLock<TokenFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut claims = Claims::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            TOKEN_ISSUED_AT,
            TOKEN_ISSUED_AT + 900,
        )
        .with_rbac(vec!["user".into()], vec!["users:read".into()]);
        claims.jti = Uuid::from_u128(3);
        claims.iss = Some("https://auth.example.com".into());
        claims.aud = vec!["https://auth.example.com".into()];
        let signing = jwt::parse_encoding_key(TOKEN_PRIVATE_KEY).expect("fixture key");
        TokenFixture {
            verifying: jwt::parse_verifying_key(TOKEN_PUBLIC_KEY).expect("fixture key"),
            token: jwt::encode_token(&claims, &signing, Some("fuzz")).expect("fixture token"),
            claims,
        }
    })
}

fn assert_same_claims(decoded: &Claims, expected: &Claims) {
    assert_eq!(
        serde_json::to_value(decoded).unwrap(),
        serde_json::to_value(expected).unwrap(),
        "a token verified with claims it was not signed with"
    );
}

/// Access tokens: arbitrary input never verifies, and the genuine token,
/// altered anywhere, never verifies to other claims.
/// Layout: the input itself, then read as (position: u16, byte) edits.
pub fn access_token(data: &[u8]) {
    let fixture = token_fixture();
    let now = TOKEN_ISSUED_AT + 60;

    if let Some(input) = text(data)
        && let Ok(claims) = jwt::decode_token(input, &fixture.verifying, now)
    {
        assert_same_claims(&claims, &fixture.claims);
    }

    let mut token = fixture.token.clone().into_bytes();
    for [high, low, byte] in data.as_chunks::<3>().0 {
        let at = usize::from(u16::from_be_bytes([*high, *low])) % token.len();
        token[at] = *byte;
    }
    if let Ok(tampered) = String::from_utf8(token)
        && let Ok(claims) = jwt::decode_token(&tampered, &fixture.verifying, now)
    {
        assert_same_claims(&claims, &fixture.claims);
    }
}

struct KeyringFixture {
    keyring: Keyring,
    plaintext: &'static str,
    ciphertext: String,
}

fn keyring_fixture() -> &'static KeyringFixture {
    static FIXTURE: OnceLock<KeyringFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let keyring = Keyring::new([7; 32], Some([9; 32]));
        let plaintext = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        KeyringFixture {
            ciphertext: keyring.encrypt(plaintext).expect("fixture ciphertext"),
            keyring,
            plaintext,
        }
    })
}

/// Secrets encrypted at rest: decryption never panics, and a ciphertext
/// altered anywhere never decrypts to another plaintext.
/// Layout: the input itself, then read as (position: u16, byte) edits.
pub fn keyring(data: &[u8]) {
    let fixture = keyring_fixture();

    if let Some(input) = text(data) {
        let _ = fixture.keyring.needs_rotation(input);
        if let Ok(plaintext) = fixture.keyring.decrypt(input) {
            assert_eq!(plaintext, fixture.plaintext, "forged ciphertext accepted");
        }
    }

    let mut ciphertext = fixture.ciphertext.clone().into_bytes();
    for [high, low, byte] in data.as_chunks::<3>().0 {
        let at = usize::from(u16::from_be_bytes([*high, *low])) % ciphertext.len();
        ciphertext[at] = *byte;
    }
    if let Ok(tampered) = String::from_utf8(ciphertext)
        && let Ok(plaintext) = fixture.keyring.decrypt(&tampered)
    {
        assert_eq!(
            plaintext, fixture.plaintext,
            "tampered ciphertext decrypted"
        );
    }
}

/// TOTP codes: only six ASCII digits can ever be accepted.
pub fn totp_code(data: &[u8]) {
    let Some(code) = text(data) else { return };
    let fixture = keyring_fixture();
    let secret = fixture
        .keyring
        .encrypt("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .expect("secret");
    for now in [0, 59, TOKEN_ISSUED_AT] {
        if totp::verify_code(&secret, code, &fixture.keyring, 1, now).unwrap_or(false) {
            assert!(
                code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
                "{code:?} accepted as a TOTP code"
            );
        }
    }
}

/// Input validators: they never panic, and what they accept fits the database.
pub fn validators(data: &[u8]) {
    let Some(input) = text(data) else { return };

    if is_valid_username(input) {
        assert!(
            !input.is_empty()
                && input
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
    }
    if validate_username(input).is_ok() {
        assert!(is_valid_username(input) && (3..=30).contains(&input.len()));
    }
    if is_storable_email(input) {
        assert!(input.is_ascii() && input.len() <= 254 && input.matches('@').count() == 1);
    }
    if validate_email(input).is_ok() {
        assert!(
            is_storable_email(input),
            "{input:?} passes validation but not the database"
        );
    }
    if let Some(label) = device_label(input) {
        assert!(!label.is_empty() && label.chars().count() <= DEVICE_NAME_MAX_CHARS);
        assert!(!label.chars().any(char::is_control) && label.trim() == label);
    }
    let masked = mask_email(input);
    match input.split_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            assert_eq!(masked, format!("{first}***@{domain}"));
        }
        None => assert_eq!(masked, "***"),
    }
    if validate_password(input).is_ok() {
        assert!(
            input.chars().count() >= 10,
            "{input:?}: fewer than 10 characters"
        );
        assert!(input.len() <= 128);
        assert!(input.chars().any(|c| c.is_ascii_digit()));
        assert!(input.chars().any(|c| c.is_ascii_uppercase()));
        assert!(input.chars().any(|c| c.is_ascii_punctuation()));
    }
    if validate_user_code(input).is_ok() {
        let (letters, digits) = input.split_once('-').expect("XXXX-XXXX");
        assert!(letters.len() == 4 && letters.bytes().all(|b| b.is_ascii_uppercase()));
        assert!(digits.len() == 4 && digits.bytes().all(|b| b.is_ascii_digit()));
    }
    if validate_locale(input).is_ok() {
        assert!(
            matches!(input, "en" | "fr"),
            "{input:?} accepted as a locale"
        );
    }
}

/// `--register-client` arguments: parsing never panics. Arguments are
/// separated by NUL.
pub fn client_registration(data: &[u8]) {
    let Some(input) = text(data) else { return };
    let args: Vec<String> = std::iter::once("auth-api")
        .chain(input.split('\0'))
        .map(str::to_owned)
        .collect();
    if let Ok(Some(registration)) = parse_client_registration(&args) {
        let new = registration.as_new();
        assert!(!new.client_id.is_empty());
    }
}

/// A fuzz target: the name of its binary in `fuzz/` and its entry point.
pub type Target = (&'static str, fn(&[u8]));

/// Every target, by name, for the corpus replay.
pub const TARGETS: &[Target] = &[
    ("access_token", access_token),
    ("audit_cursor", audit_cursor),
    ("client_ip", client_ip),
    ("client_registration", client_registration),
    ("keyring", keyring),
    ("pkce", pkce),
    ("pre_auth_state", pre_auth_state),
    ("redirect_uri", redirect_uri),
    ("totp_code", totp_code),
    ("validators", validators),
];
