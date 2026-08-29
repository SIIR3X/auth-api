use std::hint::black_box;

use auth_api::{
    config::CryptoConfig,
    services::auth::{ChallengeMethod, PreAuthState},
    utils::{jwt, password, totp},
};
use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use time::OffsetDateTime;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

fn jwt_benches(c: &mut Criterion) {
    use p256::PublicKey;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;

    fn generate_key_pair() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey) {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let private_pem = sk.to_pkcs8_pem(Default::default()).expect("pkcs8 pem");
        let public_pem = PublicKey::from(vk).to_string();
        (
            jwt::parse_encoding_key(&private_pem).expect("encoding key"),
            jwt::parse_verifying_key(&public_pem).expect("decoding key"),
        )
    }

    let mut group = c.benchmark_group("jwt");
    let claims = jwt::Claims::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        OffsetDateTime::now_utc().unix_timestamp() + 3600,
    );
    let (signing_key, verifying_key) = generate_key_pair();
    let (old_signing_key, old_verifying_key) = generate_key_pair();
    let token = jwt::encode_token(&claims, &signing_key, None).expect("failed to encode token");
    let rotated_token =
        jwt::encode_token(&claims, &old_signing_key, None).expect("failed to encode token");

    group.bench_function("encode_es256", |b| {
        b.iter(|| {
            jwt::encode_token(black_box(&claims), black_box(&signing_key), black_box(None))
                .expect("encode failed")
        })
    });

    group.bench_function("decode_es256", |b| {
        b.iter(|| {
            jwt::decode_token(black_box(&token), black_box(&verifying_key)).expect("decode failed")
        })
    });

    group.bench_function("decode_with_previous_key", |b| {
        b.iter(|| {
            jwt::decode_token_with_fallback(
                black_box(&rotated_token),
                black_box(&verifying_key),
                Some(black_box(&old_verifying_key)),
            )
            .expect("decode with fallback failed")
        })
    });
}

fn pre_auth_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("pre_auth");
    let state = PreAuthState {
        user_id: Uuid::new_v4(),
        remember_me: false,
        method: Some(ChallengeMethod::Totp),
    };
    let json = serde_json::to_string(&state).expect("failed to serialize pre-auth state");
    let legacy_uuid = state.user_id.to_string();

    group.bench_function("serialize_cached_pre_auth", |b| {
        b.iter(|| serde_json::to_string(black_box(&state)).expect("serialize failed"))
    });

    group.bench_function("deserialize_cached_pre_auth", |b| {
        b.iter(|| {
            serde_json::from_str::<PreAuthState>(black_box(&json)).expect("deserialize failed")
        })
    });

    group.bench_function("parse_legacy_pre_auth_uuid", |b| {
        b.iter(|| Uuid::parse_str(black_box(&legacy_uuid)).expect("uuid parse failed"))
    });
}

fn totp_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("totp");
    let secret = totp::generate_secret();
    // The production path: a keyring and a versioned ciphertext.
    let keyring = auth_api::utils::crypto::Keyring::new([7u8; 32], None);
    let encrypted = keyring
        .encrypt(&secret)
        .expect("failed to encrypt benchmark secret");
    let secret_bytes = Secret::Encoded(secret.clone())
        .to_bytes()
        .expect("valid secret bytes");
    let totp_ctx = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes).expect("valid totp");

    group.bench_function("generate_secret", |b| b.iter(totp::generate_secret));
    group.bench_function("build_qr_uri", |b| {
        b.iter(|| {
            totp::qr_uri(
                black_box(&secret),
                black_box("bench@example.com"),
                black_box("Bench"),
            )
        })
    });
    group.bench_function("generate_and_verify_code", |b| {
        b.iter(|| {
            let code = totp_ctx.generate_current().expect("code");
            totp::verify_code(
                black_box(&encrypted),
                black_box(&code),
                black_box(&keyring),
                1,
            )
            .expect("verify")
        })
    });
}

fn password_benches(c: &mut Criterion) {
    let config = CryptoConfig {
        argon2_memory_kib: 65_536,
        argon2_iterations: 3,
        argon2_parallelism: 1,
        argon2_max_concurrency: 4,
        totp_issuer: "bench".into(),
        encryption_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
        previous_encryption_key: None,
        totp_skew: 1,
        recovery_code_expiry_days: 365,
    };
    let password_value = "Sup3rSecureBenchmarkPassword!";
    let password_hash =
        password::hash(password_value, &config).expect("failed to create benchmark hash");

    let mut group = c.benchmark_group("password");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    group.bench_function("argon2_hash", |b| {
        b.iter(|| {
            password::hash(black_box(password_value), black_box(&config)).expect("hash failed")
        })
    });
    group.bench_function("argon2_verify", |b| {
        b.iter(|| {
            password::verify(black_box(password_value), black_box(&password_hash))
                .expect("verify failed")
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().configure_from_args();
    targets = jwt_benches, pre_auth_benches, totp_benches, password_benches
);
criterion_main!(benches);
