use std::hint::black_box;

use auth_api::{
    config::CryptoConfig,
    repositories::login_location::RiskHistoryEntry,
    services::{
        auth::{CachedRiskContext, CachedRiskEvaluation, PreAuthState},
        risk_score::{self, LoginContext, RiskDecision, RiskResult},
    },
    utils::{geoip::GeoLocation, jwt, password, totp},
};
use criterion::{BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use ipnetwork::IpNetwork;
use time::{Duration, OffsetDateTime};
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
        risk: Some(CachedRiskEvaluation {
            context: CachedRiskContext {
                ip: "203.0.113.42/32".to_string(),
                user_agent: "bench-agent/1.0".to_string(),
                country: "FR".to_string(),
                city: "Paris".to_string(),
                latitude: Some(48.8566),
                longitude: Some(2.3522),
            },
            result: Some(RiskResult {
                score: 60,
                decision: RiskDecision::Challenge,
                signals: vec!["new_device".into(), "new_country:FR".into()],
            }),
        }),
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

fn risk_score_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk_score");
    let login_time = OffsetDateTime::now_utc();
    let ctx = LoginContext {
        user_id: Uuid::new_v4(),
        ip: "198.51.100.20/32".parse::<IpNetwork>().expect("valid cidr"),
        user_agent: "Mozilla/5.0 (Benchmark)".into(),
        geo: Some(GeoLocation {
            country: "FR".into(),
            city: "Paris".into(),
            latitude: Some(48.8566),
            longitude: Some(2.3522),
        }),
        login_time,
    };

    for size in [0usize, 8, 64, 256] {
        let history = make_risk_history(size, login_time);
        group.bench_with_input(BenchmarkId::from_parameter(size), &history, |b, history| {
            b.iter(|| risk_score::compute_score(black_box(&ctx), black_box(history)))
        });
    }
}

fn totp_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("totp");
    let secret = totp::generate_secret();
    let encryption_key = [7u8; 32];
    let encrypted = auth_api::utils::crypto::encrypt(&secret, &encryption_key)
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
                black_box(&encryption_key),
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

fn make_risk_history(size: usize, login_time: OffsetDateTime) -> Vec<RiskHistoryEntry> {
    (0..size)
        .map(|index| RiskHistoryEntry {
            country: if index % 4 == 0 { "FR" } else { "DE" }.to_string(),
            city: format!("city-{index}"),
            user_agent: format!("agent/{}", index % 12),
            latitude: Some(48.0 + (index as f64 / 100.0)),
            longitude: Some(2.0 + (index as f64 / 100.0)),
            last_seen: login_time - Duration::hours((index % 72) as i64 + 1),
        })
        .collect()
}

criterion_group!(
    name = benches;
    config = Criterion::default().configure_from_args();
    targets = jwt_benches, pre_auth_benches, risk_score_benches, totp_benches, password_benches
);
criterion_main!(benches);
