//! WebAuthn (Level 2) verification for passkeys: client data, authenticator
//! data, COSE public keys and assertion signatures.
//!
//! Attestation statements are not verified: the relying party asks for `none`
//! and trusts a new passkey because the account registering it re-authenticated,
//! not because of the authenticator's make. What is verified is what protects
//! the account: the challenge, the origin, the relying party, user presence and
//! verification, and every assertion signature against the stored key.

use std::io::Cursor;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use ciborium::Value;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_RS256: i64 = -257;

/// Algorithms offered at registration, preferred first.
pub const ALGORITHMS: [i64; 3] = [ALG_ES256, ALG_EDDSA, ALG_RS256];

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKED_UP: u8 = 0x10;
const FLAG_ATTESTED: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnError(pub &'static str);

type Result<T> = std::result::Result<T, WebAuthnError>;

fn fail<T>(reason: &'static str) -> Result<T> {
    Err(WebAuthnError(reason))
}

/// `clientDataJSON`, the part the relying party checks.
#[derive(Debug, Deserialize)]
pub struct ClientData {
    #[serde(rename = "type")]
    pub kind: String,
    pub challenge: String,
    pub origin: String,
    #[serde(default, rename = "crossOrigin")]
    pub cross_origin: bool,
}

/// Parse `clientDataJSON` and check it answers `challenge` for a ceremony of
/// `kind` (`webauthn.create` or `webauthn.get`) from an allowed origin.
pub fn check_client_data(
    json: &[u8],
    kind: &str,
    challenge: &[u8],
    origins: &[String],
) -> Result<ClientData> {
    let data: ClientData =
        serde_json::from_slice(json).map_err(|_| WebAuthnError("malformed client data"))?;
    if data.kind != kind {
        return fail("wrong ceremony type");
    }
    if B64URL.decode(&data.challenge).ok().as_deref() != Some(challenge) {
        return fail("challenge mismatch");
    }
    if !origins.contains(&data.origin) {
        return fail("origin not allowed");
    }
    if data.cross_origin {
        return fail("cross-origin ceremony");
    }
    Ok(data)
}

/// The challenge a `clientDataJSON` carries, before anything is checked: it
/// names the ceremony the response belongs to.
pub fn challenge_of(json: &[u8]) -> Result<Vec<u8>> {
    let data: ClientData =
        serde_json::from_slice(json).map_err(|_| WebAuthnError("malformed client data"))?;
    B64URL
        .decode(&data.challenge)
        .map_err(|_| WebAuthnError("malformed challenge"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    /// The COSE key, as encoded by the authenticator.
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested: Option<AttestedCredential>,
}

impl AuthenticatorData {
    pub fn user_present(&self) -> bool {
        self.flags & FLAG_USER_PRESENT != 0
    }
    pub fn user_verified(&self) -> bool {
        self.flags & FLAG_USER_VERIFIED != 0
    }
    pub fn backup_eligible(&self) -> bool {
        self.flags & FLAG_BACKUP_ELIGIBLE != 0
    }
    pub fn backed_up(&self) -> bool {
        self.flags & FLAG_BACKED_UP != 0
    }

    /// The checks every ceremony shares: this relying party, a present and
    /// verified user.
    pub fn check(&self, rp_id: &str) -> Result<()> {
        if self.rp_id_hash[..] != Sha256::digest(rp_id.as_bytes())[..] {
            return fail("relying party mismatch");
        }
        if !self.user_present() {
            return fail("user not present");
        }
        if !self.user_verified() {
            return fail("user not verified");
        }
        Ok(())
    }
}

/// WebAuthn section 6.1.
pub fn parse_authenticator_data(bytes: &[u8]) -> Result<AuthenticatorData> {
    if bytes.len() < 37 {
        return fail("authenticator data too short");
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&bytes[..32]);
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    let mut rest = &bytes[37..];

    let attested = if flags & FLAG_ATTESTED != 0 {
        if rest.len() < 18 {
            return fail("attested credential data too short");
        }
        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&rest[..16]);
        let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        rest = &rest[18..];
        if id_len == 0 || id_len > 1023 || rest.len() < id_len {
            return fail("malformed credential id");
        }
        let credential_id = rest[..id_len].to_vec();
        rest = &rest[id_len..];
        let key_len = cbor_item_len(rest)?;
        let public_key = rest[..key_len].to_vec();
        rest = &rest[key_len..];
        Some(AttestedCredential {
            aaguid,
            credential_id,
            public_key,
        })
    } else {
        None
    };
    if flags & FLAG_EXTENSIONS != 0 {
        let len = cbor_item_len(rest)?;
        rest = &rest[len..];
    }
    if !rest.is_empty() {
        return fail("trailing bytes in authenticator data");
    }
    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
    })
}

/// Length of the CBOR item at the start of `bytes`.
fn cbor_item_len(bytes: &[u8]) -> Result<usize> {
    let mut cursor = Cursor::new(bytes);
    let _: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| WebAuthnError("malformed CBOR"))?;
    usize::try_from(cursor.position()).map_err(|_| WebAuthnError("malformed CBOR"))
}

/// The authenticator data of an `attestationObject`.
pub fn attestation_auth_data(attestation_object: &[u8]) -> Result<Vec<u8>> {
    let value: Value = ciborium::de::from_reader(attestation_object)
        .map_err(|_| WebAuthnError("malformed attestation object"))?;
    let Value::Map(entries) = value else {
        return fail("malformed attestation object");
    };
    entries
        .into_iter()
        .find_map(|(key, value)| match (key, value) {
            (Value::Text(key), Value::Bytes(data)) if key == "authData" => Some(data),
            _ => None,
        })
        .ok_or(WebAuthnError("attestation object without authData"))
}

/// A credential public key in the algorithms offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseKey {
    Es256 { x: Vec<u8>, y: Vec<u8> },
    EdDsa { x: Vec<u8> },
    Rs256 { n: Vec<u8>, e: Vec<u8> },
}

impl CoseKey {
    pub fn algorithm(&self) -> i64 {
        match self {
            Self::Es256 { .. } => ALG_ES256,
            Self::EdDsa { .. } => ALG_EDDSA,
            Self::Rs256 { .. } => ALG_RS256,
        }
    }
}

/// RFC 9053 key parameters for EC2 P-256, OKP Ed25519 and RSA keys.
pub fn parse_cose_key(bytes: &[u8]) -> Result<CoseKey> {
    let value: Value =
        ciborium::de::from_reader(bytes).map_err(|_| WebAuthnError("malformed COSE key"))?;
    let Value::Map(entries) = value else {
        return fail("malformed COSE key");
    };
    let int = |label: i64| {
        entries.iter().find_map(|(k, v)| match (k, v) {
            (Value::Integer(k), Value::Integer(v)) if i128::from(*k) == i128::from(label) => {
                i64::try_from(i128::from(*v)).ok()
            }
            _ => None,
        })
    };
    let bytes_at = |label: i64| {
        entries.iter().find_map(|(k, v)| match (k, v) {
            (Value::Integer(k), Value::Bytes(v)) if i128::from(*k) == i128::from(label) => {
                Some(v.clone())
            }
            _ => None,
        })
    };
    match (int(1), int(3)) {
        (Some(2), Some(ALG_ES256)) => {
            let (Some(1), Some(x), Some(y)) = (int(-1), bytes_at(-2), bytes_at(-3)) else {
                return fail("unsupported EC2 key");
            };
            if x.len() != 32 || y.len() != 32 {
                return fail("malformed EC2 key");
            }
            Ok(CoseKey::Es256 { x, y })
        }
        (Some(1), Some(ALG_EDDSA)) => {
            let (Some(6), Some(x)) = (int(-1), bytes_at(-2)) else {
                return fail("unsupported OKP key");
            };
            if x.len() != 32 {
                return fail("malformed OKP key");
            }
            Ok(CoseKey::EdDsa { x })
        }
        (Some(3), Some(ALG_RS256)) => {
            let (Some(n), Some(e)) = (bytes_at(-1), bytes_at(-2)) else {
                return fail("malformed RSA key");
            };
            if n.len() < 256 || e.is_empty() {
                return fail("RSA key too small");
            }
            Ok(CoseKey::Rs256 { n, e })
        }
        _ => fail("unsupported key algorithm"),
    }
}

/// Verify an assertion: `signature` over `authenticatorData || SHA-256(clientDataJSON)`.
pub fn verify_assertion(
    key: &CoseKey,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> bool {
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(&Sha256::digest(client_data_json));
    match key {
        CoseKey::Es256 { x, y } => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            let (Ok(key), Ok(signature)) = (
                VerifyingKey::from_sec1_bytes(&point),
                Signature::from_der(signature),
            ) else {
                return false;
            };
            key.verify(&message, &signature).is_ok()
        }
        CoseKey::EdDsa { x } => jsonwebtoken::DecodingKey::from_ed_components(&B64URL.encode(x))
            .ok()
            .and_then(|key| {
                jsonwebtoken::crypto::verify(
                    &B64URL.encode(signature),
                    &message,
                    &key,
                    jsonwebtoken::Algorithm::EdDSA,
                )
                .ok()
            })
            .unwrap_or(false),
        CoseKey::Rs256 { n, e } => {
            let key = jsonwebtoken::DecodingKey::from_rsa_raw_components(n, e);
            jsonwebtoken::crypto::verify(
                &B64URL.encode(signature),
                &message,
                &key,
                jsonwebtoken::Algorithm::RS256,
            )
            .unwrap_or(false)
        }
    }
}

/// WebAuthn section 7.2 step 21: a counter that does not grow, when the
/// authenticator keeps one, means the credential may have been cloned.
pub fn counter_regressed(stored: u32, presented: u32) -> bool {
    (stored != 0 || presented != 0) && presented <= stored
}

/// The relying party id of an origin: its host.
pub fn origin_host(origin: &str) -> Option<String> {
    reqwest::Url::parse(origin)
        .ok()?
        .host_str()
        .map(str::to_owned)
}

/// Whether `origin` may use credentials of `rp_id`: its host is the id or a
/// subdomain of it (WebAuthn section 5.1.4.1).
pub fn origin_matches_rp(origin: &str, rp_id: &str) -> bool {
    origin_host(origin).is_some_and(|host| host == rp_id || host.ends_with(&format!(".{rp_id}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ciborium::Value;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    pub const RP_ID: &str = "auth.example.com";
    pub const ORIGIN: &str = "https://auth.example.com";

    fn cbor(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).unwrap();
        out
    }

    fn cose_es256(key: &SigningKey) -> Vec<u8> {
        let point = key.verifying_key().to_encoded_point(false);
        cbor(&Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ]))
    }

    fn auth_data(flags: u8, count: u32, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
        let mut data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&count.to_be_bytes());
        if let Some((id, key)) = attested {
            data.extend_from_slice(&[7u8; 16]);
            data.extend_from_slice(&u16::try_from(id.len()).unwrap().to_be_bytes());
            data.extend_from_slice(id);
            data.extend_from_slice(key);
        }
        data
    }

    fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": kind,
            "challenge": B64URL.encode(challenge),
            "origin": origin,
        }))
        .unwrap()
    }

    #[test]
    fn a_registration_yields_the_credential_and_its_key() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let cose = cose_es256(&key);
        let data = auth_data(0x45 | 0x08, 0, Some((b"credential-1", &cose)));
        let object = cbor(&Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(data.clone())),
        ]));

        let parsed = parse_authenticator_data(&attestation_auth_data(&object).unwrap()).unwrap();
        parsed.check(RP_ID).unwrap();
        assert!(parsed.backup_eligible() && !parsed.backed_up());
        let attested = parsed.attested.unwrap();
        assert_eq!(attested.credential_id, b"credential-1");
        assert_eq!(
            parse_cose_key(&attested.public_key).unwrap().algorithm(),
            ALG_ES256
        );

        assert_eq!(
            parse_authenticator_data(&auth_data(0x01, 0, None))
                .unwrap()
                .check(RP_ID),
            Err(WebAuthnError("user not verified"))
        );
        assert_eq!(
            parse_authenticator_data(&auth_data(0x05, 0, None))
                .unwrap()
                .check("evil.example.com"),
            Err(WebAuthnError("relying party mismatch"))
        );
        let mut trailing = auth_data(0x05, 0, None);
        trailing.push(0);
        assert!(parse_authenticator_data(&trailing).is_err());
        assert!(parse_authenticator_data(&[0u8; 36]).is_err());
    }

    #[test]
    fn client_data_answers_the_challenge_from_an_allowed_origin() {
        let origins = vec![ORIGIN.to_owned()];
        let good = client_data("webauthn.get", b"challenge", ORIGIN);
        assert!(check_client_data(&good, "webauthn.get", b"challenge", &origins).is_ok());
        assert_eq!(challenge_of(&good).unwrap(), b"challenge");
        assert!(check_client_data(&good, "webauthn.create", b"challenge", &origins).is_err());
        assert!(check_client_data(&good, "webauthn.get", b"other", &origins).is_err());
        let foreign = client_data("webauthn.get", b"challenge", "https://evil.example.com");
        assert!(check_client_data(&foreign, "webauthn.get", b"challenge", &origins).is_err());
        let cross = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get", "challenge": B64URL.encode(b"challenge"),
            "origin": ORIGIN, "crossOrigin": true
        }))
        .unwrap();
        assert!(check_client_data(&cross, "webauthn.get", b"challenge", &origins).is_err());
        assert!(check_client_data(b"{", "webauthn.get", b"challenge", &origins).is_err());
    }

    #[test]
    fn assertions_verify_against_the_stored_key_only() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let cose = parse_cose_key(&cose_es256(&key)).unwrap();
        let data = auth_data(0x05, 3, None);
        let client = client_data("webauthn.get", b"c", ORIGIN);
        let mut message = data.clone();
        message.extend_from_slice(&Sha256::digest(&client));
        let signature: Signature = key.sign(&message);
        let der = signature.to_der();

        assert!(verify_assertion(&cose, &data, &client, der.as_bytes()));
        assert!(!verify_assertion(
            &cose,
            &auth_data(0x05, 4, None),
            &client,
            der.as_bytes()
        ));
        let other =
            parse_cose_key(&cose_es256(&SigningKey::random(&mut rand_core::OsRng))).unwrap();
        assert!(!verify_assertion(&other, &data, &client, der.as_bytes()));
        assert!(!verify_assertion(&cose, &data, &client, b"not a signature"));
    }

    #[test]
    fn unsupported_or_malformed_keys_are_refused() {
        let key = |entries: Vec<(i64, Value)>| {
            cbor(&Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| (Value::Integer(k.into()), v))
                    .collect(),
            ))
        };
        let int = |v: i64| Value::Integer(v.into());
        // ES384.
        assert!(parse_cose_key(&key(vec![(1, int(2)), (3, int(-35)), (-1, int(2))])).is_err());
        // P-256 with a short coordinate.
        assert!(
            parse_cose_key(&key(vec![
                (1, int(2)),
                (3, int(-7)),
                (-1, int(1)),
                (-2, Value::Bytes(vec![1; 31])),
                (-3, Value::Bytes(vec![1; 32])),
            ]))
            .is_err()
        );
        // A 1024-bit RSA key.
        assert!(
            parse_cose_key(&key(vec![
                (1, int(3)),
                (3, int(-257)),
                (-1, Value::Bytes(vec![1; 128])),
                (-2, Value::Bytes(vec![1, 0, 1])),
            ]))
            .is_err()
        );
        let ed = parse_cose_key(&key(vec![
            (1, int(1)),
            (3, int(-8)),
            (-1, int(6)),
            (-2, Value::Bytes(vec![9; 32])),
        ]))
        .unwrap();
        assert_eq!(ed.algorithm(), ALG_EDDSA);
        assert!(!verify_assertion(&ed, b"data", b"{}", &[0; 64]));
        assert!(parse_cose_key(b"\xff").is_err());
    }

    #[test]
    fn counters_must_grow_when_kept() {
        assert!(!counter_regressed(0, 0));
        assert!(!counter_regressed(4, 5));
        assert!(counter_regressed(5, 5));
        assert!(counter_regressed(5, 0));
        assert!(!counter_regressed(0, 1));
    }

    #[test]
    fn origins_belong_to_the_relying_party_or_its_subdomains() {
        assert!(origin_matches_rp(
            "https://auth.example.com",
            "auth.example.com"
        ));
        assert!(origin_matches_rp(
            "https://login.auth.example.com:8443",
            "auth.example.com"
        ));
        assert!(!origin_matches_rp(
            "https://evilauth.example.com",
            "auth.example.com"
        ));
        assert!(!origin_matches_rp("not a url", "auth.example.com"));
    }
}
