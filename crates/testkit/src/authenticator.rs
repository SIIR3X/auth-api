//! A passkey authenticator in memory: it answers the options of a WebAuthn
//! ceremony with the JSON a browser returns (`PublicKeyCredential.toJSON()`).
//! ES256, `none` attestation. Its fields can be bent to forge bad responses.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use ciborium::Value as Cbor;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub struct SoftAuthenticator {
    pub key: SigningKey,
    pub credential_id: Vec<u8>,
    /// The user handle given at registration.
    pub user_handle: Vec<u8>,
    pub counter: u32,
    /// Origin written in the client data.
    pub origin: String,
    /// Relying party id hashed in the authenticator data.
    pub rp_id: String,
    /// Authenticator data flags: user present and verified by default.
    pub flags: u8,
}

impl SoftAuthenticator {
    pub fn new(rp_id: &str, origin: &str) -> Self {
        Self {
            key: SigningKey::random(&mut rand_core::OsRng),
            credential_id: uuid::Uuid::new_v4().as_bytes().to_vec(),
            user_handle: Vec::new(),
            counter: 0,
            origin: origin.to_owned(),
            rp_id: rp_id.to_owned(),
            flags: 0x05,
        }
    }

    /// The authenticator of the test app's configuration.
    pub fn for_app(app: &crate::TestApp) -> Self {
        let config = &app.state.config.webauthn;
        Self::new(&config.rp_id, &config.origins[0])
    }

    fn client_data(&self, kind: &str, challenge: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": kind,
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": false,
        }))
        .unwrap()
    }

    fn auth_data(&self, flags: u8, attested: Option<&[u8]>) -> Vec<u8> {
        let mut data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&self.counter.to_be_bytes());
        if let Some(public_key) = attested {
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            data.extend_from_slice(&self.credential_id);
            data.extend_from_slice(public_key);
        }
        data
    }

    fn cose_key(&self) -> Vec<u8> {
        let point = self.key.verifying_key().to_encoded_point(false);
        let key = Cbor::Map(vec![
            (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
            (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
            (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
            (
                Cbor::Integer((-2).into()),
                Cbor::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                Cbor::Integer((-3).into()),
                Cbor::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&key, &mut out).unwrap();
        out
    }

    /// Answer `PublicKeyCredentialCreationOptions`.
    pub fn create(&mut self, options: &Value) -> Value {
        self.user_handle = B64URL
            .decode(options["user"]["id"].as_str().unwrap())
            .unwrap();
        let client_data =
            self.client_data("webauthn.create", options["challenge"].as_str().unwrap());
        let auth_data = self.auth_data(self.flags | 0x40, Some(&self.cose_key()));
        let object = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
        ]);
        let mut attestation = Vec::new();
        ciborium::ser::into_writer(&object, &mut attestation).unwrap();
        json!({
            "id": B64URL.encode(&self.credential_id),
            "rawId": B64URL.encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": B64URL.encode(client_data),
                "attestationObject": B64URL.encode(attestation),
            },
        })
    }

    /// Answer `PublicKeyCredentialRequestOptions`, counting one more use.
    pub fn get(&mut self, options: &Value) -> Value {
        self.counter += 1;
        let client_data = self.client_data("webauthn.get", options["challenge"].as_str().unwrap());
        let auth_data = self.auth_data(self.flags, None);
        let mut message = auth_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = self.key.sign(&message);
        json!({
            "id": B64URL.encode(&self.credential_id),
            "rawId": B64URL.encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": B64URL.encode(client_data),
                "authenticatorData": B64URL.encode(auth_data),
                "signature": B64URL.encode(signature.to_der().as_bytes()),
                "userHandle": B64URL.encode(&self.user_handle),
            },
        })
    }
}
