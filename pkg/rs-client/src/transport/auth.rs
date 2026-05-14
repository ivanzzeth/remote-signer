use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::Error;

#[derive(Clone)]
pub struct Auth {
    signing_key: SigningKey,
}

impl Auth {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Format: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
    pub fn sign_request(
        &self,
        timestamp_ms: i64,
        nonce: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let body_hash = hasher.finalize();

        let message = format!(
            "{}|{}|{}|{}|{}",
            timestamp_ms,
            nonce,
            method,
            path,
            hex::encode(body_hash)
        );

        let sig = self.signing_key.sign(message.as_bytes());
        BASE64_STD.encode(sig.to_bytes())
    }

    pub fn generate_nonce_hex() -> String {
        let mut b = [0u8; 16];
        if OsRng.try_fill_bytes(&mut b).is_err() {
            return format!("{}", time::OffsetDateTime::now_utc().unix_timestamp_nanos());
        }
        hex::encode(b)
    }

    pub fn parse_private_key_hex(hex_key: &str) -> Result<SigningKey, Error> {
        let raw = hex::decode(hex_key.trim_start_matches("0x"))
            .map_err(|e| Error::InvalidConfig(format!("invalid private key hex: {e}")))?;

        if raw.len() == 32 {
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&raw);
            return Ok(SigningKey::from_bytes(&sk));
        }
        if raw.len() == 64 {
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&raw[..32]);
            return Ok(SigningKey::from_bytes(&sk));
        }

        Err(Error::InvalidConfig(format!(
            "invalid private key length: expected 32 or 64 bytes, got {}",
            raw.len()
        )))
    }

    pub fn parse_private_key_base64_der(b64: &str) -> Result<SigningKey, Error> {
        let der = BASE64_STD
            .decode(b64)
            .map_err(|e| Error::InvalidConfig(format!("invalid private key base64: {e}")))?;

        if der.len() < 32 {
            return Err(Error::InvalidConfig(format!(
                "invalid base64 private key length: got {} bytes, need at least 32",
                der.len()
            )));
        }
        let seed = &der[der.len() - 32..];
        let mut sk = [0u8; 32];
        sk.copy_from_slice(seed);
        Ok(SigningKey::from_bytes(&sk))
    }

    /// Load Ed25519 private key from a PEM file (PKCS#8, e.g. data/admin_private.pem).
    pub fn load_private_key_from_pem_file(path: impl AsRef<Path>) -> Result<SigningKey, Error> {
        let pem_str = std::fs::read_to_string(path.as_ref())
            .map_err(|e| Error::InvalidConfig(format!("failed to read PEM file: {e}")))?;
        let keypair = ed25519_dalek::pkcs8::KeypairBytes::from_pkcs8_pem(&pem_str)
            .map_err(|e| Error::InvalidConfig(format!("failed to parse PEM: {e}")))?;
        Ok(SigningKey::from_bytes(&keypair.secret_key))
    }

    pub fn generate_keypair() -> (SigningKey, String) {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        (sk, pk_hex)
    }
}
