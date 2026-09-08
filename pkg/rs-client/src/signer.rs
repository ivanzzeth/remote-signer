//! Signer abstractions.
//!
//! These traits mirror the `ethsig` interfaces the Go SDK implements, so a
//! signing backend is a swappable dependency rather than a hard-wired one.
//! [`RemoteSigner`] is the implementation backed by the remote-signer service;
//! a caller can equally supply a local keystore, an HSM/KMS client or a test
//! double without the calling code changing.
//!
//! Every trait is object-safe, so `Box<dyn TransactionSigner>` works and the
//! backend can be chosen at runtime from configuration.

use crate::error::Error;
use crate::evm::{
    HashPayload, MessagePayload, RawMessagePayload, SignRequest, Transaction, TransactionPayload,
    TypedDataPayload, SIGN_TYPE_EIP191, SIGN_TYPE_HASH, SIGN_TYPE_PERSONAL, SIGN_TYPE_RAW_MESSAGE,
    SIGN_TYPE_TRANSACTION, SIGN_TYPE_TYPED_DATA,
};

/// Exposes the address a signer signs for.
pub trait AddressGetter {
    fn address(&self) -> &str;
}

/// Signs 32 pre-hashed bytes. No prefixing is applied.
pub trait HashSigner {
    fn sign_hash(&self, hash: &str) -> Result<Vec<u8>, Error>;
}

/// Signs raw bytes with no EIP-191 prefix.
pub trait RawMessageSigner {
    fn sign_raw_message(&self, raw: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Signs an EIP-191 formatted message.
pub trait Eip191Signer {
    fn sign_eip191_message(&self, message: &str) -> Result<Vec<u8>, Error>;
}

/// Signs via `personal_sign` (EIP-191 version byte `0x45`).
pub trait PersonalSigner {
    fn personal_sign(&self, data: &str) -> Result<Vec<u8>, Error>;
}

/// Signs EIP-712 typed data.
pub trait TypedDataSigner {
    fn sign_typed_data(&self, typed_data: &serde_json::Value) -> Result<Vec<u8>, Error>;
}

/// Signs a transaction, returning the encoded signed transaction bytes ready
/// to broadcast.
pub trait TransactionSigner {
    fn sign_transaction(&self, tx: &Transaction) -> Result<Vec<u8>, Error>;
}

/// Accepts `0x`-prefixed hex, bare hex, or base64 — matching the Go SDK's
/// tolerance for how the server encodes signatures.
pub(crate) fn decode_hex_or_base64(s: &str) -> Result<Vec<u8>, Error> {
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use base64::Engine;

    if let Some(rest) = s.strip_prefix("0x") {
        return hex::decode(rest)
            .map_err(|e| Error::InvalidConfig(format!("invalid hex signature: {e}")));
    }
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return hex::decode(s)
            .map_err(|e| Error::InvalidConfig(format!("invalid hex signature: {e}")));
    }
    BASE64_STD
        .decode(s)
        .map_err(|e| Error::InvalidConfig(format!("invalid base64 signature: {e}")))
}

pub(crate) fn decode_signature(sig: Option<&str>) -> Result<Vec<u8>, Error> {
    match sig {
        Some(s) if !s.is_empty() => decode_hex_or_base64(s),
        _ => Err(Error::InvalidPayload),
    }
}

pub(crate) fn build_request(
    chain_id: &str,
    address: &str,
    sign_type: &str,
    payload: serde_json::Value,
) -> SignRequest {
    SignRequest {
        chain_id: chain_id.to_string(),
        signer_address: address.to_string(),
        sign_type: sign_type.to_string(),
        payload,
    }
}

/// Builds the payload for each sign type. Shared by the blocking and async
/// signers so the wire format cannot diverge between them.
pub(crate) mod payload {
    use super::*;

    pub fn hash(hash: &str) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(HashPayload {
            hash: hash.to_string(),
        })?)
    }

    pub fn raw_message(raw: &[u8]) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(RawMessagePayload {
            raw_message: raw.to_vec(),
        })?)
    }

    pub fn message(message: &str) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(MessagePayload {
            message: message.to_string(),
        })?)
    }

    pub fn typed_data(typed_data: &serde_json::Value) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(TypedDataPayload {
            typed_data: typed_data.clone(),
        })?)
    }

    pub fn transaction(tx: &Transaction) -> Result<serde_json::Value, Error> {
        Ok(serde_json::to_value(TransactionPayload {
            transaction: tx.clone(),
        })?)
    }
}

/// A signer backed by the remote-signer service.
///
/// Submits through [`crate::evm::SignService`], so the service's rule engine
/// and budgets apply to every signature.
#[derive(Clone)]
pub struct RemoteSigner {
    sign: crate::evm::SignService,
    address: String,
    chain_id: String,
}

impl RemoteSigner {
    pub fn new(
        sign: crate::evm::SignService,
        address: impl Into<String>,
        chain_id: impl Into<String>,
    ) -> Self {
        Self {
            sign,
            address: address.into(),
            chain_id: chain_id.into(),
        }
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub fn set_chain_id(&mut self, chain_id: impl Into<String>) {
        self.chain_id = chain_id.into();
    }

    fn submit(&self, sign_type: &str, payload: serde_json::Value) -> Result<Vec<u8>, Error> {
        let req = build_request(&self.chain_id, &self.address, sign_type, payload);
        let resp = self.sign.execute(&req)?;
        decode_signature(resp.signature.as_deref())
    }
}

impl AddressGetter for RemoteSigner {
    fn address(&self) -> &str {
        &self.address
    }
}

impl HashSigner for RemoteSigner {
    fn sign_hash(&self, hash: &str) -> Result<Vec<u8>, Error> {
        self.submit(SIGN_TYPE_HASH, payload::hash(hash)?)
    }
}

impl RawMessageSigner for RemoteSigner {
    fn sign_raw_message(&self, raw: &[u8]) -> Result<Vec<u8>, Error> {
        self.submit(SIGN_TYPE_RAW_MESSAGE, payload::raw_message(raw)?)
    }
}

impl Eip191Signer for RemoteSigner {
    fn sign_eip191_message(&self, message: &str) -> Result<Vec<u8>, Error> {
        self.submit(SIGN_TYPE_EIP191, payload::message(message)?)
    }
}

impl PersonalSigner for RemoteSigner {
    fn personal_sign(&self, data: &str) -> Result<Vec<u8>, Error> {
        self.submit(SIGN_TYPE_PERSONAL, payload::message(data)?)
    }
}

impl TypedDataSigner for RemoteSigner {
    fn sign_typed_data(&self, typed_data: &serde_json::Value) -> Result<Vec<u8>, Error> {
        self.submit(SIGN_TYPE_TYPED_DATA, payload::typed_data(typed_data)?)
    }
}

impl TransactionSigner for RemoteSigner {
    fn sign_transaction(&self, tx: &Transaction) -> Result<Vec<u8>, Error> {
        let req = build_request(
            &self.chain_id,
            &self.address,
            SIGN_TYPE_TRANSACTION,
            payload::transaction(tx)?,
        );
        let resp = self.sign.execute(&req)?;
        match resp.signed_data.as_deref() {
            Some(s) if !s.is_empty() => decode_hex_or_base64(s),
            _ => Err(Error::InvalidPayload),
        }
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use async_trait::async_trait;

    #[async_trait]
    pub trait AsyncHashSigner: Send + Sync {
        async fn sign_hash(&self, hash: &str) -> Result<Vec<u8>, Error>;
    }

    #[async_trait]
    pub trait AsyncRawMessageSigner: Send + Sync {
        async fn sign_raw_message(&self, raw: &[u8]) -> Result<Vec<u8>, Error>;
    }

    #[async_trait]
    pub trait AsyncEip191Signer: Send + Sync {
        async fn sign_eip191_message(&self, message: &str) -> Result<Vec<u8>, Error>;
    }

    #[async_trait]
    pub trait AsyncPersonalSigner: Send + Sync {
        async fn personal_sign(&self, data: &str) -> Result<Vec<u8>, Error>;
    }

    #[async_trait]
    pub trait AsyncTypedDataSigner: Send + Sync {
        async fn sign_typed_data(&self, typed_data: &serde_json::Value)
            -> Result<Vec<u8>, Error>;
    }

    #[async_trait]
    pub trait AsyncTransactionSigner: Send + Sync {
        async fn sign_transaction(&self, tx: &Transaction) -> Result<Vec<u8>, Error>;
    }

    /// Non-blocking counterpart of [`RemoteSigner`].
    #[derive(Clone)]
    pub struct AsyncRemoteSigner {
        sign: crate::evm::AsyncSignService,
        address: String,
        chain_id: String,
    }

    impl AsyncRemoteSigner {
        pub fn new(
            sign: crate::evm::AsyncSignService,
            address: impl Into<String>,
            chain_id: impl Into<String>,
        ) -> Self {
            Self {
                sign,
                address: address.into(),
                chain_id: chain_id.into(),
            }
        }

        pub fn chain_id(&self) -> &str {
            &self.chain_id
        }

        pub fn set_chain_id(&mut self, chain_id: impl Into<String>) {
            self.chain_id = chain_id.into();
        }

        /// Automated callers should not sit on a human approval; this uses the
        /// non-waiting submit so a rule that requires approval surfaces at once.
        async fn submit(
            &self,
            sign_type: &str,
            payload: serde_json::Value,
        ) -> Result<Vec<u8>, Error> {
            let req = build_request(&self.chain_id, &self.address, sign_type, payload);
            let resp = self.sign.execute_no_wait(&req).await?;
            decode_signature(resp.signature.as_deref())
        }
    }

    impl AddressGetter for AsyncRemoteSigner {
        fn address(&self) -> &str {
            &self.address
        }
    }

    #[async_trait]
    impl AsyncHashSigner for AsyncRemoteSigner {
        async fn sign_hash(&self, hash: &str) -> Result<Vec<u8>, Error> {
            self.submit(SIGN_TYPE_HASH, payload::hash(hash)?).await
        }
    }

    #[async_trait]
    impl AsyncRawMessageSigner for AsyncRemoteSigner {
        async fn sign_raw_message(&self, raw: &[u8]) -> Result<Vec<u8>, Error> {
            self.submit(SIGN_TYPE_RAW_MESSAGE, payload::raw_message(raw)?)
                .await
        }
    }

    #[async_trait]
    impl AsyncEip191Signer for AsyncRemoteSigner {
        async fn sign_eip191_message(&self, message: &str) -> Result<Vec<u8>, Error> {
            self.submit(SIGN_TYPE_EIP191, payload::message(message)?)
                .await
        }
    }

    #[async_trait]
    impl AsyncPersonalSigner for AsyncRemoteSigner {
        async fn personal_sign(&self, data: &str) -> Result<Vec<u8>, Error> {
            self.submit(SIGN_TYPE_PERSONAL, payload::message(data)?)
                .await
        }
    }

    #[async_trait]
    impl AsyncTypedDataSigner for AsyncRemoteSigner {
        async fn sign_typed_data(
            &self,
            typed_data: &serde_json::Value,
        ) -> Result<Vec<u8>, Error> {
            self.submit(SIGN_TYPE_TYPED_DATA, payload::typed_data(typed_data)?)
                .await
        }
    }

    #[async_trait]
    impl AsyncTransactionSigner for AsyncRemoteSigner {
        async fn sign_transaction(&self, tx: &Transaction) -> Result<Vec<u8>, Error> {
            let req = build_request(
                &self.chain_id,
                &self.address,
                SIGN_TYPE_TRANSACTION,
                payload::transaction(tx)?,
            );
            let resp = self.sign.execute_no_wait(&req).await?;
            match resp.signed_data.as_deref() {
                Some(s) if !s.is_empty() => decode_hex_or_base64(s),
                _ => Err(Error::InvalidPayload),
            }
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::{
    AsyncEip191Signer, AsyncHashSigner, AsyncPersonalSigner, AsyncRawMessageSigner,
    AsyncRemoteSigner, AsyncTransactionSigner, AsyncTypedDataSigner,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_decoding_accepts_hex_and_base64() {
        assert_eq!(decode_hex_or_base64("0x010203").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_hex_or_base64("010203").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_hex_or_base64("AQID").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn empty_or_missing_signature_is_an_error() {
        assert!(matches!(
            decode_signature(None),
            Err(Error::InvalidPayload)
        ));
        assert!(matches!(
            decode_signature(Some("")),
            Err(Error::InvalidPayload)
        ));
    }

    #[test]
    fn payloads_are_wrapped_the_way_the_server_expects() {
        assert_eq!(payload::hash("0xabc").unwrap()["hash"], "0xabc");
        assert_eq!(payload::message("hi").unwrap()["message"], "hi");
        assert_eq!(payload::raw_message(&[1, 2, 3]).unwrap()["raw_message"], "AQID");

        let tx = Transaction::legacy("0", 21000, "1").nonce(3);
        let p = payload::transaction(&tx).unwrap();
        assert_eq!(p["transaction"]["nonce"], 3);

        let td = serde_json::json!({"primaryType": "Mail"});
        assert_eq!(payload::typed_data(&td).unwrap()["typed_data"]["primaryType"], "Mail");
    }

    /// A second backend can satisfy the same traits — that is the point of
    /// having them.
    struct FixedSigner(Vec<u8>);

    impl AddressGetter for FixedSigner {
        fn address(&self) -> &str {
            "0xfixed"
        }
    }

    impl TransactionSigner for FixedSigner {
        fn sign_transaction(&self, _tx: &Transaction) -> Result<Vec<u8>, Error> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn traits_are_object_safe_so_backends_are_swappable() {
        let signer: Box<dyn TransactionSigner> = Box::new(FixedSigner(vec![9, 9]));
        let tx = Transaction::legacy("0", 21000, "1").nonce(0);
        assert_eq!(signer.sign_transaction(&tx).unwrap(), vec![9, 9]);
    }
}
