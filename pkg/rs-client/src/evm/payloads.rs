//! Typed sign payloads.
//!
//! `SignRequest::payload` is a raw `serde_json::Value`, so callers previously
//! had to hand-build the JSON the server expects. These types mirror the Go
//! SDK's payload structs field for field, including the JSON names, so a
//! transaction built here is accepted by the same handler.

use serde::{Deserialize, Serialize};

pub const TX_TYPE_LEGACY: &str = "legacy";
pub const TX_TYPE_EIP1559: &str = "eip1559";
pub const TX_TYPE_EIP2930: &str = "eip2930";

/// Go marshals `[]byte` as base64; serde would emit an array of numbers.
mod base64_bytes {
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64_STD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        BASE64_STD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashPayload {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMessagePayload {
    #[serde(with = "base64_bytes")]
    pub raw_message: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataPayload {
    pub typed_data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPayload {
    pub transaction: Transaction,
}

/// An EVM transaction to be signed.
///
/// Field names match the server's expected JSON exactly. Amounts are decimal
/// strings (wei), matching the Go SDK — not hex, and not numbers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub value: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data: String,
    /// Left unset, the **server** fetches the nonce with a single
    /// `eth_getTransactionCount`. That is fine for interactive wallet use and
    /// unsafe for concurrent automated signing on one address: two in-flight
    /// requests can be handed the same nonce. Automated callers should assign
    /// nonces themselves and always set this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    pub gas: u64,
    #[serde(rename = "gasPrice", default, skip_serializing_if = "String::is_empty")]
    pub gas_price: String,
    #[serde(rename = "gasTipCap", default, skip_serializing_if = "String::is_empty")]
    pub gas_tip_cap: String,
    #[serde(rename = "gasFeeCap", default, skip_serializing_if = "String::is_empty")]
    pub gas_fee_cap: String,
    #[serde(rename = "txType")]
    pub tx_type: String,
}

impl Transaction {
    /// Start a legacy (`gasPrice`) transaction.
    pub fn legacy(value: impl Into<String>, gas: u64, gas_price: impl Into<String>) -> Self {
        Self {
            to: None,
            value: value.into(),
            data: String::new(),
            nonce: None,
            gas,
            gas_price: gas_price.into(),
            gas_tip_cap: String::new(),
            gas_fee_cap: String::new(),
            tx_type: TX_TYPE_LEGACY.to_string(),
        }
    }

    /// Start an EIP-1559 (`gasTipCap` / `gasFeeCap`) transaction.
    pub fn eip1559(
        value: impl Into<String>,
        gas: u64,
        tip_cap: impl Into<String>,
        fee_cap: impl Into<String>,
    ) -> Self {
        Self {
            to: None,
            value: value.into(),
            data: String::new(),
            nonce: None,
            gas,
            gas_price: String::new(),
            gas_tip_cap: tip_cap.into(),
            gas_fee_cap: fee_cap.into(),
            tx_type: TX_TYPE_EIP1559.to_string(),
        }
    }

    pub fn to(mut self, to: impl Into<String>) -> Self {
        self.to = Some(to.into());
        self
    }

    pub fn data(mut self, data: impl Into<String>) -> Self {
        self.data = data.into();
        self
    }

    /// Set the nonce explicitly. See the field docs for why automated callers
    /// must do this.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// True when the caller assigned a nonce rather than deferring to the
    /// server. Automated callers can assert on this before signing.
    pub fn has_explicit_nonce(&self) -> bool {
        self.nonce.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_json_matches_server_field_names() {
        let tx = Transaction::eip1559("1000", 21000, "1", "2")
            .to("0xabc")
            .data("0xdeadbeef")
            .nonce(7);

        let v = serde_json::to_value(TransactionPayload { transaction: tx }).unwrap();
        let t = &v["transaction"];

        assert_eq!(t["to"], "0xabc");
        assert_eq!(t["value"], "1000");
        assert_eq!(t["data"], "0xdeadbeef");
        assert_eq!(t["nonce"], 7);
        assert_eq!(t["gas"], 21000);
        assert_eq!(t["gasTipCap"], "1");
        assert_eq!(t["gasFeeCap"], "2");
        assert_eq!(t["txType"], "eip1559");
        // Unset gas fields must be absent, not empty strings.
        assert!(t.get("gasPrice").is_none());
    }

    #[test]
    fn legacy_transaction_omits_1559_fields() {
        let tx = Transaction::legacy("0", 21000, "5000000000").to("0xabc");
        let v = serde_json::to_value(&tx).unwrap();

        assert_eq!(v["gasPrice"], "5000000000");
        assert!(v.get("gasTipCap").is_none());
        assert!(v.get("gasFeeCap").is_none());
        assert_eq!(v["txType"], "legacy");
    }

    #[test]
    fn unset_nonce_is_omitted_so_the_server_fetches_it() {
        let tx = Transaction::legacy("0", 21000, "1");
        assert!(!tx.has_explicit_nonce());
        let v = serde_json::to_value(&tx).unwrap();
        assert!(v.get("nonce").is_none());
    }

    #[test]
    fn raw_message_is_base64_like_the_go_sdk() {
        // Go marshals []byte as base64; a serde default would emit [1,2,3].
        let p = RawMessagePayload {
            raw_message: vec![1, 2, 3],
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["raw_message"], "AQID");

        let back: RawMessagePayload = serde_json::from_value(v).unwrap();
        assert_eq!(back.raw_message, vec![1, 2, 3]);
    }
}
