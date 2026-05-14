use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub event_type: String,
    pub severity: String,
    pub timestamp: OffsetDateTime,
    #[serde(default)]
    pub api_key_id: Option<String>,
    #[serde(default)]
    pub actor_address: Option<String>,
    #[serde(default)]
    pub sign_request_id: Option<String>,
    #[serde(default)]
    pub signer_address: Option<String>,
    #[serde(default)]
    pub chain_type: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    #[serde(default)]
    pub error_message: String,
    #[serde(default)]
    pub request_method: Option<String>,
    #[serde(default)]
    pub request_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub records: Vec<Record>,
    pub total: i32,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub next_cursor_id: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub event_type: Option<String>,
    pub severity: Option<String>,
    pub api_key_id: Option<String>,
    pub signer_address: Option<String>,
    pub chain_type: Option<String>,
    pub chain_id: Option<String>,
    pub start_time: Option<OffsetDateTime>,
    pub end_time: Option<OffsetDateTime>,
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub cursor_id: Option<String>,
}
