use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const SIGN_TYPE_HASH: &str = "hash";
pub const SIGN_TYPE_RAW_MESSAGE: &str = "raw_message";
pub const SIGN_TYPE_EIP191: &str = "eip191";
pub const SIGN_TYPE_PERSONAL: &str = "personal";
pub const SIGN_TYPE_TYPED_DATA: &str = "typed_data";
pub const SIGN_TYPE_TRANSACTION: &str = "transaction";

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_AUTHORIZING: &str = "authorizing";
pub const STATUS_SIGNING: &str = "signing";
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_REJECTED: &str = "rejected";
pub const STATUS_FAILED: &str = "failed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub chain_id: String,
    pub signer_address: String,
    pub sign_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub request_id: String,
    pub status: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signed_data: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub rule_matched_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestStatus {
    pub id: String,
    pub api_key_id: String,
    pub chain_type: String,
    pub chain_id: String,
    pub signer_address: String,
    pub sign_type: String,
    pub status: String,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signed_data: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub rule_matched_id: Option<String>,
    #[serde(default)]
    pub rule_matched_name: Option<String>,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub approved_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    #[serde(default)]
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRequestsResponse {
    pub requests: Vec<RequestStatus>,
    pub total: i32,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub next_cursor_id: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListRequestsFilter {
    pub status: Option<String>,
    pub signer_address: Option<String>,
    pub chain_id: Option<String>,
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    pub cursor_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveRequest {
    pub approved: bool,
    #[serde(default)]
    pub rule_type: Option<String>,
    #[serde(default)]
    pub rule_mode: Option<String>,
    #[serde(default)]
    pub rule_name: Option<String>,
    #[serde(default)]
    pub max_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewRuleRequest {
    pub rule_type: String,
    pub rule_mode: String,
    #[serde(default)]
    pub rule_name: Option<String>,
    #[serde(default)]
    pub max_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewRuleResponse {
    pub rule: Rule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveResponse {
    pub request_id: String,
    pub status: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signed_data: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub generated_rule: Option<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub mode: String,
    pub source: String,
    #[serde(default)]
    pub chain_type: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub api_key_id: Option<String>,
    #[serde(default)]
    pub signer_address: Option<String>,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    #[serde(default)]
    pub expires_at: Option<OffsetDateTime>,
    pub match_count: u64,
    #[serde(default)]
    pub last_matched_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub budget_period: Option<String>,
    #[serde(default)]
    pub budget_period_start: Option<String>,
    #[serde(default)]
    pub variables: Option<serde_json::Value>,
    #[serde(default)]
    pub variable_defs: Option<Vec<RuleVariableDef>>,
    #[serde(default)]
    pub matrix: Option<serde_json::Value>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub immutable: bool,
    #[serde(default)]
    pub applied_to: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleVariableDef {
    pub name: String,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub required: bool,
    #[serde(default)]
    pub default_value: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default)]
    pub hint: Option<String>,
    #[serde(default)]
    pub options: Option<Vec<String>>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRulesResponse {
    pub rules: Vec<Rule>,
    pub total: i32,
}

#[derive(Debug, Clone, Default)]
pub struct ListRulesFilter {
    pub chain_type: Option<String>,
    pub signer_address: Option<String>,
    pub api_key_id: Option<String>,
    pub rule_type: Option<String>,
    pub mode: Option<String>,
    pub enabled: Option<bool>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub mode: String,
    #[serde(default)]
    pub chain_type: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub api_key_id: Option<String>,
    #[serde(default)]
    pub signer_address: Option<String>,
    pub config: serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateRuleRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub variables: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub matrix: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBudget {
    pub id: String,
    pub rule_id: String,
    pub unit: String,
    pub max_total: String,
    pub max_per_tx: String,
    pub spent: String,
    pub alert_pct: i32,
    pub alert_sent: bool,
    pub tx_count: i32,
    pub max_tx_count: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedKeyInfo {
    pub id: String,
    pub name: String,
    pub access_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    pub address: String,
    #[serde(rename = "type")]
    pub signer_type: String,
    pub enabled: bool,
    pub locked: bool,
    #[serde(default)]
    pub unlocked_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub allowed_keys: Vec<AllowedKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSignersResponse {
    pub signers: Vec<Signer>,
    pub total: i32,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListSignersFilter {
    pub signer_type: Option<String>,
    pub offset: Option<i32>,
    pub limit: Option<i32>,
}

/// Response from POST /api/v1/evm/signers (create); server does not return `locked`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSignerResponse {
    pub address: String,
    #[serde(rename = "type")]
    pub signer_type: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSignerRequest {
    #[serde(rename = "type")]
    pub signer_type: String,
    #[serde(default)]
    pub keystore: Option<CreateKeystoreParams>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeystoreParams {
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockSignerRequest {
    pub password: String,
}

pub type UnlockSignerResponse = Signer;
pub type LockSignerResponse = Signer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    pub address: String,
    #[serde(rename = "type")]
    pub signer_type: String,
    pub enabled: bool,
    pub locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateHdWalletRequest {
    pub action: String,
    pub password: String,
    #[serde(default)]
    pub mnemonic: Option<String>,
    #[serde(default)]
    pub entropy_bits: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HdWalletResponse {
    pub primary_address: String,
    pub base_path: String,
    pub derived_count: i32,
    #[serde(default)]
    pub derived: Vec<SignerInfo>,
    pub locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListHdWalletsResponse {
    pub wallets: Vec<HdWalletResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeriveAddressRequest {
    #[serde(default)]
    pub index: Option<u32>,
    #[serde(default)]
    pub start: Option<u32>,
    #[serde(default)]
    pub count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeriveAddressResponse {
    pub derived: Vec<SignerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDerivedAddressesResponse {
    pub derived: Vec<SignerInfo>,
}

// ── Signer lifecycle ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOwnershipRequest {
    pub new_owner_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantAccessRequest {
    pub api_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerAccessEntry {
    pub api_key_id: String,
    pub granted_by: String,
    pub created_at: OffsetDateTime,
}

// ── Broadcast ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastRequest {
    pub chain_id: String,
    pub signed_tx_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastResponse {
    pub tx_hash: String,
}

// ── Simulation ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateRequest {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub gas: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateResponse {
    pub success: bool,
    pub gas_used: u64,
    pub balance_changes: Vec<BalanceChange>,
    pub events: Vec<SimEvent>,
    pub has_approval: bool,
    #[serde(default)]
    pub revert_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceChange {
    pub token: String,
    pub standard: String,
    pub amount: String,
    pub direction: String,
    #[serde(default)]
    pub token_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimEvent {
    pub address: String,
    pub event: String,
    pub standard: String,
    pub args: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateBatchRequest {
    pub chain_id: String,
    pub from: String,
    pub transactions: Vec<SimulateTx>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateTx {
    pub to: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub gas: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateBatchResponse {
    pub results: Vec<SimulateResult>,
    pub net_balance_changes: Vec<BalanceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateResult {
    pub index: i32,
    pub success: bool,
    pub gas_used: u64,
    pub balance_changes: Vec<BalanceChange>,
    pub events: Vec<SimEvent>,
    pub has_approval: bool,
    #[serde(default)]
    pub revert_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationStatusResponse {
    pub enabled: bool,
    pub engine_version: String,
    pub chains: std::collections::HashMap<String, ChainStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    pub status: String,
    pub port: i32,
    #[serde(default)]
    pub block_number: Option<String>,
    pub restart_count: i32,
    pub dirty: bool,
    #[serde(default)]
    pub error: Option<String>,
}
