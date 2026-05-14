use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub source: String,
    pub admin: bool,
    pub enabled: bool,
    pub rate_limit: i32,
    pub allow_all_signers: bool,
    pub allow_all_hd_wallets: bool,
    #[serde(default)]
    pub allowed_signers: Vec<String>,
    #[serde(default)]
    pub allowed_hd_wallets: Vec<String>,
    #[serde(default)]
    pub allowed_chain_types: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    #[serde(default)]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub keys: Vec<ApiKey>,
    pub total: i32,
}

#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub source: Option<String>,
    pub enabled: Option<bool>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRequest {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub admin: bool,
    #[serde(default)]
    pub rate_limit: Option<i32>,
    pub allow_all_signers: bool,
    pub allow_all_hd_wallets: bool,
    #[serde(default)]
    pub allowed_signers: Vec<String>,
    #[serde(default)]
    pub allowed_hd_wallets: Vec<String>,
    #[serde(default)]
    pub allowed_chain_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub admin: Option<bool>,
    #[serde(default)]
    pub rate_limit: Option<i32>,
    #[serde(default)]
    pub allow_all_signers: Option<bool>,
    #[serde(default)]
    pub allow_all_hd_wallets: Option<bool>,
    #[serde(default)]
    pub allowed_signers: Vec<String>,
    #[serde(default)]
    pub allowed_hd_wallets: Vec<String>,
    #[serde(default)]
    pub allowed_chain_types: Vec<String>,
}
