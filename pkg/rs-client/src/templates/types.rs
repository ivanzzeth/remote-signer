use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariable {
    pub name: String,
    #[serde(rename = "type")]
    pub var_type: String,
    #[serde(default)]
    pub description: Option<String>,
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub template_type: String,
    pub mode: String,
    pub source: String,
    #[serde(default)]
    pub variables: Vec<TemplateVariable>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub budget_metering: Option<serde_json::Value>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub templates: Vec<Template>,
    pub total: i32,
}

#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub template_type: Option<String>,
    pub source: Option<String>,
    pub enabled: Option<bool>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub template_type: String,
    pub mode: String,
    #[serde(default)]
    pub variables: Vec<TemplateVariable>,
    pub config: serde_json::Value,
    #[serde(default)]
    pub budget_metering: Option<serde_json::Value>,
    #[serde(default)]
    pub test_variables: Option<std::collections::HashMap<String, String>>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    pub max_total: String,
    pub max_per_tx: String,
    #[serde(default)]
    pub max_tx_count: Option<i32>,
    #[serde(default)]
    pub alert_pct: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    pub period: String,
    #[serde(default)]
    pub start_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantiateRequest {
    #[serde(default)]
    pub template_name: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub variables: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub chain_type: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub api_key_id: Option<String>,
    #[serde(default)]
    pub signer_address: Option<String>,
    #[serde(default)]
    pub expires_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub expires_in: Option<String>,
    #[serde(default)]
    pub budget: Option<BudgetConfig>,
    #[serde(default)]
    pub schedule: Option<ScheduleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantiateResponse {
    pub rule: serde_json::Value,
    #[serde(default)]
    pub budget: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeInstanceResponse {
    pub status: String,
    pub rule_id: String,
}
