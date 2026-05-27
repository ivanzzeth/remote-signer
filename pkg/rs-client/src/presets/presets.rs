use std::collections::HashMap;

use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::transport::transport::Transport;

#[derive(Clone)]
pub struct Service {
    transport: Transport,
}

impl Service {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn list(&self) -> Result<ListResponse, Error> {
        self.transport
            .request_json(Method::GET, "/api/v1/presets", Option::<&()>::None, Some(&[200]))
    }

    pub fn vars(&self, id: &str) -> Result<VarsResponse, Error> {
        let path = format!("/api/v1/presets/{}/vars", urlencoding::encode(id));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn get(&self, id: &str) -> Result<DetailResponse, Error> {
        let path = format!("/api/v1/presets/{}", urlencoding::encode(id));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn apply(&self, id: &str, req: Option<&ApplyRequest>) -> Result<ApplyResponse, Error> {
        let path = format!("/api/v1/presets/{}/apply", urlencoding::encode(id));
        let r = req.unwrap_or(&ApplyRequest { variables: None });
        self.transport
            .request_json(Method::POST, &path, Some(r), Some(&[201]))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetEntry {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub chain_type: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub template_ids: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub presets: Vec<PresetEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarsResponse {
    #[serde(default)]
    pub override_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyRequest {
    #[serde(default)]
    pub variables: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResultItem {
    pub rule: serde_json::Value,
    #[serde(default)]
    pub budget: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableDetail {
    pub name: String,
    #[serde(rename = "type", default)]
    pub field_type: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_value: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailResponse {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub chain_type: Option<String>,
    #[serde(default)]
    pub chain_id: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub template_ids: Vec<String>,
    #[serde(default)]
    pub variables: Vec<VariableDetail>,
    #[serde(default)]
    pub matrix: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResponse {
    pub results: Vec<ApplyResultItem>,
}
