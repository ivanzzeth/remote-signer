use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{CreateRuleRequest, ListRulesFilter, ListRulesResponse, Rule, RuleBudget, UpdateRuleRequest};

#[derive(Clone)]
pub struct RuleService {
    transport: Transport,
}

impl RuleService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn list(&self, filter: Option<&ListRulesFilter>) -> Result<ListRulesResponse, Error> {
        let mut path = String::from("/api/v1/evm/rules");
        let mut params = vec![];
        if let Some(f) = filter {
            if let Some(v) = &f.chain_type {
                params.push(format!("chain_type={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.signer_address {
                params.push(format!("signer_address={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.api_key_id {
                params.push(format!("api_key_id={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.rule_type {
                params.push(format!("type={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.mode {
                params.push(format!("mode={}", urlencoding::encode(v)));
            }
            if let Some(v) = f.enabled {
                params.push(format!("enabled={}", v));
            }
            if let Some(v) = f.limit {
                params.push(format!("limit={}", v));
            }
            if let Some(v) = f.offset {
                params.push(format!("offset={}", v));
            }
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }

        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn get(&self, rule_id: &str) -> Result<Rule, Error> {
        let path = format!("/api/v1/evm/rules/{}", urlencoding::encode(rule_id));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn create(&self, req: &CreateRuleRequest) -> Result<Rule, Error> {
        self.transport
            .request_json(Method::POST, "/api/v1/evm/rules", Some(req), Some(&[200, 201]))
    }

    pub fn update(&self, rule_id: &str, req: &UpdateRuleRequest) -> Result<Rule, Error> {
        let path = format!("/api/v1/evm/rules/{}", urlencoding::encode(rule_id));
        self.transport
            .request_json(Method::PATCH, &path, Some(req), Some(&[200]))
    }

    pub fn delete(&self, rule_id: &str) -> Result<(), Error> {
        let path = format!("/api/v1/evm/rules/{}", urlencoding::encode(rule_id));
        let _ = self
            .transport
            .request_raw(Method::DELETE, &path, Option::<&()>::None, Some(&[200, 204]))?;
        Ok(())
    }

    pub fn toggle(&self, rule_id: &str, enabled: bool) -> Result<Rule, Error> {
        let path = format!("/api/v1/evm/rules/{}", urlencoding::encode(rule_id));
        let body = serde_json::json!({"enabled": enabled});
        self.transport
            .request_json(Method::PATCH, &path, Some(&body), Some(&[200]))
    }

    pub fn list_budgets(&self, rule_id: &str) -> Result<Vec<RuleBudget>, Error> {
        let path = format!("/api/v1/evm/rules/{}/budgets", urlencoding::encode(rule_id));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }
}
