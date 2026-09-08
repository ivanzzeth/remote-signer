use reqwest::Method;

use crate::error::Error;
use crate::evm::paths;
use crate::transport::transport::Transport;

use super::{
    CreateRuleRequest, ListRulesFilter, ListRulesResponse, ProposeRuleRequest, Rule, RuleBudget,
    UpdateRuleRequest,
};

fn toggle_body(enabled: bool) -> serde_json::Value {
    serde_json::json!({ "enabled": enabled })
}

fn reject_body(reason: &str) -> serde_json::Value {
    serde_json::json!({ "reason": reason })
}

#[derive(Clone)]
pub struct RuleService {
    transport: Transport,
}

impl RuleService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn list(&self, filter: Option<&ListRulesFilter>) -> Result<ListRulesResponse, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::rules_list(filter),
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn get(&self, rule_id: &str) -> Result<Rule, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::rule(rule_id),
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn create(&self, req: &CreateRuleRequest) -> Result<Rule, Error> {
        self.transport
            .request_json(Method::POST, paths::RULES, Some(req), Some(&[200, 201]))
    }

    pub fn update(&self, rule_id: &str, req: &UpdateRuleRequest) -> Result<Rule, Error> {
        self.transport
            .request_json(Method::PATCH, &paths::rule(rule_id), Some(req), Some(&[200]))
    }

    pub fn delete(&self, rule_id: &str) -> Result<(), Error> {
        self.transport.request_raw(
            Method::DELETE,
            &paths::rule(rule_id),
            Option::<&()>::None,
            Some(&[200, 204]),
        )?;
        Ok(())
    }

    pub fn toggle(&self, rule_id: &str, enabled: bool) -> Result<Rule, Error> {
        self.transport.request_json(
            Method::PATCH,
            &paths::rule(rule_id),
            Some(&toggle_body(enabled)),
            Some(&[200]),
        )
    }

    pub fn list_budgets(&self, rule_id: &str) -> Result<Vec<RuleBudget>, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::rule_budgets(rule_id),
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn approve_rule(&self, rule_id: &str) -> Result<(), Error> {
        self.transport.request_raw(
            Method::POST,
            &paths::rule_approve(rule_id),
            Option::<&()>::None,
            Some(&[200]),
        )?;
        Ok(())
    }

    pub fn reject_rule(&self, rule_id: &str, reason: &str) -> Result<(), Error> {
        self.transport.request_raw(
            Method::POST,
            &paths::rule_reject(rule_id),
            Some(&reject_body(reason)),
            Some(&[200]),
        )?;
        Ok(())
    }

    pub fn propose_rule(&self, rule_id: &str, req: &ProposeRuleRequest) -> Result<Rule, Error> {
        self.transport.request_json(
            Method::POST,
            &paths::rule_propose(rule_id),
            Some(req),
            Some(&[202]),
        )
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`RuleService`].
    #[derive(Clone)]
    pub struct AsyncRuleService {
        transport: AsyncTransport,
    }

    impl AsyncRuleService {
        pub fn new(transport: AsyncTransport) -> Self {
            Self { transport }
        }

        pub async fn list(
            &self,
            filter: Option<&ListRulesFilter>,
        ) -> Result<ListRulesResponse, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::rules_list(filter),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn get(&self, rule_id: &str) -> Result<Rule, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::rule(rule_id),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn create(&self, req: &CreateRuleRequest) -> Result<Rule, Error> {
            self.transport
                .request_json(Method::POST, paths::RULES, Some(req), Some(&[200, 201]))
                .await
        }

        pub async fn update(&self, rule_id: &str, req: &UpdateRuleRequest) -> Result<Rule, Error> {
            self.transport
                .request_json(Method::PATCH, &paths::rule(rule_id), Some(req), Some(&[200]))
                .await
        }

        pub async fn delete(&self, rule_id: &str) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::DELETE,
                    &paths::rule(rule_id),
                    Option::<&()>::None,
                    Some(&[200, 204]),
                )
                .await?;
            Ok(())
        }

        pub async fn toggle(&self, rule_id: &str, enabled: bool) -> Result<Rule, Error> {
            self.transport
                .request_json(
                    Method::PATCH,
                    &paths::rule(rule_id),
                    Some(&toggle_body(enabled)),
                    Some(&[200]),
                )
                .await
        }

        pub async fn list_budgets(&self, rule_id: &str) -> Result<Vec<RuleBudget>, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::rule_budgets(rule_id),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn approve_rule(&self, rule_id: &str) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::POST,
                    &paths::rule_approve(rule_id),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await?;
            Ok(())
        }

        pub async fn reject_rule(&self, rule_id: &str, reason: &str) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::POST,
                    &paths::rule_reject(rule_id),
                    Some(&reject_body(reason)),
                    Some(&[200]),
                )
                .await?;
            Ok(())
        }

        pub async fn propose_rule(
            &self,
            rule_id: &str,
            req: &ProposeRuleRequest,
        ) -> Result<Rule, Error> {
            self.transport
                .request_json(
                    Method::POST,
                    &paths::rule_propose(rule_id),
                    Some(req),
                    Some(&[202]),
                )
                .await
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncRuleService;
