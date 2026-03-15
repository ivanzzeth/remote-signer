use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{ApproveRequest, ApproveResponse, ListRequestsFilter, ListRequestsResponse, PreviewRuleRequest, PreviewRuleResponse, RequestStatus};

#[derive(Clone)]
pub struct RequestService {
    transport: Transport,
}

impl RequestService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn get(&self, request_id: &str) -> Result<RequestStatus, Error> {
        let path = format!("/api/v1/evm/requests/{}", urlencoding::encode(request_id));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn list(&self, filter: Option<&ListRequestsFilter>) -> Result<ListRequestsResponse, Error> {
        let mut path = String::from("/api/v1/evm/requests");
        let mut params = vec![];
        if let Some(f) = filter {
            if let Some(v) = &f.status {
                params.push(format!("status={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.signer_address {
                params.push(format!("signer_address={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.chain_id {
                params.push(format!("chain_id={}", urlencoding::encode(v)));
            }
            if let Some(v) = f.limit {
                params.push(format!("limit={}", v));
            }
            if let Some(v) = &f.cursor {
                params.push(format!("cursor={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.cursor_id {
                params.push(format!("cursor_id={}", urlencoding::encode(v)));
            }
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn approve(&self, request_id: &str, req: &ApproveRequest) -> Result<ApproveResponse, Error> {
        let path = format!(
            "/api/v1/evm/requests/{}/approve",
            urlencoding::encode(request_id)
        );
        self.transport
            .request_json(Method::POST, &path, Some(req), Some(&[200]))
    }

    pub fn preview_rule(&self, request_id: &str, req: &PreviewRuleRequest) -> Result<PreviewRuleResponse, Error> {
        let path = format!(
            "/api/v1/evm/requests/{}/preview-rule",
            urlencoding::encode(request_id)
        );
        self.transport
            .request_json(Method::POST, &path, Some(req), Some(&[200]))
    }
}
