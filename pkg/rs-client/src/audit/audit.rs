use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{ListFilter, ListResponse};

#[derive(Clone)]
pub struct Service {
    transport: Transport,
}

impl Service {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn list(&self, filter: Option<&ListFilter>) -> Result<ListResponse, Error> {
        let mut path = String::from("/api/v1/audit");
        let mut params = vec![];
        if let Some(f) = filter {
            if let Some(v) = &f.event_type {
                params.push(format!("event_type={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.severity {
                params.push(format!("severity={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.api_key_id {
                params.push(format!("api_key_id={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.signer_address {
                params.push(format!("signer_address={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.chain_type {
                params.push(format!("chain_type={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.chain_id {
                params.push(format!("chain_id={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.start_time {
                params.push(format!("start_time={}", urlencoding::encode(&v.format(&time::format_description::well_known::Rfc3339).map_err(|e| Error::InvalidConfig(e.to_string()))?)));
            }
            if let Some(v) = &f.end_time {
                params.push(format!("end_time={}", urlencoding::encode(&v.format(&time::format_description::well_known::Rfc3339).map_err(|e| Error::InvalidConfig(e.to_string()))?)));
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
}
