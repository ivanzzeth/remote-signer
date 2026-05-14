use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{CreateRequest, InstantiateRequest, InstantiateResponse, ListFilter, ListResponse, RevokeInstanceResponse, Template, UpdateRequest};

#[derive(Clone)]
pub struct Service {
    transport: Transport,
}

impl Service {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn list(&self, filter: Option<&ListFilter>) -> Result<ListResponse, Error> {
        let mut path = String::from("/api/v1/templates");
        let mut params = vec![];
        if let Some(f) = filter {
            if let Some(v) = &f.template_type {
                params.push(format!("type={}", urlencoding::encode(v)));
            }
            if let Some(v) = &f.source {
                params.push(format!("source={}", urlencoding::encode(v)));
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

    pub fn get(&self, template_id: &str) -> Result<Template, Error> {
        let path = format!("/api/v1/templates/{}", urlencoding::encode(template_id));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn create(&self, req: &CreateRequest) -> Result<Template, Error> {
        self.transport
            .request_json(Method::POST, "/api/v1/templates", Some(req), Some(&[200, 201]))
    }

    pub fn update(&self, template_id: &str, req: &UpdateRequest) -> Result<Template, Error> {
        let path = format!("/api/v1/templates/{}", urlencoding::encode(template_id));
        self.transport
            .request_json(Method::PATCH, &path, Some(req), Some(&[200]))
    }

    pub fn delete(&self, template_id: &str) -> Result<(), Error> {
        let path = format!("/api/v1/templates/{}", urlencoding::encode(template_id));
        let _ = self
            .transport
            .request_raw(Method::DELETE, &path, Option::<&()>::None, Some(&[200, 204]))?;
        Ok(())
    }

    pub fn instantiate(&self, template_id: &str, req: &InstantiateRequest) -> Result<InstantiateResponse, Error> {
        let path = format!("/api/v1/templates/{}/instantiate", urlencoding::encode(template_id));
        self.transport
            .request_json(Method::POST, &path, Some(req), Some(&[200, 201]))
    }

    pub fn revoke_instance(&self, rule_id: &str) -> Result<RevokeInstanceResponse, Error> {
        let path = format!("/api/v1/templates/instances/{}/revoke", urlencoding::encode(rule_id));
        self.transport
            .request_json(Method::POST, &path, Option::<&()>::None, Some(&[200]))
    }
}
