use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{ApiKey, CreateRequest, ListFilter, ListResponse, UpdateRequest};

#[derive(Clone)]
pub struct Service {
    transport: Transport,
}

impl Service {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn list(&self, filter: Option<&ListFilter>) -> Result<ListResponse, Error> {
        let mut path = String::from("/api/v1/api-keys");
        let mut params = vec![];
        if let Some(f) = filter {
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

    pub fn get(&self, id: &str) -> Result<ApiKey, Error> {
        let path = format!("/api/v1/api-keys/{}", urlencoding::encode(id));
        self.transport
            .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
    }

    pub fn create(&self, req: &CreateRequest) -> Result<ApiKey, Error> {
        self.transport
            .request_json(Method::POST, "/api/v1/api-keys", Some(req), Some(&[200, 201]))
    }

    pub fn update(&self, id: &str, req: &UpdateRequest) -> Result<ApiKey, Error> {
        let path = format!("/api/v1/api-keys/{}", urlencoding::encode(id));
        self.transport
            .request_json(Method::PATCH, &path, Some(req), Some(&[200]))
    }

    pub fn delete(&self, id: &str) -> Result<(), Error> {
        let path = format!("/api/v1/api-keys/{}", urlencoding::encode(id));
        let _ = self
            .transport
            .request_raw(Method::DELETE, &path, Option::<&()>::None, Some(&[200, 204]))?;
        Ok(())
    }
}
