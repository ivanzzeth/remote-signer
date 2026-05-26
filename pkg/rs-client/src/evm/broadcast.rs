use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{BroadcastRequest, BroadcastResponse};

#[derive(Clone)]
pub struct BroadcastService {
    transport: Transport,
}

impl BroadcastService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn broadcast(&self, req: &BroadcastRequest) -> Result<BroadcastResponse, Error> {
        self.transport
            .request_json(Method::POST, "/api/v1/evm/broadcast", Some(req), Some(&[200]))
    }
}
