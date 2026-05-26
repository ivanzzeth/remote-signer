use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

use super::{SimulateBatchRequest, SimulateBatchResponse, SimulateRequest, SimulateResponse, SimulationStatusResponse};

#[derive(Clone)]
pub struct SimulateService {
    transport: Transport,
}

impl SimulateService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn status(&self) -> Result<SimulationStatusResponse, Error> {
        self.transport
            .request_json(Method::GET, "/api/v1/evm/simulate/status", Option::<&()>::None, Some(&[200]))
    }

    pub fn simulate(&self, req: &SimulateRequest) -> Result<SimulateResponse, Error> {
        self.transport
            .request_json(Method::POST, "/api/v1/evm/simulate", Some(req), Some(&[200]))
    }

    pub fn simulate_batch(&self, req: &SimulateBatchRequest) -> Result<SimulateBatchResponse, Error> {
        self.transport
            .request_json(Method::POST, "/api/v1/evm/simulate/batch", Some(req), Some(&[200]))
    }
}
