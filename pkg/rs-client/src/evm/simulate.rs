use reqwest::Method;

use crate::error::Error;
use crate::evm::paths;
use crate::transport::transport::Transport;

use super::{
    SimulateBatchRequest, SimulateBatchResponse, SimulateRequest, SimulateResponse,
    SimulationStatusResponse,
};

#[derive(Clone)]
pub struct SimulateService {
    transport: Transport,
}

impl SimulateService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn status(&self) -> Result<SimulationStatusResponse, Error> {
        self.transport.request_json(
            Method::GET,
            paths::SIMULATE_STATUS,
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn simulate(&self, req: &SimulateRequest) -> Result<SimulateResponse, Error> {
        self.transport
            .request_json(Method::POST, paths::SIMULATE, Some(req), Some(&[200]))
    }

    pub fn simulate_batch(
        &self,
        req: &SimulateBatchRequest,
    ) -> Result<SimulateBatchResponse, Error> {
        self.transport
            .request_json(Method::POST, paths::SIMULATE_BATCH, Some(req), Some(&[200]))
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`SimulateService`].
    #[derive(Clone)]
    pub struct AsyncSimulateService {
        transport: AsyncTransport,
    }

    impl AsyncSimulateService {
        pub fn new(transport: AsyncTransport) -> Self {
            Self { transport }
        }

        pub async fn status(&self) -> Result<SimulationStatusResponse, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    paths::SIMULATE_STATUS,
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn simulate(&self, req: &SimulateRequest) -> Result<SimulateResponse, Error> {
            self.transport
                .request_json(Method::POST, paths::SIMULATE, Some(req), Some(&[200]))
                .await
        }

        pub async fn simulate_batch(
            &self,
            req: &SimulateBatchRequest,
        ) -> Result<SimulateBatchResponse, Error> {
            self.transport
                .request_json(Method::POST, paths::SIMULATE_BATCH, Some(req), Some(&[200]))
                .await
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncSimulateService;
