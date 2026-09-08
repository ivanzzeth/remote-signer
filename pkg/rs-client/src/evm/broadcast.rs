use reqwest::Method;

use crate::error::Error;
use crate::evm::paths;
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
            .request_json(Method::POST, paths::BROADCAST, Some(req), Some(&[200]))
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`BroadcastService`].
    #[derive(Clone)]
    pub struct AsyncBroadcastService {
        transport: AsyncTransport,
    }

    impl AsyncBroadcastService {
        pub fn new(transport: AsyncTransport) -> Self {
            Self { transport }
        }

        pub async fn broadcast(
            &self,
            req: &BroadcastRequest,
        ) -> Result<BroadcastResponse, Error> {
            self.transport
                .request_json(Method::POST, paths::BROADCAST, Some(req), Some(&[200]))
                .await
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncBroadcastService;
