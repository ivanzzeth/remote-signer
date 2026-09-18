use reqwest::Method;

use crate::error::Error;
use crate::evm::paths;
use crate::transport::transport::Transport;

use super::{
    ApproveRequest, ApproveResponse, ListRequestsFilter, ListRequestsResponse, PreviewRuleRequest,
    PreviewRuleResponse, RequestStatus, SimulateResponse,
};

#[derive(Clone)]
pub struct RequestService {
    transport: Transport,
}

impl RequestService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn get(&self, request_id: &str) -> Result<RequestStatus, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::request(request_id),
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn list(&self, filter: Option<&ListRequestsFilter>) -> Result<ListRequestsResponse, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::requests_list(filter),
            Option::<&()>::None,
            Some(&[200]),
        )
    }

    pub fn approve(&self, request_id: &str, req: &ApproveRequest) -> Result<ApproveResponse, Error> {
        self.transport.request_json(
            Method::POST,
            &paths::request_approve(request_id),
            Some(req),
            Some(&[200]),
        )
    }

    pub fn preview_rule(
        &self,
        request_id: &str,
        req: &PreviewRuleRequest,
    ) -> Result<PreviewRuleResponse, Error> {
        self.transport.request_json(
            Method::POST,
            &paths::request_preview_rule(request_id),
            Some(req),
            Some(&[200]),
        )
    }

    pub fn get_simulation(&self, request_id: &str) -> Result<SimulateResponse, Error> {
        self.transport.request_json(
            Method::GET,
            &paths::request_simulation(request_id),
            Option::<&()>::None,
            Some(&[200]),
        )
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`RequestService`].
    #[derive(Clone)]
    pub struct AsyncRequestService {
        transport: AsyncTransport,
    }

    impl AsyncRequestService {
        pub fn new(transport: AsyncTransport) -> Self {
            Self { transport }
        }

        pub async fn get(&self, request_id: &str) -> Result<RequestStatus, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::request(request_id),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn list(
            &self,
            filter: Option<&ListRequestsFilter>,
        ) -> Result<ListRequestsResponse, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::requests_list(filter),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }

        pub async fn approve(
            &self,
            request_id: &str,
            req: &ApproveRequest,
        ) -> Result<ApproveResponse, Error> {
            self.transport
                .request_json(
                    Method::POST,
                    &paths::request_approve(request_id),
                    Some(req),
                    Some(&[200]),
                )
                .await
        }

        pub async fn preview_rule(
            &self,
            request_id: &str,
            req: &PreviewRuleRequest,
        ) -> Result<PreviewRuleResponse, Error> {
            self.transport
                .request_json(
                    Method::POST,
                    &paths::request_preview_rule(request_id),
                    Some(req),
                    Some(&[200]),
                )
                .await
        }

        pub async fn get_simulation(&self, request_id: &str) -> Result<SimulateResponse, Error> {
            self.transport
                .request_json(
                    Method::GET,
                    &paths::request_simulation(request_id),
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncRequestService;
