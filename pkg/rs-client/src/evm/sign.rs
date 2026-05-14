use std::thread::sleep;
use std::time::{Duration, Instant};

use reqwest::Method;

use crate::error::{Error, SignError};
use crate::transport::transport::Transport;

use super::{RequestStatus, SignRequest, SignResponse, STATUS_AUTHORIZING, STATUS_COMPLETED, STATUS_FAILED, STATUS_PENDING, STATUS_REJECTED};

#[derive(Clone)]
pub struct SignService {
    transport: Transport,
    poll_interval: Duration,
    poll_timeout: Duration,
}

impl SignService {
    pub fn new(transport: Transport, poll_interval: Duration, poll_timeout: Duration) -> Self {
        Self {
            transport,
            poll_interval,
            poll_timeout,
        }
    }

    pub fn execute(&self, req: &SignRequest) -> Result<SignResponse, Error> {
        self.sign_with_options(req, true)
    }

    pub fn execute_async(&self, req: &SignRequest) -> Result<SignResponse, Error> {
        self.sign_with_options(req, false)
    }

    fn sign_with_options(&self, req: &SignRequest, wait_for_approval: bool) -> Result<SignResponse, Error> {
        let resp: SignResponse = self.transport.request_json(
            Method::POST,
            "/api/v1/evm/sign",
            Some(req),
            Some(&[200, 201, 202]),
        )?;

        if resp.status == STATUS_COMPLETED {
            return Ok(resp);
        }

        if resp.status == STATUS_REJECTED || resp.status == STATUS_FAILED {
            return Err(Error::Sign(SignError {
                request_id: resp.request_id,
                status: resp.status,
                message: resp.message.unwrap_or_default(),
            }));
        }

        if wait_for_approval && (resp.status == STATUS_PENDING || resp.status == STATUS_AUTHORIZING) {
            return self.poll_for_result(&resp.request_id);
        }

        Err(Error::Sign(SignError {
            request_id: resp.request_id,
            status: resp.status,
            message: resp.message.unwrap_or_default(),
        }))
    }

    fn poll_for_result(&self, request_id: &str) -> Result<SignResponse, Error> {
        let start = Instant::now();
        loop {
            if start.elapsed() > self.poll_timeout {
                return Err(Error::Timeout);
            }
            sleep(self.poll_interval);

            let status: RequestStatus = self.transport.request_json(
                Method::GET,
                &format!("/api/v1/evm/requests/{}", urlencoding::encode(request_id)),
                Option::<&()>::None,
                Some(&[200]),
            )?;

            match status.status.as_str() {
                STATUS_COMPLETED => {
                    return Ok(SignResponse {
                        request_id: status.id,
                        status: status.status,
                        signature: status.signature,
                        signed_data: status.signed_data,
                        message: None,
                        rule_matched_id: status.rule_matched_id,
                    })
                }
                STATUS_REJECTED | STATUS_FAILED => {
                    return Err(Error::Sign(SignError {
                        request_id: status.id,
                        status: status.status,
                        message: status.error_message.unwrap_or_default(),
                    }))
                }
                _ => {}
            }
        }
    }
}
