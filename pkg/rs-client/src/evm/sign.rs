use std::time::Duration;

use reqwest::Method;

use crate::error::{Error, SignError};
use crate::evm::paths;
use crate::transport::transport::Transport;

use super::{
    RequestStatus, SignRequest, SignResponse, STATUS_AUTHORIZING, STATUS_COMPLETED, STATUS_FAILED,
    STATUS_PENDING, STATUS_REJECTED,
};

/// What to do after the server answers a sign request.
///
/// Kept separate from the HTTP call so the blocking and async services share
/// one state machine, and so it can be tested without a server.
#[derive(Debug)]
pub(crate) enum SignOutcome {
    /// Terminal success.
    Done(Box<SignResponse>),
    /// Approval pending — poll this request id until it settles.
    Poll(String),
    /// Terminal failure.
    Failed(SignError),
}

pub(crate) fn classify_sign_response(resp: SignResponse, wait_for_approval: bool) -> SignOutcome {
    if resp.status == STATUS_COMPLETED {
        return SignOutcome::Done(Box::new(resp));
    }

    let awaiting = resp.status == STATUS_PENDING || resp.status == STATUS_AUTHORIZING;
    if awaiting && wait_for_approval {
        return SignOutcome::Poll(resp.request_id);
    }

    SignOutcome::Failed(SignError {
        request_id: resp.request_id,
        status: resp.status,
        message: resp.message.unwrap_or_default(),
    })
}

/// Interpret one poll tick. `None` means "not settled yet, keep polling".
pub(crate) fn classify_poll_status(status: RequestStatus) -> Option<Result<SignResponse, Error>> {
    match status.status.as_str() {
        STATUS_COMPLETED => Some(Ok(SignResponse {
            request_id: status.id,
            status: status.status,
            signature: status.signature,
            signed_data: status.signed_data,
            message: None,
            rule_matched_id: status.rule_matched_id,
        })),
        STATUS_REJECTED | STATUS_FAILED => Some(Err(Error::Sign(SignError {
            request_id: status.id,
            status: status.status,
            message: status.error_message.unwrap_or_default(),
        }))),
        _ => None,
    }
}

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

    /// Submit and, if the request needs approval, block until it settles.
    pub fn execute(&self, req: &SignRequest) -> Result<SignResponse, Error> {
        self.sign_with_options(req, true)
    }

    /// Submit without waiting. A request that needs approval returns
    /// [`Error::Sign`] carrying the request id to poll later.
    pub fn execute_async(&self, req: &SignRequest) -> Result<SignResponse, Error> {
        self.sign_with_options(req, false)
    }

    pub fn execute_batch(&self, reqs: Vec<SignRequest>) -> Result<Vec<SignResponse>, Error> {
        self.transport.request_json(
            Method::POST,
            paths::SIGN_BATCH,
            Some(&reqs),
            Some(&[200, 201, 202]),
        )
    }

    fn sign_with_options(
        &self,
        req: &SignRequest,
        wait_for_approval: bool,
    ) -> Result<SignResponse, Error> {
        let resp: SignResponse = self.transport.request_json(
            Method::POST,
            paths::SIGN,
            Some(req),
            Some(&[200, 201, 202]),
        )?;

        match classify_sign_response(resp, wait_for_approval) {
            SignOutcome::Done(r) => Ok(*r),
            SignOutcome::Failed(e) => Err(Error::Sign(e)),
            SignOutcome::Poll(request_id) => self.poll_for_result(&request_id),
        }
    }

    fn poll_for_result(&self, request_id: &str) -> Result<SignResponse, Error> {
        let start = std::time::Instant::now();
        let path = paths::request(request_id);
        loop {
            if start.elapsed() > self.poll_timeout {
                return Err(Error::Timeout);
            }
            std::thread::sleep(self.poll_interval);

            let status: RequestStatus = self.transport.request_json(
                Method::GET,
                &path,
                Option::<&()>::None,
                Some(&[200]),
            )?;

            if let Some(settled) = classify_poll_status(status) {
                return settled;
            }
        }
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`SignService`].
    ///
    /// Shares the approval state machine with the blocking service; only the
    /// I/O and the sleep differ.
    #[derive(Clone)]
    pub struct AsyncSignService {
        transport: AsyncTransport,
        poll_interval: Duration,
        poll_timeout: Duration,
    }

    impl AsyncSignService {
        pub fn new(
            transport: AsyncTransport,
            poll_interval: Duration,
            poll_timeout: Duration,
        ) -> Self {
            Self {
                transport,
                poll_interval,
                poll_timeout,
            }
        }

        /// Submit and, if the request needs approval, await until it settles.
        ///
        /// Automated callers on a latency budget should prefer
        /// [`Self::execute_no_wait`]: a request that lands in `pending` means a
        /// rule requires human approval, which is usually a configuration
        /// problem rather than something to wait out.
        pub async fn execute(&self, req: &SignRequest) -> Result<SignResponse, Error> {
            self.sign_with_options(req, true).await
        }

        /// Submit without waiting. A request that needs approval returns
        /// [`Error::Sign`] carrying the request id to poll later.
        pub async fn execute_no_wait(&self, req: &SignRequest) -> Result<SignResponse, Error> {
            self.sign_with_options(req, false).await
        }

        pub async fn execute_batch(
            &self,
            reqs: Vec<SignRequest>,
        ) -> Result<Vec<SignResponse>, Error> {
            self.transport
                .request_json(
                    Method::POST,
                    paths::SIGN_BATCH,
                    Some(&reqs),
                    Some(&[200, 201, 202]),
                )
                .await
        }

        async fn sign_with_options(
            &self,
            req: &SignRequest,
            wait_for_approval: bool,
        ) -> Result<SignResponse, Error> {
            let resp: SignResponse = self
                .transport
                .request_json(Method::POST, paths::SIGN, Some(req), Some(&[200, 201, 202]))
                .await?;

            match classify_sign_response(resp, wait_for_approval) {
                SignOutcome::Done(r) => Ok(*r),
                SignOutcome::Failed(e) => Err(Error::Sign(e)),
                SignOutcome::Poll(request_id) => self.poll_for_result(&request_id).await,
            }
        }

        async fn poll_for_result(&self, request_id: &str) -> Result<SignResponse, Error> {
            let start = tokio::time::Instant::now();
            let path = paths::request(request_id);
            loop {
                if start.elapsed() > self.poll_timeout {
                    return Err(Error::Timeout);
                }
                tokio::time::sleep(self.poll_interval).await;

                let status: RequestStatus = self
                    .transport
                    .request_json(Method::GET, &path, Option::<&()>::None, Some(&[200]))
                    .await?;

                if let Some(settled) = classify_poll_status(status) {
                    return settled;
                }
            }
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncSignService;

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: &str) -> SignResponse {
        SignResponse {
            request_id: "req-1".to_string(),
            status: status.to_string(),
            signature: Some("0xsig".to_string()),
            signed_data: None,
            message: Some("because".to_string()),
            rule_matched_id: None,
        }
    }

    #[test]
    fn completed_is_terminal_success() {
        let out = classify_sign_response(response(STATUS_COMPLETED), true);
        assert!(matches!(out, SignOutcome::Done(r) if r.signature.as_deref() == Some("0xsig")));
    }

    #[test]
    fn pending_polls_when_waiting_is_requested() {
        for status in [STATUS_PENDING, STATUS_AUTHORIZING] {
            let out = classify_sign_response(response(status), true);
            assert!(matches!(out, SignOutcome::Poll(id) if id == "req-1"));
        }
    }

    #[test]
    fn pending_fails_fast_when_not_waiting() {
        // This is the path automated callers use: an approval-gated request is
        // surfaced immediately instead of blocking.
        let out = classify_sign_response(response(STATUS_PENDING), false);
        assert!(matches!(out, SignOutcome::Failed(e) if e.status == STATUS_PENDING));
    }

    #[test]
    fn rejected_and_failed_never_poll() {
        for status in [STATUS_REJECTED, STATUS_FAILED] {
            let out = classify_sign_response(response(status), true);
            assert!(matches!(out, SignOutcome::Failed(e) if e.status == status));
        }
    }

    #[test]
    fn failure_carries_server_message() {
        let out = classify_sign_response(response(STATUS_REJECTED), true);
        assert!(matches!(out, SignOutcome::Failed(e) if e.message == "because"));
    }

    fn status_row(status: &str) -> RequestStatus {
        let epoch = time::OffsetDateTime::UNIX_EPOCH;
        RequestStatus {
            id: "req-1".to_string(),
            api_key_id: "key-1".to_string(),
            chain_type: "evm".to_string(),
            chain_id: "56".to_string(),
            signer_address: "0xabc".to_string(),
            sign_type: "tx".to_string(),
            status: status.to_string(),
            client_ip: None,
            payload: None,
            signature: Some("0xsig".to_string()),
            signed_data: None,
            error_message: Some("nope".to_string()),
            rule_matched_id: Some("rule-9".to_string()),
            rule_matched_name: None,
            approved_by: None,
            approved_at: None,
            created_at: epoch,
            updated_at: epoch,
            completed_at: None,
        }
    }

    #[test]
    fn poll_keeps_going_while_unsettled() {
        assert!(classify_poll_status(status_row(STATUS_PENDING)).is_none());
        assert!(classify_poll_status(status_row(STATUS_AUTHORIZING)).is_none());
    }

    #[test]
    fn poll_completion_maps_signature_and_rule() {
        let settled = classify_poll_status(status_row(STATUS_COMPLETED)).expect("settled");
        let resp = settled.expect("ok");
        assert_eq!(resp.signature.as_deref(), Some("0xsig"));
        assert_eq!(resp.rule_matched_id.as_deref(), Some("rule-9"));
    }

    #[test]
    fn poll_failure_uses_error_message_field() {
        let settled = classify_poll_status(status_row(STATUS_FAILED)).expect("settled");
        let err = settled.expect_err("should fail");
        assert!(matches!(err, Error::Sign(e) if e.message == "nope"));
    }
}
