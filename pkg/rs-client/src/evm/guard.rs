use reqwest::Method;

use crate::error::Error;
use crate::transport::transport::Transport;

#[derive(Clone)]
pub struct GuardService {
    transport: Transport,
}

impl GuardService {
    pub fn new(transport: Transport) -> Self {
        Self { transport }
    }

    pub fn resume(&self) -> Result<(), Error> {
        let _ = self
            .transport
            .request_raw(Method::POST, "/api/v1/evm/guard/resume", Option::<&()>::None, Some(&[200]))?;
        Ok(())
    }
}
