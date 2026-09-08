use reqwest::Method;

use crate::error::Error;
use crate::evm::paths;
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
        self.transport.request_raw(
            Method::POST,
            paths::GUARD_RESUME,
            Option::<&()>::None,
            Some(&[200]),
        )?;
        Ok(())
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::*;
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`GuardService`].
    #[derive(Clone)]
    pub struct AsyncGuardService {
        transport: AsyncTransport,
    }

    impl AsyncGuardService {
        pub fn new(transport: AsyncTransport) -> Self {
            Self { transport }
        }

        pub async fn resume(&self) -> Result<(), Error> {
            self.transport
                .request_raw(
                    Method::POST,
                    paths::GUARD_RESUME,
                    Option::<&()>::None,
                    Some(&[200]),
                )
                .await?;
            Ok(())
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncGuardService;
