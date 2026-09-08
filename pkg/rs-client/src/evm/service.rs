use std::time::Duration;

use crate::transport::transport::Transport;

use super::{
    BroadcastService, GuardService, HdWalletService, RequestService, RuleService, SignService,
    SignerService, SimulateService,
};

#[derive(Clone)]
pub struct Service {
    pub sign: SignService,
    pub requests: RequestService,
    pub rules: RuleService,
    pub signers: SignerService,
    pub hdwallets: HdWalletService,
    pub guard: GuardService,
    pub broadcast: BroadcastService,
    pub simulate: SimulateService,
}

impl Service {
    pub fn new(transport: Transport, poll_interval: Duration, poll_timeout: Duration) -> Self {
        let sign = SignService::new(transport.clone(), poll_interval, poll_timeout);
        Self {
            requests: RequestService::new(transport.clone()),
            rules: RuleService::new(transport.clone()),
            signers: SignerService::new(transport.clone()),
            hdwallets: HdWalletService::new(transport.clone()),
            broadcast: BroadcastService::new(transport.clone()),
            simulate: SimulateService::new(transport.clone()),
            guard: GuardService::new(transport),
            sign,
        }
    }
}

#[cfg(feature = "async")]
mod asynchronous {
    use super::Duration;
    use crate::evm::{
        AsyncBroadcastService, AsyncGuardService, AsyncHdWalletService, AsyncRequestService,
        AsyncRuleService, AsyncSignService, AsyncSignerService, AsyncSimulateService,
    };
    use crate::transport::async_transport::AsyncTransport;

    /// Non-blocking counterpart of [`super::Service`].
    #[derive(Clone)]
    pub struct AsyncService {
        pub sign: AsyncSignService,
        pub requests: AsyncRequestService,
        pub rules: AsyncRuleService,
        pub signers: AsyncSignerService,
        pub hdwallets: AsyncHdWalletService,
        pub guard: AsyncGuardService,
        pub broadcast: AsyncBroadcastService,
        pub simulate: AsyncSimulateService,
    }

    impl AsyncService {
        pub fn new(
            transport: AsyncTransport,
            poll_interval: Duration,
            poll_timeout: Duration,
        ) -> Self {
            let sign = AsyncSignService::new(transport.clone(), poll_interval, poll_timeout);
            Self {
                requests: AsyncRequestService::new(transport.clone()),
                rules: AsyncRuleService::new(transport.clone()),
                signers: AsyncSignerService::new(transport.clone()),
                hdwallets: AsyncHdWalletService::new(transport.clone()),
                broadcast: AsyncBroadcastService::new(transport.clone()),
                simulate: AsyncSimulateService::new(transport.clone()),
                guard: AsyncGuardService::new(transport),
                sign,
            }
        }
    }
}

#[cfg(feature = "async")]
pub use asynchronous::AsyncService;
